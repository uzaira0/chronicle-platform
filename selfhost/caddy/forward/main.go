// chronicle-forward publishes a service's ports for a container that has no route off the host.
//
// Docker publishes ports only on a network it connects to the host, and a container on such a
// network has a default route: if the host's upstream routes the bridge subnet, the container
// reaches the internet even with masquerading off. So web, Grafana and Fluent Bit sit on internal
// networks only, and this program, in a container with no data, credentials or volumes, holds
// their published ports and copies each TCP connection to them (docs/NETWORK-EGRESS.md).
//
//	chronicle-forward LISTEN=HOST:PORT[+proxy] ...
//	chronicle-forward -check LISTEN=HOST:PORT[+proxy] ...   (healthcheck: every listener accepts)
//	chronicle-forward -connect PORT -allow FILE              (egress-proxy: connect.go)
//	chronicle-forward -check -connect PORT                   (its healthcheck)
//
// +proxy starts each upstream connection with a PROXY protocol v2 header carrying the client's
// address, so Caddy's IP allowlists, rate limits and trusted proxies see the real client
// (Caddy's proxy_protocol listener wrapper accepts it from this container's address only).
//
// Go standard library only: nothing here comes from a third-party module.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	dialTimeout = 10 * time.Second
	// After one side has finished sending, the other gets this long to finish too, so a client
	// that never closes cannot hold a connection slot once Caddy has closed its side.
	drainTimeout = 60 * time.Second
)

// proxySignature opens every PROXY protocol v2 header (haproxy proxy-protocol.txt, section 2.2).
var proxySignature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

type mapping struct {
	listen   string // port number this program listens on
	upstream string // host:port it connects to
	proxy    bool   // send a PROXY v2 header first
}

func parseMapping(text string) (mapping, error) {
	listen, upstream, found := strings.Cut(text, "=")
	if !found {
		return mapping{}, fmt.Errorf("%q: want LISTEN=HOST:PORT[+proxy]", text)
	}
	port, err := strconv.Atoi(listen)
	if err != nil || port < 1 || port > 65535 {
		return mapping{}, fmt.Errorf("%q: listen port must be 1-65535", text)
	}
	upstream, proxy := strings.CutSuffix(upstream, "+proxy")
	host, upstreamPort, err := net.SplitHostPort(upstream)
	if err != nil || host == "" {
		return mapping{}, fmt.Errorf("%q: upstream must be HOST:PORT", text)
	}
	if number, err := strconv.Atoi(upstreamPort); err != nil || number < 1 || number > 65535 {
		return mapping{}, fmt.Errorf("%q: upstream port must be 1-65535", text)
	}
	return mapping{listen: listen, upstream: upstream, proxy: proxy}, nil
}

// proxyHeader is the PROXY v2 header for a connection from client to local.
func proxyHeader(client, local net.Addr) []byte {
	header := append([]byte{}, proxySignature...)
	source, sourceOK := client.(*net.TCPAddr)
	destination, destinationOK := local.(*net.TCPAddr)
	if !sourceOK || !destinationOK {
		// LOCAL command, no address: the receiver uses the connection's own addresses.
		return append(header, 0x20, 0x00, 0x00, 0x00)
	}
	var addresses []byte
	family := byte(0x11) // TCP over IPv4
	if source4, destination4 := source.IP.To4(), destination.IP.To4(); source4 != nil && destination4 != nil {
		addresses = append(append(addresses, source4...), destination4...)
	} else {
		family = 0x21 // TCP over IPv6
		addresses = append(append(addresses, source.IP.To16()...), destination.IP.To16()...)
	}
	addresses = binary.BigEndian.AppendUint16(addresses, uint16(source.Port))
	addresses = binary.BigEndian.AppendUint16(addresses, uint16(destination.Port))
	header = append(header, 0x21, family)
	header = binary.BigEndian.AppendUint16(header, uint16(len(addresses)))
	return append(header, addresses...)
}

// pipe copies one direction, then half-closes the destination so the other side sees EOF.
func pipe(destination, source *net.TCPConn, done chan<- struct{}) {
	_, _ = io.Copy(destination, source)
	_ = destination.CloseWrite()
	_ = source.CloseRead()
	done <- struct{}{}
}

func forward(client *net.TCPConn, route mapping) {
	defer client.Close()
	connection, err := net.DialTimeout("tcp", route.upstream, dialTimeout)
	if err != nil {
		log.Printf("forward %s -> %s: %v", route.listen, route.upstream, err)
		return
	}
	upstream := connection.(*net.TCPConn)
	defer upstream.Close()
	if route.proxy {
		if _, err := upstream.Write(proxyHeader(client.RemoteAddr(), client.LocalAddr())); err != nil {
			log.Printf("forward %s -> %s: PROXY header: %v", route.listen, route.upstream, err)
			return
		}
	}
	done := make(chan struct{}, 2)
	go pipe(upstream, client, done)
	go pipe(client, upstream, done)
	<-done
	deadline := time.Now().Add(drainTimeout)
	_ = client.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	<-done
}

func serve(listener *net.TCPListener, route mapping, slots chan struct{}) error {
	for {
		slots <- struct{}{}
		client, err := listener.AcceptTCP()
		if err != nil {
			<-slots
			var temporary interface{ Timeout() bool }
			if errors.As(err, &temporary) && temporary.Timeout() {
				continue
			}
			return err
		}
		go func() {
			defer func() { <-slots }()
			forward(client, route)
		}()
	}
}

func check(routes []mapping) error {
	for _, route := range routes {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", route.listen), 3*time.Second)
		if err != nil {
			return err
		}
		connection.Close()
	}
	return nil
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("chronicle-forward: ")
	checkOnly := flag.Bool("check", false, "exit 0 when every listener accepts a connection")
	maxConnections := flag.Int("max-connections", 4096, "open client connections across all listeners")
	connectPort := flag.String("connect", "", "serve an HTTP CONNECT proxy on this port (with -allow)")
	allowFile := flag.String("allow", "", "the CONNECT proxy's allowlist: one HOST:PORT per line")
	flag.Parse()
	if *connectPort != "" {
		if flag.NArg() != 0 || *maxConnections < 1 || (!*checkOnly && *allowFile == "") {
			fmt.Fprintln(os.Stderr, "usage: chronicle-forward [-max-connections N] -connect PORT -allow FILE | -check -connect PORT")
			os.Exit(2)
		}
		if *checkOnly {
			if err := check([]mapping{{listen: *connectPort}}); err != nil {
				log.Fatal(err)
			}
			return
		}
		runConnect(*connectPort, *allowFile, *maxConnections)
		return
	}
	if flag.NArg() == 0 || *maxConnections < 1 {
		fmt.Fprintln(os.Stderr, "usage: chronicle-forward [-check] [-max-connections N] LISTEN=HOST:PORT[+proxy] ...")
		os.Exit(2)
	}
	routes := make([]mapping, 0, flag.NArg())
	for _, argument := range flag.Args() {
		route, err := parseMapping(argument)
		if err != nil {
			log.Fatal(err)
		}
		routes = append(routes, route)
	}
	if *checkOnly {
		if err := check(routes); err != nil {
			log.Fatal(err)
		}
		return
	}
	slots := make(chan struct{}, *maxConnections)
	failed := make(chan error, len(routes))
	for _, route := range routes {
		address, err := net.ResolveTCPAddr("tcp", ":"+route.listen)
		if err != nil {
			log.Fatal(err)
		}
		listener, err := net.ListenTCP("tcp", address)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("listening on :%s for %s (PROXY header: %t)", route.listen, route.upstream, route.proxy)
		go func(route mapping) { failed <- serve(listener, route, slots) }(route)
	}
	log.Fatal(<-failed)
}
