package main

// chronicle-forward -connect PORT -allow FILE: the self-host's one way out (docs/NETWORK-EGRESS.md).
//
// An HTTP CONNECT proxy that opens a tunnel only to a host:port listed in FILE, one per line
// ('#' starts a comment). Its clients (public-probe, and Grafana while the alert webhook is off
// the host) sit on an internal network with no route out and no external name resolution, so
// this is the only path any Chronicle container has to the internet. Everything else is refused
// before a name is resolved or a connection opened: a target outside the list (403), and any
// method but CONNECT (405), which also refuses plain-HTTP forwarding.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// headerTimeout bounds how long a client may take to send its CONNECT request.
const headerTimeout = 10 * time.Second

// normalizeTarget returns host:port with the host lower-cased and without a trailing dot, or an
// error for anything that is not exactly HOST:PORT.
func normalizeTarget(authority string) (string, error) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil || host == "" {
		return "", fmt.Errorf("%q: want HOST:PORT", authority)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", fmt.Errorf("%q: port must be 1-65535", authority)
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || strings.ContainsAny(host, "/@ \t\\") {
		return "", fmt.Errorf("%q: not a host name or address", authority)
	}
	if address := net.ParseIP(host); address != nil {
		host = address.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(number)), nil
}

// loadAllowlist reads FILE. A missing or malformed file is an error: the proxy does not start
// with a list it cannot read.
func loadAllowlist(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for number, line := range strings.Split(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		target, err := normalizeTarget(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, number+1, err)
		}
		allowed[target] = true
	}
	return allowed, nil
}

func reply(connection net.Conn, status int) {
	fmt.Fprintf(connection, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status))
}

func tunnel(client *net.TCPConn, allowed map[string]bool) {
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(headerTimeout))
	reader := bufio.NewReaderSize(client, 4096)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	if request.Method != http.MethodConnect {
		log.Printf("refused %s (only CONNECT is served)", request.Method)
		reply(client, http.StatusMethodNotAllowed)
		return
	}
	target, err := normalizeTarget(request.Host)
	if err != nil || !allowed[target] {
		log.Printf("refused CONNECT %q: not in the allowlist", request.Host)
		reply(client, http.StatusForbidden)
		return
	}
	connection, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		log.Printf("CONNECT %s: %v", target, err)
		reply(client, http.StatusBadGateway)
		return
	}
	upstream := connection.(*net.TCPConn)
	defer upstream.Close()
	_ = client.SetReadDeadline(time.Time{})
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	// Bytes the client sent right behind its request (a TLS ClientHello) are already buffered.
	if buffered := reader.Buffered(); buffered > 0 {
		pending, _ := reader.Peek(buffered)
		if _, err := upstream.Write(pending); err != nil {
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

func serveConnectListener(listener *net.TCPListener, allowed map[string]bool, slots chan struct{}) error {
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
			tunnel(client, allowed)
		}()
	}
}

// runConnect serves the CONNECT proxy on port until the listener fails.
func runConnect(port, allowFile string, maxConnections int) {
	allowed, err := loadAllowlist(allowFile)
	if err != nil {
		log.Fatal(err)
	}
	address, err := net.ResolveTCPAddr("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("CONNECT proxy on :%s for %d allowed target(s)", port, len(allowed))
	log.Fatal(serveConnectListener(listener, allowed, make(chan struct{}, maxConnections)))
}
