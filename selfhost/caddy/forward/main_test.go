package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// upstream accepts one connection, reports the PROXY header (or nil) and what the client sent
// before closing its side, and answers "pong".
func upstream(t *testing.T, expectHeader bool) (string, <-chan [2][]byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	result := make(chan [2][]byte, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		var header []byte
		if expectHeader {
			fixed := make([]byte, 16)
			if _, err := io.ReadFull(reader, fixed); err != nil {
				return
			}
			rest := make([]byte, binary.BigEndian.Uint16(fixed[14:16]))
			if _, err := io.ReadFull(reader, rest); err != nil {
				return
			}
			header = append(fixed, rest...)
		}
		body, _ := io.ReadAll(reader) // the client half-closes after sending
		connection.Write([]byte("pong"))
		result <- [2][]byte{header, body}
	}()
	return listener.Addr().String(), result
}

func freePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
}

func start(t *testing.T, route mapping) {
	t.Helper()
	address, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:"+route.listen)
	listener, err := net.ListenTCP("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go serve(listener, route, make(chan struct{}, 8))
}

func exchange(t *testing.T, port string) (*net.TCPConn, []byte) {
	t.Helper()
	connection, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	client := connection.(*net.TCPConn)
	client.Write([]byte("ping"))
	client.CloseWrite()
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	answer, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	return client, answer
}

func TestForwardsBothDirectionsWithAProxyHeaderNamingTheClient(t *testing.T) {
	target, result := upstream(t, true)
	route := mapping{listen: freePort(t), upstream: target, proxy: true}
	start(t, route)
	client, answer := exchange(t, route.listen)
	defer client.Close()
	if string(answer) != "pong" {
		t.Fatalf("answer %q", answer)
	}
	got := <-result
	header, body := got[0], got[1]
	if string(body) != "ping" {
		t.Fatalf("upstream read %q", body)
	}
	if !bytes.Equal(header[:12], proxySignature) || header[12] != 0x21 || header[13] != 0x11 {
		t.Fatalf("not a PROXY v2 TCP4 header: % x", header[:16])
	}
	local := client.LocalAddr().(*net.TCPAddr)
	source := net.IP(header[16:20])
	sourcePort := binary.BigEndian.Uint16(header[24:26])
	destinationPort := binary.BigEndian.Uint16(header[26:28])
	if !source.Equal(local.IP) || int(sourcePort) != local.Port {
		t.Fatalf("header names %s:%d, client is %s", source, sourcePort, local)
	}
	if strconv.Itoa(int(destinationPort)) != route.listen {
		t.Fatalf("header destination port %d, listener %s", destinationPort, route.listen)
	}
}

func TestWithoutProxyTheStreamIsUnchanged(t *testing.T) {
	target, result := upstream(t, false)
	route := mapping{listen: freePort(t), upstream: target}
	start(t, route)
	client, answer := exchange(t, route.listen)
	defer client.Close()
	if got := <-result; string(answer) != "pong" || string(got[1]) != "ping" {
		t.Fatalf("answer %q, upstream read %q", answer, got[1])
	}
}

func TestAnUnreachableUpstreamClosesTheClient(t *testing.T) {
	route := mapping{listen: freePort(t), upstream: "127.0.0.1:" + freePort(t)}
	start(t, route)
	connection, err := net.Dial("tcp", "127.0.0.1:"+route.listen)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	// The forwarder closes the client (EOF, or a reset when the client's bytes were unread).
	answer, err := io.ReadAll(connection)
	if len(answer) != 0 || (err != nil && !errors.Is(err, syscall.ECONNRESET)) {
		t.Fatalf("answer %q, error %v from a closed upstream", answer, err)
	}
}

func TestIPv6ClientsGetATCP6Header(t *testing.T) {
	client := &net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 40000}
	local := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 8443}
	header := proxyHeader(client, local)
	if header[13] != 0x21 || binary.BigEndian.Uint16(header[14:16]) != 36 || !net.IP(header[16:32]).Equal(client.IP) {
		t.Fatalf("bad TCP6 header % x", header)
	}
	if got := proxyHeader(&net.UnixAddr{}, local); !bytes.Equal(got[12:], []byte{0x20, 0x00, 0x00, 0x00}) {
		t.Fatalf("non-TCP address must give a LOCAL header, got % x", got[12:])
	}
}

func TestMappingsAreValidated(t *testing.T) {
	for text, valid := range map[string]bool{
		"8443=web:443+proxy": true, "3000=grafana:3000": true, "0=web:443": false, "8443": false,
		"8443=web": false, "8443=:443": false, "8443=web:99999": false, "x=web:443": false,
	} {
		route, err := parseMapping(text)
		if (err == nil) != valid {
			t.Errorf("%s: valid=%t, err=%v", text, valid, err)
		}
		if text == "8443=web:443+proxy" && (route.listen != "8443" || route.upstream != "web:443" || !route.proxy) {
			t.Errorf("parsed %+v", route)
		}
	}
}

func TestCheckFailsUntilEveryListenerAccepts(t *testing.T) {
	route := mapping{listen: freePort(t), upstream: "127.0.0.1:9"}
	if check([]mapping{route}) == nil {
		t.Fatal("check passed with nothing listening")
	}
	start(t, route)
	if err := check([]mapping{route}); err != nil {
		t.Fatal(err)
	}
}
