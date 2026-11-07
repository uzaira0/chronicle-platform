package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeAllowlist(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allow")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// startProxy serves CONNECT on a free loopback port with the given allowlist file.
func startProxy(t *testing.T, allowFile string) string {
	t.Helper()
	allowed, err := loadAllowlist(allowFile)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go serveConnectListener(listener, allowed, make(chan struct{}, 8))
	return listener.Addr().String()
}

// connect sends a CONNECT for target and returns the status code and the open connection.
func connect(t *testing.T, proxy, target string) (int, net.Conn, *bufio.Reader) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close() })
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(connection, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, connection, reader
}

func TestAnAllowedTargetGetsATunnel(t *testing.T) {
	address, result := upstream(t, false)
	proxy := startProxy(t, writeAllowlist(t, "# comment", "", address))
	status, connection, reader := connect(t, proxy, address)
	if status != http.StatusOK {
		t.Fatalf("status %d, want 200", status)
	}
	io.WriteString(connection, "ping")
	connection.(*net.TCPConn).CloseWrite()
	answer, _ := io.ReadAll(reader)
	if string(answer) != "pong" {
		t.Fatalf("answer %q", answer)
	}
	if got := <-result; string(got[1]) != "ping" {
		t.Fatalf("upstream received %q", got[1])
	}
}

func TestATargetOutsideTheAllowlistIsRefusedWithoutAConnection(t *testing.T) {
	address, result := upstream(t, false)
	_, port, _ := net.SplitHostPort(address)
	proxy := startProxy(t, writeAllowlist(t, "chronicle.example.org:443"))
	for _, target := range []string{address, "127.0.0.1:" + port, "localhost:" + port, "chronicle.example.org:444",
		"evil.example:443", "chronicle.example.org.evil.example:443"} {
		if status, _, _ := connect(t, proxy, target); status != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", target, status)
		}
	}
	select {
	case <-result:
		t.Fatal("the proxy connected to a target outside its allowlist")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestOnlyConnectIsServed(t *testing.T) {
	address, _ := upstream(t, false)
	proxy := startProxy(t, writeAllowlist(t, address))
	connection, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	// A plain-HTTP proxy request (absolute URI) would send the request itself unencrypted.
	io.WriteString(connection, "GET http://"+address+"/ HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status %d, want 405", response.StatusCode)
	}
}

func TestAllowlistEntriesAreNormalised(t *testing.T) {
	allowed, err := loadAllowlist(writeAllowlist(t, "Chronicle.Example.ORG.:443", "[2001:DB8::5]:8443"))
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"chronicle.example.org:443", "CHRONICLE.example.org.:443", "[2001:db8::5]:8443"} {
		normal, err := normalizeTarget(target)
		if err != nil || !allowed[normal] {
			t.Errorf("%s: not allowed (%v)", target, err)
		}
	}
	for _, line := range []string{"no-port.example.org", "host:0", "host:70000", "user@host:443", "https://host:443"} {
		if _, err := loadAllowlist(writeAllowlist(t, line)); err == nil {
			t.Errorf("%q: accepted", line)
		}
	}
}

func TestAMissingAllowlistRefusesToStart(t *testing.T) {
	if _, err := loadAllowlist(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing allowlist loaded")
	}
}
