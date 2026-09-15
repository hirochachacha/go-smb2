package smb2

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
)

func TestResolveServerAddr(t *testing.T) {
	for _, tc := range []struct {
		serverName  string
		defaultPort int
		want        string
	}{
		{"example.com", 445, "example.com:445"},
		{"example.com:8445", 445, "example.com:8445"},
		{"127.0.0.1", 443, "127.0.0.1:443"},
		{"127.0.0.1:8443", 443, "127.0.0.1:8443"},
		{"::1", 445, "[::1]:445"},
		{"[::1]:8445", 445, "[::1]:8445"},
	} {
		got := resolveServerAddr(tc.serverName, tc.defaultPort)
		if got != tc.want {
			t.Errorf("resolveServerAddr(%q, %d) = %q, want %q", tc.serverName, tc.defaultPort, got, tc.want)
		}
	}
}

func TestTCPDialer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	// 1. Port from dialer
	d := TCPDialer{Port: port}
	tr, err := d.Dial(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	serverConn := <-accepted
	defer serverConn.Close()

	// 2. Port from serverName takes precedence over dialer Port
	dWrongPort := TCPDialer{Port: 1} // invalid port
	tr2, err := dWrongPort.Dial(context.Background(), net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("serverName port failed: %v", err)
	}
	defer tr2.Close()

	serverConn2 := <-accepted
	defer serverConn2.Close()
}

func TestQUICDialer(t *testing.T) {
	listener, clientTLS := newQUICTestListener(t)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				defer conn.CloseWithError(0, "done")
				stream, err := conn.AcceptStream(context.Background())
				if err != nil {
					return
				}
				defer stream.Close()
			}()
		}
	}()

	port := listener.Addr().(*net.UDPAddr).Port

	// 1. Port from dialer
	d := QUICDialer{
		Port:      port,
		TLSConfig: clientTLS,
	}
	tr, err := d.Dial(context.Background(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	// 2. Port from serverName takes precedence over dialer Port
	dWrongPort := QUICDialer{
		Port:      1, // invalid port
		TLSConfig: clientTLS,
	}
	tr2, err := dWrongPort.Dial(context.Background(), net.JoinHostPort("localhost", fmt.Sprintf("%d", port)))
	if err != nil {
		t.Fatalf("serverName port failed: %v", err)
	}
	defer tr2.Close()
}
