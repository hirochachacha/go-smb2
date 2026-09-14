package smb2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/quic-go/quic-go"
)

func TestDialQUICTransportFramesPackets(t *testing.T) {
	listener, clientTLS := newQUICTestListener(t)
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.CloseWithError(0, "test complete")
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()
		frame := make([]byte, 4)
		if _, err := io.ReadFull(stream, frame); err != nil {
			serverDone <- err
			return
		}
		got := be.Uint32(frame)
		if got != uint32(len("request")) {
			serverDone <- errors.New("unexpected request frame size")
			return
		}
		body := make([]byte, got)
		if _, err := io.ReadFull(stream, body); err != nil {
			serverDone <- err
			return
		}
		if string(body) != "request" {
			serverDone <- errors.New("unexpected request body")
			return
		}
		be.PutUint32(frame, uint32(len("response")))
		if _, err := stream.Write(append(frame, []byte("response")...)); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
		// Keep the connection open until the client closes it. This avoids
		// combining the final response with an EOF before the client has
		// consumed the framed packet.
		_, _ = io.Copy(io.Discard, stream)
	}()

	transport, err := DialQUICTransport(context.Background(), listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if err := transport.Send([]byte("req"), []byte("uest")); err != nil {
		t.Fatal(err)
	}
	response, err := transport.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("response = %q, want response", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialQUICTransportCloseUnblocksReceive(t *testing.T) {
	listener, clientTLS := newQUICTestListener(t)
	defer listener.Close()

	serverReady := make(chan struct{})
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "test complete")
		stream, err := conn.AcceptStream(context.Background())
		if err == nil {
			close(serverReady)
			_, _ = io.Copy(io.Discard, stream)
		}
	}()

	transport, err := DialQUICTransport(context.Background(), listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if err := transport.Send([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-serverReady:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not accept the QUIC stream")
	}

	readDone := make(chan error, 1)
	go func() {
		_, err := transport.Receive()
		readDone <- err
	}()
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("Receive returned nil after transport close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Receive remained blocked after transport close")
	}
}

func TestDialQUICTransportWriteDeadline(t *testing.T) {
	listener, clientTLS := newQUICTestListener(t, &quic.Config{
		InitialStreamReceiveWindow:     64 << 10,
		MaxStreamReceiveWindow:         64 << 10,
		InitialConnectionReceiveWindow: 64 << 10,
		MaxConnectionReceiveWindow:     64 << 10,
	})
	defer listener.Close()

	serverStop := make(chan struct{})
	defer close(serverStop)
	go func() {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "test complete")
		_, err = conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		<-serverStop
	}()

	transport, err := DialQUICTransport(context.Background(), listener.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if err := transport.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	err = transport.Send(make([]byte, 8<<20))
	if err == nil {
		t.Fatal("Send completed despite a blocked QUIC peer")
	}
	var timeoutErr interface{ Timeout() bool }
	if !errors.As(err, &timeoutErr) || !timeoutErr.Timeout() {
		t.Fatalf("Send error = %T %v, want a timeout", err, err)
	}
}

func TestDialQUICTransportRejectsCertificateName(t *testing.T) {
	listener, clientTLS := newQUICTestListener(t)
	defer listener.Close()
	clientTLS.ServerName = "other.example"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := DialQUICTransport(ctx, listener.Addr().String(), clientTLS)
	if err == nil {
		t.Fatal("DialQUICTransport accepted a certificate name mismatch")
	}
	var hostnameErr x509.HostnameError
	if !errors.As(err, &hostnameErr) {
		t.Fatalf("certificate mismatch error = %T %v, want x509.HostnameError", err, err)
	}
}

func TestDialQUICTransportRejectsUntrustedCertificate(t *testing.T) {
	listener, clientTLS := newQUICTestListener(t)
	defer listener.Close()
	clientTLS.RootCAs = nil

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := DialQUICTransport(ctx, listener.Addr().String(), clientTLS)
	if err == nil {
		t.Fatal("DialQUICTransport accepted an untrusted certificate")
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("untrusted certificate error = %T %v, want x509.UnknownAuthorityError", err, err)
	}
}

func TestCloneQUICClientTLSDoesNotMutateConfig(t *testing.T) {
	original := &tls.Config{NextProtos: []string{"other"}}
	cloned := cloneQUICClientTLS("localhost:443", original)
	if cloned.MinVersion != tls.VersionTLS13 || cloned.ServerName != "localhost" {
		t.Fatalf("cloned TLS config = %#v", cloned)
	}
	if len(cloned.NextProtos) != 1 || cloned.NextProtos[0] != smbQUICALPN {
		t.Fatalf("cloned ALPN = %v", cloned.NextProtos)
	}
	if len(original.NextProtos) != 1 || original.NextProtos[0] != "other" {
		t.Fatalf("original TLS config was mutated: %v", original.NextProtos)
	}
}

func TestQUICTransportRequiresSMB311(t *testing.T) {
	_, err := (&negotiator{SpecifiedDialect: smb2.SMB302}).negotiate(
		context.Background(), quicDialectTransport{}, openAccount(8), 0, 0)
	if !errors.Is(err, errQUICTransportDialect) {
		t.Fatalf("negotiate error = %v, want %v", err, errQUICTransportDialect)
	}
}

type quicDialectTransport struct{}

func (quicDialectTransport) isSMBQUICTransport()              {}
func (quicDialectTransport) Send(...[]byte) error             { return nil }
func (quicDialectTransport) SetReadDeadline(time.Time) error  { return nil }
func (quicDialectTransport) SetWriteDeadline(time.Time) error { return nil }
func (quicDialectTransport) SetPacketReadTimeout(time.Duration) {}
func (quicDialectTransport) Receive() ([]byte, error)         { return nil, io.EOF }
func (quicDialectTransport) Close() error                     { return nil }

func newQUICTestListener(t *testing.T, configs ...*quic.Config) (*quic.Listener, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	var config *quic.Config
	if len(configs) > 0 {
		config = configs[0]
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{smbQUICALPN},
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return listener, &tls.Config{RootCAs: roots, ServerName: "localhost"}
}
