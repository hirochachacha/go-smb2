package smb2

import (
	"context"
	"encoding/asn1"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/auth"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

type testCredentialsFunc func(context.Context, string) (auth.Initiator, error)

func (f testCredentialsFunc) NewInitiator(ctx context.Context, serverName string) (auth.Initiator, error) {
	return f(ctx, serverName)
}

type transportDialerFunc func(context.Context, string) (Transport, error)

func (f transportDialerFunc) Dial(ctx context.Context, serverName string) (Transport, error) {
	return f(ctx, serverName)
}

type singleRoundInitiator struct {
	key      []byte
	complete bool
}

func (*singleRoundInitiator) OID() asn1.ObjectIdentifier { return spnego.NlmpOid }
func (i *singleRoundInitiator) InitSecContext() ([]byte, error) {
	i.complete = false
	return []byte("client-initial-token"), nil
}
func (i *singleRoundInitiator) AcceptSecContext(token []byte) ([]byte, error) {
	if string(token) != "server-final-token" {
		return nil, errors.New("unexpected server token")
	}
	i.complete = true
	return nil, nil
}
func (i *singleRoundInitiator) GetMIC([]byte) ([]byte, error)  { return nil, nil }
func (i *singleRoundInitiator) VerifyMIC([]byte, []byte) error { return nil }
func (i *singleRoundInitiator) Complete() bool                 { return i.complete }
func (i *singleRoundInitiator) SessionKey() []byte             { return i.key }

func TestDialerConfigurationErrors(t *testing.T) {
	ctx := context.Background()
	_, err := (*Dialer)(nil).Dial(ctx, "server")
	require.ErrorContains(t, err, "nil Dialer")
	require.ErrorIs(t, err, os.ErrInvalid)
	_, err = (&Dialer{}).Dial(ctx, "server")
	require.ErrorContains(t, err, "Credentials is required")
	require.ErrorIs(t, err, os.ErrInvalid)
	_, err = (&Dialer{Credentials: testCredentialsFunc(func(context.Context, string) (auth.Initiator, error) {
		return nil, nil
	})}).Dial(ctx, "server")
	require.ErrorContains(t, err, "nil Initiator")
	for _, test := range []struct {
		name string
		set  func(*Dialer)
		want string
	}{
		{name: "excessive pipeline depth", set: func(d *Dialer) { d.IOPipelineDepth = ^uint(0) }, want: "IOPipelineDepth exceeds"},
		{name: "pipeline depth overflow", set: func(d *Dialer) { d.IOPipelineDepth = 65536 }, want: "IOPipelineDepth exceeds"},
		{name: "unsupported dialect", set: func(d *Dialer) { d.SpecifiedDialects = []Dialect{0x9999} }, want: "unsupported dialect specified"},
		{name: "unsupported cipher", set: func(d *Dialer) { d.Ciphers = []Cipher{0x9999} }, want: "unsupported cipher specified"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			d := &Dialer{Credentials: testCredentialsFunc(func(context.Context, string) (auth.Initiator, error) { return &singleRoundInitiator{}, nil }), TransportDialer: transportDialerFunc(func(context.Context, string) (Transport, error) { return NewTransport(client), nil })}
			test.set(d)
			_, err := d.Dial(context.Background(), "server")
			require.ErrorContains(t, err, test.want)
		})
	}
}

type countingConn struct {
	net.Conn
	closes *atomic.Int32
}

func (c *countingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func TestDialCancellationClosesUnpublishedTransportOnce(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	var closes atomic.Int32
	dialer := &Dialer{
		Credentials: testCredentialsFunc(func(context.Context, string) (auth.Initiator, error) {
			return &singleRoundInitiator{key: []byte("0123456789abcdef")}, nil
		}),
		SpecifiedDialects: []Dialect{SMB210},
		TransportDialer: transportDialerFunc(func(context.Context, string) (Transport, error) {
			return NewTransport(&countingConn{Conn: clientConn, closes: &closes}), nil
		}),
	}
	go func() { _, _ = readMsg(serverConn) }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := dialer.Dial(ctx, "server")
	require.Error(t, err)
	require.Eventually(t, func() bool { return closes.Load() == 1 }, time.Second, time.Millisecond)
}

func serveDialTestSession(server net.Conn, key []byte) {
	defer server.Close()
	request, err := readMsg(server)
	if err != nil {
		return
	}
	neg := &wire.NegotiateResponse{PacketHeader: wire.PacketHeader{Flags: wire.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: wire.PacketCodec(request).MessageId()}, SecurityMode: 1, DialectRevision: wire.SMB210, MaxTransactSize: 65536, MaxReadSize: 65536, MaxWriteSize: 65536, SystemTime: wire.Filetime{}, ServerStartTime: wire.Filetime{}}
	if err := testWriteResponse(server, request, neg, 0, 0, 0); err != nil {
		return
	}
	request, err = readMsg(server)
	if err != nil {
		return
	}
	token, err := spnego.EncodeNegTokenResp(0, spnego.NlmpOid, []byte("server-final-token"), nil)
	if err != nil {
		return
	}
	if err := testWriteResponse(server, request, &wire.SessionSetupResponse{SessionFlags: wire.SMB2_SESSION_FLAG_IS_GUEST, SecurityBuffer: token}, 0, 0x100, 0); err != nil {
		return
	}

	for {
		request, err = readMsg(server)
		if err != nil {
			return
		}
		switch wire.PacketCodec(request).Command() {
		case wire.SMB2_ECHO:
			_ = testWriteResponse(server, request, &wire.EchoResponse{}, 0, 0x100, 0)
		case wire.SMB2_LOGOFF:
			_ = testWriteResponse(server, request, &wire.LogoffResponse{}, 0, 0x100, 0)
			return
		}
	}
}

func TestDialReturnsIndependentSessions(t *testing.T) {
	const count = 4
	var serversMu sync.Mutex
	var servers []net.Conn
	dialer := &Dialer{
		Credentials: testCredentialsFunc(func(context.Context, string) (auth.Initiator, error) {
			return &singleRoundInitiator{key: []byte("0123456789abcdef")}, nil
		}),
		SpecifiedDialects: []Dialect{SMB210},
		TransportDialer: transportDialerFunc(func(context.Context, string) (Transport, error) {
			client, server := net.Pipe()
			serversMu.Lock()
			servers = append(servers, server)
			serversMu.Unlock()
			go serveDialTestSession(server, nil)
			return NewTransport(client), nil
		}),
	}
	sessions := make([]*Session, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := range sessions {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var err error
			sessions[i], err = dialer.Dial(context.Background(), "server")
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	for _, session := range sessions {
		require.NotNil(t, session)
	}
	require.NoError(t, sessions[0].Close())
	require.NoError(t, sessions[1].Echo(context.Background()))
	for _, session := range sessions[1:] {
		_ = session.Close()
	}
	for _, server := range servers {
		_ = server.Close()
	}
}

func TestDialContextCancellationAfterReturnDoesNotCloseSession(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	dialer := &Dialer{
		Credentials: testCredentialsFunc(func(context.Context, string) (auth.Initiator, error) {
			return &singleRoundInitiator{key: []byte("0123456789abcdef")}, nil
		}),
		SpecifiedDialects: []Dialect{SMB210},
		TransportDialer:   transportDialerFunc(func(context.Context, string) (Transport, error) { return NewTransport(client), nil }),
	}
	go serveDialTestSession(server, nil)
	ctx, cancel := context.WithCancel(context.Background())
	session, err := dialer.Dial(ctx, "server")
	require.NoError(t, err)
	cancel()
	require.NoError(t, session.Echo(context.Background()))
	require.NoError(t, session.Close())
}

type blockingDialConn struct {
	net.Conn
	closeStarted chan struct{}
	unblock      chan struct{}
	writeStarted chan struct{}
	closeOnce    sync.Once
	writeOnce    sync.Once
}

func (c *blockingDialConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	return c.Conn.Write(p)
}

func (c *blockingDialConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closeStarted); <-c.unblock })
	return err
}

func TestDialWaitsForCancellationWatcherBeforeReturning(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := &blockingDialConn{Conn: client, closeStarted: make(chan struct{}), unblock: make(chan struct{}), writeStarted: make(chan struct{})}
	dialer := &Dialer{
		Credentials:       testCredentialsFunc(func(context.Context, string) (auth.Initiator, error) { return &singleRoundInitiator{}, nil }),
		SpecifiedDialects: []Dialect{SMB210},
		TransportDialer:   transportDialerFunc(func(context.Context, string) (Transport, error) { return NewTransport(conn), nil }),
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := dialer.Dial(ctx, "server"); result <- err }()
	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("Dial did not start writing the negotiate request")
	}
	cancel()
	select {
	case <-conn.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("cancellation watcher did not begin closing the transport")
	}
	select {
	case err := <-result:
		t.Fatalf("Dial returned before watcher completion: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(conn.unblock)
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("Dial did not return after watcher completion")
	}
}

func TestDialerDoesNotMutateConfigurationSlices(t *testing.T) {
	for _, test := range []struct {
		name     string
		dialects []Dialect
		ciphers  []Cipher
	}{
		{name: "defaults"},
		{name: "explicit", dialects: []Dialect{SMB210}, ciphers: []Cipher{AES128CCM}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			go serveDialTestSession(server, nil)
			dialer := &Dialer{
				Credentials:       testCredentialsFunc(func(context.Context, string) (auth.Initiator, error) { return &singleRoundInitiator{}, nil }),
				SpecifiedDialects: test.dialects,
				Ciphers:           test.ciphers,
				TransportDialer:   transportDialerFunc(func(context.Context, string) (Transport, error) { return NewTransport(client), nil }),
			}
			wantDialects := append([]Dialect(nil), test.dialects...)
			wantCiphers := append([]Cipher(nil), test.ciphers...)
			session, err := dialer.Dial(context.Background(), "server")
			require.NoError(t, err)
			require.Equal(t, wantDialects, dialer.SpecifiedDialects)
			require.Equal(t, wantCiphers, dialer.Ciphers)
			require.NoError(t, session.Close())
		})
	}
}
