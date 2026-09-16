package smb2

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/stretchr/testify/require"
)

type testCredentialsFunc func(context.Context, string) (Initiator, error)

func (f testCredentialsFunc) NewInitiator(ctx context.Context, serverName string) (Initiator, error) {
	return f(ctx, serverName)
}

type testTransportDialerFunc func(context.Context, string) (Transport, error)

func (f testTransportDialerFunc) Dial(ctx context.Context, serverName string) (Transport, error) {
	return f(ctx, serverName)
}

func TestDialerConfigurationErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, err := (*Dialer)(nil).Dial(ctx, "server")
	require.ErrorContains(t, err, "nil Dialer")

	_, err = (&Dialer{}).Dial(ctx, "server")
	require.ErrorContains(t, err, "Credentials is required")

	_, err = (&Dialer{Credentials: testCredentialsFunc(func(context.Context, string) (Initiator, error) {
		return nil, nil
	})}).Dial(ctx, "server")
	require.ErrorContains(t, err, "nil Initiator")

	validCredentials := testCredentialsFunc(func(context.Context, string) (Initiator, error) {
		return &singleRoundInitiator{key: []byte("0123456789abcdef")}, nil
	})
	for _, test := range []struct {
		name   string
		dialer *Dialer
		want   string
	}{
		{
			name:   "unsupported dialect",
			dialer: &Dialer{Credentials: validCredentials, SpecifiedDialects: []Dialect{0x9999}},
			want:   "unsupported dialect specified",
		},
		{
			name:   "unsupported cipher",
			dialer: &Dialer{Credentials: validCredentials, Ciphers: []Cipher{0x9999}},
			want:   "unsupported cipher specified",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			dialer := test.dialer
			dialer.TransportDialer = testTransportDialerFunc(func(context.Context, string) (Transport, error) {
				return NewTransport(clientConn), nil
			})
			_, err := dialer.Dial(ctx, "server")
			require.ErrorContains(t, err, test.want)
		})
	}
}

type countingClientTransport struct {
	Transport
	closes *atomic.Int32
}

func (t *countingClientTransport) Close() error {
	t.closes.Add(1)
	return t.Transport.Close()
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
	t.Parallel()
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	var closes atomic.Int32
	transport := NewTransport(&countingConn{Conn: clientConn, closes: &closes})
	dialer := &Dialer{
		Credentials: testCredentialsFunc(func(context.Context, string) (Initiator, error) {
			return &singleRoundInitiator{key: []byte("0123456789abcdef")}, nil
		}),
		SpecifiedDialects: []Dialect{SMB210},
		TransportDialer: testTransportDialerFunc(func(context.Context, string) (Transport, error) {
			return transport, nil
		}),
	}

	serverRead := make(chan struct{})
	go func() {
		defer close(serverRead)
		_, _ = readMsg(NewTransport(serverConn))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := dialer.Dial(ctx, "server")
	require.Error(t, err)
	<-serverRead
	require.Eventually(t, func() bool { return closes.Load() == 1 }, time.Second, time.Millisecond)
	require.Equal(t, int32(1), closes.Load())
}

func TestDialReturnsIndependentSessions(t *testing.T) {
	t.Parallel()
	key := []byte("0123456789abcdef")
	const sessionCount = 4
	var serversMu sync.Mutex
	var servers []net.Conn
	dialer := &Dialer{
		Credentials: testCredentialsFunc(func(context.Context, string) (Initiator, error) {
			return &singleRoundInitiator{key: key}, nil
		}),
		SpecifiedDialects: []Dialect{SMB210},
		TransportDialer: testTransportDialerFunc(func(context.Context, string) (Transport, error) {
			clientConn, serverConn := net.Pipe()
			serversMu.Lock()
			servers = append(servers, serverConn)
			serversMu.Unlock()
			go serveDialTestSession(serverConn, key)
			return NewTransport(clientConn), nil
		}),
	}

	sessions := make([]*Session, sessionCount)
	errs := make(chan error, sessionCount)
	var wg sync.WaitGroup
	for i := range sessions {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			session, err := dialer.Dial(context.Background(), "server")
			sessions[i] = session
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	seen := make(map[*Session]bool, sessionCount)
	for _, session := range sessions {
		require.NotNil(t, session)
		require.False(t, seen[session])
		seen[session] = true
	}

	// Closing one independent session must not affect another session's
	// connection.
	require.NoError(t, sessions[0].Close())
	require.NoError(t, sessions[1].Echo(context.Background()))
	for _, session := range sessions[1:] {
		require.NoError(t, session.Close())
	}
	for _, server := range servers {
		_ = server.Close()
	}
}

func TestDialContextCancellationAfterReturnDoesNotCloseSession(t *testing.T) {
	t.Parallel()
	key := []byte("0123456789abcdef")
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	dialer := &Dialer{
		Credentials:       testCredentialsFunc(func(context.Context, string) (Initiator, error) { return &singleRoundInitiator{key: key}, nil }),
		SpecifiedDialects: []Dialect{SMB210},
		TransportDialer: testTransportDialerFunc(func(context.Context, string) (Transport, error) {
			return NewTransport(clientConn), nil
		}),
	}
	go serveDialTestSession(serverConn, key)

	ctx, cancel := context.WithCancel(context.Background())
	session, err := dialer.Dial(ctx, "server")
	require.NoError(t, err)
	cancel()
	// The Dial watcher has already been joined before ownership is returned;
	// canceling this original context must not affect the published session.
	require.NoError(t, session.Echo(context.Background()))
	require.NoError(t, session.Close())
}

func serveDialTestSession(server net.Conn, key []byte) {
	defer server.Close()
	t := NewTransport(server)
	request, err := readMsg(t)
	if err != nil {
		return
	}
	neg := &smb2.NegotiateResponse{
		PacketHeader: smb2.PacketHeader{Flags: smb2.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: smb2.PacketCodec(request).MessageId()},
		SecurityMode: 1, DialectRevision: smb2.SMB210,
		MaxTransactSize: 65536, MaxReadSize: 65536, MaxWriteSize: 65536,
		SystemTime: &smb2.Filetime{}, ServerStartTime: &smb2.Filetime{},
	}
	response := make([]byte, neg.Size())
	neg.Encode(response)
	smb2.PacketCodec(response).SetCreditResponse(1)
	if _, err = t.writev(response); err != nil {
		return
	}
	runSingleRoundSessionSetupServerKeepOpen(t, &singleRoundInitiator{key: key}, singleRoundUnsigned)
	for {
		request, err = readMsg(t)
		if err != nil {
			return
		}
		if smb2.PacketCodec(request).Command() != smb2.SMB2_LOGOFF {
			if smb2.PacketCodec(request).Command() == smb2.SMB2_ECHO {
				response := make([]byte, (&smb2.EchoResponse{}).Size())
				(&smb2.EchoResponse{}).Encode(response)
				p := smb2.PacketCodec(response)
				p.SetProtocolId()
				p.SetStructureSize()
				p.SetCommand(smb2.SMB2_ECHO)
				p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
				p.SetMessageId(smb2.PacketCodec(request).MessageId())
				p.SetSessionId(smb2.PacketCodec(request).SessionId())
				p.SetCreditResponse(smb2.PacketCodec(request).CreditRequest())
				_, _ = t.writev(response)
			}
			continue
		}
		_, _ = t.writev(testLogoffResponse(request))
		return
	}
}

func testLogoffResponse(request []byte) []byte {
	response := make([]byte, (&smb2.LogoffResponse{}).Size())
	(&smb2.LogoffResponse{}).Encode(response)
	p := smb2.PacketCodec(response)
	p.SetProtocolId()
	p.SetStructureSize()
	p.SetCommand(smb2.SMB2_LOGOFF)
	p.SetFlags(smb2.SMB2_FLAGS_SERVER_TO_REDIR)
	p.SetMessageId(smb2.PacketCodec(request).MessageId())
	p.SetSessionId(smb2.PacketCodec(request).SessionId())
	p.SetCreditResponse(smb2.PacketCodec(request).CreditRequest())
	return response
}

func TestDialerDoesNotMutateConfigurationSlices(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		dialects []Dialect
		ciphers  []Cipher
	}{
		{name: "defaults"},
		{name: "explicit", dialects: []Dialect{SMB210}, ciphers: []Cipher{AES128CCM}},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := []byte("0123456789abcdef")
			var serverMu sync.Mutex
			var servers []net.Conn
			dialer := &Dialer{
				Credentials:       testCredentialsFunc(func(context.Context, string) (Initiator, error) { return &singleRoundInitiator{key: key}, nil }),
				SpecifiedDialects: test.dialects,
				Ciphers:           test.ciphers,
				TransportDialer: testTransportDialerFunc(func(context.Context, string) (Transport, error) {
					clientConn, serverConn := net.Pipe()
					serverMu.Lock()
					servers = append(servers, serverConn)
					serverMu.Unlock()
					go serveDialTestSession(serverConn, key)
					return NewTransport(clientConn), nil
				}),
			}
			wantDialects := append([]Dialect(nil), dialer.SpecifiedDialects...)
			wantCiphers := append([]Cipher(nil), dialer.Ciphers...)
			session, err := dialer.Dial(context.Background(), "server")
			require.NoError(t, err)
			require.Equal(t, wantDialects, dialer.SpecifiedDialects)
			require.Equal(t, wantCiphers, dialer.Ciphers)
			require.NoError(t, session.Close())
			for _, server := range servers {
				_ = server.Close()
			}
		})
	}
}
