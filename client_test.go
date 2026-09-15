package smb2

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/stretchr/testify/require"
)

type testCredentialsFunc func(context.Context, string) (Initiator, error)

func (f testCredentialsFunc) NewInitiator(ctx context.Context, serverName string) (Initiator, error) {
	return f(ctx, serverName)
}

type testTransportDialerFunc func(context.Context, string) (Transport, error)

func (f testTransportDialerFunc) DialTransport(ctx context.Context, serverName string) (Transport, error) {
	return f(ctx, serverName)
}

func TestNewClientRequiresCredentials(t *testing.T) {
	require.PanicsWithValue(t, "smb2: Credentials is required", func() {
		NewClient(ClientConfig{})
	})
}

func TestNewClientDefaultsToTCPDialer(t *testing.T) {
	client := NewClient(ClientConfig{Credentials: NTLMCredential{}})
	require.Equal(t, TCPDialer{}, client.config.TransportDialer)
}

func TestClientMountSelectsCredentialsAndTransport(t *testing.T) {
	wantErr := errors.New("transport failed")
	var credentialServer, transportServer string
	client := NewClient(ClientConfig{
		Credentials: testCredentialsFunc(func(_ context.Context, serverName string) (Initiator, error) {
			credentialServer = serverName
			return &NTLMInitiator{User: "user"}, nil
		}),
		TransportDialer: testTransportDialerFunc(func(_ context.Context, serverName string) (Transport, error) {
			transportServer = serverName
			return nil, wantErr
		}),
	})
	_, err := client.Mount(context.Background(), `\\files.example.com\share`)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Mount error = %v, want %v", err, wantErr)
	}
	if credentialServer != "files.example.com" || transportServer != "files.example.com" {
		t.Fatalf("credential/transport servers = %q, %q", credentialServer, transportServer)
	}
}

func TestClientClosePreventsConnections(t *testing.T) {
	providerCalled := false
	client := NewClient(ClientConfig{
		Credentials: testCredentialsFunc(func(context.Context, string) (Initiator, error) {
			providerCalled = true
			return &NTLMInitiator{}, nil
		}),
		TransportDialer: TCPDialer{},
	})
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	_, err := client.Mount(context.Background(), `\\server\share`)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Mount after Close = %v", err)
	}
	if providerCalled {
		t.Fatal("Credentials called after Close")
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

func TestClientConnectDeduplicatesCaseInsensitiveServer(t *testing.T) {
	var credentialCalls atomic.Int32
	var transportCalls atomic.Int32
	var transportCloses atomic.Int32
	var firstCredentialName atomic.Value
	var firstTransportName atomic.Value
	key := bytes.Repeat([]byte{0x42}, 16)

	client := NewClient(ClientConfig{
		Credentials: testCredentialsFunc(func(_ context.Context, serverName string) (Initiator, error) {
			credentialCalls.Add(1)
			firstCredentialName.Store(serverName)
			return &singleRoundInitiator{key: key}, nil
		}),
		SpecifiedDialects: []uint16{smb2.SMB210},
		TransportDialer: testTransportDialerFunc(func(_ context.Context, serverName string) (Transport, error) {
			transportCalls.Add(1)
			firstTransportName.Store(serverName)
			clientConn, serverConn := net.Pipe()
			go func() {
				defer serverConn.Close()
				st := direct(serverConn)
				buf, readErr := readMsg(st)
				if readErr != nil {
					return
				}
				p := smb2.PacketCodec(buf)
				resp := &smb2.NegotiateResponse{
					PacketHeader: smb2.PacketHeader{
						Flags:     smb2.SMB2_FLAGS_SERVER_TO_REDIR,
						MessageId: p.MessageId(),
					},
					SecurityMode:    1,
					DialectRevision: smb2.SMB210,
					MaxTransactSize: 65536,
					MaxReadSize:     65536,
					MaxWriteSize:    65536,
					SystemTime:      &smb2.Filetime{},
					ServerStartTime: &smb2.Filetime{},
				}
				respBuf := make([]byte, resp.Size())
				resp.Encode(respBuf)
				smb2.PacketCodec(respBuf).SetCreditResponse(1)
				if _, writeErr := st.Writev(respBuf); writeErr != nil {
					return
				}
				runSingleRoundSessionSetupServerKeepOpen(st, &singleRoundInitiator{key: key}, singleRoundUnsigned)
				for {
					buf, readErr = readMsg(st)
					if readErr != nil {
						return
					}
					if smb2.PacketCodec(buf).Command() != smb2.SMB2_LOGOFF {
						continue
					}
					sendTestResponse(st, buf, &smb2.LogoffResponse{}, uint32(erref.STATUS_SUCCESS))
					return
				}
			}()
			return &countingClientTransport{
				Transport: direct(clientConn),
				closes:    &transportCloses,
			}, nil
		}),
	})

	names := []string{"SERVER", "server", "SeRvEr", "SERVER"}
	sessions := make([]*clientSession, len(names))
	errs := make(chan error, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			session, connectErr := client.connect(context.Background(), name)
			sessions[i] = session
			if connectErr != nil {
				errs <- connectErr
			}
		}(i, name)
	}
	wg.Wait()
	close(errs)
	for connectErr := range errs {
		require.NoError(t, connectErr)
	}
	require.Equal(t, int32(1), credentialCalls.Load())
	require.Equal(t, int32(1), transportCalls.Load())
	credentialName := firstCredentialName.Load().(string)
	require.Contains(t, names, credentialName)
	require.Equal(t, credentialName, firstTransportName.Load())
	for _, session := range sessions {
		require.Same(t, sessions[0], session)
	}
	require.Equal(t, int32(0), transportCloses.Load())
	require.NoError(t, client.Close())
	require.NoError(t, client.Close())
	require.Equal(t, int32(1), transportCloses.Load())
}

func TestClientReusesSessionAfterLastUnmount(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	var transportCloses atomic.Int32
	transport := &countingClientTransport{Transport: direct(clientConn), closes: &transportCloses}
	c := &conn{
		t:                   transport,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(512),
		rdone:               make(chan struct{}, 1),
		dialect:             smb2.SMB302,
		maxReadSize:         1 << 20,
		maxWriteSize:        1 << 20,
		maxTransactSize:     1 << 20,
		capabilities:        smb2.SMB2_GLOBAL_CAP_LARGE_MTU,
	}
	c.account.charge(511)
	go c.runReceiver()
	cleanup := func() {
		select {
		case c.rdone <- struct{}{}:
		default:
		}
		_ = clientConn.Close()
	}
	defer cleanup()
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()

	client := &Client{sessions: make(map[string]*clientSession), connecting: make(map[string]*sessionConnect)}
	base := &clientSession{s: c.session, addr: "server", client: client}
	client.sessions["server"] = base

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		st := direct(serverConn)
		for i := 0; i < 6; i++ {
			req, err := readMsg(st)
			if err != nil {
				return
			}
			p := smb2.PacketCodec(req)
			switch p.Command() {
			case smb2.SMB2_TREE_CONNECT:
				if i == 0 {
					sendTestResponse(st, req, &smb2.ErrorResponse{CommandCode: smb2.SMB2_TREE_CONNECT}, uint32(erref.STATUS_ACCESS_DENIED))
					continue
				}
				sendTestResponse(st, req, &smb2.TreeConnectResponse{}, uint32(erref.STATUS_SUCCESS))
			case smb2.SMB2_TREE_DISCONNECT:
				sendTestResponse(st, req, &smb2.TreeDisconnectResponse{}, uint32(erref.STATUS_SUCCESS))
			case smb2.SMB2_LOGOFF:
				sendTestResponse(st, req, &smb2.LogoffResponse{}, uint32(erref.STATUS_SUCCESS))
				return
			default:
				return
			}
		}
	}()

	_, err := client.Mount(context.Background(), `\\server\denied`)
	require.ErrorIs(t, err, erref.STATUS_ACCESS_DENIED)
	require.Equal(t, int32(0), transportCloses.Load())

	for _, serverName := range []string{"server", "SeRvEr"} {
		share, err := client.Mount(context.Background(), `\\`+serverName+`\share`)
		require.NoError(t, err)
		require.Same(t, base.s, share.session)
		require.NoError(t, share.Unmount(context.Background()))
		require.NoError(t, share.Unmount(context.Background()))
		require.Equal(t, int32(0), transportCloses.Load())
	}
	require.NoError(t, client.Close())
	require.NoError(t, client.Close())
	require.Equal(t, int32(1), transportCloses.Load())
	<-serverDone
}

func TestClientCanceledUnmountRetainsSession(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	var transportCloses atomic.Int32
	transport := &countingClientTransport{Transport: direct(clientConn), closes: &transportCloses}
	c := &conn{
		t:                   transport,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(32),
		rdone:               make(chan struct{}, 1),
		dialect:             smb2.SMB302,
		maxReadSize:         65536,
		maxWriteSize:        65536,
		maxTransactSize:     65536,
	}
	c.account.charge(31)
	c.session = &session{conn: c, sessionId: 0x100}
	c.enableSession()
	go c.runReceiver()
	client := &Client{sessions: make(map[string]*clientSession), connecting: make(map[string]*sessionConnect)}
	base := &clientSession{s: c.session, addr: "server", client: client}
	client.sessions["server"] = base
	share := &Share{treeConn: &treeConn{session: c.session, treeId: 1}}

	t.Cleanup(func() { _ = c.close(nil) })
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		st := direct(serverConn)
		for _, command := range []smb2.Command{smb2.SMB2_ECHO, smb2.SMB2_LOGOFF} {
			req, err := readMsg(st)
			if err != nil {
				return
			}
			if got := smb2.PacketCodec(req).Command(); got != command {
				t.Errorf("command = %v, want %v", got, command)
				return
			}
			if command == smb2.SMB2_ECHO {
				sendTestResponse(st, req, &smb2.EchoResponse{}, 0)
			} else {
				sendTestResponse(st, req, &smb2.LogoffResponse{}, 0)
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := share.Unmount(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, int32(0), transportCloses.Load())
	reused, err := client.connect(context.Background(), "server")
	require.NoError(t, err)
	require.Same(t, base, reused)
	require.NoError(t, reused.Echo(context.Background()))
	require.NoError(t, client.Close())
	require.Equal(t, int32(1), transportCloses.Load())
	<-serverDone
}
