package smb2

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
	"github.com/stretchr/testify/require"
)

type negotiateQUICTransport struct{ Transport }

func (negotiateQUICTransport) isSMBQUICTransport() {}

type transportContextBytes []byte

func (b transportContextBytes) Size() int { return 8 + len(b) }
func (b transportContextBytes) Encode(p []byte) {
	le.PutUint16(p[:2], smb2.SMB2_TRANSPORT_CAPABILITIES)
	le.PutUint16(p[2:4], uint16(len(b)))
	copy(p[8:], b)
}

func TestNegotiateTransportSecurity(t *testing.T) {
	for _, tt := range []struct {
		name         string
		quic, optIn  bool
		contexts     []smb2.Encoder
		accepted     bool
		errorMessage string
	}{
		{"accepted", true, true, []smb2.Encoder{&smb2.TransportContext{Flags: 1}}, true, ""},
		{"declined", true, true, []smb2.Encoder{&smb2.TransportContext{}}, false, ""},
		{"absent", true, true, nil, false, ""},
		{"TCP", false, true, []smb2.Encoder{&smb2.TransportContext{Flags: 1}}, false, ""},
		{"disabled", true, false, []smb2.Encoder{&smb2.TransportContext{Flags: 1}}, false, ""},
		{"unknown flags", true, true, []smb2.Encoder{&smb2.TransportContext{Flags: 2}}, false, ""},
		{"extended", true, true, []smb2.Encoder{transportContextBytes{1, 0, 0, 0, 9}}, true, ""},
		{"truncated", true, true, []smb2.Encoder{transportContextBytes{1, 0, 0}}, false, "broken transport context data format"},
		{"duplicate", true, true, []smb2.Encoder{&smb2.TransportContext{Flags: 1}, &smb2.TransportContext{Flags: 1}}, false, "duplicate transport capabilities context"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			offered := make(chan bool, 1)
			go func() {
				st := direct(server)
				buf, err := readMsg(st)
				if err != nil {
					return
				}
				p := smb2.PacketCodec(buf)
				req := smb2.NegotiateRequestDecoder(p.Body())
				list := req.NegotiateContextList()
				found := false
				for i := req.NegotiateContextCount(); i > 0; i-- {
					nc := smb2.NegotiateContextDecoder(list)
					if nc.IsInvalid() {
						return
					}
					if nc.ContextType() == smb2.SMB2_TRANSPORT_CAPABILITIES {
						found = len(nc.Data()) == 4 && le.Uint32(nc.Data()) == 1
					}
					if i > 1 {
						list = list[nc.Next():]
					}
				}
				offered <- found
				resp := &smb2.NegotiateResponse{
					PacketHeader: smb2.PacketHeader{Flags: smb2.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: p.MessageId()},
					SecurityMode: 1, DialectRevision: smb2.SMB311,
					MaxTransactSize: 65536, MaxReadSize: 65536, MaxWriteSize: 65536,
					SystemTime: &smb2.Filetime{}, ServerStartTime: &smb2.Filetime{},
					Contexts: append([]smb2.Encoder{&smb2.HashContext{HashAlgorithms: []uint16{smb2.SHA512}}, &smb2.CipherContext{Ciphers: []uint16{smb2.AES128GCM}}}, tt.contexts...),
				}
				out := make([]byte, resp.Size())
				resp.Encode(out)
				smb2.PacketCodec(out).SetCreditResponse(1)
				_, _ = st.Writev(out)
			}()
			var transport Transport = direct(client)
			if tt.quic {
				transport = negotiateQUICTransport{transport}
			}
			n := Negotiator{DisableEncryptionOverSecureTransport: tt.optIn}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := n.negotiate(ctx, transport, openAccount(8), 0)
			if tt.errorMessage != "" {
				require.ErrorContains(t, err, tt.errorMessage)
			} else {
				require.NoError(t, err)
				defer c.close(nil)
				require.Equal(t, tt.accepted, c.acceptTransportSecurity)
			}
			select {
			case got := <-offered:
				require.Equal(t, tt.quic && tt.optIn, got)
			case <-ctx.Done():
				t.Fatal("request not inspected")
			}
		})
	}
}

func TestTransportSecuritySkipsSMBEncryption(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		c := &conn{outstandingRequests: newOutstandingRequests(), acceptTransportSecurity: accepted}
		c.session = &session{conn: c, sessionId: 42}
		rrs, parts, err := c.makeOutstandingRequest(context.Background(), true, []uint64{1}, &smb2.EchoRequest{})
		if !accepted {
			require.ErrorContains(t, err, "encryption required but no cipher negotiated")
			continue
		}
		require.NoError(t, err)
		require.False(t, rrs[0].requireEncryption)
		require.Equal(t, smb2.MAGIC, string(parts[0][:4]))
	}
}
