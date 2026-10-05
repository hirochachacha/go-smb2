package protocol

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
	"github.com/stretchr/testify/require"
)

func TestLegacyCipherPolicy(t *testing.T) {
	t.Parallel()
	for _, dialect := range []Dialect{SMB210, SMB300, SMB302} {
		for _, policy := range []struct {
			name     string
			ciphers  []Cipher
			allowCCM bool
		}{
			{name: "nil", allowCCM: true},
			{name: "empty", ciphers: []Cipher{}, allowCCM: true},
			{name: "CCM-included", ciphers: []Cipher{AES256GCM, AES128CCM}, allowCCM: true},
			{name: "CCM-excluded", ciphers: []Cipher{AES256GCM}},
		} {
			for _, scope := range []string{"plaintext", "session", "share"} {
				if dialect == SMB210 && scope != "plaintext" {
					continue
				}
				t.Run(fmt.Sprintf("%x/%s/%s", dialect, policy.name, scope), func(t *testing.T) {
					client, peer := net.Pipe()
					defer peer.Close()
					defer client.Close()
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					initiator := &singleRoundInitiator{key: bytes.Repeat([]byte{0x42}, 16)}
					var flags uint16
					if scope == "session" {
						flags = wire.SMB2_SESSION_FLAG_ENCRYPT_DATA
					}
					type result struct {
						packet []byte
						err    error
					}
					done := make(chan result, 1)
					go func() {
						st := NewTransport(peer)
						request, err := readMsg(st)
						if err != nil {
							done <- result{err: err}
							return
						}
						response := &wire.NegotiateResponse{
							Flags: wire.SMB2_FLAGS_SERVER_TO_REDIR, MessageId: wire.PacketCodec(request).MessageId(),
							SecurityMode: wire.SMB2_NEGOTIATE_SIGNING_ENABLED, DialectRevision: uint16(dialect),
							Capabilities: wire.SMB2_GLOBAL_CAP_ENCRYPTION, MaxTransactSize: 65536, MaxReadSize: 65536, MaxWriteSize: 65536,
						}
						data := make([]byte, response.Size())
						response.Encode(data)
						wire.PacketCodec(data).SetCreditResponse(1)
						if _, err := st.writev(data); err != nil {
							done <- result{err: err}
							return
						}
						runSingleRoundSessionSetupServerModeWithCapabilities(st, initiator, singleRoundUnsigned, false, nil, flags)
						packet, err := readMsg(st)
						done <- result{packet, err}
					}()
					d := &Dialer{SpecifiedDialects: []Dialect{dialect}, Ciphers: policy.ciphers}
					session, err := d.Dial(ctx, initiator, NewTransport(client))
					require.NoError(t, err, "plaintext legacy connections remain permitted")
					defer session.Abort()
					s := session.s
					if scope == "share" {
						tree := &Tree{session: s, treeId: 42, shareFlags: wire.SMB2_SHAREFLAG_ENCRYPT_DATA}
						_, err = tree.send(ctx, &wire.FlushRequest{})
					} else {
						_, err = s.send(ctx, s.sessionFlags&wire.SMB2_SESSION_FLAG_ENCRYPT_DATA != 0, &wire.EchoRequest{})
					}
					blocked := scope != "plaintext" && !policy.allowCCM
					if blocked {
						if err == nil {
							got := <-done
							require.NoError(t, got.err)
							transform := wire.TransformCodec(got.packet)
							decryptor := newSessionTestAEAD(t, wire.AES128CCM, kdfForTest(initiator.key, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"), 16))
							ciphertext := append(bytes.Clone(got.packet[52:]), transform.Signature()...)
							_, err := decryptor.Open(nil, transform.Nonce()[:11], ciphertext, transform.AssociatedData())
							require.NoError(t, err)
							t.Fatal("sent an AES-128-CCM transform excluded by Ciphers")
						}
						require.ErrorContains(t, err, "encryption required but no cipher negotiated")
						require.NoError(t, session.Abort())
						got := <-done
						require.Empty(t, got.packet, "excluded CCM must never be sent")
						require.Error(t, got.err)
						return
					}
					require.NoError(t, err)
					got := <-done
					require.NoError(t, got.err)
					packet := got.packet
					if scope != "plaintext" {
						require.Equal(t, byte(0xfd), packet[0], "legacy encryption uses an SMB transform")
						decryptor := newSessionTestAEAD(t, wire.AES128CCM, kdfForTest(initiator.key, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"), 16))
						transform := wire.TransformCodec(packet)
						ciphertext := append(bytes.Clone(packet[52:]), transform.Signature()...)
						packet, err = decryptor.Open(nil, transform.Nonce()[:11], ciphertext, transform.AssociatedData())
						require.NoError(t, err, "on-wire packet must decrypt with AES-128-CCM")
					} else {
						require.Equal(t, byte(0xfe), packet[0])
					}
					if scope == "share" {
						require.Equal(t, wire.SMB2_FLUSH, wire.PacketCodec(packet).Command())
						require.EqualValues(t, 42, wire.PacketCodec(packet).TreeId())
					} else {
						require.Equal(t, wire.SMB2_ECHO, wire.PacketCodec(packet).Command())
					}
				})
			}
		}
	}
}

func TestDialerInvalidArgumentsPanic(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"nil Dialer", "nil Initiator", "nil Transport"} {
		t.Run(name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			d := &Dialer{}
			var initiator Initiator = &singleRoundInitiator{}
			transport := NewTransport(client)
			switch name {
			case "nil Dialer":
				d = nil
			case "nil Initiator":
				initiator = nil
			case "nil Transport":
				transport = nil
			}
			require.PanicsWithValue(t, "protocol: "+name, func() {
				_, _ = d.Dial(context.Background(), initiator, transport)
			})
			if transport != nil {
				_ = server.SetReadDeadline(time.Now().Add(time.Second))
				_, err := server.Read(make([]byte, 1))
				require.ErrorIs(t, err, io.EOF)
			}
		})
	}
}
