package smb2

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"
	krbspnego "github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/types"
	"github.com/hirochachacha/go-smb2/internal/spnego"
	"github.com/stretchr/testify/require"
)

func kerberosExchange(t *testing.T, keyType int32) (*KerberosInitiator, types.EncryptionKey, messages.EncAPRepPart) {
	t.Helper()
	size := 16
	if keyType == 18 || keyType == 20 {
		size = 32
	}
	key := types.EncryptionKey{KeyType: keyType, KeyValue: bytes.Repeat([]byte{0x31}, size)}
	i := &KerberosInitiator{Client: client.NewWithPassword("user", "EXAMPLE.COM", "unused", config.New()), TargetSPN: "cifs/server.example.com"}
	ticket := messages.Ticket{TktVNO: 5, Realm: "EXAMPLE.COM", SName: types.NewPrincipalName(2, i.TargetSPN), EncPart: types.EncryptedData{EType: keyType, Cipher: []byte("opaque ticket")}}
	token, err := i.createAPReq(ticket, key)
	require.NoError(t, err)
	var req krbspnego.KRB5Token
	require.NoError(t, req.Unmarshal(token))
	require.True(t, req.IsAPReq())
	require.True(t, types.IsFlagSet(&req.APReq.APOptions, flags.APOptionMutualRequired))
	require.NoError(t, req.APReq.DecryptAuthenticator(key))
	auth := req.APReq.Authenticator
	require.Equal(t, int32(0x8003), auth.Cksum.CksumType)
	require.NotZero(t, binary.LittleEndian.Uint32(auth.Cksum.Checksum[20:])&uint32(gssapi.ContextFlagMutual|gssapi.ContextFlagInteg))
	require.False(t, i.Complete())
	require.Empty(t, i.SessionKey())
	return i, key, messages.EncAPRepPart{CTime: auth.CTime, Cusec: auth.Cusec, SequenceNumber: 42, Subkey: types.EncryptionKey{KeyType: keyType, KeyValue: bytes.Repeat([]byte{0x72}, size)}}
}

func kerberosReply(t testing.TB, key types.EncryptionKey, part messages.EncAPRepPart) []byte {
	t.Helper()
	plain, err := part.Marshal()
	require.NoError(t, err)
	enc, err := crypto.GetEncryptedData(plain, key, keyusage.AP_REP_ENCPART, 0)
	require.NoError(t, err)
	rep := messages.APRep{PVNO: 5, MsgType: 15, EncPart: enc}
	body, err := rep.Marshal()
	require.NoError(t, err)
	token, err := marshalKerberosToken(2, body)
	require.NoError(t, err)
	return token
}

func TestKerberosMutualAuthentication(t *testing.T) {
	for _, enctype := range []int32{17, 18, 19, 20} {
		t.Run(kerberosEncryptionName(enctype), func(t *testing.T) {
			i, key, part := kerberosExchange(t, enctype)
			reply := kerberosReply(t, key, part)
			output, err := i.AcceptSecContext(reply)
			require.NoError(t, err)
			require.Empty(t, output)
			require.True(t, i.Complete())
			require.Equal(t, part.Subkey.KeyValue, i.SessionKey())
			copyKey := i.SessionKey()
			copyKey[0] ^= 1
			require.Equal(t, part.Subkey.KeyValue, i.SessionKey())
			_, err = i.AcceptSecContext(reply)
			require.Error(t, err)
		})
	}
}

func kerberosEncryptionName(id int32) string {
	return map[int32]string{17: "AES128-SHA1", 18: "AES256-SHA1", 19: "AES128-SHA256", 20: "AES256-SHA384"}[id]
}

func TestKerberosRejectsInvalidReply(t *testing.T) {
	for _, name := range []string{"time", "microseconds", "missing-subkey", "short-key", "unsupported-key", "ciphertext", "trailing-bytes", "missing-reply", "truncated"} {
		t.Run(name, func(t *testing.T) {
			i, key, part := kerberosExchange(t, 18)
			switch name {
			case "time":
				part.CTime = part.CTime.Add(time.Second)
			case "microseconds":
				part.Cusec++
			case "missing-subkey":
				part.Subkey = types.EncryptionKey{}
			case "short-key":
				part.Subkey.KeyValue = []byte{1}
			case "unsupported-key":
				part.Subkey.KeyType = 23
			}
			reply := kerberosReply(t, key, part)
			switch name {
			case "ciphertext":
				reply[len(reply)-1] ^= 1
			case "trailing-bytes":
				reply = append(reply, 0)
			case "missing-reply":
				reply = nil
			case "truncated":
				reply = reply[:len(reply)-1]
			}
			_, err := i.AcceptSecContext(reply)
			require.Error(t, err)
			require.False(t, i.Complete())
			require.Empty(t, i.SessionKey())
		})
	}
}

func TestKerberosMIC(t *testing.T) {
	i, key, part := kerberosExchange(t, 18)
	_, err := i.GetMIC([]byte("mechs"))
	require.Error(t, err)
	_, err = i.AcceptSecContext(kerberosReply(t, key, part))
	require.NoError(t, err)
	payload, err := asn1.Marshal([]asn1.ObjectIdentifier{spnego.KerberosOid})
	require.NoError(t, err)
	seq := i.sendSeq
	for n := range 2 {
		token, err := i.GetMIC(payload)
		require.NoError(t, err)
		var mic gssapi.MICToken
		require.NoError(t, mic.Unmarshal(token, false))
		require.Equal(t, seq+uint64(n), mic.SndSeqNum)
		require.Equal(t, byte(gssapi.MICTokenFlagAcceptorSubkey), mic.Flags)
		mic.Payload = payload
		ok, err := mic.Verify(part.Subkey, keyusage.GSSAPI_INITIATOR_SIGN)
		require.NoError(t, err)
		require.True(t, ok)
	}
	mic := gssapi.MICToken{Flags: 5, SndSeqNum: 42, Payload: payload}
	require.NoError(t, mic.SetChecksum(part.Subkey, keyusage.GSSAPI_ACCEPTOR_SIGN))
	token, err := mic.Marshal()
	require.NoError(t, err)
	bad := append([]byte(nil), token...)
	bad[len(bad)-1] ^= 1
	require.Error(t, i.VerifyMIC(payload, bad))
	require.NoError(t, i.VerifyMIC(payload, token))
	require.Error(t, i.VerifyMIC(payload, token), "replayed MIC must fail")
}

func TestKerberosInitValidation(t *testing.T) {
	i := &KerberosInitiator{}
	_, err := i.InitSecContext()
	require.Error(t, err)
	_, err = i.AcceptSecContext(nil)
	require.Error(t, err)
	require.Error(t, i.VerifyMIC(nil, nil))
}

func FuzzKerberosReply(f *testing.F) {
	key := types.EncryptionKey{KeyType: 17, KeyValue: make([]byte, 16)}
	f.Add(kerberosReply(f, key, messages.EncAPRepPart{CTime: time.Unix(0, 0).UTC(), Subkey: key}))
	f.Add([]byte{})
	f.Add([]byte{0x60, 0x02, 0x06, 0x00})
	f.Fuzz(func(t *testing.T, token []byte) {
		i := &KerberosInitiator{pending: true, ticketKey: types.EncryptionKey{KeyType: 17, KeyValue: make([]byte, 16)}}
		_, _ = i.AcceptSecContext(token)
	})
}

func marshalKerberosToken(id byte, body []byte) ([]byte, error) {
	oid, err := asn1.Marshal(spnego.KerberosOid)
	if err != nil {
		return nil, err
	}
	payload := append(oid, id, 0)
	payload = append(payload, body...)
	return asn1.Marshal(asn1.RawValue{Class: 1, Tag: 0, IsCompound: true, Bytes: payload})
}

func TestKerberosSPNEGOMICExchange(t *testing.T) {
	for _, final := range []string{"valid", "missing-mic", "bad-mic"} {
		t.Run(final, func(t *testing.T) {
			i, key, part := kerberosExchange(t, 18)
			c := newSpnegoClient([]Initiator{i})
			first, err := spnego.EncodeNegTokenResp(negStateRequestMIC, i.OID(), kerberosReply(t, key, part), nil)
			require.NoError(t, err)
			response, err := c.acceptSecContext(first, false)
			require.NoError(t, err)
			resp, err := spnego.DecodeNegTokenResp(response)
			require.NoError(t, err)
			require.Empty(t, resp.ResponseToken)
			var clientMIC gssapi.MICToken
			require.NoError(t, clientMIC.Unmarshal(resp.MechListMIC, false))
			mechs, err := asn1.Marshal(c.mechTypes)
			require.NoError(t, err)
			clientMIC.Payload = mechs
			ok, err := clientMIC.Verify(part.Subkey, keyusage.GSSAPI_INITIATOR_SIGN)
			require.NoError(t, err)
			require.True(t, ok)
			serverMIC := gssapi.MICToken{Flags: 5, SndSeqNum: 42, Payload: mechs}
			require.NoError(t, serverMIC.SetChecksum(part.Subkey, keyusage.GSSAPI_ACCEPTOR_SIGN))
			mic, err := serverMIC.Marshal()
			require.NoError(t, err)
			if final == "missing-mic" {
				mic = nil
			}
			if final == "bad-mic" {
				mic[len(mic)-1] ^= 1
			}
			token, err := spnego.EncodeNegTokenResp(negStateAcceptCompleted, nil, nil, mic)
			require.NoError(t, err)
			_, err = c.acceptSecContext(token, true)
			if final == "valid" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestKerberosSPNEGORequiresMutualAuthentication(t *testing.T) {
	i, _, _ := kerberosExchange(t, 17)
	c := newSpnegoClient([]Initiator{i})
	token, err := spnego.EncodeNegTokenResp(negStateAcceptCompleted, i.OID(), nil, nil)
	require.NoError(t, err)
	_, err = c.acceptSecContext(token, true)
	require.Error(t, err)
	require.False(t, i.Complete())
}

func TestKerberosServerError(t *testing.T) {
	i, _, _ := kerberosExchange(t, 17)
	reply := messages.NewKRBError(types.NewPrincipalName(2, i.TargetSPN), "EXAMPLE.COM", 41, "test authentication failure")
	body, err := reply.Marshal()
	require.NoError(t, err)
	token, err := marshalKerberosToken(3, body)
	require.NoError(t, err)
	_, err = i.AcceptSecContext(token)
	var serverError messages.KRBError
	require.True(t, errors.As(err, &serverError))
	require.Equal(t, int32(41), serverError.ErrorCode)
	require.False(t, i.Complete())
	require.Empty(t, i.SessionKey())
}

func TestKerberosSPNEGOCompletionAcknowledgement(t *testing.T) {
	i, key, part := kerberosExchange(t, 17)
	c := newSpnegoClient([]Initiator{i})
	token, err := spnego.EncodeNegTokenResp(negStateAcceptIncomplete, i.OID(), kerberosReply(t, key, part), nil)
	require.NoError(t, err)
	output, err := c.acceptSecContext(token, false)
	require.NoError(t, err)
	resp, err := spnego.DecodeNegTokenResp(output)
	require.NoError(t, err)
	require.Equal(t, negStateAcceptCompleted, resp.NegState)
	require.Empty(t, resp.ResponseToken)
	require.Empty(t, resp.MechListMIC)
	token, err = spnego.EncodeNegTokenResp(negStateAcceptCompleted, nil, nil, nil)
	require.NoError(t, err)
	_, err = c.acceptSecContext(token, true)
	require.NoError(t, err)
}
