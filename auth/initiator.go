// Package auth provides SMB authentication mechanisms and credentials.
package auth

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/crypto"
	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/flags"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/messages"
	krbspnego "github.com/go-krb5/krb5/spnego"
	"github.com/go-krb5/krb5/types"
	"github.com/hirochachacha/go-smb2/v2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/v2/internal/spnego"
)

// Initiator performs one authentication handshake. Create a fresh initiator
// for each session; it must not be used by concurrent handshakes.
type Initiator interface {
	OID() asn1.ObjectIdentifier
	InitSecContext() ([]byte, error)
	AcceptSecContext([]byte) ([]byte, error)
	GetMIC([]byte) ([]byte, error)
	VerifyMIC([]byte, []byte) error
	Complete() bool
	SessionKey() []byte
}

// ntlmInitiator implements session-setup through NTLMv2.
// It doesn't support NTLMv1. You can use Hash instead of Password.
type ntlmInitiator struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	Workstation string
	TargetSPN   string

	ntlm       *ntlm.Client
	seqNum     uint32
	recvSeqNum uint32
	complete   bool
}

func (i *ntlmInitiator) OID() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

// IsAnonymous reports whether the initiator authenticates without credentials,
// which makes the server establish an anonymous session that cannot sign.
func (i *ntlmInitiator) IsAnonymous() bool {
	return i.User == "" && i.Password == "" && i.Hash == nil
}

func (i *ntlmInitiator) InitSecContext() ([]byte, error) {
	i.seqNum, i.recvSeqNum, i.complete = 0, 0, false
	i.ntlm = &ntlm.Client{
		User:        i.User,
		Password:    i.Password,
		Hash:        append([]byte(nil), i.Hash...),
		Domain:      i.Domain,
		Workstation: i.Workstation,
		TargetSPN:   i.TargetSPN,
	}
	nmsg, err := i.ntlm.Negotiate()
	if err != nil {
		return nil, err
	}
	return nmsg, nil
}

func (i *ntlmInitiator) AcceptSecContext(sc []byte) ([]byte, error) {
	if i.ntlm == nil || i.complete {
		return nil, errors.New("ntlm: unexpected authentication token")
	}
	amsg, err := i.ntlm.Authenticate(sc)
	if err != nil {
		return nil, err
	}
	i.complete = true
	return amsg, nil
}

func (i *ntlmInitiator) GetMIC(message []byte) ([]byte, error) {
	if !i.complete || i.ntlm == nil || i.ntlm.Session() == nil {
		return nil, errors.New("ntlm: authentication is incomplete")
	}
	var mic []byte
	mic, i.seqNum = i.ntlm.Session().Sign(message, i.seqNum)
	return mic, nil
}

func (i *ntlmInitiator) SessionKey() []byte {
	if i.ntlm == nil || i.ntlm.Session() == nil {
		return nil
	}
	return i.ntlm.Session().SessionKey()
}

func (i *ntlmInitiator) Complete() bool { return i.complete }

func (i *ntlmInitiator) VerifyMIC(message, mic []byte) error {
	if !i.complete || i.ntlm == nil || i.ntlm.Session() == nil {
		return errors.New("ntlm: authentication is incomplete")
	}
	ok, next := i.ntlm.Session().Verify(mic, message, i.recvSeqNum)
	if !ok {
		return errors.New("ntlm: invalid mechanism list MIC")
	}
	i.recvSeqNum = next
	return nil
}

// kerberosInitiator authenticates an SMB session using AES Kerberos mutual
// authentication. Client must already have credentials (Login or a ccache),
// and TargetSPN must name the service, for example cifs/server.example.com.
// The owning KerberosCredential serializes ticket acquisition and cleanup.
// An initiator must not be used by concurrent handshakes.
type kerberosInitiator struct {
	owner     *KerberosCredential
	Client    *client.Client
	TargetSPN string

	ticketKey  types.EncryptionKey
	contextKey types.EncryptionKey
	authTime   time.Time
	authUsec   int
	sendSeq    uint64
	recvSeq    uint64
	pending    bool
	complete   bool
}

var _ Initiator = (*kerberosInitiator)(nil)

func (i *kerberosInitiator) OID() asn1.ObjectIdentifier { return spnego.KerberosOid }

func (i *kerberosInitiator) InitSecContext() ([]byte, error) {
	if i.owner != nil {
		i.owner.mu.Lock()
		defer i.owner.mu.Unlock()
		if i.owner.closed {
			return nil, os.ErrClosed
		}
	}
	*i = kerberosInitiator{Client: i.Client, TargetSPN: i.TargetSPN, owner: i.owner}
	if i.Client == nil || i.Client.Credentials == nil || i.TargetSPN == "" {
		return nil, errors.New("kerberos: Client and TargetSPN are required")
	}
	ticket, key, err := i.Client.GetServiceTicket(i.TargetSPN)
	if err != nil {
		return nil, fmt.Errorf("kerberos: get service ticket: %w", err)
	}
	return i.createAPReq(ticket, key)
}

func validateKerberosKey(key types.EncryptionKey) error {
	var size int
	switch key.KeyType {
	case 17, 19:
		size = 16 // AES128 SHA1 / SHA256
	case 18, 20:
		size = 32 // AES256 SHA1 / SHA384
	default:
		return fmt.Errorf("kerberos: unsupported encryption type %d (AES required)", key.KeyType)
	}
	if len(key.KeyValue) != size {
		return errors.New("kerberos: invalid AES key length")
	}
	return nil
}

func (i *kerberosInitiator) createAPReq(ticket messages.Ticket, key types.EncryptionKey) ([]byte, error) {
	if err := validateKerberosKey(key); err != nil {
		return nil, err
	}
	req, err := krbspnego.NewKRB5TokenAPREQ(i.Client, ticket, key,
		[]int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagReplay, gssapi.ContextFlagSequence},
		[]int{flags.APOptionMutualRequired})
	if err != nil {
		return nil, err
	}
	token, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	auth := req.APReq.Authenticator
	i.ticketKey = types.EncryptionKey{KeyType: key.KeyType, KeyValue: append([]byte(nil), key.KeyValue...)}
	i.authTime, i.authUsec = auth.CTime.Truncate(time.Second), auth.Cusec
	i.sendSeq = uint64(auth.SeqNumber)
	i.pending = true
	return token, nil
}

// unwrapKerberosToken checks the complete envelope before handing the inner
// message to the Kerberos decoder, which otherwise accepts trailing bytes.
func unwrapKerberosToken(token []byte) (byte, []byte, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(token, &outer)
	if err != nil || len(rest) != 0 || outer.Class != 1 || outer.Tag != 0 || !outer.IsCompound {
		return 0, nil, errors.New("kerberos: invalid GSS token envelope")
	}
	var oid asn1.ObjectIdentifier
	payload, err := asn1.Unmarshal(outer.Bytes, &oid)
	if err != nil || !oid.Equal(spnego.KerberosOid) || len(payload) < 3 || payload[1] != 0 {
		return 0, nil, errors.New("kerberos: invalid GSS mechanism or token ID")
	}
	var message asn1.RawValue
	rest, err = asn1.Unmarshal(payload[2:], &message)
	if err != nil || len(rest) != 0 || message.Class != 1 || !message.IsCompound {
		return 0, nil, errors.New("kerberos: invalid GSS message")
	}
	if (payload[0] == 2 && message.Tag != 15) || (payload[0] == 3 && message.Tag != 30) {
		return 0, nil, errors.New("kerberos: unexpected message tag")
	}
	return payload[0], payload[2:], nil
}

func (i *kerberosInitiator) AcceptSecContext(token []byte) ([]byte, error) {
	if !i.pending {
		return nil, errors.New("kerberos: unexpected authentication token")
	}
	i.pending = false
	defer func() { i.ticketKey = types.EncryptionKey{} }()
	id, body, err := unwrapKerberosToken(token)
	if err != nil {
		return nil, err
	}
	if id == 3 {
		var reply messages.KRBError
		if err := reply.Unmarshal(body); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("kerberos: server error: %w", reply)
	}
	if id != 2 {
		return nil, errors.New("kerberos: expected AP-REP")
	}
	var reply messages.APRep
	if err := reply.Unmarshal(body); err != nil {
		return nil, err
	}
	if reply.PVNO != 5 || reply.EncPart.EType != i.ticketKey.KeyType {
		return nil, errors.New("kerberos: invalid AP-REP version or encryption type")
	}
	plaintext, err := crypto.DecryptEncPart(reply.EncPart, i.ticketKey, keyusage.AP_REP_ENCPART)
	if err != nil {
		return nil, fmt.Errorf("kerberos: decrypt AP-REP: %w", err)
	}
	var part messages.EncAPRepPart
	if err := part.Unmarshal(plaintext); err != nil {
		return nil, err
	}
	if !part.CTime.Equal(i.authTime) || part.Cusec != i.authUsec {
		return nil, errors.New("kerberos: AP-REP authenticator time mismatch")
	}
	// MS-KILE 3.1.1.2 requires the acceptor subkey for AES mutual auth.
	if err := validateKerberosKey(part.Subkey); err != nil {
		return nil, err
	}
	if part.SequenceNumber < 0 || part.SequenceNumber > 0xffffffff {
		return nil, errors.New("kerberos: invalid acceptor sequence number")
	}
	i.contextKey = part.Subkey
	i.recvSeq = uint64(part.SequenceNumber)
	i.complete = true
	return nil, nil
}

func (i *kerberosInitiator) Complete() bool { return i.complete }

func (i *kerberosInitiator) SessionKey() []byte {
	return append([]byte(nil), i.contextKey.KeyValue...)
}

func (i *kerberosInitiator) GetMIC(message []byte) ([]byte, error) {
	if !i.complete {
		return nil, errors.New("kerberos: authentication is incomplete")
	}
	mic := gssapi.MICToken{Flags: gssapi.MICTokenFlagAcceptorSubkey, SndSeqNum: i.sendSeq, Payload: message}
	if err := mic.SetChecksum(i.contextKey, keyusage.GSSAPI_INITIATOR_SIGN); err != nil {
		return nil, err
	}
	token, err := mic.Marshal()
	if err != nil {
		return nil, err
	}
	i.sendSeq++
	return token, nil
}

func (i *kerberosInitiator) VerifyMIC(message, micToken []byte) error {
	if !i.complete {
		return errors.New("kerberos: authentication is incomplete")
	}
	var mic gssapi.MICToken
	if err := mic.Unmarshal(micToken, true); err != nil {
		return err
	}
	if mic.Flags&7 != gssapi.MICTokenFlagSentByAcceptor|gssapi.MICTokenFlagAcceptorSubkey || mic.SndSeqNum != i.recvSeq {
		return errors.New("kerberos: invalid MIC flags or sequence number")
	}
	mic.Payload = message
	ok, err := mic.Verify(i.contextKey, keyusage.GSSAPI_ACCEPTOR_SIGN)
	if err != nil || !ok {
		return errors.New("kerberos: invalid mechanism list MIC")
	}
	i.recvSeq++
	return nil
}
