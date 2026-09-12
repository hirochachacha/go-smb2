package smb2

import (
	"encoding/asn1"
	"errors"

	"github.com/hirochachacha/go-smb2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/internal/spnego"
)

type Initiator interface {
	OID() asn1.ObjectIdentifier
	InitSecContext() ([]byte, error)            // GSS_Init_sec_context
	AcceptSecContext(sc []byte) ([]byte, error) // GSS_Accept_sec_context
	Sum(bs []byte) ([]byte, error)              // GSS_getMIC
	VerifySum(bs, sum []byte) error             // GSS_verifyMIC
	Complete() bool                             // Whether mechanism authentication has completed.
	SessionKey() []byte                         // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
}

// NTLMInitiator implements session-setup through NTLMv2.
// It doesn't support NTLMv1. You can use Hash instead of Password.
type NTLMInitiator struct {
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

func (i *NTLMInitiator) OID() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

// isAnonymous reports whether the initiator authenticates without credentials,
// which makes the server establish an anonymous session that cannot sign.
func (i *NTLMInitiator) isAnonymous() bool {
	return i.User == "" && i.Password == "" && i.Hash == nil
}

func (i *NTLMInitiator) InitSecContext() ([]byte, error) {
	i.seqNum, i.recvSeqNum, i.complete = 0, 0, false
	i.ntlm = &ntlm.Client{
		User:        i.User,
		Password:    i.Password,
		Hash:        i.Hash,
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

func (i *NTLMInitiator) AcceptSecContext(sc []byte) ([]byte, error) {
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

func (i *NTLMInitiator) Sum(bs []byte) ([]byte, error) {
	if !i.complete {
		return nil, errors.New("ntlm: authentication is incomplete")
	}
	var mic []byte
	mic, i.seqNum = i.ntlm.Session().Sum(bs, i.seqNum)
	return mic, nil
}

func (i *NTLMInitiator) SessionKey() []byte {
	return i.ntlm.Session().SessionKey()
}

func (i *NTLMInitiator) infoMap() *ntlm.InfoMap {
	return i.ntlm.Session().InfoMap()
}

func (i *NTLMInitiator) Complete() bool { return i.complete }

func (i *NTLMInitiator) VerifySum(bs, sum []byte) error {
	if !i.complete {
		return errors.New("ntlm: authentication is incomplete")
	}
	ok, next := i.ntlm.Session().CheckSum(sum, bs, i.recvSeqNum)
	if !ok {
		return errors.New("ntlm: invalid mechanism list MIC")
	}
	i.recvSeqNum = next
	return nil
}
