package smb2

import (
	"encoding/asn1"

	"github.com/omnifocal/go-smb2/internal/ntlm"
	"github.com/omnifocal/go-smb2/internal/spnego"
)

type Initiator interface {
	oid() asn1.ObjectIdentifier
	init(ctx *interface{}, inputToken []byte) (outputToken []byte, done bool, err error) // GSS_Init_sec_context with GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG
	sum(ctx *interface{}, input []byte) []byte                                           // GSS_getMIC
	sessionKey(ctx *interface{}) []byte                                                  // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
}

type spnegoInitiatorContext struct {
	mechList []asn1.ObjectIdentifier
	ctx      interface{}
}

type spnegoInitiator struct {
	i Initiator
}

func (i *spnegoInitiator) init(ctx *interface{}, inputToken []byte) (outputToken []byte, done bool, err error) {
	if *ctx == nil {
		c := new(spnegoInitiatorContext)

		// DecodeNegTokenInit2

		outputToken, done, err = i.i.init(&c.ctx, nil)
		if err != nil {
			return nil, false, err
		}

		c.mechList = []asn1.ObjectIdentifier{i.i.oid()}

		negTokenInitBytes, err := spnego.EncodeNegTokenInit(c.mechList, outputToken)
		if err != nil {
			return nil, false, err
		}

		*ctx = c

		return negTokenInitBytes, done, nil
	}

	c, ok := (*ctx).(*spnegoInitiatorContext)
	if !ok {
		return nil, false, &InvalidResponseError{"invalid spnego context"}
	}

	negTokenResp, err := spnego.DecodeNegTokenResp(inputToken)
	if err != nil {
		return nil, false, err
	}

	outputToken, done, err = i.i.init(&c.ctx, negTokenResp.ResponseToken)
	if err != nil {
		return nil, false, err
	}

	ms, err := asn1.Marshal(c.mechList)
	if err != nil {
		return nil, false, err
	}

	mechListMIC := i.i.sum(&c.ctx, ms)

	negTokenRespBytes, err := spnego.EncodeNegTokenResp(1, nil, outputToken, mechListMIC)
	if err != nil {
		return nil, false, err
	}

	return negTokenRespBytes, done, nil
}

type ntlmInitiatorContext struct {
	c      *ntlm.Client
	nmsg   []byte
	cs     *ntlm.Session
	seqNum uint32
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
}

func (i *NTLMInitiator) oid() asn1.ObjectIdentifier {
	return spnego.NlmpOid
}

func (i *NTLMInitiator) init(ctx *interface{}, inputToken []byte) (outputToken []byte, done bool, err error) {
	if *ctx == nil { // Negotiate
		c := &ntlmInitiatorContext{
			c: &ntlm.Client{
				User:        i.User,
				Password:    i.Password,
				Hash:        i.Hash,
				Domain:      i.Domain,
				Workstation: i.Workstation,
				TargetSPN:   i.TargetSPN,
			},
		}

		nmsg, err := c.c.Negotiate()
		if err != nil {
			return nil, false, err
		}

		c.nmsg = nmsg

		*ctx = c

		return nmsg, false, nil
	}

	// Authenticate

	c, ok := (*ctx).(*ntlmInitiatorContext)
	if !ok {
		return nil, false, &InvalidResponseError{"invalid ntlm context"}
	}

	cs, amsg, err := c.c.Authenticate(c.nmsg, inputToken)
	if err != nil {
		return nil, false, err
	}

	c.cs = cs

	return amsg, true, nil
}

func (i *NTLMInitiator) sum(ctx *interface{}, input []byte) []byte {
	if *ctx == nil {
		return nil
	}

	if c, ok := (*ctx).(*ntlmInitiatorContext); ok {
		sum, _ := c.cs.Sum(input, c.seqNum)

		return sum
	}

	return nil
}

func (i *NTLMInitiator) sessionKey(ctx *interface{}) []byte {
	if *ctx == nil {
		return nil
	}

	if c, ok := (*ctx).(*ntlmInitiatorContext); ok {
		return c.cs.SessionKey()
	}

	return nil
}
