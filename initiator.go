package smb2

import (
	"encoding/asn1"

	"github.com/hirochachacha/go-smb2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/internal/spnego"
)

type Initiator interface {
	init(ctx *interface{}, inputToken []byte) (outputToken []byte, done bool, err error) // GSS_Init_sec_context with GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG
	sessionKey(ctx *interface{}) []byte                                                  // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
}

type ntlmContext struct {
	c    *ntlm.Client
	nmsg []byte
	cs   *ntlm.Session
}

// NTLMInitiator implements session-setup through NTLMv2.
// It doesn't support NTLMv1. You can use Hash instead of Password.
type NTLMInitiator struct {
	User        string
	Password    string
	Hash        [16]byte
	Domain      string
	Workstation string
	TargetSPN   string
}

func (i *NTLMInitiator) init(ctx *interface{}, inputToken []byte) (outputToken []byte, done bool, err error) {
	if *ctx == nil { // Negotiate
		c := &ntlmContext{
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
			return nil, false, &InternalError{err.Error()}
		}

		mechList := []asn1.ObjectIdentifier{spnego.NlmpOid}

		negTokenInitBytes, err := spnego.EncodeNegTokenInit(mechList, nmsg)
		if err != nil {
			return nil, false, &InternalError{err.Error()}
		}

		c.nmsg = nmsg

		*ctx = c

		return negTokenInitBytes, false, nil
	}

	// Authenticate

	c, ok := (*ctx).(*ntlmContext)
	if !ok {
		return nil, false, &InternalError{"broken ntlm context"}
	}

	negTokenResp, err := spnego.DecodeNegTokenResp(inputToken)
	if err != nil {
		return nil, false, &InvalidResponseError{err.Error()}
	}

	cs, amsg, err := c.c.Authenticate(c.nmsg, negTokenResp.ResponseToken)
	if err != nil {
		return nil, false, &InvalidResponseError{err.Error()}
	}

	mechList := []asn1.ObjectIdentifier{spnego.NlmpOid}

	ms, err := asn1.Marshal(mechList)
	if err != nil {
		return nil, false, &InternalError{err.Error()}
	}

	mechListMIC, _ := cs.Sum(ms, 0)

	negTokenRespBytes, err := spnego.EncodeNegTokenResp(1, nil, amsg, mechListMIC)
	if err != nil {
		return nil, false, &InternalError{err.Error()}
	}

	c.cs = cs

	return negTokenRespBytes, true, nil
}

func (i *NTLMInitiator) sessionKey(ctx *interface{}) []byte {
	c, ok := (*ctx).(*ntlmContext)
	if !ok {
		return nil
	}
	if c.cs == nil {
		return nil
	}
	return c.cs.SessionKey()
}
