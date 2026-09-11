package smb2

import (
	"encoding/asn1"

	"github.com/hirochachacha/go-smb2/internal/spnego"
)

// negTokenResp.negState values (RFC 2478/4178 negotiation results)
const (
	negStateAcceptCompleted  asn1.Enumerated = 0
	negStateAcceptIncomplete asn1.Enumerated = 1
	negStateReject           asn1.Enumerated = 2
)

type spnegoClient struct {
	mechs        []Initiator
	mechTypes    []asn1.ObjectIdentifier
	selectedMech Initiator
}

func newSpnegoClient(mechs []Initiator) *spnegoClient {
	mechTypes := make([]asn1.ObjectIdentifier, len(mechs))
	for i, mech := range mechs {
		mechTypes[i] = mech.OID()
	}
	return &spnegoClient{
		mechs:     mechs,
		mechTypes: mechTypes,
	}
}

func (c *spnegoClient) oid() asn1.ObjectIdentifier {
	return spnego.SpnegoOid
}

func (c *spnegoClient) initSecContext() (negTokenInitBytes []byte, err error) {
	mechToken, err := c.mechs[0].InitSecContext()
	if err != nil {
		return nil, err
	}
	negTokenInitBytes, err = spnego.EncodeNegTokenInit(c.mechTypes, mechToken)
	if err != nil {
		return nil, err
	}
	return negTokenInitBytes, nil
}

func (c *spnegoClient) acceptSecContext(negTokenRespBytes []byte, complete bool) (negTokenRespBytes1 []byte, err error) {
	negTokenResp, err := spnego.DecodeNegTokenResp(negTokenRespBytes)
	if err != nil {
		return nil, err
	}

	if negTokenResp.NegState == negStateReject {
		return nil, &InvalidResponseError{"server rejected the negotiation"}
	}

	if negTokenResp.NegState == negStateAcceptIncomplete && len(negTokenResp.ResponseToken) == 0 {
		return nil, &InvalidResponseError{"server didn't provide a response token"}
	}

	if len(negTokenResp.SupportedMech) != 0 {
		for i, mechType := range c.mechTypes {
			if mechType.Equal(negTokenResp.SupportedMech) {
				c.selectedMech = c.mechs[i]
				break
			}
		}
	}

	if c.selectedMech == nil {
		return nil, &InvalidResponseError{"server selected an unsupported mechanism"}
	}

	responseToken, err := c.selectedMech.AcceptSecContext(negTokenResp.ResponseToken)
	if err != nil {
		return nil, err
	}

	// A successful SESSION_SETUP cannot carry another client token.
	if complete {
		if negTokenResp.NegState != negStateAcceptCompleted || len(responseToken) != 0 {
			return nil, &InvalidResponseError{"security context is not complete"}
		}
		return nil, nil
	}

	ms, err := asn1.Marshal(c.mechTypes)
	if err != nil {
		return nil, err
	}

	mechListMIC := c.selectedMech.Sum(ms)

	negTokenRespBytes1, err = spnego.EncodeNegTokenResp(1, nil, responseToken, mechListMIC)
	if err != nil {
		return nil, err
	}

	return negTokenRespBytes1, nil
}

// completeSecContext processes the GSS token on the final SESSION_SETUP
// response. The token still carries a SPNEGO result even when the mechanism
// has no ResponseToken ([MS-SMB2] 3.2.5.3.1; [RFC 4178] 4.2.2).
func (c *spnegoClient) completeSecContext(negTokenRespBytes []byte) error {
	if c.selectedMech == nil {
		return &InvalidResponseError{"server selected no mechanism"}
	}

	negTokenResp, err := spnego.DecodeNegTokenResp(negTokenRespBytes)
	if err != nil {
		return err
	}

	if negTokenResp.NegState != negStateAcceptCompleted {
		return &InvalidResponseError{"security context is not complete"}
	}

	if len(negTokenResp.SupportedMech) != 0 &&
		!negTokenResp.SupportedMech.Equal(c.selectedMech.OID()) {
		return &InvalidResponseError{"server selected an unexpected mechanism"}
	}

	// An absent ResponseToken means the selected mechanism has completed; it
	// must not be passed to NTLM as a new challenge.
	if len(negTokenResp.ResponseToken) == 0 {
		return nil
	}

	responseToken, err := c.selectedMech.AcceptSecContext(negTokenResp.ResponseToken)
	if err != nil {
		return err
	}
	if len(responseToken) != 0 {
		return &InvalidResponseError{"security context is not complete"}
	}

	return nil
}

func (c *spnegoClient) sum(bs []byte) []byte {
	return c.selectedMech.Sum(bs)
}

func (c *spnegoClient) sessionKey() []byte {
	return c.selectedMech.SessionKey()
}
