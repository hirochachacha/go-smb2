package smb2

import (
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/ntlm"
	"github.com/hirochachacha/go-smb2/internal/spnego"
	"github.com/stretchr/testify/require"
)

func TestSpnegoClientAcceptSecContextNegState(t *testing.T) {
	initiator := &NTLMInitiator{
		User:     "testuser",
		Password: "testpassword",
	}
	if _, err := initiator.InitSecContext(); err != nil {
		t.Fatalf("failed to init security context: %v", err)
	}

	client := &spnegoClient{
		mechs:     []Initiator{initiator},
		mechTypes: []asn1.ObjectIdentifier{spnego.NlmpOid},
	}

	tests := []struct {
		name     string
		negState asn1.Enumerated
		token    []byte
	}{
		{
			name:     "negState reject",
			negState: 2,
			token:    []byte("NTLMSSP\x00\x02\x00\x00\x00"),
		},
		{
			name:     "negState accept-incomplete without response token",
			negState: 1,
			token:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			negTokenRespBytes, err := spnego.EncodeNegTokenResp(tt.negState, spnego.NlmpOid, tt.token, nil)
			if err != nil {
				t.Fatalf("failed to encode negTokenResp: %v", err)
			}

			_, err = client.acceptSecContext(negTokenRespBytes, false)
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			var want *InvalidResponseError
			if !errors.As(err, &want) {
				t.Fatalf("expected *InvalidResponseError, got %v (%T)", err, err)
			}
		})
	}
}

func TestSpnegoClientCompleteSecContext(t *testing.T) {
	tests := []struct {
		name          string
		state         asn1.Enumerated
		supportedMech asn1.ObjectIdentifier
		responseToken []byte
		acceptErr     error
		outputToken   []byte
		wantErr       bool
	}{
		{name: "reject", state: negStateReject, wantErr: true},
		{name: "accept-incomplete", state: negStateAcceptIncomplete, wantErr: true},
		{name: "request-mic", state: 3, wantErr: true},
		{name: "unknown-state", state: 99, wantErr: true},
		{name: "unexpected-mechanism", supportedMech: spnego.KerberosOid, wantErr: true},
		{name: "empty-response-token"},
		{name: "mechanism-error", responseToken: []byte("challenge"), acceptErr: errors.New("GSS failure"), wantErr: true},
		{name: "additional-output-token", responseToken: []byte("challenge"), outputToken: []byte("continuation"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initiator := &singleRoundInitiator{acceptErr: tt.acceptErr, outputToken: tt.outputToken}
			client := &spnegoClient{
				mechs:        []Initiator{initiator},
				mechTypes:    []asn1.ObjectIdentifier{spnego.NlmpOid},
				selectedMech: initiator,
			}
			response, err := spnego.EncodeNegTokenResp(tt.state, tt.supportedMech, tt.responseToken, nil)
			require.NoError(t, err)

			_, err = client.acceptSecContext(response, true)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Nil(t, initiator.accepted)
			}
			if tt.acceptErr != nil {
				require.ErrorIs(t, err, tt.acceptErr)
			}
		})
	}
}

func TestSpnegoClientCompleteSecContextRejectsEmptySecurityBuffer(t *testing.T) {
	initiator := &singleRoundInitiator{}
	client := &spnegoClient{selectedMech: initiator}

	_, err := client.acceptSecContext(nil, true)
	require.Error(t, err)
}

func TestNTLMSPNEGOMICExchange(t *testing.T) {
	for _, tampered := range []bool{false, true} {
		name := "valid"
		if tampered {
			name = "tampered"
		}
		t.Run(name, func(t *testing.T) {
			server := ntlm.NewServer("server")
			server.AddAccount("user", "password")
			i := &NTLMInitiator{User: "user", Password: "password"}
			c := newSpnegoClient([]Initiator{i})
			first, err := c.initSecContext()
			require.NoError(t, err)
			init, err := spnego.DecodeNegTokenInit(first)
			require.NoError(t, err)
			challenge, err := server.Challenge(init.MechToken)
			require.NoError(t, err)
			token, err := spnego.EncodeNegTokenResp(negStateRequestMIC, i.OID(), challenge, nil)
			require.NoError(t, err)
			output, err := c.acceptSecContext(token, false)
			require.NoError(t, err)
			resp, err := spnego.DecodeNegTokenResp(output)
			require.NoError(t, err)
			require.NoError(t, server.Authenticate(resp.ResponseToken))
			mechs, err := asn1.Marshal(c.mechTypes)
			require.NoError(t, err)
			ok, _ := server.Session().Verify(resp.MechListMIC, mechs, 0)
			require.True(t, ok)
			mic, _ := server.Session().Sign(mechs, 0)
			if tampered {
				mic[len(mic)-1] ^= 1
			}
			token, err = spnego.EncodeNegTokenResp(negStateAcceptCompleted, nil, nil, mic)
			require.NoError(t, err)
			_, err = c.acceptSecContext(token, true)
			if tampered {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
