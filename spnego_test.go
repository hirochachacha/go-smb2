package smb2

import (
	"encoding/asn1"
	"errors"
	"testing"

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

			err = client.completeSecContext(response)
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

	err := client.completeSecContext(nil)
	require.Error(t, err)
}
