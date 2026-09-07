package smb2

import (
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/hirochachacha/go-smb2/internal/spnego"
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

			_, err = client.acceptSecContext(negTokenRespBytes)
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
