package smb2

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestValidateReferralPathForms(t *testing.T) {
	for _, path := range []string{
		"",
		`\dc-one`,
		`\\dc-two`,
		`\\server\share`,
		`\\server\share\root\link`,
	} {
		t.Run(path, func(t *testing.T) {
			if err := validateReferralPath(path); err != nil {
				t.Fatalf("validateReferralPath(%q) = %v", path, err)
			}
		})
	}
}

func TestGetDFSReferralsRejectsUndocumentedPathFormsBeforeSessionUse(t *testing.T) {
	var session *Session
	for _, path := range []string{
		`domain`,
		`server\share`,
		`\server\share`,
		`\\server\`,
		`\\\server\share`,
		`\\server\\share`,
	} {
		t.Run(path, func(t *testing.T) {
			validationErr := validateReferralPath(path)
			if validationErr == nil {
				t.Fatalf("validateReferralPath(%q) accepted undocumented path form", path)
			}
			_, publicErr := session.GetDFSReferrals(context.Background(), path)
			if publicErr == nil || publicErr.Error() != validationErr.Error() {
				t.Fatalf("GetDFSReferrals(%q) error = %v, want path validation error %v", path, publicErr, validationErr)
			}
			if errors.Is(publicErr, net.ErrClosed) {
				t.Fatalf("GetDFSReferrals(%q) reached session use: %v", path, publicErr)
			}
		})
	}
}
