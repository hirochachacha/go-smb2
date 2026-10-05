package auth

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestNTLMCredentialCreatesFreshInitiators(t *testing.T) {
	t.Parallel()
	hash := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	domain := "domain"
	credentials := NTLMCredential{User: "user", Password: "password", Hash: hash, Domain: &domain, Workstation: "workstation"}
	firstValue, err := credentials.NewInitiator(context.Background(), "server")
	if err != nil {
		t.Fatal(err)
	}
	secondValue, err := credentials.NewInitiator(context.Background(), "server")
	if err != nil {
		t.Fatal(err)
	}
	first := firstValue.(*ntlmInitiator)
	second := secondValue.(*ntlmInitiator)
	if first == second || first.TargetSPN != "cifs/server" || second.TargetSPN != "cifs/server" {
		t.Fatalf("initiators were not created independently: %p, %p", first, second)
	}
	hash[0] = 9
	domain = "changed"
	if first.Domain == nil || second.Domain == nil || *first.Domain != "domain" || *second.Domain != "domain" {
		t.Fatal("credential domain was not copied")
	}
	if first.Hash[0] != 1 || second.Hash[0] != 1 {
		t.Fatal("credential hash was not copied")
	}

	// Custom SPN
	credentials.TargetSPN = new("cifs/custom")
	thirdValue, err := credentials.NewInitiator(context.Background(), "server")
	if err != nil {
		t.Fatal(err)
	}
	if thirdValue.(*ntlmInitiator).TargetSPN != "cifs/custom" {
		t.Fatalf("TargetSPN = %q, want cifs/custom", thirdValue.(*ntlmInitiator).TargetSPN)
	}
}

func TestNTLMCredentialRejectsInvalidHash(t *testing.T) {
	t.Parallel()
	for _, hash := range [][]byte{{}, {1}, make([]byte, 17)} {
		creds := NTLMCredential{Hash: hash}
		if _, err := creds.NewInitiator(context.Background(), "server"); !errors.Is(err, errInvalidCredential) || errors.Is(err, os.ErrInvalid) {
			t.Errorf("hash length %d: NewInitiator = %v, want auth error", len(hash), err)
		}
	}
}

func TestKerberosCredentialErrorsAndNil(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var nilCtx context.Context

	var nilCreds *KerberosCredential
	if _, err := nilCreds.NewInitiator(ctx, "server"); !errors.Is(err, errInvalidCredential) || errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilCreds.NewInitiator = %v, want auth error", err)
	}
	if err := nilCreds.Close(); !errors.Is(err, errInvalidCredential) || errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilCreds.Close = %v, want auth error", err)
	}

	// Nil context panics
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic on nil context")
			}
		}()
		_, _ = nilCreds.NewInitiator(nilCtx, "server")
	}()

	var zeroCreds KerberosCredential
	if _, err := zeroCreds.NewInitiator(ctx, "server"); err == nil || errors.Is(err, os.ErrInvalid) {
		t.Fatalf("zeroCreds.NewInitiator = %v, want auth error", err)
	}

	// Canceled context
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := zeroCreds.NewInitiator(canceledCtx, "server"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context = %v, want context.Canceled", err)
	}
}

func TestNTLMCredentialNilContext(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil context")
		}
	}()
	var creds NTLMCredential
	var nilCtx context.Context
	_, _ = creds.NewInitiator(nilCtx, "server")
}

func TestNTLMCredentialCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var creds NTLMCredential
	if _, err := creds.NewInitiator(ctx, "server"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context = %v, want context.Canceled", err)
	}
}

func TestNTLMCredentialEmptyTargetSPN(t *testing.T) {
	t.Parallel()
	credential := NTLMCredential{User: "user", TargetSPN: new("")}
	initiator, err := credential.NewInitiator(context.Background(), "server")
	if err != nil {
		t.Fatal(err)
	}
	if got := initiator.(*ntlmInitiator).TargetSPN; got != "" {
		t.Fatalf("TargetSPN = %q, want empty", got)
	}
}
