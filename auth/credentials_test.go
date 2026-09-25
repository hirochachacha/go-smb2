package auth

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestNTLMCredentialCreatesFreshInitiators(t *testing.T) {
	t.Parallel()
	hash := []byte{1, 2, 3}
	credentials := NTLMCredential{User: "user", Password: "password", Hash: hash, Domain: "domain", Workstation: "workstation"}
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
	if first.Hash[0] != 1 || second.Hash[0] != 1 {
		t.Fatal("credential hash was not copied")
	}

	// Custom SPN
	credentials.TargetSPN = "cifs/custom"
	thirdValue, err := credentials.NewInitiator(context.Background(), "server")
	if err != nil {
		t.Fatal(err)
	}
	if thirdValue.(*ntlmInitiator).TargetSPN != "cifs/custom" {
		t.Fatalf("TargetSPN = %q, want cifs/custom", thirdValue.(*ntlmInitiator).TargetSPN)
	}
}

func TestKerberosCredentialErrorsAndNil(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var nilCtx context.Context

	var nilCreds *KerberosCredential
	if _, err := nilCreds.NewInitiator(ctx, "server"); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilCreds.NewInitiator = %v, want os.ErrInvalid", err)
	}
	if err := nilCreds.Close(); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nilCreds.Close = %v, want os.ErrInvalid", err)
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
	if _, err := zeroCreds.NewInitiator(ctx, "server"); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("zeroCreds.NewInitiator = %v, want os.ErrInvalid", err)
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

