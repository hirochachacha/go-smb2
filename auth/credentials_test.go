package auth

import (
	"context"
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
}

func TestKerberosCredentialNilClient(t *testing.T) {
	t.Parallel()
	var creds KerberosCredential
	_, err := creds.NewInitiator(context.Background(), "server")
	if err == nil {
		t.Fatal("expected error for nil client, got nil")
	}
}
