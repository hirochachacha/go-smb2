package auth

import (
	"context"
	"errors"

	krbclient "github.com/go-krb5/krb5/client"
)

// NTLMCredential creates NTLM initiators using the same account for each
// server selected by a DFS referral.
type NTLMCredential struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	Workstation string
	TargetSPN   string
}

func (c NTLMCredential) NewInitiator(_ context.Context, serverName string) (Initiator, error) {
	spn := c.TargetSPN
	if spn == "" {
		spn = "cifs/" + serverName
	}
	return &ntlmInitiator{
		User:        c.User,
		Password:    c.Password,
		Hash:        append([]byte(nil), c.Hash...),
		Domain:      c.Domain,
		Workstation: c.Workstation,
		TargetSPN:   spn,
	}, nil
}

// KerberosCredential creates Kerberos initiators using the supplied Kerberos
// client. The caller remains responsible for destroying the Kerberos client.
type KerberosCredential struct {
	Client    *krbclient.Client
	TargetSPN string
}

func (c KerberosCredential) NewInitiator(_ context.Context, serverName string) (Initiator, error) {
	if c.Client == nil {
		return nil, errors.New("kerberos: Client is required")
	}
	spn := c.TargetSPN
	if spn == "" {
		spn = "cifs/" + serverName
	}
	return &kerberosInitiator{Client: c.Client, TargetSPN: spn}, nil
}
