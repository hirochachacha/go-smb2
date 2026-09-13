package smb2

import (
	"context"

	krbclient "github.com/go-krb5/krb5/client"
)

// Credentials creates a fresh Initiator for an SMB server. Initiators contain
// handshake state and must not be reused between sessions. Credentials
// implementations must be safe for concurrent use.
type Credentials interface {
	NewInitiator(context.Context, string) (Initiator, error)
}

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
	return &NTLMInitiator{
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
	spn := c.TargetSPN
	if spn == "" {
		spn = "cifs/" + serverName
	}
	return &KerberosInitiator{Client: c.Client, TargetSPN: spn}, nil
}
