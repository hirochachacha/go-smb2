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
}

func (c NTLMCredential) NewInitiator(_ context.Context, serverName string) (Initiator, error) {
	return &NTLMInitiator{
		User:        c.User,
		Password:    c.Password,
		Hash:        append([]byte(nil), c.Hash...),
		Domain:      c.Domain,
		Workstation: c.Workstation,
		TargetSPN:   "cifs/" + serverName,
	}, nil
}

// KerberosCredential creates Kerberos initiators using the supplied Kerberos
// client. The caller remains responsible for destroying the Kerberos client.
type KerberosCredential struct {
	Client *krbclient.Client
}

func (c KerberosCredential) NewInitiator(_ context.Context, serverName string) (Initiator, error) {
	return &KerberosInitiator{Client: c.Client, TargetSPN: "cifs/" + serverName}, nil
}
