package auth

import (
	"context"
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
