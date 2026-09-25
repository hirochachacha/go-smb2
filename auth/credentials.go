package auth

import (
	"context"
	"fmt"
	"os"
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

func (c NTLMCredential) NewInitiator(ctx context.Context, serverName string) (Initiator, error) {
	if ctx == nil {
		panic("nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Hash != nil && len(c.Hash) != 16 {
		return nil, fmt.Errorf("auth: NTLM hash must be 16 bytes: %w", os.ErrInvalid)
	}
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
