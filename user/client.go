package user

import (
	"context"
	"errors"
	"os"
	"time"

	smb2 "github.com/hirochachacha/go-smb2/v2"
	"github.com/hirochachacha/go-smb2/v2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

const maxResponseSize = 1024 * 1024

// PrincipalType identifies the kind of account associated with a SID.
type PrincipalType uint32

const (
	PrincipalUser           PrincipalType = 1
	PrincipalGroup          PrincipalType = 2
	PrincipalDomain         PrincipalType = 3
	PrincipalAlias          PrincipalType = 4
	PrincipalWellKnownGroup PrincipalType = 5
	PrincipalDeletedAccount PrincipalType = 6
	PrincipalInvalid        PrincipalType = 7
	PrincipalUnknown        PrincipalType = 8
	PrincipalComputer       PrincipalType = 9
	PrincipalLabel          PrincipalType = 10
)

// Identity is an account name and its security identifier.
type Identity struct {
	Name   string
	Domain string
	SID    *security.SID
	Type   PrincipalType
}

// Client resolves account names and SIDs through an IPC$ share.
type Client struct {
	pipe       *msrpc.Pipe
	handle     msrpc.PolicyHandle
	turn       chan struct{}
	policyOpen bool
	closed     bool
}

// NewClient opens and binds the LSARPC pipe on share. It does not unmount share.
func NewClient(ctx context.Context, share *smb2.Share) (client *Client, err error) {
	if ctx == nil {
		panic("nil context")
	}
	if share == nil {
		return nil, os.ErrInvalid
	}
	pipe, err := msrpc.OpenPipe(ctx, share, "lsarpc", msrpc.LSARPC_UUID, msrpc.LSARPC_VERSION)
	if err != nil {
		return nil, err
	}
	c := &Client{
		pipe: pipe,
		turn: make(chan struct{}, 1),
	}
	c.turn <- struct{}{}
	defer func() {
		if err != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = errors.Join(err, c.pipe.Close(closeCtx))
		}
	}()
	response, err := c.callLocked(ctx, msrpc.OP_LSAR_OPEN_POLICY2, msrpc.OpenPolicy2Stub())
	if err != nil {
		return nil, err
	}
	handle, err := msrpc.ReadOpenPolicy2Response(response)
	if err != nil {
		return nil, err
	}
	c.handle = handle
	c.policyOpen = true
	return c, nil
}

// Current resolves the account associated with the authenticated session.
func (c *Client) Current(ctx context.Context) (*Identity, error) {
	if ctx == nil {
		panic("nil context")
	}
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	if c.closed {
		return nil, os.ErrClosed
	}
	name, domain, err := c.getUserNameLocked(ctx)
	if err != nil {
		return nil, err
	}
	identity, err := c.lookupLocked(ctx, name)
	if err != nil {
		return nil, err
	}
	identity.Name = name
	identity.Domain = domain
	return identity, nil
}

// Lookup resolves name to a SID. The returned Name is the requested name.
func (c *Client) Lookup(ctx context.Context, name string) (*Identity, error) {
	if ctx == nil {
		panic("nil context")
	}
	if name == "" {
		return nil, os.ErrInvalid
	}
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	if c.closed {
		return nil, os.ErrClosed
	}
	return c.lookupLocked(ctx, name)
}

func (c *Client) lookupLocked(ctx context.Context, name string) (*Identity, error) {
	var empty msrpc.PolicyHandle
	stub, err := msrpc.LookupNames3Stub(empty, []string{name})
	if err != nil {
		return nil, &os.PathError{Op: "lookup", Path: name, Err: err}
	}
	copy(stub[:len(c.handle)], c.handle[:])
	response, err := c.callLocked(ctx, msrpc.OP_LSAR_LOOKUP_NAMES3, stub)
	if err != nil {
		return nil, &os.PathError{Op: "lookup", Path: name, Err: err}
	}
	results, err := msrpc.ReadLookupNames3Response(response, 1)
	if err != nil {
		return nil, &os.PathError{Op: "lookup", Path: name, Err: err}
	}
	if results[0].Use == uint32(PrincipalInvalid) || results[0].Use == uint32(PrincipalUnknown) || results[0].SID == nil {
		return nil, &os.PathError{Op: "lookup", Path: name, Err: os.ErrNotExist}
	}
	return &Identity{Name: name, Domain: results[0].Domain, SID: results[0].SID, Type: PrincipalType(results[0].Use)}, nil
}

// LookupSID resolves sid to an account name.
func (c *Client) LookupSID(ctx context.Context, sid *security.SID) (*Identity, error) {
	if ctx == nil {
		panic("nil context")
	}
	if sid == nil {
		return nil, os.ErrInvalid
	}
	if err := c.lock(ctx); err != nil {
		return nil, err
	}
	defer c.unlock()
	if c.closed {
		return nil, os.ErrClosed
	}
	var empty msrpc.PolicyHandle
	stub, err := msrpc.LookupSidsStub(empty, []*security.SID{sid})
	if err != nil {
		return nil, &os.PathError{Op: "lookupSID", Path: sid.String(), Err: err}
	}
	copy(stub[:len(c.handle)], c.handle[:])
	response, err := c.callLocked(ctx, msrpc.OP_LSAR_LOOKUP_SIDS, stub)
	if err != nil {
		return nil, &os.PathError{Op: "lookupSID", Path: sid.String(), Err: err}
	}
	results, err := msrpc.ReadLookupSidsResponse(response, 1)
	if err != nil {
		return nil, &os.PathError{Op: "lookupSID", Path: sid.String(), Err: err}
	}
	if results[0].Use == uint32(PrincipalInvalid) || results[0].Use == uint32(PrincipalUnknown) {
		return nil, &os.PathError{Op: "lookupSID", Path: sid.String(), Err: os.ErrNotExist}
	}
	return &Identity{Name: results[0].Name, Domain: results[0].Domain, SID: sid, Type: PrincipalType(results[0].Use)}, nil
}

func (c *Client) getUserNameLocked(ctx context.Context) (string, string, error) {
	response, err := c.callLocked(ctx, msrpc.OP_LSAR_GET_USER_NAME, msrpc.GetUserNameStub())
	if err != nil {
		return "", "", &os.PathError{Op: "current", Path: "lsarpc", Err: err}
	}
	name, domain, err := msrpc.ReadGetUserNameResponse(response)
	if err != nil {
		return "", "", &os.PathError{Op: "current", Path: "lsarpc", Err: err}
	}
	return name, domain, nil
}

func (c *Client) callLocked(ctx context.Context, opnum uint16, stub []byte) ([]byte, error) {
	data, callID, err := c.pipe.Call(ctx, func(callID uint32) (wire.Encoder, error) {
		return msrpc.NewLsarCall(callID, opnum, stub)
	})
	if err != nil {
		return nil, err
	}
	return msrpc.ReadStub(data, callID, maxResponseSize, func(buffer []byte, minimum int) (int, error) {
		return c.pipe.ReadAtLeast(ctx, buffer, minimum)
	})
}

func (c *Client) lock(ctx context.Context) error {
	if c == nil || c.turn == nil {
		return os.ErrInvalid
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.turn:
		if err := ctx.Err(); err != nil {
			c.unlock()
			return err
		}
		return nil
	}
}

func (c *Client) unlock() {
	c.turn <- struct{}{}
}

// Close releases the policy handle and pipe opened by NewClient.
func (c *Client) Close(ctx context.Context) error {
	if ctx == nil {
		panic("nil context")
	}
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if c.closed {
		return nil
	}
	var policyErr error
	if c.policyOpen {
		response, err := c.callLocked(ctx, msrpc.OP_LSAR_CLOSE, msrpc.ClosePolicyStub(c.handle))
		if err == nil {
			err = msrpc.ReadClosePolicyResponse(response)
		}
		if err == nil {
			c.policyOpen = false
		}
		policyErr = err
	}
	pipeErr := c.pipe.Close(ctx)
	if pipeErr == nil {
		c.closed = true
		c.policyOpen = false
	}
	return errors.Join(policyErr, pipeErr)
}
