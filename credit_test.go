package smb2

import (
	"context"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestCreditManager_InitialBalance(t *testing.T) {
	req := require.New(t)
	a := openAccount(10)

	p := &smb2.CreateRequest{}
	ctx := context.Background()

	// Initial balance is 1 credit.
	msgIds, charge, err := a.loan(ctx, p)
	req.NoError(err)
	req.Equal(uint64(0), msgIds[0])
	req.Equal(uint16(1), charge)
	req.Equal(uint64(0), p.MessageId)
	req.Equal(uint16(1), p.CreditCharge())
	req.Equal(uint16(10), p.CreditRequestResponse)
}

func TestCreditManager_BlockingAndCharge(t *testing.T) {
	req := require.New(t)
	a := openAccount(10)
	ctx := context.Background()

	// Consume initial credit.
	p1 := &smb2.CreateRequest{}
	_, _, err := a.loan(ctx, p1)
	req.NoError(err)

	// Second request should block because available credits = 0.
	p2 := &smb2.CreateRequest{}
	done := make(chan struct{})

	go func() {
		msgIds, charge, err := a.loan(ctx, p2)
		req.NoError(err)
		req.Equal(uint64(1), msgIds[0])
		req.Equal(uint16(1), charge)
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("expected loan to block when credits exhausted")
	case <-time.After(50 * time.Millisecond):
		// Expected: loan is blocking
	}

	// Replenish credits from server response.
	a.charge(5)

	select {
	case <-done:
		// Succeeded after charge
	case <-time.After(1 * time.Second):
		t.Fatal("expected loan to unblock after charge")
	}
}

func TestCreditManager_ContextCancel(t *testing.T) {
	req := require.New(t)
	a := openAccount(10)
	ctx, cancel := context.WithCancel(context.Background())

	// Consume initial credit.
	p1 := &smb2.CreateRequest{}
	_, _, err := a.loan(ctx, p1)
	req.NoError(err)

	// Second request should block, then be canceled.
	p2 := &smb2.CreateRequest{}
	done := make(chan error)

	go func() {
		_, _, err := a.loan(ctx, p2)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		req.Error(err)
		req.IsType(&ContextError{}, err)
	case <-time.After(1 * time.Second):
		t.Fatal("expected loan to exit on context cancellation")
	}
}

func TestCreditManager_Unloan(t *testing.T) {
	req := require.New(t)
	a := openAccount(10)
	ctx := context.Background()

	// Consume initial credit.
	p1 := &smb2.CreateRequest{}
	_, _, err := a.loan(ctx, p1)
	req.NoError(err)

	// Restore credit via unloan.
	a.unloan(1)

	// Now loaning should succeed without blocking.
	p2 := &smb2.CreateRequest{}
	msgIds, charge, err := a.loan(ctx, p2)
	req.NoError(err)
	req.Equal(uint64(1), msgIds[0])
	req.Equal(uint16(1), charge)
}

func TestCreditManager_RequestTypes(t *testing.T) {
	req := require.New(t)

	ctx := context.Background()

	// ReadRequest (128KB payload -> credit charge 2)
	a := openAccount(10)
	a.charge(10)
	readReq := &smb2.ReadRequest{Length: 128 * 1024}
	_, charge, err := a.loan(ctx, readReq)
	req.NoError(err)
	req.Equal(uint16(2), charge)
	req.Equal(uint16(2), readReq.CreditCharge())

	// WriteRequest (128KB data -> credit charge 2)
	a = openAccount(10)
	a.charge(10)
	writeReq := &smb2.WriteRequest{Data: make([]byte, 128*1024)}
	_, charge, err = a.loan(ctx, writeReq)
	req.NoError(err)
	req.Equal(uint16(2), charge)
	req.Equal(uint16(2), writeReq.CreditCharge())

	// QueryDirectoryRequest (128KB output -> credit charge 2)
	a = openAccount(10)
	a.charge(10)
	qdReq := &smb2.QueryDirectoryRequest{OutputBufferLength: 128 * 1024}
	_, charge, err = a.loan(ctx, qdReq)
	req.NoError(err)
	req.Equal(uint16(2), charge)
	req.Equal(uint16(2), qdReq.CreditCharge())
}
