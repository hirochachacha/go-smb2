package smb2

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

// fakeEncoder is a minimal smb2.Encoder of a fixed byte size.
type fakeEncoder struct {
	size int
}

func (e *fakeEncoder) Size() int       { return e.size }
func (e *fakeEncoder) Encode(b []byte) {}

func creditRequest(p smb2.Packet) uint16 {
	switch p := p.(type) {
	case *smb2.CreateRequest:
		return p.CreditRequestResponse
	case *smb2.CloseRequest:
		return p.CreditRequestResponse
	case *smb2.ReadRequest:
		return p.CreditRequestResponse
	case *smb2.QueryInfoRequest:
		return p.CreditRequestResponse
	default:
		panic("unsupported packet type")
	}
}

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

func TestCreditManager_AbortUnblocksLoan(t *testing.T) {
	req := require.New(t)
	a := openAccount(10)
	ctx := context.Background()

	// Consume initial credit.
	p1 := &smb2.CreateRequest{}
	_, _, err := a.loan(ctx, p1)
	req.NoError(err)

	// Requests should block because available credits = 0.
	p2 := &smb2.CreateRequest{}
	p3 := &smb2.CreateRequest{}
	done1 := make(chan error, 1)
	done2 := make(chan error, 1)

	go func() {
		_, _, err := a.loan(ctx, p2)
		done1 <- err
	}()
	go func() {
		_, _, err := a.loan(ctx, p3)
		done2 <- err
	}()

	select {
	case <-done1:
		t.Fatal("expected loan 1 to block when credits exhausted")
	case <-done2:
		t.Fatal("expected loan 2 to block when credits exhausted")
	case <-time.After(50 * time.Millisecond):
		// Expected: loans are blocking
	}

	// Aborting the account must unblock all pending loans with the given error.
	abortErr := errors.New("connection closed")
	a.abort(abortErr)

	select {
	case err := <-done1:
		req.Error(err)
		req.ErrorIs(err, abortErr)
	case <-time.After(1 * time.Second):
		t.Fatal("expected loan 1 to unblock after abort")
	}

	select {
	case err := <-done2:
		req.Error(err)
		req.ErrorIs(err, abortErr)
	case <-time.After(1 * time.Second):
		t.Fatal("expected loan 2 to unblock after abort")
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

	// IoctlRequest with nil Input (should not panic)
	a = openAccount(10)
	a.charge(10)
	ioctlNilReq := &smb2.IoctlRequest{MaxOutputResponse: 1024}
	_, charge, err = a.loan(ctx, ioctlNilReq)
	req.NoError(err)
	req.Equal(uint16(1), charge)
	req.Equal(uint16(1), ioctlNilReq.CreditCharge())

	// IoctlRequest with both Input and MaxOutputResponse (64KB each -> credit charge 1,
	// based on max(input, output), not their sum)
	a = openAccount(10)
	a.charge(10)
	ioctlReq := &smb2.IoctlRequest{
		Input:             &fakeEncoder{size: 64 * 1024},
		MaxOutputResponse: 64 * 1024,
	}
	_, charge, err = a.loan(ctx, ioctlReq)
	req.NoError(err)
	req.Equal(uint16(1), charge)
	req.Equal(uint16(1), ioctlReq.CreditCharge())
}

func TestCreditManager_FailFastOnExcessiveCharge(t *testing.T) {
	req := require.New(t)
	a := openAccount(10)
	ctx := context.Background()

	// Request requiring 11 credits when target is 10 and max seen is 1 (initial).
	// 11 * 64KB = 704KB. calcCreditCharge((11-1)*65536 + 1) = 11.
	bigReq := &smb2.ReadRequest{Length: 11 * 64 * 1024}
	_, _, err := a.loan(ctx, bigReq)
	req.Error(err)
	req.IsType(&InternalError{}, err)
}

func TestCreditManager_MaxCreditCap(t *testing.T) {
	req := require.New(t)
	a := openAccount(10)

	// Initially 1 credit observed
	req.Equal(uint16(1), a.maxCreditCap())

	// Replenish 4 credits -> available 5, max 5
	a.charge(4)
	req.Equal(uint16(5), a.maxCreditCap())

	// Replenish 10 credits -> available 15, but target is 10, so cap is 10
	a.charge(10)
	req.Equal(uint16(10), a.maxCreditCap())
}

func TestCreditManager_MaintainAndSurplus(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()

	// Initial target is 10. Bring available credits to 10 (target reached).
	a := openAccount(10)
	a.charge(9) // available: 10, inFlight: 0

	// 1st request: consumes 1 credit. Target is maintained, so creditRequest = 1.
	p1 := &smb2.CreateRequest{}
	_, charge, err := a.loan(ctx, p1)
	req.NoError(err)
	req.Equal(uint16(1), charge)
	req.Equal(uint16(1), p1.CreditRequestResponse)

	// 2nd concurrent request (before 1st finishes): should ALSO request 1 (its own charge),
	// not compounding deficit!
	p2 := &smb2.CreateRequest{}
	_, charge, err = a.loan(ctx, p2)
	req.NoError(err)
	req.Equal(uint16(1), charge)
	req.Equal(uint16(1), p2.CreditRequestResponse)

	// 3rd concurrent request: should ALSO request 1.
	p3 := &smb2.CreateRequest{}
	_, charge, err = a.loan(ctx, p3)
	req.NoError(err)
	req.Equal(uint16(1), charge)
	req.Equal(uint16(1), p3.CreditRequestResponse)

	// Complete all 3 requests with 1 credit each returned
	a.charge(1, 1)
	a.charge(1, 1)
	a.charge(1, 1)
	// Now available: 10, inFlight: 0

	// Server gives surplus credits (e.g. 5 extra credits granted)
	a.charge(5) // available: 15, inFlight: 0

	// 4th request: since total (15) > maxCreditBalance (10), request should ask for 0
	// to drain excess credits towards maxCreditBalance.
	p4 := &smb2.CreateRequest{}
	_, charge, err = a.loan(ctx, p4)
	req.NoError(err)
	req.Equal(uint16(1), charge)
	req.Equal(uint16(0), p4.CreditRequestResponse)
}

func TestCreditManager_CompoundCreditRequestAllocation(t *testing.T) {
	tests := []struct {
		name      string
		replenish uint16
		reqs      func() []smb2.Packet
		charges   []uint16
		want      []uint16
	}{
		{
			name:      "target balance",
			replenish: 9,
			reqs: func() []smb2.Packet {
				return []smb2.Packet{&smb2.CreateRequest{}, &smb2.QueryInfoRequest{FileId: &smb2.FileId{}}, &smb2.CloseRequest{}}
			},
			charges: []uint16{1, 1, 1},
			want:    []uint16{1, 1, 1},
		},
		{
			name:      "multiple credit charge",
			replenish: 9,
			reqs: func() []smb2.Packet {
				return []smb2.Packet{&smb2.ReadRequest{Length: 128 * 1024}, &smb2.CreateRequest{}}
			},
			charges: []uint16{2, 1},
			want:    []uint16{2, 1},
		},
		{
			name:      "target deficit",
			replenish: 2,
			reqs: func() []smb2.Packet {
				return []smb2.Packet{&smb2.CreateRequest{}, &smb2.CreateRequest{}, &smb2.CreateRequest{}}
			},
			charges: []uint16{1, 1, 1},
			want:    []uint16{8, 1, 1},
		},
		{
			name:      "partial surplus",
			replenish: 10,
			reqs: func() []smb2.Packet {
				return []smb2.Packet{&smb2.CreateRequest{}, &smb2.CreateRequest{}, &smb2.CreateRequest{}}
			},
			charges: []uint16{1, 1, 1},
			want:    []uint16{1, 1, 0},
		},
		{
			name:      "surplus",
			replenish: 14,
			reqs: func() []smb2.Packet {
				return []smb2.Packet{&smb2.CreateRequest{}, &smb2.CreateRequest{}, &smb2.CreateRequest{}}
			},
			charges: []uint16{1, 1, 1},
			want:    []uint16{0, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			a := openAccount(10)
			a.charge(tt.replenish)

			reqs := tt.reqs()
			for _, p := range reqs {
				p.SetCreditRequest(99) // All headers, including zero grants, must be overwritten.
			}
			_, _, err := a.loan(context.Background(), reqs...)
			req.NoError(err)

			got := make([]uint16, len(reqs))
			var total uint32
			for i, p := range reqs {
				got[i] = creditRequest(p)
				total += uint32(got[i])
				req.Equal(tt.charges[i], p.CreditCharge())
			}
			req.Equal(tt.want, got)
			var wantTotal uint32
			for _, want := range tt.want {
				wantTotal += uint32(want)
			}
			req.Equal(wantTotal, total)
		})
	}
}

func TestCreditManager_CompoundCreditSettlement(t *testing.T) {
	models := []struct {
		name  string
		grant func([]smb2.Packet) []uint16
	}{
		{
			name: "per request",
			grant: func(reqs []smb2.Packet) []uint16 {
				grants := make([]uint16, len(reqs))
				for i, p := range reqs {
					grants[i] = min(creditRequest(p), p.CreditCharge())
				}
				return grants
			},
		},
		{
			name: "final response aggregate",
			grant: func(reqs []smb2.Packet) []uint16 {
				grants := make([]uint16, len(reqs))
				for _, p := range reqs {
					grants[len(grants)-1] += creditRequest(p)
				}
				return grants
			},
		},
	}

	for _, model := range models {
		t.Run(model.name, func(t *testing.T) {
			req := require.New(t)
			a := openAccount(10)
			a.charge(9)

			for i := 0; i < 3; i++ {
				reqs := []smb2.Packet{&smb2.CreateRequest{}, &smb2.CreateRequest{}, &smb2.CreateRequest{}}
				_, _, err := a.loan(context.Background(), reqs...)
				req.NoError(err)

				grants := model.grant(reqs)
				for j, grant := range grants {
					a.charge(grant, reqs[j].CreditCharge())
				}

				a.m.Lock()
				req.Equal(uint16(10), a.availableCredits)
				req.Equal(uint16(0), a.inFlightCredits)
				a.m.Unlock()
			}
		})
	}
}

func TestCreditOverflow_RejectCompoundChargeExceedingUint16(t *testing.T) {
	req := require.New(t)
	a := openAccount(128)
	ctx := context.Background()

	// Compound of 65536 requests, each with a credit charge of 1.
	// The cumulative charge (65536) exceeds uint16 and must not wrap to 0.
	reqs := make([]smb2.Packet, 65536)
	for i := range reqs {
		reqs[i] = &smb2.CreateRequest{}
	}

	msgIds, charge, err := a.loan(ctx, reqs...)
	req.Error(err)
	req.IsType(&InternalError{}, err)
	req.Nil(msgIds)
	req.Equal(uint16(0), charge)
}

func TestCreditManager_ChargeClampsAtMaxUint16(t *testing.T) {
	req := require.New(t)
	a := openAccount(128)

	// Simulate a large available balance close to the uint16 limit.
	a.m.Lock()
	a.availableCredits = math.MaxUint16 - 1
	a.m.Unlock()

	// Granting more credits must not wrap around to a small value.
	a.charge(10)

	a.m.Lock()
	defer a.m.Unlock()
	req.Equal(uint16(math.MaxUint16), a.availableCredits)
}

func TestCreditManager_UnloanClampsAtMaxUint16(t *testing.T) {
	req := require.New(t)
	a := openAccount(128)

	// Simulate a large available balance close to the uint16 limit.
	a.m.Lock()
	a.availableCredits = math.MaxUint16 - 1
	a.inFlightCredits = 5
	a.m.Unlock()

	// Restoring credits must not wrap around to a small value.
	a.unloan(5)

	a.m.Lock()
	defer a.m.Unlock()
	req.Equal(uint16(math.MaxUint16), a.availableCredits)
}

func TestCreditManager_DeficitRampUp(t *testing.T) {
	req := require.New(t)
	ctx := context.Background()

	// Initial balance is 1 credit, target is 10
	a := openAccount(10)

	// 1st request consumes 1 credit.
	// balance after loan = 0. needed = 10 - 0 = 10.
	p1 := &smb2.CreateRequest{}
	_, charge, err := a.loan(ctx, p1)
	req.NoError(err)
	req.Equal(uint16(1), charge)
	req.Equal(uint16(10), p1.CreditRequestResponse)

	// Server partially grants 2 credits (instead of 10)
	a.charge(2, 1) // available: 2, inFlight: 0

	// 2nd request consumes 1 credit.
	// balance after loan = 2 - 1 = 1. needed = 10 - 1 = 9.
	p2 := &smb2.CreateRequest{}
	_, charge, err = a.loan(ctx, p2)
	req.NoError(err)
	req.Equal(uint16(1), charge)
	req.Equal(uint16(9), p2.CreditRequestResponse)
}
