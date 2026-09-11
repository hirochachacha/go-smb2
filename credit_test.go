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
	case *directReadRequest:
		return p.CreditRequestResponse
	case *smb2.IoctlRequest:
		return p.CreditRequestResponse
	case *smb2.QueryDirectoryRequest:
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

func TestCalcCreditCharge(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize uint64
		want        uint16
		wantErr     bool
	}{
		{name: "empty", payloadSize: 0, want: 1},
		{name: "one credit boundary", payloadSize: 65536, want: 1},
		{name: "two credit boundary", payloadSize: 65537, want: 2},
		{name: "maximum representable", payloadSize: 4294901760, want: math.MaxUint16},
		{name: "just over maximum representable", payloadSize: 4294901761, wantErr: true},
		{name: "maximum uint32", payloadSize: math.MaxUint32, wantErr: true},
		{name: "maximum uint64", payloadSize: math.MaxUint64, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := calcCreditCharge(tt.payloadSize)
			if tt.wantErr {
				require.Error(t, err)
				require.IsType(t, &InternalError{}, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
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

	// QueryInfoRequest (128KB output -> credit charge 2)
	a = openAccount(10)
	a.charge(10)
	qiReq := &smb2.QueryInfoRequest{OutputBufferLength: 128 * 1024}
	_, charge, err = a.loan(ctx, qiReq)
	req.NoError(err)
	req.Equal(uint16(2), charge)
	req.Equal(uint16(2), qiReq.CreditCharge())

	// QueryInfoRequest input larger than output follows the input size
	a = openAccount(10)
	a.charge(10)
	qiInputReq := &smb2.QueryInfoRequest{
		Input:              &fakeEncoder{size: 128 * 1024},
		OutputBufferLength: 64 * 1024,
	}
	_, charge, err = a.loan(ctx, qiInputReq)
	req.NoError(err)
	req.Equal(uint16(2), charge)
	req.Equal(uint16(2), qiInputReq.CreditCharge())

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

	// Direct READ uses the same charge calculation without allocating its payload.
	a = openAccount(65535)
	directReadReq := &directReadRequest{
		ReadRequest: &smb2.ReadRequest{Length: math.MaxUint32},
	}
	_, charge, err = a.loan(ctx, directReadReq)
	req.Error(err)
	req.IsType(&InternalError{}, err)
	req.Equal(uint16(1), directReadReq.CreditCharge())

	// A negative encoder size is invalid and must not be converted to uint64.
	a = openAccount(10)
	negativeInputReq := &smb2.IoctlRequest{Input: &fakeEncoder{size: -1}}
	_, charge, err = a.loan(ctx, negativeInputReq)
	req.Error(err)
	req.IsType(&InternalError{}, err)
	req.Equal(uint16(0), charge)
	req.Equal(uint16(1), negativeInputReq.CreditCharge())

	// A negative encoder size is invalid for QueryInfoRequest too.
	a = openAccount(10)
	negativeQiReq := &smb2.QueryInfoRequest{Input: &fakeEncoder{size: -1}, OutputBufferLength: 1}
	_, charge, err = a.loan(ctx, negativeQiReq)
	req.Error(err)
	req.IsType(&InternalError{}, err)
	req.Equal(uint16(0), charge)
	req.Equal(uint16(1), negativeQiReq.CreditCharge())
}

func TestCreditManager_IOCTLBufferSums(t *testing.T) {
	tests := []struct {
		name    string
		request smb2.IoctlRequest
		want    uint16
	}{
		{name: "response sum 65536", request: smb2.IoctlRequest{Input: &fakeEncoder{size: 1}, MaxInputResponse: 65535, MaxOutputResponse: 1}, want: 1},
		{name: "response sum 65537", request: smb2.IoctlRequest{Input: &fakeEncoder{size: 1}, MaxInputResponse: 65536, MaxOutputResponse: 1}, want: 2},
		{name: "larger input", request: smb2.IoctlRequest{Input: &fakeEncoder{size: 131073}, MaxInputResponse: 65536, MaxOutputResponse: 1}, want: 3},
		{name: "request sum", request: smb2.IoctlRequest{Input: &fakeEncoder{size: 65536}, OutputCount: 1}, want: 2},
		{name: "nil input", request: smb2.IoctlRequest{MaxInputResponse: 65536, MaxOutputResponse: 1}, want: 2},
		{name: "empty", request: smb2.IoctlRequest{}, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := openAccount(10)
			a.charge(9)
			msgIds, charge, err := a.loan(context.Background(), &tt.request)
			require.NoError(t, err)
			require.Equal(t, tt.want, charge)
			require.Equal(t, tt.want, tt.request.CreditCharge())
			require.Equal(t, []uint64{0}, msgIds)
			require.Equal(t, uint16(10)-tt.want, a.availableCredits)
			require.Equal(t, tt.want, a.inFlightCredits)
			require.Equal(t, uint64(tt.want), a.nextMessageId)
		})
	}
}

func TestCreditManager_IOCTLInvalidSizesPreserveState(t *testing.T) {
	tests := []struct {
		name      string
		request   smb2.IoctlRequest
		wantError string
	}{
		{name: "negative input", request: smb2.IoctlRequest{Input: &fakeEncoder{size: -1}}, wantError: "negative IOCTL input size"},
		{name: "maximum response fields", request: smb2.IoctlRequest{MaxInputResponse: math.MaxUint32, MaxOutputResponse: math.MaxUint32}, wantError: "credit charge exceeds uint16"},
		{name: "response sum wraps uint32", request: smb2.IoctlRequest{MaxInputResponse: math.MaxUint32, MaxOutputResponse: 2}, wantError: "credit charge exceeds uint16"},
		{name: "request sum wraps uint32", request: smb2.IoctlRequest{Input: &fakeEncoder{size: 2}, OutputCount: math.MaxUint32}, wantError: "credit charge exceeds uint16"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := openAccount(math.MaxUint16)
			a.charge(math.MaxUint16 - 1)
			_, _, err := a.loan(context.Background(), &smb2.CreateRequest{})
			require.NoError(t, err)
			tt.request.SetCreditCharge(7)
			tt.request.SetCreditRequest(8)
			tt.request.SetMessageId(9)
			want := tt.request

			msgIds, charge, err := a.loan(context.Background(), &tt.request)
			require.IsType(t, &InternalError{}, err)
			require.ErrorContains(t, err, tt.wantError)
			require.Nil(t, msgIds)
			require.Zero(t, charge)
			require.Equal(t, want, tt.request)
			require.Equal(t, uint16(math.MaxUint16-1), a.availableCredits)
			require.Equal(t, uint16(1), a.inFlightCredits)
			require.Equal(t, uint16(math.MaxUint16), a.maxCredits)
			require.Equal(t, uint64(1), a.nextMessageId)
		})
	}
}

func TestCreditManager_IOCTLWireChargeAndMessageIds(t *testing.T) {
	a := openAccount(10)
	a.charge(9)
	p := &smb2.IoctlRequest{
		Input:             &fakeEncoder{size: 1},
		MaxInputResponse:  65536,
		MaxOutputResponse: 1,
		// [MS-SMB2] 2.2.31 requires client OutputCount to be zero.
		OutputCount: 0,
	}
	msgIds, charge, err := a.loan(context.Background(), p)
	require.NoError(t, err)
	require.Equal(t, uint16(2), charge)
	encoded := make([]byte, p.Size())
	p.Encode(encoded)
	packet := smb2.PacketCodec(encoded)
	require.Equal(t, uint16(2), packet.CreditCharge())
	require.Equal(t, msgIds[0], packet.MessageId())
	require.Zero(t, smb2.IoctlRequestDecoder(packet.Body()).OutputCount())

	next := &smb2.CreateRequest{}
	msgIds, _, err = a.loan(context.Background(), next)
	require.NoError(t, err)
	require.Equal(t, packet.MessageId()+2, msgIds[0])
	require.Equal(t, msgIds[0], next.MessageId)
}

func TestCreditManager_ChargeBoundaries(t *testing.T) {
	tests := []struct {
		name string
		new  func(uint32) smb2.Packet
	}{
		{
			name: "read",
			new: func(size uint32) smb2.Packet {
				return &smb2.ReadRequest{Length: size}
			},
		},
		{
			name: "direct read",
			new: func(size uint32) smb2.Packet {
				return &directReadRequest{ReadRequest: &smb2.ReadRequest{Length: size}}
			},
		},
		{
			name: "query directory",
			new: func(size uint32) smb2.Packet {
				return &smb2.QueryDirectoryRequest{OutputBufferLength: size}
			},
		},
		{
			name: "ioctl output",
			new: func(size uint32) smb2.Packet {
				return &smb2.IoctlRequest{MaxOutputResponse: size}
			},
		},
	}

	const payloadSize uint32 = 4294901760
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			a := openAccount(math.MaxUint16)
			a.charge(math.MaxUint16 - 1)
			p := tt.new(payloadSize)

			msgIds, charge, err := a.loan(context.Background(), p)
			req.NoError(err)
			req.Equal([]uint64{0}, msgIds)
			req.Equal(uint16(math.MaxUint16), charge)
			req.Equal(uint16(math.MaxUint16), p.CreditCharge())
			req.Equal(uint16(math.MaxUint16), creditRequest(p))
			req.Equal(uint16(0), a.availableCredits)
			req.Equal(uint16(math.MaxUint16), a.inFlightCredits)
			req.Equal(uint64(math.MaxUint16), a.nextMessageId)

			for _, size := range []uint32{payloadSize + 1, math.MaxUint32} {
				a := openAccount(math.MaxUint16)
				a.charge(math.MaxUint16 - 1)
				p, want := tt.new(size), tt.new(size)
				for _, packet := range []smb2.Packet{p, want} {
					packet.SetCreditCharge(7)
					packet.SetCreditRequest(8)
					packet.SetMessageId(9)
				}
				msgIds, charge, err := a.loan(context.Background(), p)
				req.IsType(&InternalError{}, err)
				req.Nil(msgIds)
				req.Zero(charge)
				req.Equal(want, p)
				req.Equal(uint16(math.MaxUint16), a.availableCredits)
				req.Zero(a.inFlightCredits)
				req.Equal(uint16(math.MaxUint16), a.maxCredits)
				req.Zero(a.nextMessageId)
			}
		})
	}
}

func TestCreditManager_RejectsUnrepresentableIOCTLInput(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	inputSize := uint64(4294901761)
	if uint64(maxInt) < inputSize {
		t.Skip("fakeEncoder cannot represent an unrepresentable IOCTL input size")
	}

	req := require.New(t)
	a := openAccount(10)
	p := &smb2.IoctlRequest{Input: &fakeEncoder{size: int(inputSize)}}
	p.SetCreditCharge(7)
	p.SetCreditRequest(8)
	p.SetMessageId(9)

	msgIds, charge, err := a.loan(context.Background(), p)
	req.Error(err)
	req.IsType(&InternalError{}, err)
	req.Nil(msgIds)
	req.Equal(uint16(0), charge)
	req.Equal(uint16(7), p.CreditCharge())
	req.Equal(uint16(8), p.CreditRequestResponse)
	req.Equal(uint64(9), p.MessageId)
	req.Equal(uint16(1), a.availableCredits)
	req.Zero(a.inFlightCredits)
	req.Equal(uint16(1), a.maxCredits)
	req.Zero(a.nextMessageId)
}

func TestCreditManager_RejectedLoanPreservesRequestsAndAccount(t *testing.T) {
	t.Run("single request", func(t *testing.T) {
		req := require.New(t)
		a := openAccount(10)
		p := &smb2.ReadRequest{Length: 4294901761}
		p.SetCreditCharge(1)
		p.SetCreditRequest(11)
		p.SetMessageId(12)

		msgIds, charge, err := a.loan(context.Background(), p)
		req.Error(err)
		req.IsType(&InternalError{}, err)
		req.Nil(msgIds)
		req.Equal(uint16(0), charge)
		req.Equal(uint16(1), p.CreditCharge())
		req.Equal(uint16(11), p.CreditRequestResponse)
		req.Equal(uint64(12), p.MessageId)
		req.Equal(uint16(1), a.availableCredits)
		req.Equal(uint16(0), a.inFlightCredits)
		req.Equal(uint16(1), a.maxCredits)
		req.Equal(uint64(0), a.nextMessageId)
	})

	t.Run("normal request followed by excessive request", func(t *testing.T) {
		req := require.New(t)
		a := openAccount(10)
		p1 := &smb2.ReadRequest{Length: 0}
		p1.SetCreditCharge(7)
		p1.SetCreditRequest(11)
		p1.SetMessageId(12)
		p2 := &smb2.ReadRequest{Length: 4294901761}
		p2.SetCreditCharge(2)
		p2.SetCreditRequest(21)
		p2.SetMessageId(22)

		msgIds, charge, err := a.loan(context.Background(), p1, p2)
		req.Error(err)
		req.IsType(&InternalError{}, err)
		req.Nil(msgIds)
		req.Equal(uint16(0), charge)
		req.Equal(uint16(7), p1.CreditCharge())
		req.Equal(uint16(11), p1.CreditRequestResponse)
		req.Equal(uint64(12), p1.MessageId)
		req.Equal(uint16(2), p2.CreditCharge())
		req.Equal(uint16(21), p2.CreditRequestResponse)
		req.Equal(uint64(22), p2.MessageId)
		req.Equal(uint16(1), a.availableCredits)
		req.Equal(uint16(0), a.inFlightCredits)
		req.Equal(uint16(1), a.maxCredits)
		req.Equal(uint64(0), a.nextMessageId)
	})

	t.Run("individually valid requests over cumulative limit", func(t *testing.T) {
		req := require.New(t)
		a := openAccount(math.MaxUint16)
		p1 := &smb2.ReadRequest{Length: 4294901760}
		p1.SetCreditCharge(3)
		p1.SetCreditRequest(31)
		p1.SetMessageId(32)
		p2 := &smb2.ReadRequest{Length: 4294901760}
		p2.SetCreditCharge(4)
		p2.SetCreditRequest(41)
		p2.SetMessageId(42)

		msgIds, charge, err := a.loan(context.Background(), p1, p2)
		req.Error(err)
		req.IsType(&InternalError{}, err)
		req.Nil(msgIds)
		req.Equal(uint16(0), charge)
		req.Equal(uint16(3), p1.CreditCharge())
		req.Equal(uint16(31), p1.CreditRequestResponse)
		req.Equal(uint64(32), p1.MessageId)
		req.Equal(uint16(4), p2.CreditCharge())
		req.Equal(uint16(41), p2.CreditRequestResponse)
		req.Equal(uint64(42), p2.MessageId)
		req.Equal(uint16(1), a.availableCredits)
		req.Equal(uint16(0), a.inFlightCredits)
		req.Equal(uint16(1), a.maxCredits)
		req.Equal(uint64(0), a.nextMessageId)
	})
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
