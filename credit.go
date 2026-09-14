package smb2

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2/v2/internal/smb2"
)

// The tree connection handles this before any part of a compound is sent.
var errCompoundCredits = errors.New("compound requires sequential requests")

type account struct {
	creditTimeout    time.Duration // immutable after the account is published
	m                sync.Mutex
	notify           chan struct{}
	closed           bool   // set once the account is aborted; no further loans are possible
	closeErr         error  // error returned to pending loans after abort
	maxCreditBalance uint16 // configured maximum credit balance (e.g., 128)
	availableCredits uint16 // credits currently available in sequence window
	inFlightCredits  uint16 // credits currently in flight
	maxCredits       uint16 // maximum observed credits granted by the server
	nextMessageId    uint64
}

// saturatingAddUint16 adds two uint16 values, clamping the result at math.MaxUint16
// to prevent wraparound of the credit sequence window.
func saturatingAddUint16(a, b uint16) uint16 {
	sum := uint32(a) + uint32(b)
	if sum > math.MaxUint16 {
		return math.MaxUint16
	}
	return uint16(sum)
}

func openAccount(maxCreditBalance uint16) *account {
	return &account{
		notify:           make(chan struct{}),
		maxCreditBalance: maxCreditBalance,
		availableCredits: 1, // MS-SMB2 3.3.1.2 / 3.2.4.1.6: initial credit is 1
		maxCredits:       1,
		nextMessageId:    0,
	}
}

// notifyWaitersLocked wakes every loan currently waiting for credits. The
// caller must hold a.m. The channel is closed to broadcast the wakeup: a
// waiter that still cannot proceed (for example, because it needs more
// credits than were replenished) must not consume the only wakeup and leave
// the remaining waiters blocked. The closed channel is replaced immediately
// under the same lock so that later waiters block on a fresh channel. No
// notification is lost because close happens before the replacement and the
// waiters capture the channel while holding a.m.
//
// The wait/notify scheme itself is client-side and implementation-defined per
// [MS-SMB2] 3.2.4.1.2, but it must preserve the requirement of [MS-SMB2]
// 3.2.4.1.3 that a request only proceeds once it can reserve its CreditCharge
// from the available credits.
func (a *account) notifyWaitersLocked() {
	close(a.notify)
	a.notify = make(chan struct{})
}

// abort closes the account so that any pending or subsequent loan fails
// immediately with err instead of blocking forever on credit availability.
func (a *account) abort(err error) {
	a.m.Lock()
	if a.closed {
		a.m.Unlock()
		return
	}
	if err == nil {
		err = &TransportError{Err: net.ErrClosed}
	}
	a.closeErr = err
	a.closed = true
	a.notifyWaitersLocked()
	a.m.Unlock()
}

// [MS-SMB2] 3.1.5.2 calculates CreditCharge from the payload size. Keep the
// calculation wide until it is known to fit the uint16 wire field, so the
// consecutive MessageIds required by [MS-SMB2] 3.2.4.1.5 are not undercounted.
func calcCreditCharge(payloadSize uint64) (uint16, error) {
	if payloadSize == 0 {
		return 1, nil
	}

	charge := (payloadSize-1)/uint64(maxSingleCreditPayloadSize) + 1
	if charge > math.MaxUint16 {
		return 0, &InternalError{Message: "credit charge exceeds uint16"}
	}
	return uint16(charge), nil
}

func (a *account) maxCreditCap() uint16 {
	a.m.Lock()
	defer a.m.Unlock()

	cap := a.maxCredits
	if a.maxCreditBalance > 0 && cap > a.maxCreditBalance {
		cap = a.maxCreditBalance
	}
	if cap < 1 {
		cap = 1
	}
	return cap
}

// loan requests credits for one or more packets, blocks until available, and assigns header fields.
func (a *account) loan(ctx context.Context, reqs ...smb2.Packet) (msgIds []uint64, totalCreditCharge uint16, err error) {
	// Charges are accumulated in uint32 to detect overflow of the uint16 wire field.
	if len(reqs) == 0 {
		return nil, 0, nil
	}

	charges := make([]uint16, len(reqs))
	var total uint32
	for i, req := range reqs {
		var cc uint16
		switch r := req.(type) {
		case *directReadRequest:
			cc, err = calcCreditCharge(uint64(r.Length))
		case *smb2.ReadRequest:
			cc, err = calcCreditCharge(uint64(r.Length))
		case *smb2.WriteRequest:
			cc, err = calcCreditCharge(uint64(len(r.Data)))
		case *smb2.IoctlRequest:
			var inputSize uint64
			if r.Input != nil {
				size := r.Input.Size()
				if size < 0 {
					return nil, 0, &InternalError{Message: "negative IOCTL input size"}
				}
				inputSize = uint64(size)
			}
			// [MS-SMB2] 3.3.5.15 validates credits using the larger of the
			// request and response buffer sums. Widen before adding.
			requestSize := inputSize + uint64(r.OutputCount)
			responseSize := uint64(r.MaxInputResponse) + uint64(r.MaxOutputResponse)
			cc, err = calcCreditCharge(max(requestSize, responseSize))
		case *smb2.QueryDirectoryRequest:
			cc, err = calcCreditCharge(uint64(r.OutputBufferLength))
		case *smb2.QueryInfoRequest:
			var inputSize uint64
			if r.Input != nil {
				size := r.Input.Size()
				if size < 0 {
					return nil, 0, &InternalError{Message: "negative QUERY_INFO input size"}
				}
				inputSize = uint64(size)
			}
			// [MS-SMB2] 3.3.5.20 requires the server to validate CreditCharge
			// against max(InputBufferLength, OutputBufferLength). That
			// contradicts 3.2.4.1.5, which tells the client to send 1 for every
			// command other than READ/WRITE/IOCTL/QUERY_DIRECTORY. Samba 4.19
			// enforces the server-side rule and rejects a >64 KiB QUERY_INFO
			// sent with CreditCharge 1, so the server-side document is adopted
			// deliberately. Do not revert this to a fixed charge of 1.
			cc, err = calcCreditCharge(max(inputSize, uint64(r.OutputBufferLength)))
		case *smb2.SetInfoRequest:
			var inputSize uint64
			if r.Input != nil {
				size := r.Input.Size()
				if size < 0 {
					return nil, 0, &InternalError{Message: "negative SET_INFO input size"}
				}
				inputSize = uint64(size)
			}
			// [MS-SMB2] 3.3.5.21 requires the server to validate CreditCharge
			// against BufferLength. Like QUERY_INFO above, this contradicts
			// 3.2.4.1.5, and Samba 4.19 enforces the server-side rule, so the
			// server-side document is adopted deliberately. Do not revert this
			// to a fixed charge of 1.
			cc, err = calcCreditCharge(inputSize)
		default:
			cc = req.CreditCharge()
		}
		if err != nil {
			return nil, 0, err
		}
		charges[i] = cc
		total += uint32(cc)
		if total > math.MaxUint16 {
			return nil, 0, &InternalError{Message: "compound credit charge exceeds uint16"}
		}
	}

	a.m.Lock()
	maxPossible := max(max(a.maxCredits, a.maxCreditBalance), 1)
	if total > math.MaxUint16 || total > uint32(maxPossible) {
		a.m.Unlock()
		if len(reqs) > 1 && total <= math.MaxUint16 {
			return nil, 0, errCompoundCredits
		}
		return nil, 0, &InternalError{Message: "requested credit charge exceeds maximum credit balance"}
	}
	totalCreditCharge = uint16(total)
	a.m.Unlock()

	var timeout <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-timeout:
			return nil, 0, context.DeadlineExceeded
		default:
		}

		a.m.Lock()

		if a.closed {
			err := a.closeErr
			a.m.Unlock()
			return nil, 0, err
		}

		if a.availableCredits >= totalCreditCharge {
			a.availableCredits -= totalCreditCharge
			a.inFlightCredits += totalCreditCharge
			startMsgId := a.nextMessageId
			a.nextMessageId += uint64(totalCreditCharge)

			var creditRequest uint16
			// MS-SMB2 3.2.4.1.2:
			// Request credits sufficient to maintain total outstanding limit at maxCreditBalance.
			balance := int32(a.availableCredits) + int32(a.inFlightCredits) - int32(totalCreditCharge)
			needed := int32(a.maxCreditBalance) - balance
			if needed > 0 {
				creditRequest = uint16(needed)
			}

			a.m.Unlock()

			msgIds = make([]uint64, len(reqs))
			msgId := startMsgId
			for i, req := range reqs {
				switch req.(type) {
				case *directReadRequest, *smb2.ReadRequest, *smb2.WriteRequest,
					*smb2.IoctlRequest, *smb2.QueryDirectoryRequest, *smb2.QueryInfoRequest,
					*smb2.SetInfoRequest:
					req.SetCreditCharge(charges[i])
				}
				msgIds[i] = msgId

				req.SetMessageId(msgId)

				msgId += uint64(charges[i])
			}

			// [MS-SMB2] 3.2.4.1.2 and 3.2.4.1.4 require each compound
			// request to replenish its charge when maintaining the balance.
			// Preserve the total request when adjusting the balance: assign
			// up to each charge, then put any extra on the first request.
			// The assignments sum to creditRequest, so each fits in uint16.
			remaining := uint32(creditRequest)
			assigned := make([]uint32, len(reqs))
			for i, charge := range charges {
				assigned[i] = min(uint32(charge), remaining)
				remaining -= assigned[i]
			}
			assigned[0] += remaining
			for i, req := range reqs {
				req.SetCreditRequest(uint16(assigned[i]))
			}

			return msgIds, totalCreditCharge, nil
		}
		// With no requests in flight, make progress using the credits already
		// granted rather than depending on a future unrelated operation. A
		// compound can be sent separately; an indivisible multi-credit request
		// exceeding this idle window hits our local limit ([MS-SMB2] 3.2.4.1.3).
		if a.inFlightCredits == 0 && a.availableCredits > 0 {
			a.m.Unlock()
			if len(reqs) > 1 {
				return nil, 0, errCompoundCredits
			}
			return nil, 0, &InternalError{Message: "requested credit charge exceeds idle credit window"}
		}
		// Capture the current notification channel under the lock so that a
		// replenishment racing with this wait cannot be missed. The channel is
		// closed (not sent to) by notifyWaitersLocked, so a waiter that was
		// woken but still lacks credits simply waits on the replacement channel.
		notify := a.notify
		a.m.Unlock()

		// Bound the entire credit wait, including retries after insufficient
		// grants. Keep this timer local so it cannot cancel a sent request or
		// affect other requests sharing the account.
		if timeout == nil {
			duration := a.creditTimeout
			if duration <= 0 {
				duration = clientCreditTimeout
			}
			timer := time.NewTimer(duration)
			defer timer.Stop()
			timeout = timer.C
		}

		select {
		case <-notify:
			// Replenished, retry loan
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-timeout:
			return nil, 0, context.DeadlineExceeded
		}
	}
}

// charge replenishes credits granted by server response.
func (a *account) charge(granted uint16, consumed ...uint16) {
	var c uint16
	if len(consumed) > 0 {
		c = consumed[0]
	}
	if granted == 0 && c == 0 {
		return
	}

	a.m.Lock()
	if a.inFlightCredits >= c {
		a.inFlightCredits -= c
	} else {
		a.inFlightCredits = 0
	}
	// Saturate instead of wrapping around the uint16 wire field.
	a.availableCredits = saturatingAddUint16(a.availableCredits, granted)
	if a.availableCredits > a.maxCredits {
		a.maxCredits = a.availableCredits
	}
	a.notifyWaitersLocked()
	a.m.Unlock()
}

// unloan restores credits if sending a packet fails before network transmission.
func (a *account) unloan(creditCharge uint16) {
	if creditCharge == 0 {
		return
	}

	a.m.Lock()
	// Saturate instead of wrapping around the uint16 wire field.
	a.availableCredits = saturatingAddUint16(a.availableCredits, creditCharge)
	if a.inFlightCredits >= creditCharge {
		a.inFlightCredits -= creditCharge
	} else {
		a.inFlightCredits = 0
	}
	if a.availableCredits > a.maxCredits {
		a.maxCredits = a.availableCredits
	}
	a.notifyWaitersLocked()
	a.m.Unlock()
}
