package smb2

import (
	"context"
	"math"
	"sync"

	"github.com/hirochachacha/go-smb2/internal/smb2"
)

type account struct {
	m                sync.Mutex
	notify           chan struct{}
	maxCreditBalance uint16 // configured maximum credit balance (e.g., 128)
	availableCredits uint16 // credits currently available in sequence window
	inFlightCredits  uint16 // credits currently in flight
	maxCredits       uint16 // maximum observed credits granted by the server
	nextMessageId    uint64
}

func openAccount(maxCreditBalance uint16) *account {
	return &account{
		notify:           make(chan struct{}, 1),
		maxCreditBalance: maxCreditBalance,
		availableCredits: 1, // MS-SMB2 3.3.1.2 / 3.2.4.1.6: initial credit is 1
		maxCredits:       1,
		nextMessageId:    0,
	}
}

func (a *account) signal() {
	select {
	case a.notify <- struct{}{}:
	default:
	}
}

func calcCreditCharge(payloadSize int) uint16 {
	return uint16((payloadSize-1)/singleCreditMaxPayloadSize + 1)
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
		switch r := req.(type) {
		case *smb2.ReadRequest:
			req.SetCreditCharge(calcCreditCharge(int(r.Length)))
		case *smb2.WriteRequest:
			req.SetCreditCharge(calcCreditCharge(len(r.Data)))
		case *smb2.IoctlRequest:
			inputSize := 0
			if r.Input != nil {
				inputSize = r.Input.Size()
			}
			req.SetCreditCharge(calcCreditCharge(max(inputSize, int(r.MaxOutputResponse))))
		case *smb2.QueryDirectoryRequest:
			req.SetCreditCharge(calcCreditCharge(int(r.OutputBufferLength)))
		}
		cc := req.CreditCharge()
		charges[i] = cc
		total += uint32(cc)
	}

	a.m.Lock()
	maxPossible := a.maxCreditBalance
	if a.maxCredits > maxPossible {
		maxPossible = a.maxCredits
	}
	if maxPossible < 1 {
		maxPossible = 1
	}
	if total > math.MaxUint16 || total > uint32(maxPossible) {
		a.m.Unlock()
		return nil, 0, &InternalError{Message: "requested credit charge exceeds maximum credit balance"}
	}
	totalCreditCharge = uint16(total)
	a.m.Unlock()

	for {
		select {
		case <-ctx.Done():
			return nil, 0, &ContextError{Err: ctx.Err()}
		default:
		}

		a.m.Lock()

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

			a.signal()

			msgIds = make([]uint64, len(reqs))
			msgId := startMsgId
			for i, req := range reqs {
				msgIds[i] = msgId

				req.SetMessageId(msgId)

				msgId += uint64(charges[i])
			}

			reqs[0].SetCreditRequest(creditRequest)

			return msgIds, totalCreditCharge, nil
		}
		a.m.Unlock()

		select {
		case <-a.notify:
			// Replenished, retry loan
		case <-ctx.Done():
			return nil, 0, &ContextError{Err: ctx.Err()}
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
	a.availableCredits += granted
	if a.availableCredits > a.maxCredits {
		a.maxCredits = a.availableCredits
	}
	a.m.Unlock()

	a.signal()
}

// unloan restores credits if sending a packet fails before network transmission.
func (a *account) unloan(creditCharge uint16) {
	if creditCharge == 0 {
		return
	}

	a.m.Lock()
	a.availableCredits += creditCharge
	if a.inFlightCredits >= creditCharge {
		a.inFlightCredits -= creditCharge
	} else {
		a.inFlightCredits = 0
	}
	if a.availableCredits > a.maxCredits {
		a.maxCredits = a.availableCredits
	}
	a.m.Unlock()

	a.signal()
}
