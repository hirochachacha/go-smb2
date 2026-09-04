package smb2

import (
	"context"
	"sync"

	"github.com/hirochachacha/go-smb2/internal/smb2"
)

type account struct {
	m                   sync.Mutex
	notify              chan struct{}
	targetCreditBalance uint16
	availableCredits    uint16
	maxCredits          uint16
	nextMessageId       uint64
}

func openAccount(targetCreditBalance uint16) *account {
	return &account{
		notify:              make(chan struct{}, 1),
		targetCreditBalance: targetCreditBalance,
		availableCredits:    1, // MS-SMB2 3.3.1.2 / 3.2.4.1.6: initial credit is 1
		maxCredits:          1,
		nextMessageId:       0,
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
	if a.targetCreditBalance > 0 && cap > a.targetCreditBalance {
		cap = a.targetCreditBalance
	}
	if cap < 1 {
		cap = 1
	}
	return cap
}

// loan requests credits for one or more packets, blocks until available, and assigns header fields.
func (a *account) loan(ctx context.Context, reqs ...smb2.Packet) (msgIds []uint64, totalCreditCharge uint16, err error) {
	if len(reqs) == 0 {
		return nil, 0, nil
	}

	charges := make([]uint16, len(reqs))
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
			req.SetCreditCharge(calcCreditCharge(inputSize + int(r.MaxOutputResponse)))
		case *smb2.QueryDirectoryRequest:
			req.SetCreditCharge(calcCreditCharge(int(r.OutputBufferLength)))
		}
		cc := req.CreditCharge()
		charges[i] = cc
		totalCreditCharge += cc
	}

	a.m.Lock()
	maxPossible := a.targetCreditBalance
	if a.maxCredits > maxPossible {
		maxPossible = a.maxCredits
	}
	if maxPossible < 1 {
		maxPossible = 1
	}
	if totalCreditCharge > maxPossible {
		a.m.Unlock()
		return nil, 0, &InternalError{Message: "requested credit charge exceeds maximum credit balance"}
	}
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
			startMsgId := a.nextMessageId
			a.nextMessageId += uint64(totalCreditCharge)

			var creditRequest uint16
			if a.targetCreditBalance > a.availableCredits {
				creditRequest = a.targetCreditBalance - a.availableCredits
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
func (a *account) charge(granted uint16) {
	if granted == 0 {
		return
	}

	a.m.Lock()
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
	if a.availableCredits > a.maxCredits {
		a.maxCredits = a.availableCredits
	}
	a.m.Unlock()

	a.signal()
}
