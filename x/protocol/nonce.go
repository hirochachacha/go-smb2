package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync/atomic"
)

var errEncryptionNonceExhausted = errors.New("protocol: session encryption nonce space exhausted")

// encryptionNonces belongs to the session encryption key, not a connection.
// Every channel shares this object, including pinned compound/LOGOFF sessions.
// A random prefix separates independently authenticated sessions, whose GSS
// keys should already be distinct. The counter guarantees uniqueness within
// this key's session lifetime; reservations are never rolled back.
type encryptionNonces struct {
	prefix [4]byte
	used   atomic.Uint64
}

func newEncryptionNonces(random io.Reader) (*encryptionNonces, error) {
	a := new(encryptionNonces)
	if _, err := io.ReadFull(random, a.prefix[:]); err != nil {
		return nil, fmt.Errorf("protocol: initialize encryption nonce prefix: %w", err)
	}
	return a, nil
}

func (a *encryptionNonces) next(size int) (nonce [16]byte, err error) {
	// [MS-SMB2] 2.2.41: 11 bytes for CCM, 12 for GCM; reserved bytes zero.
	if size != 11 && size != 12 {
		return nonce, errors.New("protocol: invalid encryption nonce size")
	}
	if a == nil {
		return nonce, errors.New("protocol: missing session encryption nonce state")
	}
	for {
		previous := a.used.Load()
		if previous == math.MaxUint64 {
			return nonce, errEncryptionNonceExhausted
		}
		if a.used.CompareAndSwap(previous, previous+1) {
			copy(nonce[:size-8], a.prefix[:])
			binary.LittleEndian.PutUint64(nonce[size-8:size], previous+1)
			return nonce, nil
		}
	}
}
