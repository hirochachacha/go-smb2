package protocol

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncryptionNoncesLengthsAndInitialization(t *testing.T) {
	t.Parallel()
	for _, size := range []int{11, 12} {
		a, err := newEncryptionNonces(bytes.NewReader([]byte{1, 2, 3, 4}))
		require.NoError(t, err)
		for want := uint64(1); want <= 2; want++ {
			nonce, err := a.next(size)
			require.NoError(t, err)
			require.Equal(t, []byte{1, 2, 3, 4}[:size-8], nonce[:size-8])
			require.Equal(t, want, binary.LittleEndian.Uint64(nonce[size-8:size]))
			require.Equal(t, make([]byte, 16-size), nonce[size:])
		}
	}
	_, err := newEncryptionNonces(bytes.NewReader([]byte{1}))
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestEncryptionNoncesConcurrentExhaustionNeverWraps(t *testing.T) {
	t.Parallel()
	a := new(encryptionNonces)
	a.used.Store(math.MaxUint64 - 1)
	var wg sync.WaitGroup
	results := make(chan error, 32)
	for range 32 {
		wg.Go(func() {
			nonce, err := a.next(12)
			if err == nil {
				require.Equal(t, uint64(math.MaxUint64), binary.LittleEndian.Uint64(nonce[4:12]))
			}
			results <- err
		})
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, errEncryptionNonceExhausted)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, uint64(math.MaxUint64), a.used.Load())
	_, err := a.next(11)
	require.ErrorIs(t, err, errEncryptionNonceExhausted)
}

func TestEncryptionNoncesConcurrentReservations(t *testing.T) {
	t.Parallel()
	a := new(encryptionNonces)
	var wg sync.WaitGroup
	results := make(chan [16]byte, 1024)
	for range 8 {
		wg.Go(func() {
			for range 128 {
				nonce, err := a.next(11)
				require.NoError(t, err)
				results <- nonce
			}
		})
	}
	wg.Wait()
	close(results)
	seen := make(map[[16]byte]bool)
	for nonce := range results {
		require.False(t, seen[nonce])
		seen[nonce] = true
	}
	require.Len(t, seen, 1024)
	_, err := a.next(10)
	require.Error(t, err)
	require.Equal(t, uint64(1024), a.used.Load())
}
