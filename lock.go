package smb2

import (
	"context"
	"math"
	"os"

	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// ByteRange identifies a byte range associated with a File handle. A zero
// Length is sent to the server unchanged; it is not interpreted as EOF.
type ByteRange struct {
	Offset int64
	Length int64
}

// LockRange describes one shared or exclusive byte-range lock.
type LockRange struct {
	Range     ByteRange
	Exclusive bool
}

const maxLockRequestSize = 64 * 1024

func validateByteRange(r ByteRange) error {
	if r.Offset < 0 || r.Length < 0 {
		return os.ErrInvalid
	}
	if r.Length > 0 && r.Length-1 > math.MaxInt64-r.Offset {
		return os.ErrInvalid
	}
	return nil
}

func validateLockRangeCount(count int) error {
	if count == 0 || count > math.MaxUint16 || 64+24+count*24 > maxLockRequestSize {
		return os.ErrInvalid
	}
	return nil
}

// Lock acquires shared or exclusive byte-range locks on this File handle.
// With failImmediately false, multiple ranges are rejected because SMB2 only
// permits a multi-range request to be immediate. A transport failure leaves
// the server-side lock state uncertain; multiple ranges are not retried or
// rolled back.
// Cancellation sends SMB2 CANCEL and waits for the server's final result.
// A successful lock is returned as success even if ctx has expired; cancellation
// does not release locks. The request rules are defined by [MS-SMB2] 3.2.4.19.
func (f *File) Lock(ctx context.Context, ranges []LockRange, failImmediately bool) error {
	if ctx == nil {
		panic("nil context")
	}
	if err := f.checkValid(); err != nil {
		return err
	}
	if !failImmediately && len(ranges) > 1 {
		return os.ErrInvalid
	}
	if err := validateLockRangeCount(len(ranges)); err != nil {
		return err
	}

	locks := make([]wire.LockElement, len(ranges))
	for i, lock := range ranges {
		if err := validateByteRange(lock.Range); err != nil {
			return err
		}
		flags := uint32(wire.SMB2_LOCKFLAG_SHARED_LOCK)
		if lock.Exclusive {
			flags = wire.SMB2_LOCKFLAG_EXCLUSIVE_LOCK
		}
		if failImmediately {
			flags |= wire.SMB2_LOCKFLAG_FAIL_IMMEDIATELY
		}
		locks[i] = wire.LockElement{
			Offset: uint64(lock.Range.Offset),
			Length: uint64(lock.Range.Length),
			Flags:  flags,
		}
	}

	res, err := f.fs.Request().WithFollowSymlinks(true).WithFileID(f.fd).Lock(locks).Do(ctx)
	if err != nil {
		return &os.PathError{Op: "lock", Path: f.name, Err: err}
	}
	res.Close()
	return nil
}

// Unlock releases byte-range locks on this File handle. Each range must be
// identical to the range used to acquire the lock; the server may process a
// multi-range unlock only partially before returning an error. A transport
// failure leaves the server-side lock state uncertain and is not retried.
// The exact-match and partial-processing rules are from [MS-SMB2] 3.3.5.14.1.
func (f *File) Unlock(ctx context.Context, ranges []ByteRange) error {
	if ctx == nil {
		panic("nil context")
	}
	if err := f.checkValid(); err != nil {
		return err
	}
	if err := validateLockRangeCount(len(ranges)); err != nil {
		return err
	}

	locks := make([]wire.LockElement, len(ranges))
	for i, r := range ranges {
		if err := validateByteRange(r); err != nil {
			return err
		}
		locks[i] = wire.LockElement{
			Offset: uint64(r.Offset),
			Length: uint64(r.Length),
			Flags:  wire.SMB2_LOCKFLAG_UNLOCK,
		}
	}

	res, err := f.fs.Request().WithFollowSymlinks(true).WithFileID(f.fd).Lock(locks).Do(ctx)
	if err != nil {
		return &os.PathError{Op: "unlock", Path: f.name, Err: err}
	}
	res.Close()
	return nil
}
