package smb2

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
)

// SymlinkError reports a CREATE stopped at an ordinary symbolic link. Path is
// the actual UNC used by the CREATE; ResolvedPath already includes its suffix.
type SymlinkError struct {
	Path         string // Actual path used by the stopped CREATE.
	Target       string // Symbolic-link target, normalized as a user-visible path.
	Relative     bool   // Whether the target was marked relative by the server.
	UnparsedPath string // Suffix the server did not parse at the link.
	ResolvedPath string // Target with UnparsedPath appended.
	err          error
}

func (e *SymlinkError) Error() string {
	return fmt.Sprintf("symbolic link at %q points to %q", e.Path, e.Target)
}
func (e *SymlinkError) Unwrap() error { return e.err }

// DFSReferralError reports a DFS CREATE stopped with STATUS_PATH_NOT_COVERED.
type DFSReferralError struct {
	Path string // Full UNC path used by the stopped CREATE.
	err  error
}

func (e *DFSReferralError) Error() string { return fmt.Sprintf("DFS referral required for %q", e.Path) }
func (e *DFSReferralError) Unwrap() error { return e.err }

// TransportError represents a error come from net.Conn layer.
type TransportError struct {
	Err error
}

func (err *TransportError) Error() string {
	return fmt.Sprintf("connection error: %v", err.Err)
}

func (err *TransportError) Unwrap() error {
	return err.Err
}

// InternalError represents internal error.
type InternalError struct {
	Message string
}

func (err *InternalError) Error() string {
	return fmt.Sprintf("internal error: %s", err.Message)
}

// InvalidResponseError represents a data sent by the server is corrupted or unexpected.
type InvalidResponseError struct {
	Message string
}

func (err *InvalidResponseError) Error() string {
	return fmt.Sprintf("invalid response error: %s", err.Message)
}

// ResponseError represents a error with a nt status code sent by the server.
// The NTSTATUS is defined in [MS-ERREF].
// https://msdn.microsoft.com/en-au/library/cc704588.aspx
type ResponseError struct {
	Code uint32 // NTSTATUS
	data [][]byte

	// requiredBufferLength is populated only after conn.accept validates the
	// QUERY_INFO error-data format. It is intentionally private so callers
	// cannot mistake arbitrary server error data for a retry instruction.
	requiredBufferLength uint32
}

// requireBufferLength returns the required buffer length reported by the server,
// if any, for errors such as STATUS_BUFFER_TOO_SMALL or STATUS_INFO_LENGTH_MISMATCH.
func (err *ResponseError) requireBufferLength() (int, bool) {
	if err == nil || err.requiredBufferLength == 0 {
		return 0, false
	}
	return int(err.requiredBufferLength), true
}

func (err ResponseError) Error() string {
	return fmt.Sprintf("response error: %v", erref.NtStatus(err.Code))
}

func (err ResponseError) Unwrap() error {
	switch erref.NtStatus(err.Code) {
	case erref.STATUS_OBJECT_NAME_NOT_FOUND,
		erref.STATUS_OBJECT_PATH_NOT_FOUND:
		return os.ErrNotExist
	case erref.STATUS_OBJECT_NAME_COLLISION:
		return os.ErrExist
	case erref.STATUS_ACCESS_DENIED,
		erref.STATUS_CANNOT_DELETE,
		erref.STATUS_NETWORK_ACCESS_DENIED:
		return os.ErrPermission
	case erref.STATUS_FILE_CLOSED,
		erref.STATUS_CONNECTION_DISCONNECTED:
		return os.ErrClosed
	}
	return nil
}

func (err ResponseError) As(target any) bool {
	if p, ok := target.(*erref.NtStatus); ok {
		*p = erref.NtStatus(err.Code)
		return true
	}
	return false
}

func (err ResponseError) Is(target error) bool {
	if status, ok := target.(erref.NtStatus); ok {
		return erref.NtStatus(err.Code) == status
	}
	switch target {
	case os.ErrNotExist, syscall.ENOENT:
		switch erref.NtStatus(err.Code) {
		case erref.STATUS_OBJECT_NAME_NOT_FOUND,
			erref.STATUS_OBJECT_PATH_NOT_FOUND:
			return true
		}
	case os.ErrExist, syscall.EEXIST:
		switch erref.NtStatus(err.Code) {
		case erref.STATUS_OBJECT_NAME_COLLISION:
			return true
		}
	case os.ErrPermission, syscall.EACCES, syscall.EPERM:
		switch erref.NtStatus(err.Code) {
		case erref.STATUS_ACCESS_DENIED,
			erref.STATUS_CANNOT_DELETE,
			erref.STATUS_NETWORK_ACCESS_DENIED:
			return true
		}
	case os.ErrClosed:
		switch erref.NtStatus(err.Code) {
		case erref.STATUS_FILE_CLOSED,
			erref.STATUS_CONNECTION_DISCONNECTED:
			return true
		}
	}
	if unwrapped := err.Unwrap(); unwrapped != nil {
		return errors.Is(unwrapped, target) || unwrapped == target
	}
	return false
}

// CompoundResponseError represents errors that occurred during execution of a compound request.
type CompoundResponseError struct {
	Errors []error
}

func (e *CompoundResponseError) Error() string {
	if e == nil {
		return "empty error"
	}
	var b []byte
	for _, err := range e.Errors {
		b = append(b, '\n')
		if err != nil {
			b = append(b, err.Error()...)
		}
	}
	if len(b) == 0 {
		return "empty error"
	}
	return unsafe.String(&b[0], len(b))
}

func (e *CompoundResponseError) Unwrap() []error {
	return e.Errors
}

func (e *CompoundResponseError) OpError(i int) error {
	if i < 0 || i >= len(e.Errors) {
		return nil
	}
	return e.Errors[i]
}

// requireBufferLength returns the required buffer length from the failed operation at index i in the compound.
func (e *CompoundResponseError) requireBufferLength(i int) (int, bool) {
	if e == nil {
		return 0, false
	}
	// A compound's later operations only reference the handle opened by op 0,
	// so a required buffer length from a later op is meaningful only when that
	// opening operation succeeded.
	if i > 0 && len(e.Errors) > 0 && e.Errors[0] != nil {
		return 0, false
	}
	if rerr, ok := errors.AsType[*ResponseError](e.OpError(i)); ok {
		return rerr.requireBufferLength()
	}
	return 0, false
}

// requireBufferLength returns the required buffer length reported by the server
// for operation i, if err indicates that a query buffer was too small (such as
// STATUS_BUFFER_TOO_SMALL or STATUS_INFO_LENGTH_MISMATCH).
func requireBufferLength(err error, i int) (int, bool) {
	if cerr, ok := errors.AsType[*CompoundResponseError](err); ok {
		return cerr.requireBufferLength(i)
	}
	if rerr, ok := errors.AsType[*ResponseError](err); ok {
		return rerr.requireBufferLength()
	}
	return 0, false
}

// bufferOverflowData returns the partial output carried by a
// STATUS_BUFFER_OVERFLOW response. Servers return the truncated result in the
// response body so callers can use it without requesting a larger buffer.
func bufferOverflowData(err error) ([]byte, bool) {
	rerr, ok := errors.AsType[*ResponseError](err)
	if !ok || erref.NtStatus(rerr.Code) != erref.STATUS_BUFFER_OVERFLOW || len(rerr.data) == 0 {
		return nil, false
	}
	return rerr.data[0], true
}
