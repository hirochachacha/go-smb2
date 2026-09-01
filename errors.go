package smb2

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/hirochachacha/go-smb2/internal/erref"
)

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

func (err ResponseError) Is(target error) bool {
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

// ContextError wraps a context error to support os.IsTimeout function.
type ContextError struct {
	Err error
}

func (err *ContextError) Timeout() bool {
	return err.Err == context.DeadlineExceeded
}

func (err *ContextError) Error() string {
	return err.Err.Error()
}

func (err *ContextError) Unwrap() error {
	return err.Err
}
