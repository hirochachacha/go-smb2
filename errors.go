package smb2

import (
	"fmt"
	"os"

	. "github.com/omnifocal/go-smb2/internal/erref"
)

type TimeoutError struct {
	// TODO  informative error
	msg string
}

func (err *TimeoutError) Error() string {
	return fmt.Sprintf("timeout error: %v", err.msg)
}

// TransportError represents a error come from net.Conn layer.
type TransportError struct {
	Err error
}

func (err *TransportError) Error() string {
	return fmt.Sprintf("connection error: %v", err.Err)
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

func (err *ResponseError) Error() string {
	return fmt.Sprintf("response error: %v", NtStatus(err.Code))
}

type MultipleError []error

func (err MultipleError) Error() string {
	msg := "multiple error:"
	for _, e := range err {
		msg += "\n\t" + e.Error()
	}
	return msg
}

func multiError(errs ...error) error {
	var err MultipleError

	for _, e := range errs {
		switch e := e.(type) {
		case nil:
		case MultipleError:
			err = append(err, e...)
		default:
			err = append(err, e)
		}
	}

	switch len(err) {
	case 0:
		return nil
	case 1:
		return err[0]
	}

	return err
}

func IsExist(err error) bool {
	switch e := err.(type) {
	case nil:
		return false
	case *os.PathError:
		err = e.Err
	case *os.LinkError:
		err = e.Err
	}

	if err, ok := err.(*ResponseError); ok {
		switch NtStatus(err.Code) {
		case STATUS_OBJECT_NAME_COLLISION:
			return true
		}
		return false
	}

	return err == os.ErrExist
}

func IsNotExist(err error) bool {
	switch e := err.(type) {
	case nil:
		return false
	case *os.PathError:
		err = e.Err
	case *os.LinkError:
		err = e.Err
	}

	if err, ok := err.(*ResponseError); ok {
		switch NtStatus(err.Code) {
		case STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND:
			return true
		}
		return false
	}

	return err == os.ErrNotExist
}

func IsPermission(err error) bool {
	switch e := err.(type) {
	case nil:
		return false
	case *os.PathError:
		err = e.Err
	case *os.LinkError:
		err = e.Err
	}

	if err, ok := err.(*ResponseError); ok {
		switch NtStatus(err.Code) {
		case STATUS_ACCESS_DENIED:
			return true
		}
		return false
	}

	return err == os.ErrPermission
}
