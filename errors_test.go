package smb2

import (
	"errors"
	"os"
	"testing"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/stretchr/testify/require"
)

func TestResponseErrorIs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code     uint32
		target   error
		expected bool
	}{
		{0xC0000034, os.ErrNotExist, true},   // STATUS_OBJECT_NAME_NOT_FOUND
		{0xC000003A, os.ErrNotExist, true},   // STATUS_OBJECT_PATH_NOT_FOUND
		{0xC0000035, os.ErrExist, true},      // STATUS_OBJECT_NAME_COLLISION
		{0xC0000022, os.ErrPermission, true}, // STATUS_ACCESS_DENIED
		{0xC0000121, os.ErrPermission, true}, // STATUS_CANNOT_DELETE
		{0xC0000128, os.ErrClosed, true},     // STATUS_FILE_CLOSED
		{0xC0000034, os.ErrPermission, false},
		{0xC0000034, os.ErrExist, false},
		{uint32(erref.STATUS_OBJECT_NAME_NOT_FOUND), erref.STATUS_OBJECT_NAME_NOT_FOUND, true},
		{uint32(erref.STATUS_ACCESS_DENIED), erref.STATUS_ACCESS_DENIED, true},
		{uint32(erref.STATUS_ACCESS_DENIED), erref.STATUS_BUFFER_OVERFLOW, false},
	}

	for _, tc := range tests {
		err := &ResponseError{Code: tc.code}
		pathErr := &os.PathError{Op: "open", Path: "test", Err: err}

		if errors.Is(err, tc.target) != tc.expected {
			t.Errorf("ResponseError{Code: 0x%X}.Is(%v) = %v, expected %v", tc.code, tc.target, !tc.expected, tc.expected)
		}
		if errors.Is(pathErr, tc.target) != tc.expected {
			t.Errorf("PathError wrapping ResponseError{Code: 0x%X}.Is(%v) = %v, expected %v", tc.code, tc.target, !tc.expected, tc.expected)
		}
	}
}

func TestResponseErrorAsNtStatus(t *testing.T) {
	t.Parallel()
	err := &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)}
	pathErr := &os.PathError{Op: "open", Path: "test", Err: err}

	var status erref.NtStatus
	require.True(t, errors.As(err, &status))
	require.Equal(t, erref.STATUS_ACCESS_DENIED, status)

	var statusFromPathErr erref.NtStatus
	require.True(t, errors.As(pathErr, &statusFromPathErr))
	require.Equal(t, erref.STATUS_ACCESS_DENIED, statusFromPathErr)

	// Verify coexistence of NtStatus and standard errors
	require.True(t, errors.Is(err, erref.STATUS_ACCESS_DENIED))
	require.True(t, errors.Is(err, os.ErrPermission))
	require.True(t, errors.Is(pathErr, erref.STATUS_ACCESS_DENIED))
	require.True(t, errors.Is(pathErr, os.ErrPermission))
}

func TestCompoundResponseError(t *testing.T) {
	t.Parallel()
	err0 := &ResponseError{Code: uint32(erref.STATUS_OBJECT_NAME_COLLISION)}
	err1 := &ResponseError{Code: uint32(erref.STATUS_ACCESS_DENIED)}
	cerr := &CompoundResponseError{Errors: []error{err0, nil, err1}}

	firstIdx, firstErr := cerr.FirstError()
	require.Equal(t, 0, firstIdx)
	require.Equal(t, err0, firstErr)
	require.Equal(t, err0, cerr.OpError(0))
	require.Nil(t, cerr.OpError(1))
	require.Equal(t, err1, cerr.OpError(2))
	require.Nil(t, cerr.OpError(3))
	require.Nil(t, cerr.OpError(-1))

	// Unwrap only non-nil
	unwrapped := cerr.Unwrap()
	require.Equal(t, []error{err0, err1}, unwrapped)

	// errors.Is
	require.True(t, errors.Is(cerr, os.ErrExist))
	require.True(t, errors.Is(cerr, os.ErrPermission))
	require.True(t, errors.Is(cerr, erref.STATUS_OBJECT_NAME_COLLISION))
	require.True(t, errors.Is(cerr, erref.STATUS_ACCESS_DENIED))
	require.False(t, errors.Is(cerr, os.ErrNotExist))

	// errors.As
	var rerr *ResponseError
	require.True(t, errors.As(cerr, &rerr))
	require.Equal(t, err0, rerr)

	var status erref.NtStatus
	require.True(t, errors.As(cerr, &status))
	require.Equal(t, erref.STATUS_OBJECT_NAME_COLLISION, status)
}
