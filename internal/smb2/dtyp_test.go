package smb2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFiletime_Time(t *testing.T) {
	now := time.Unix(1700000000, 123456700).UTC()
	ft := NsecToFiletime(now.UnixNano())
	require.NotNil(t, ft)

	// ft.Time() returns equivalent time
	require.Equal(t, now.UnixNano(), ft.Time().UTC().UnixNano())

	// nil *Filetime returns zero time
	var nilFt *Filetime
	require.True(t, nilFt.Time().IsZero())

	// FiletimeDecoder.Time()
	buf := make([]byte, 8)
	ft.Encode(buf)
	dec := FiletimeDecoder(buf)
	require.Equal(t, now.UnixNano(), dec.Time().UTC().UnixNano())
}
