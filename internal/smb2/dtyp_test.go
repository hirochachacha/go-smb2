package smb2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFiletimeTime(t *testing.T) {
	const (
		unixEpochFiletime = uint64(116444736000000000)
		modernFiletime    = uint64(133444736001234567)
		boundaryFiletime  = uint64(208678456368547758)
		futureFiletime    = uint64(283696992000000000)
	)

	tests := []struct {
		name  string
		ticks uint64
		want  time.Time
	}{
		{
			name:  "zero",
			ticks: 0,
			want:  time.Date(1601, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:  "unix epoch minus 100ns",
			ticks: unixEpochFiletime - 1,
			want:  time.Date(1969, time.December, 31, 23, 59, 59, 999999900, time.UTC),
		},
		{
			name:  "unix epoch",
			ticks: unixEpochFiletime,
			want:  time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:  "modern date",
			ticks: modernFiletime,
			want:  time.Date(2023, time.November, 14, 22, 13, 20, 123456700, time.UTC),
		},
		{
			name:  "2262 boundary",
			ticks: boundaryFiletime,
			want:  time.Date(2262, time.April, 11, 23, 47, 16, 854775800, time.UTC),
		},
		{
			name:  "2262 boundary plus 100ns",
			ticks: boundaryFiletime + 1,
			want:  time.Date(2262, time.April, 11, 23, 47, 16, 854775900, time.UTC),
		},
		{
			name:  "2500",
			ticks: futureFiletime,
			want:  time.Date(2500, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:  "high bit",
			ticks: uint64(1 << 63),
			want:  time.Date(30828, time.September, 14, 2, 48, 5, 477580800, time.UTC),
		},
		{
			name:  "maximum uint64",
			ticks: ^uint64(0),
			want:  time.Date(60056, time.May, 28, 5, 36, 10, 955161500, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft := &Filetime{
				LowDateTime:  uint32(tt.ticks),
				HighDateTime: uint32(tt.ticks >> 32),
			}
			require.True(t, ft.Time().Equal(tt.want), "Filetime.Time() = %v, want %v", ft.Time(), tt.want)

			buf := make([]byte, ft.Size())
			ft.Encode(buf)
			dec := FiletimeDecoder(buf)
			require.True(t, dec.Time().Equal(tt.want), "FiletimeDecoder.Time() = %v, want %v", dec.Time(), tt.want)

			encoded := TimeToFiletime(dec.Time())
			require.NotNil(t, encoded)
			require.Equal(t, tt.ticks, uint64(encoded.HighDateTime)<<32|uint64(encoded.LowDateTime))
		})
	}

	var nilFt *Filetime
	require.True(t, nilFt.Time().IsZero())
}
