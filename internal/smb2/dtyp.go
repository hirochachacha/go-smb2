// ref: MS-DTYP

package smb2

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// FILETIME is an unsigned count of 100-nanosecond intervals, so split the
// value before converting it to time.Unix ([MS-DTYP] 2.3.3).
func filetimeToTime(ticks uint64) time.Time {
	return time.Unix(int64(ticks/10000000)-11644473600, int64(ticks%10000000)*100)
}

func (ft *Filetime) Size() int {
	return 8
}

func (ft *Filetime) Encode(p []byte) {
	le.PutUint32(p[:4], ft.LowDateTime)
	le.PutUint32(p[4:8], ft.HighDateTime)
}

func (ft *Filetime) Time() time.Time {
	if ft == nil {
		return time.Time{}
	}
	return filetimeToTime(uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime))
}

func TimeToFiletime(t time.Time) *Filetime {
	if t.IsZero() {
		return nil
	}

	const unixToFiletimeSeconds = int64(11644473600)
	const maxFiletimeSeconds = int64(^uint64(0) / 10000000)
	seconds := t.Unix()
	if seconds < -unixToFiletimeSeconds || seconds > maxFiletimeSeconds-unixToFiletimeSeconds {
		return nil
	}

	filetimeSeconds := uint64(seconds + unixToFiletimeSeconds)
	nanoseconds := uint64(t.Nanosecond() / 100)
	if filetimeSeconds > (^uint64(0)-nanoseconds)/10000000 {
		return nil
	}

	filetime := filetimeSeconds*10000000 + nanoseconds
	return &Filetime{
		LowDateTime:  uint32(filetime),
		HighDateTime: uint32(filetime >> 32),
	}
}

type FiletimeDecoder []byte

func (ft FiletimeDecoder) LowDateTime() uint32 {
	return le.Uint32(ft[:4])
}

func (ft FiletimeDecoder) HighDateTime() uint32 {
	return le.Uint32(ft[4:8])
}

func (ft FiletimeDecoder) Time() time.Time {
	return filetimeToTime(uint64(ft.HighDateTime())<<32 | uint64(ft.LowDateTime()))
}

func (ft FiletimeDecoder) Decode() *Filetime {
	return &Filetime{
		LowDateTime:  ft.LowDateTime(),
		HighDateTime: ft.HighDateTime(),
	}
}

type Sid struct {
	Revision            uint8
	IdentifierAuthority uint64
	SubAuthority        []uint32
}

func (sid *Sid) String() string {
	if sid == nil {
		return "<nil>"
	}
	list := make([]string, 0, 3+len(sid.SubAuthority))
	list = append(list, "S")
	list = append(list, strconv.Itoa(int(sid.Revision)))
	if sid.IdentifierAuthority < uint64(1<<32) {
		list = append(list, strconv.FormatUint(sid.IdentifierAuthority, 10))
	} else {
		list = append(list, fmt.Sprintf("0x%012x", sid.IdentifierAuthority))
	}
	for _, a := range sid.SubAuthority {
		list = append(list, strconv.FormatUint(uint64(a), 10))
	}
	return strings.Join(list, "-")
}

func (sid *Sid) Size() int {
	if sid == nil {
		return 0
	}
	return 8 + len(sid.SubAuthority)*4
}

func (sid *Sid) Encode(p []byte) {
	if sid == nil || len(p) < sid.Size() {
		return
	}
	p[0] = sid.Revision
	p[1] = uint8(len(sid.SubAuthority))
	for j := range 6 {
		p[2+j] = byte(sid.IdentifierAuthority >> uint64(8*(5-j)))
	}
	off := 8
	for _, u := range sid.SubAuthority {
		le.PutUint32(p[off:off+4], u)
		off += 4
	}
}

type SidDecoder []byte

func (c SidDecoder) IsInvalid() bool {
	if len(c) < 8 {
		return true
	}

	if c.Revision() != 1 || c.SubAuthorityCount() > 15 {
		return true
	}

	if uint64(len(c)) < 8+4*uint64(c.SubAuthorityCount()) {
		return true
	}

	return false
}

func (c SidDecoder) Revision() uint8 {
	if len(c) < 1 {
		return 0
	}
	return c[0]
}

func (c SidDecoder) SubAuthorityCount() uint8 {
	if len(c) < 2 {
		return 0
	}
	return c[1]
}

func (c SidDecoder) IdentifierAuthority() uint64 {
	if len(c) < 8 {
		return 0
	}
	var u uint64
	for j := range 6 {
		u += uint64(c[7-j]) << uint64(8*j)
	}
	return u
}

func (c SidDecoder) SubAuthority() []uint32 {
	if c.IsInvalid() {
		return nil
	}
	count := c.SubAuthorityCount()
	as := make([]uint32, count)
	off := 8
	for i := range count {
		as[i] = le.Uint32(c[off : off+4])
		off += 4
	}
	return as
}

func (c SidDecoder) Decode() *Sid {
	if c.IsInvalid() {
		return nil
	}
	return &Sid{
		Revision:            c.Revision(),
		IdentifierAuthority: c.IdentifierAuthority(),
		SubAuthority:        c.SubAuthority(),
	}
}

