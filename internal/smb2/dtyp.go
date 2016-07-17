// ref: MS-DTYP

package smb2

type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

func (ft *Filetime) Size() int {
	return 8
}

func (ft *Filetime) Encode(p []byte) {
	le.PutUint32(p[:4], ft.LowDateTime)
	le.PutUint32(p[4:8], ft.HighDateTime)
}

func (ft *Filetime) Nanoseconds() int64 {
	nsec := int64(ft.HighDateTime)<<32 + int64(ft.LowDateTime)
	nsec -= 116444736000000000
	nsec *= 100
	return nsec
}

func NsecToFiletime(nsec int64) (ft *Filetime) {
	nsec /= 100
	nsec += 116444736000000000

	return &Filetime{
		LowDateTime:  uint32(nsec & 0xffffffff),
		HighDateTime: uint32(nsec >> 32 & 0xffffffff),
	}
}

type FiletimeDecoder []byte

func (ft FiletimeDecoder) LowDateTime() uint32 {
	return le.Uint32(ft[:4])
}

func (ft FiletimeDecoder) HighDateTime() uint32 {
	return le.Uint32(ft[4:8])
}

func (ft FiletimeDecoder) Nanoseconds() int64 {
	nsec := int64(ft.HighDateTime())<<32 + int64(ft.LowDateTime())
	nsec -= 116444736000000000
	nsec *= 100
	return nsec
}

func (ft FiletimeDecoder) Decode() *Filetime {
	return &Filetime{
		LowDateTime:  ft.LowDateTime(),
		HighDateTime: ft.HighDateTime(),
	}
}
