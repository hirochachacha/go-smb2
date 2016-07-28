package smb2

var zero [16]byte

// ----------------------------------------------------------------------------
// SMB2 FILEID
//

type FileId struct {
	Persistent [8]byte
	Volatile   [8]byte
}

func (fd *FileId) IsZero() bool {
	if fd == nil {
		return true
	}

	for _, b := range fd.Persistent[:] {
		if b != 0 {
			return false
		}
	}
	for _, b := range fd.Volatile[:] {
		if b != 0 {
			return false
		}
	}
	return true
}

func (fd *FileId) Size() int {
	return 16
}

func (fd *FileId) Encode(p []byte) {
	if fd == nil {
		copy(p[:16], zero[:])
	} else {
		copy(p[:8], fd.Persistent[:])
		copy(p[8:16], fd.Volatile[:])
	}
}

type FileIdDecoder []byte

func (fd FileIdDecoder) Persistent() []byte {
	return fd[:8]
}

func (fd FileIdDecoder) Volatile() []byte {
	return fd[8:16]
}

func (fd FileIdDecoder) Decode() *FileId {
	var ret FileId
	copy(ret.Persistent[:], fd[:8])
	copy(ret.Volatile[:], fd[8:16])
	return &ret
}

// ----------------------------------------------------------------------------
// SMB2 NEGOTIATE Contexts
//

// From SMB311

type HashContext struct {
	HashAlgorithms []uint16
	HashSalt       []byte
}

func (c *HashContext) Size() int {
	return 8 + 4 + len(c.HashAlgorithms)*2 + len(c.HashSalt)
}

func (c *HashContext) Encode(p []byte) {
	le.PutUint16(p[:2], SMB2_PREAUTH_INTEGRITY_CAPABILITIES)                // ContextType
	le.PutUint16(p[2:4], uint16(4+len(c.HashAlgorithms)*2+len(c.HashSalt))) // DataLength

	{
		d := NegotiateContextDecoder(p).Data()

		// HashAlgorithms
		{
			bs := d[4:]
			for i, alg := range c.HashAlgorithms {
				le.PutUint16(bs[2*i:2*i+2], alg)
			}
			le.PutUint16(d[:2], uint16(len(c.HashAlgorithms)))
		}

		// HashSalt
		{
			off := 4 + len(c.HashAlgorithms)*2
			copy(d[off:], c.HashSalt)
			le.PutUint16(d[2:4], uint16(len(c.HashSalt)))
		}
	}
}

type CipherContext struct {
	Ciphers []uint16
}

func (c *CipherContext) Size() int {
	return 8 + 2 + len(c.Ciphers)*2
}

func (c *CipherContext) Encode(p []byte) {
	le.PutUint16(p[:2], SMB2_ENCRYPTION_CAPABILITIES) // ContextType
	le.PutUint16(p[2:4], uint16(2+len(c.Ciphers)*2))  // DataLength

	{
		d := NegotiateContextDecoder(p).Data()

		{ // Ciphers
			bs := d[2:]
			for i, c := range c.Ciphers {
				le.PutUint16(bs[2*i:2*i+2], c)
			}
			le.PutUint16(d[:2], uint16(len(c.Ciphers))) // CipherCount
		}
	}
}

// From SMB311

type NegotiateContextDecoder []byte

func (ctx NegotiateContextDecoder) IsInvalid() bool {
	if len(ctx) < 8 {
		return true
	}

	if len(ctx) < 8+int(ctx.DataLength()) {
		return true
	}

	return false
}

func (ctx NegotiateContextDecoder) ContextType() uint16 {
	return le.Uint16(ctx[:2])
}

func (ctx NegotiateContextDecoder) DataLength() uint16 {
	return le.Uint16(ctx[2:4])
}

func (ctx NegotiateContextDecoder) Data() []byte {
	len := ctx.DataLength()
	return ctx[8 : 8+len]
}

func (ctx NegotiateContextDecoder) Next() int {
	return Roundup(8+int(ctx.DataLength()), 8)
}

// From SMB311

type HashContextDataDecoder []byte

func (h HashContextDataDecoder) IsInvalid() bool {
	if len(h) < 4 {
		return true
	}

	if len(h) < 4+int(h.HashAlgorithmCount())*2+int(h.SaltLength()) {
		return true
	}

	return false
}

func (h HashContextDataDecoder) HashAlgorithmCount() uint16 {
	return le.Uint16(h[:2])
}

func (h HashContextDataDecoder) SaltLength() uint16 {
	return le.Uint16(h[2:4])
}

func (h HashContextDataDecoder) HashAlgorithms() []uint16 {
	bs := h[4:]
	algs := make([]uint16, h.HashAlgorithmCount())
	for i := range algs {
		algs[i] = le.Uint16(bs[2*i : 2*i+2])
	}
	return algs
}

func (h HashContextDataDecoder) Salt() []byte {
	off := 4 + h.HashAlgorithmCount()*2
	len := h.SaltLength()
	return h[off : off+len]
}

type CipherContextDataDecoder []byte

func (c CipherContextDataDecoder) IsInvalid() bool {
	if len(c) < 2 {
		return true
	}

	if len(c) < 2+int(c.CipherCount())*2 {
		return true
	}

	return false
}

func (c CipherContextDataDecoder) CipherCount() uint16 {
	return le.Uint16(c[:2])
}

func (c CipherContextDataDecoder) Ciphers() []uint16 {
	bs := c[2:]
	cs := make([]uint16, c.CipherCount())
	for i := range cs {
		cs[i] = le.Uint16(bs[2*i : 2*i+2])
	}
	return cs
}
