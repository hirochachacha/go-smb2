package wire

import (
	"bytes"
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func FuzzDecoder(f *testing.F) {
	cases := decoderFuzzCases()
	for i, c := range cases {
		f.Add(uint8(i), c.seed)
	}

	f.Fuzz(func(t *testing.T, index uint8, data []byte) {
		c := cases[int(index)%len(cases)]

		d := c.decode(data)
		if d.IsInvalid() {
			// Raw mutations often break the wire invariants; only accepted
			// inputs are meaningful for the getter contract.
			return
		}

		checkGettersDoNotPanic(t, d)
	})
}

func FuzzEncodeDecode(f *testing.F) {
	cases := encodeDecodeCases()
	for i := range cases {
		f.Add(uint8(i), []byte("seed"), uint64(1), uint64(2), uint32(3), uint32(0), uint16(1), uint32(0))
	}

	f.Fuzz(func(
		t *testing.T,
		index uint8,
		entropy []byte,
		msgId, sessionId uint64,
		treeId, nextCmd uint32,
		creditReq uint16,
		flags uint32,
	) {
		c := cases[int(index)%len(cases)]

		enc := c.new()
		fillValue(reflect.ValueOf(enc).Elem(), newByteStream(entropy))

		if pkt, ok := enc.(Packet); ok {
			testHeaderSettersAndCodec(t, pkt, pkt.Command(), pkt.CreditCharge(), msgId, sessionId, treeId, nextCmd, creditReq, flags)
		}

		buf := make([]byte, enc.Size())
		enc.Encode(buf)

		body := buf
		if isPacketEncoder(enc) {
			body = buf[64:]
		}

		d := c.decode(body)
		if d.IsInvalid() {
			return
		}

		compareRoundTrip(t, reflect.ValueOf(enc), reflect.ValueOf(d))
	})
}

// checkGettersDoNotPanic invokes every exported, zero-argument getter of a
// decoder and fails the test if any of them panics. IsInvalid is skipped
// because callers must have already confirmed that it returns false.
func checkGettersDoNotPanic(t *testing.T, decoder any) {
	t.Helper()

	v := reflect.ValueOf(decoder)
	typ := v.Type()

	getters := 0
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		if m.Name == "IsInvalid" {
			continue
		}
		// Only zero-argument methods that return at least one value are
		// getters; skip setters and anything taking arguments.
		if m.Type.NumIn() != 1 || m.Type.NumOut() == 0 {
			continue
		}
		getters++

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s.%s panicked after IsInvalid returned false: %v", typ, m.Name, r)
				}
			}()
			v.Method(i).Call(nil)
		}()
	}

	if getters == 0 {
		t.Fatalf("%s: no getters found by reflection", typ)
	}
}

type decoder interface {
	IsInvalid() bool
}

type decoderFuzzCase struct {
	name   string
	decode func([]byte) decoder
	seed   []byte
}

// packetSeed encodes a request or response and returns its body, i.e. the bytes
// that follow the 64-byte SMB2 header.
func packetSeed(enc Encoder) []byte {
	pkt := make([]byte, enc.Size())
	enc.Encode(pkt)
	return pkt[64:]
}

// encodeBytes encodes any structure and returns the full byte representation,
// including the SMB2 header for requests and responses.
func encodeBytes(enc Encoder) []byte {
	b := make([]byte, enc.Size())
	enc.Encode(b)
	return b
}

func directoryInformationSeed() []byte {
	name := []byte{'a', 0}
	b := make([]byte, 64+len(name))
	binary.LittleEndian.PutUint32(b[60:64], uint32(len(name)))
	copy(b[64:], name)
	return b
}

func idBothDirectoryInformationSeed() []byte {
	name := []byte{'a', 0}
	b := make([]byte, 104+len(name))
	binary.LittleEndian.PutUint32(b[60:64], uint32(len(name)))
	copy(b[104:], name)
	return b
}

func notifyInformationSeed() []byte {
	name := []byte{'a', 0}
	b := make([]byte, 16) // 12-byte header + 2-byte name, padded to 4
	binary.LittleEndian.PutUint32(b[4:8], FILE_ACTION_ADDED)
	binary.LittleEndian.PutUint32(b[8:12], uint32(len(name)))
	copy(b[12:], name)
	return b
}

func quotaInformationSeed() []byte {
	b := make([]byte, 48) // 40-byte fixed part + 8-byte SID header
	binary.LittleEndian.PutUint32(b[4:8], 8)
	b[40] = 1 // SID Revision
	return b
}

func transformCodecSeed() []byte {
	b := make([]byte, 116)
	b[0], b[1], b[2], b[3] = 0xfd, 'S', 'M', 'B'
	binary.LittleEndian.PutUint32(b[36:40], uint32(len(b)-52))
	return b
}

func compressionCodecSeed() []byte {
	b := make([]byte, 16)
	b[0], b[1], b[2], b[3] = 0xfc, 'S', 'M', 'B'
	return b
}

func negotiateResponseSeed(dialect uint16) []byte {
	return packetSeed(&NegotiateResponse{
		DialectRevision: dialect,
		SystemTime:      &Filetime{},
		ServerStartTime: &Filetime{},
		SecurityBuffer:  []byte("security buffer"),
		Contexts: []Encoder{
			&HashContext{HashAlgorithms: []uint16{SHA512}, HashSalt: make([]byte, 32)},
		},
	})
}

func createContextsSeed() []byte {
	contexts := CreateContexts{&mockEncoder{data: make([]byte, 16)}}
	b := make([]byte, contexts.Size())
	contexts.Encode(b)
	return b
}

func decoderFuzzCases() []decoderFuzzCase {
	type c = decoderFuzzCase
	return []c{
		// SMB2 request decoders
		{"NegotiateRequest", func(b []byte) decoder { return NegotiateRequestDecoder(b) }, packetSeed(&NegotiateRequest{Dialects: []Dialect{SMB210}})},
		{"SessionSetupRequest", func(b []byte) decoder { return SessionSetupRequestDecoder(b) }, packetSeed(&SessionSetupRequest{SecurityBuffer: []byte("x")})},
		{"LogoffRequest", func(b []byte) decoder { return LogoffRequestDecoder(b) }, packetSeed(&LogoffRequest{})},
		{"EchoRequest", func(b []byte) decoder { return EchoRequestDecoder(b) }, packetSeed(&EchoRequest{})},
		{"TreeConnectRequest", func(b []byte) decoder { return TreeConnectRequestDecoder(b) }, packetSeed(&TreeConnectRequest{Path: `\\server\share`})},
		{"TreeDisconnectRequest", func(b []byte) decoder { return TreeDisconnectRequestDecoder(b) }, packetSeed(&TreeDisconnectRequest{})},
		{"CreateRequest", func(b []byte) decoder { return CreateRequestDecoder(b) }, packetSeed(&CreateRequest{Name: "a", FileAttributes: FILE_ATTRIBUTE_NORMAL, ShareAccess: 7, CreateDisposition: 1})},
		{"CloseRequest", func(b []byte) decoder { return CloseRequestDecoder(b) }, packetSeed(&CloseRequest{FileId: &FileId{}})},
		{"FlushRequest", func(b []byte) decoder { return FlushRequestDecoder(b) }, packetSeed(&FlushRequest{FileId: &FileId{}})},
		{"ReadRequest", func(b []byte) decoder { return ReadRequestDecoder(b) }, packetSeed(&ReadRequest{Length: 4096, FileId: &FileId{}})},
		{"WriteRequest", func(b []byte) decoder { return WriteRequestDecoder(b) }, packetSeed(&WriteRequest{Data: []byte("data"), FileId: &FileId{}})},
		{"LockRequest", func(b []byte) decoder { return LockRequestDecoder(b) }, packetSeed(&LockRequest{FileId: &FileId{}, Locks: []LockElement{{Flags: SMB2_LOCKFLAG_EXCLUSIVE_LOCK, Length: 1}}})},
		{"LockElement", func(b []byte) decoder { return LockElementDecoder(b) }, encodeBytes(&LockElement{Flags: SMB2_LOCKFLAG_EXCLUSIVE_LOCK, Length: 1})},
		{"FileId", func(b []byte) decoder { return FileIdDecoder(b) }, encodeBytes(&FileId{})},
		{"CancelRequest", func(b []byte) decoder { return CancelRequestDecoder(b) }, packetSeed(&CancelRequest{})},
		{"IoctlRequest", func(b []byte) decoder { return IoctlRequestDecoder(b) }, packetSeed(&IoctlRequest{CtlCode: 0x001440F2, FileId: &FileId{}, MaxInputResponse: 1, MaxOutputResponse: 1})},
		{"QueryDirectoryRequest", func(b []byte) decoder { return QueryDirectoryRequestDecoder(b) }, packetSeed(&QueryDirectoryRequest{FileId: &FileId{}, OutputBufferLength: 4096, FileName: "*.txt"})},
		{"ChangeNotifyRequest", func(b []byte) decoder { return ChangeNotifyRequestDecoder(b) }, packetSeed(&ChangeNotifyRequest{FileId: &FileId{}, OutputBufferLength: 4096, CompletionFilter: 1})},
		{"QueryInfoRequest", func(b []byte) decoder { return QueryInfoRequestDecoder(b) }, packetSeed(&QueryInfoRequest{FileId: &FileId{}, OutputBufferLength: 4096})},
		{"SetInfoRequest", func(b []byte) decoder { return SetInfoRequestDecoder(b) }, packetSeed(&SetInfoRequest{FileId: &FileId{}})},

		// SMB2 response decoders
		{"ErrorResponse", func(b []byte) decoder { return ErrorResponseDecoder(b) }, packetSeed(&ErrorResponse{CommandCode: SMB2_READ, ErrorData: &SmallBufferErrorResponse{RequiredBufferLength: 4}})},
		{"ErrorContextResponse", func(b []byte) decoder { return ErrorContextResponseDecoder(b) }, encodeBytes(&ErrorContextResponse{ErrorData: &SmallBufferErrorResponse{RequiredBufferLength: 4}})},
		{"SmallBufferErrorResponse", func(b []byte) decoder { return SmallBufferErrorResponseDecoder(b) }, encodeBytes(&SmallBufferErrorResponse{RequiredBufferLength: 4})},
		{"SymbolicLinkErrorResponse", func(b []byte) decoder { return SymbolicLinkErrorResponseDecoder(b) }, encodeBytes(&SymbolicLinkErrorResponse{Flags: SYMLINK_FLAG_RELATIVE, SubstituteName: "target", PrintName: "target"})},
		{"NegotiateResponse", func(b []byte) decoder { return NegotiateResponseDecoder(b) }, negotiateResponseSeed(SMB311)},
		{"SessionSetupResponse", func(b []byte) decoder { return SessionSetupResponseDecoder(b) }, packetSeed(&SessionSetupResponse{SecurityBuffer: []byte("x")})},
		{"LogoffResponse", func(b []byte) decoder { return LogoffResponseDecoder(b) }, packetSeed(&LogoffResponse{})},
		{"EchoResponse", func(b []byte) decoder { return EchoResponseDecoder(b) }, packetSeed(&EchoResponse{})},
		{"TreeConnectResponse", func(b []byte) decoder { return TreeConnectResponseDecoder(b) }, packetSeed(&TreeConnectResponse{ShareType: SMB2_SHARE_TYPE_DISK, MaximalAccess: 0x1f01ff})},
		{"TreeDisconnectResponse", func(b []byte) decoder { return TreeDisconnectResponseDecoder(b) }, packetSeed(&TreeDisconnectResponse{})},
		{"CreateResponse", func(b []byte) decoder { return CreateResponseDecoder(b) }, packetSeed(&CreateResponse{OplockLevel: SMB2_OPLOCK_LEVEL_NONE, CreateAction: FILE_CREATED, CreationTime: &Filetime{}, LastAccessTime: &Filetime{}, LastWriteTime: &Filetime{}, ChangeTime: &Filetime{}, FileId: &FileId{}})},
		{"CloseResponse", func(b []byte) decoder { return CloseResponseDecoder(b) }, packetSeed(&CloseResponse{CreationTime: &Filetime{}, LastAccessTime: &Filetime{}, LastWriteTime: &Filetime{}, ChangeTime: &Filetime{}})},
		{"FlushResponse", func(b []byte) decoder { return FlushResponseDecoder(b) }, packetSeed(&FlushResponse{})},
		{"ReadResponse", func(b []byte) decoder { return ReadResponseDecoder(b) }, packetSeed(&ReadResponse{Data: []byte("data")})},
		{"WriteResponse", func(b []byte) decoder { return WriteResponseDecoder(b) }, packetSeed(&WriteResponse{Count: 4})},
		{"LockResponse", func(b []byte) decoder { return LockResponseDecoder(b) }, packetSeed(&LockResponse{})},
		{"IoctlResponse", func(b []byte) decoder { return IoctlResponseDecoder(b) }, packetSeed(&IoctlResponse{CtlCode: 0x001440F2, FileId: &FileId{}})},
		{"QueryDirectoryResponse", func(b []byte) decoder { return QueryDirectoryResponseDecoder(b) }, packetSeed(&QueryDirectoryResponse{Output: &mockEncoder{data: []byte("out")}})},
		{"ChangeNotifyResponse", func(b []byte) decoder { return ChangeNotifyResponseDecoder(b) }, packetSeed(&ChangeNotifyResponse{Output: &mockEncoder{data: []byte("out")}})},
		{"QueryInfoResponse", func(b []byte) decoder { return QueryInfoResponseDecoder(b) }, packetSeed(&QueryInfoResponse{Output: &mockEncoder{data: []byte("out")}})},
		{"SetInfoResponse", func(b []byte) decoder { return SetInfoResponseDecoder(b) }, packetSeed(&SetInfoResponse{})},

		// SMB2 negotiate contexts
		{"NegotiateContext", func(b []byte) decoder { return NegotiateContextDecoder(b) }, encodeBytes(&HashContext{HashAlgorithms: []uint16{SHA512}, HashSalt: make([]byte, 32)})},
		{"HashContextData", func(b []byte) decoder { return HashContextDataDecoder(b) }, encodeBytes(&HashContext{HashAlgorithms: []uint16{SHA512}, HashSalt: make([]byte, 32)})[8:]},
		{"CipherContextData", func(b []byte) decoder { return CipherContextDataDecoder(b) }, encodeBytes(&CipherContext{Ciphers: []Cipher{SMB2_ENCRYPTION_AES128_CCM}})[8:]},
		{"CompressionContextData", func(b []byte) decoder { return CompressionContextDataDecoder(b) }, encodeBytes(&CompressionContext{CompressionAlgorithms: []uint16{SMB2_COMPRESSION_ALGORITHM_LZ4}})[8:]},
		{"TransportContextData", func(b []byte) decoder { return TransportContextDataDecoder(b) }, encodeBytes(&TransportContext{})[8:]},
		{"NegotiateContexts", func(b []byte) decoder { return NegotiateContextsDecoder(b) }, encodeBytes(&HashContext{HashAlgorithms: []uint16{SHA512}, HashSalt: make([]byte, 32)})},
		{"CreateContexts", func(b []byte) decoder { return CreateContextsDecoder(b) }, createContextsSeed()},

		// FSCC decoders
		{"SymbolicLinkReparseDataBuffer", func(b []byte) decoder { return SymbolicLinkReparseDataBufferDecoder(b) }, encodeBytes(&SymbolicLinkReparseDataBuffer{SubstituteName: `\??\C:\target`, PrintName: `C:\target`})},
		{"SrvRequestResumeKeyResponse", func(b []byte) decoder { return SrvRequestResumeKeyResponseDecoder(b) }, encodeBytes(&SrvRequestResumeKeyResponse{})},
		{"SrvCopychunkResponse", func(b []byte) decoder { return SrvCopychunkResponseDecoder(b) }, encodeBytes(&SrvCopychunkResponse{ChunksWritten: 1, ChunksBytesWritten: 1, TotalBytesWritten: 1})},
		{"FileNotifyInformation", func(b []byte) decoder { return FileNotifyInformationDecoder(b) }, notifyInformationSeed()},
		{"FileDirectoryInformation", func(b []byte) decoder { return FileDirectoryInformationDecoder(b) }, directoryInformationSeed()},
		{"FileIdBothDirectoryInformation", func(b []byte) decoder { return FileIdBothDirectoryInformationDecoder(b) }, idBothDirectoryInformationSeed()},
		{"FileFsFullSizeInformation", func(b []byte) decoder { return FileFsFullSizeInformationDecoder(b) }, make([]byte, 32)},
		{"FileQuotaInformation", func(b []byte) decoder { return FileQuotaInformationDecoder(b) }, quotaInformationSeed()},
		{"FileEndOfFileInformation", func(b []byte) decoder { return FileEndOfFileInformationDecoder(b) }, make([]byte, 8)},
		{"FileAllInformation", func(b []byte) decoder { return FileAllInformationDecoder(b) }, make([]byte, 100)},
		{"FileNetworkOpenInformation", func(b []byte) decoder { return FileNetworkOpenInformationDecoder(b) }, make([]byte, 56)},
		{"FileBasicInformation", func(b []byte) decoder { return FileBasicInformationDecoder(b) }, make([]byte, 40)},
		{"FileStandardInformation", func(b []byte) decoder { return FileStandardInformationDecoder(b) }, make([]byte, 24)},
		{"FileInternalInformation", func(b []byte) decoder { return FileInternalInformationDecoder(b) }, make([]byte, 8)},
		{"FileEaInformation", func(b []byte) decoder { return FileEaInformationDecoder(b) }, make([]byte, 4)},
		{"FileAccessInformation", func(b []byte) decoder { return FileAccessInformationDecoder(b) }, make([]byte, 4)},
		{"FilePositionInformation", func(b []byte) decoder { return FilePositionInformationDecoder(b) }, make([]byte, 8)},
		{"FileModeInformation", func(b []byte) decoder { return FileModeInformationDecoder(b) }, make([]byte, 4)},
		{"FileAttributeTagInformation", func(b []byte) decoder { return FileAttributeTagInformationDecoder(b) }, make([]byte, 8)},
		{"FileAlignmentInformation", func(b []byte) decoder { return FileAlignmentInformationDecoder(b) }, make([]byte, 4)},
		{"FileNameInformation", func(b []byte) decoder { return FileNameInformationDecoder(b) }, make([]byte, 4)},

		// MS-DTYP decoders
		{"Filetime", func(b []byte) decoder { return FiletimeDecoder(b) }, make([]byte, 8)},
		{"Sid", func(b []byte) decoder { return SidDecoder(b) }, []byte{1, 0, 0, 0, 0, 0, 0, 0}},

		// SMB2 packet codecs
		{"PacketCodec", func(b []byte) decoder { return PacketCodec(b) }, encodeBytes(&EchoRequest{})},
		{"TransformCodec", func(b []byte) decoder { return TransformCodec(b) }, transformCodecSeed()},
		{"CompressionCodec", func(b []byte) decoder { return CompressionCodec(b) }, compressionCodecSeed()},
	}
}

// TestEncodeDecodeRoundTrip exercises every encoder/decoder pair with a fixed
// entropy so mismatches are reported deterministically. The fuzz target uses
// the same comparison but explores the field space.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	entropy := make([]byte, 256)
	for i := range entropy {
		entropy[i] = byte(i*7 + 3)
	}

	for _, c := range encodeDecodeCases() {
		enc := c.new()
		fillValue(reflect.ValueOf(enc).Elem(), newByteStream(entropy))

		buf := make([]byte, enc.Size())
		enc.Encode(buf)

		body := buf
		if isPacketEncoder(enc) {
			body = buf[64:]
		}

		d := c.decode(body)
		if d.IsInvalid() {
			continue
		}

		compareRoundTrip(t, reflect.ValueOf(enc), reflect.ValueOf(d))
	}
}

// TestDecoderFuzzSeeds guards the fuzz corpus: every seed must be accepted by
// its decoder, otherwise the fuzzer would waste its budget on invalid inputs.
func TestDecoderFuzzSeeds(t *testing.T) {
	for _, c := range decoderFuzzCases() {
		if c.decode(c.seed).IsInvalid() {
			t.Errorf("%s: seed is rejected by IsInvalid", c.name)
		}
	}
}

// TestDecoderFuzzCasesAreExhaustive uses go/ast to verify that every []byte
// type implementing IsInvalid in the package has a fuzz case. Adding a new
// decoder without updating decoderFuzzCases fails this test.
func TestDecoderFuzzCasesAreExhaustive(t *testing.T) {
	declared := declaredDecoderTypes(t)

	covered := make(map[string]bool)
	for _, c := range decoderFuzzCases() {
		covered[reflect.TypeOf(c.decode(nil)).Name()] = true
	}

	for name := range declared {
		if !covered[name] {
			t.Errorf("decoder %q is not covered by decoderFuzzCases", name)
		}
	}
	for name := range covered {
		if !declared[name] {
			t.Errorf("decoderFuzzCases covers %q, which is not a declared []byte decoder", name)
		}
	}
}

// TestEncodeDecodeCasesAreExhaustive uses go/ast to verify that every decoder
// with a name-matching encoder is registered in encoderFactories. Decoders
// without an encoder are intentionally out of scope for FuzzEncodeDecode.
func TestEncodeDecodeCasesAreExhaustive(t *testing.T) {
	decoders := declaredDecoderTypes(t)
	encoders := declaredEncoderTypes(t)

	want := make(map[string]string)
	for decoder := range decoders {
		base := strings.TrimSuffix(decoder, "Decoder")
		switch {
		case encoders[base]:
			want[decoder] = base
		case encoders[base+"Encoder"]:
			want[decoder] = base + "Encoder"
		}
	}

	got := make(map[string]bool)
	for _, c := range encodeDecodeCases() {
		got[reflect.TypeOf(c.decode(nil)).Name()] = true
	}

	for decoder, encoder := range want {
		if !got[decoder] {
			t.Errorf("decoder %q has encoder %q but is not covered by encoderFactories", decoder, encoder)
		}
	}

	for _, c := range encodeDecodeCases() {
		encoderName := reflect.TypeOf(c.new()).Elem().Name()
		if !encoders[encoderName] {
			t.Errorf("encoderFactories covers %q with %q, which is not a declared encoder", c.name, encoderName)
		}
	}
}

// declaredDecoderTypes parses the non-test sources of this package and returns
// the names of every []byte type that implements IsInvalid() bool.
func declaredDecoderTypes(t *testing.T) map[string]bool {
	t.Helper()

	sliceTypes := make(map[string]bool)
	invalidImplementers := make(map[string]bool)

	for _, file := range packageFiles(t) {
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.TypeSpec:
				if array, ok := n.Type.(*ast.ArrayType); ok {
					if elt, ok := array.Elt.(*ast.Ident); ok && elt.Name == "byte" {
						sliceTypes[n.Name.Name] = true
					}
				}
			case *ast.FuncDecl:
				if isIsInvalidMethod(n) {
					invalidImplementers[receiverTypeName(n.Recv.List[0].Type)] = true
				}
			}
			return true
		})
	}

	decoders := make(map[string]bool)
	for name := range sliceTypes {
		if invalidImplementers[name] {
			decoders[name] = true
		}
	}
	return decoders
}

// declaredEncoderTypes parses the non-test sources of this package and returns
// the names of every type implementing Encoder (Size() int and Encode([]byte)).
func declaredEncoderTypes(t *testing.T) map[string]bool {
	t.Helper()

	sizeTypes := make(map[string]bool)
	encodeTypes := make(map[string]bool)

	for _, file := range packageFiles(t) {
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
				return true
			}
			name := receiverTypeName(fn.Recv.List[0].Type)
			switch fn.Name.Name {
			case "Size":
				if returnsInt(fn) {
					sizeTypes[name] = true
				}
			case "Encode":
				if takesByteSlice(fn) {
					encodeTypes[name] = true
				}
			}
			return true
		})
	}

	encoders := make(map[string]bool)
	for name := range sizeTypes {
		if encodeTypes[name] {
			encoders[name] = true
		}
	}
	return encoders
}

// packageFiles parses the non-test sources of this package.
func packageFiles(t *testing.T) []*ast.File {
	t.Helper()

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, filepath.Dir(source), func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}

	var files []*ast.File
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			files = append(files, file)
		}
	}
	return files
}

func isIsInvalidMethod(fn *ast.FuncDecl) bool {
	if fn.Name.Name != "IsInvalid" || fn.Recv == nil || len(fn.Recv.List) != 1 {
		return false
	}
	results := fn.Type.Results
	if results == nil || len(results.List) != 1 {
		return false
	}
	id, ok := results.List[0].Type.(*ast.Ident)
	return ok && id.Name == "bool"
}

func returnsInt(fn *ast.FuncDecl) bool {
	results := fn.Type.Results
	if results == nil || len(results.List) != 1 {
		return false
	}
	id, ok := results.List[0].Type.(*ast.Ident)
	return ok && id.Name == "int"
}

func takesByteSlice(fn *ast.FuncDecl) bool {
	params := fn.Type.Params
	if params == nil || len(params.List) != 1 {
		return false
	}
	array, ok := params.List[0].Type.(*ast.ArrayType)
	if !ok {
		return false
	}
	elt, ok := array.Elt.(*ast.Ident)
	return ok && elt.Name == "byte"
}

func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return receiverTypeName(e.X)
	}
	return ""
}

type encodeDecodeCase struct {
	name   string
	new    func() Encoder
	decode func([]byte) decoder
}

// encoderFactories maps a decoder name (from decoderFuzzCases) to the encoder
// that produces the matching wire structure. Decoders without an encoder are
// intentionally absent: the encode/decode round-trip cannot cover them.
func encoderFactories() map[string]func() Encoder {
	return map[string]func() Encoder{
		// SMB2 requests
		"NegotiateRequest":      func() Encoder { return &NegotiateRequest{} },
		"SessionSetupRequest":   func() Encoder { return &SessionSetupRequest{} },
		"LogoffRequest":         func() Encoder { return &LogoffRequest{} },
		"EchoRequest":           func() Encoder { return &EchoRequest{} },
		"TreeConnectRequest":    func() Encoder { return &TreeConnectRequest{} },
		"TreeDisconnectRequest": func() Encoder { return &TreeDisconnectRequest{} },
		"CreateRequest":         func() Encoder { return &CreateRequest{} },
		"CloseRequest":          func() Encoder { return &CloseRequest{} },
		"FlushRequest":          func() Encoder { return &FlushRequest{} },
		"ReadRequest":           func() Encoder { return &ReadRequest{} },
		"WriteRequest":          func() Encoder { return &WriteRequest{} },
		"LockRequest":           func() Encoder { return &LockRequest{} },
		"LockElement":           func() Encoder { return &LockElement{} },
		"FileId":                func() Encoder { return &FileId{} },
		"CancelRequest":         func() Encoder { return &CancelRequest{} },
		"IoctlRequest":          func() Encoder { return &IoctlRequest{} },
		"QueryDirectoryRequest": func() Encoder { return &QueryDirectoryRequest{} },
		"ChangeNotifyRequest":   func() Encoder { return &ChangeNotifyRequest{} },
		"QueryInfoRequest":      func() Encoder { return &QueryInfoRequest{} },
		"SetInfoRequest":        func() Encoder { return &SetInfoRequest{} },

		// SMB2 responses
		"ErrorResponse":             func() Encoder { return &ErrorResponse{} },
		"ErrorContextResponse":      func() Encoder { return &ErrorContextResponse{} },
		"SmallBufferErrorResponse":  func() Encoder { return &SmallBufferErrorResponse{} },
		"SymbolicLinkErrorResponse": func() Encoder { return &SymbolicLinkErrorResponse{} },
		"NegotiateResponse":         func() Encoder { return &NegotiateResponse{} },
		"SessionSetupResponse":      func() Encoder { return &SessionSetupResponse{} },
		"LogoffResponse":            func() Encoder { return &LogoffResponse{} },
		"EchoResponse":              func() Encoder { return &EchoResponse{} },
		"TreeConnectResponse":       func() Encoder { return &TreeConnectResponse{} },
		"TreeDisconnectResponse":    func() Encoder { return &TreeDisconnectResponse{} },
		"CreateResponse":            func() Encoder { return &CreateResponse{} },
		"CloseResponse":             func() Encoder { return &CloseResponse{} },
		"FlushResponse":             func() Encoder { return &FlushResponse{} },
		"ReadResponse":              func() Encoder { return &ReadResponse{} },
		"WriteResponse":             func() Encoder { return &WriteResponse{} },
		"LockResponse":              func() Encoder { return &LockResponse{} },
		"IoctlResponse":             func() Encoder { return &IoctlResponse{} },
		"QueryDirectoryResponse":    func() Encoder { return &QueryDirectoryResponse{} },
		"ChangeNotifyResponse":      func() Encoder { return &ChangeNotifyResponse{} },
		"QueryInfoResponse":         func() Encoder { return &QueryInfoResponse{} },
		"SetInfoResponse":           func() Encoder { return &SetInfoResponse{} },

		// SMB2 negotiate contexts
		"NegotiateContext": func() Encoder { return &HashContext{} },

		"NegotiateContexts": func() Encoder { return &NegotiateContexts{} },
		"CreateContexts":    func() Encoder { return &CreateContexts{} },

		// FSCC structures
		"SymbolicLinkReparseDataBuffer": func() Encoder { return &SymbolicLinkReparseDataBuffer{} },
		"SrvRequestResumeKeyResponse":   func() Encoder { return &SrvRequestResumeKeyResponse{} },
		"SrvCopychunkResponse":          func() Encoder { return &SrvCopychunkResponse{} },
		"FileBasicInformation":          func() Encoder { return &FileBasicInformationEncoder{} },
		"FileEndOfFileInformation":      func() Encoder { return &FileEndOfFileInformationEncoder{} },
		"FilePositionInformation":       func() Encoder { return &FilePositionInformationEncoder{} },

		// MS-DTYP structures
		"Filetime": func() Encoder { return &Filetime{} },
		"Sid":      func() Encoder { return &Sid{} },
	}
}

func encodeDecodeCases() []encodeDecodeCase {
	factories := encoderFactories()

	var cases []encodeDecodeCase
	for _, c := range decoderFuzzCases() {
		newEncoder, ok := factories[c.name]
		if !ok {
			continue
		}
		cases = append(cases, encodeDecodeCase{name: c.name, new: newEncoder, decode: c.decode})
	}
	return cases
}

// byteStream feeds entropy to the reflective field generator. Bytes are reused
// cyclically so an empty or short fuzz input still produces a value.
type byteStream struct {
	data  []byte
	index int
}

func newByteStream(data []byte) *byteStream {
	return &byteStream{data: data}
}

func (s *byteStream) next() byte {
	if len(s.data) == 0 {
		return 0
	}
	b := s.data[s.index%len(s.data)]
	s.index++
	return b
}

var (
	encoderInterfaceType  = reflect.TypeOf((*Encoder)(nil)).Elem()
	filetimeStructType    = reflect.TypeOf(Filetime{})
	sidStructType         = reflect.TypeOf(Sid{})
	negotiateResponseType = reflect.TypeOf(NegotiateResponse{})
	packetHeaderType      = reflect.TypeOf(PacketHeader{})
)

func fillStruct(v reflect.Value, s *byteStream) {
	t := v.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		// The SMB2 header has union fields (AsyncId / TreeId /
		// ChannelSequence) that testHeaderSettersAndCodec manages; filling them
		// here would leave the union in an inconsistent state.
		if field.Anonymous && field.Type == packetHeaderType {
			continue
		}
		fillValue(v.Field(i), s)
	}
}

func fillValue(v reflect.Value, s *byteStream) {
	if !v.CanSet() {
		return
	}

	switch v.Type() {
	case encoderInterfaceType:
		v.Set(reflect.ValueOf(&mockEncoder{data: randomBytes(s)}))
		return
	case filetimeStructType:
		v.FieldByName("LowDateTime").SetUint(readUint(s, 4))
		v.FieldByName("HighDateTime").SetUint(readUint(s, 3)) // high bit clear
		return
	case sidStructType:
		v.FieldByName("Revision").SetUint(1)
		// IdentifierAuthority is a 6-byte big-endian value.
		v.FieldByName("IdentifierAuthority").SetUint(readUint(s, 6))
		count := int(s.next() % 3)
		sub := reflect.MakeSlice(v.FieldByName("SubAuthority").Type(), count, count)
		for i := range count {
			sub.Index(i).SetUint(uint64(s.next()))
		}
		v.FieldByName("SubAuthority").Set(sub)
		return
	case negotiateResponseType:
		fillStruct(v, s)
		// [MS-SMB2] 2.2.4: negotiate contexts only exist for SMB 3.1.1.
		// Older dialects reserve the count/offset fields, which the decoder
		// must ignore, so keep the generated response consistent.
		if v.FieldByName("Contexts").Len() > 0 {
			v.FieldByName("DialectRevision").SetUint(SMB311)
		}
		return
	}

	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(s.next()&1 != 0)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(readUint(s, v.Type().Bits()/8)))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(readUint(s, v.Type().Bits()/8))
	case reflect.String:
		v.SetString(randomString(s))
	case reflect.Slice:
		fillSlice(v, s)
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			for i := range v.Len() {
				v.Index(i).SetUint(uint64(s.next()))
			}
		}
	case reflect.Ptr:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		fillValue(v.Elem(), s)
	case reflect.Interface:
		// Non-Encoder interfaces are left zero.
	case reflect.Struct:
		fillStruct(v, s)
	}
}

func fillSlice(v reflect.Value, s *byteStream) {
	if v.Type().Elem().Kind() == reflect.Uint8 {
		v.SetBytes(randomBytes(s))
		return
	}

	if v.Type().Elem() == encoderInterfaceType {
		count := 1 + int(s.next()%2)
		slice := reflect.MakeSlice(v.Type(), count, count)
		for i := range count {
			slice.Index(i).Set(reflect.ValueOf(&mockEncoder{data: randomContextBytes(s)}))
		}
		v.Set(slice)
		return
	}

	count := 1 + int(s.next()%3)
	slice := reflect.MakeSlice(v.Type(), count, count)
	for i := range count {
		fillValue(slice.Index(i), s)
	}
	v.Set(slice)
}

func readUint(s *byteStream, n int) uint64 {
	var v uint64
	for i := range n {
		v |= uint64(s.next()) << (8 * i)
	}
	return v
}

func randomBytes(s *byteStream) []byte {
	n := int(s.next() % 8)
	b := make([]byte, n)
	for i := range b {
		b[i] = s.next()
	}
	return b
}

// randomContextBytes returns at least 8 bytes because SMB2 context structures
// always start with a 4-byte Next/Type field followed by 4 more bytes, and the
// encoders write those fields unconditionally.
func randomContextBytes(s *byteStream) []byte {
	n := 8 + int(s.next()%8)
	b := make([]byte, n)
	for i := range b {
		b[i] = s.next()
	}
	return b
}

func randomString(s *byteStream) string {
	n := int(s.next() % 8)
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + s.next()%26
	}
	return string(b)
}

func isPacketEncoder(enc Encoder) bool {
	t := reflect.TypeOf(enc)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	_, ok := t.FieldByName("PacketHeader")
	return ok
}

// compareRoundTrip compares the encoder's exported fields with the decoder's
// same-named getters. Fields the generator cannot reproduce are skipped.
func compareRoundTrip(t *testing.T, encValue, decValue reflect.Value) {
	t.Helper()

	if encValue.Kind() == reflect.Ptr {
		encValue = encValue.Elem()
	}

	// Non-struct encoders (such as NegotiateContexts) have no named fields;
	// compare the whole encoding against the decoder bytes.
	if encValue.Kind() != reflect.Struct {
		enc, ok := encValue.Interface().(Encoder)
		if !ok {
			return
		}
		gotBytes, ok := bytesOf(decValue)
		if !ok {
			return
		}
		encoded := make([]byte, enc.Size())
		enc.Encode(encoded)
		if !bytes.Equal(encoded, gotBytes) {
			t.Errorf("%s round-trip mismatch", decValue.Type())
		}
		return
	}

	encType := encValue.Type()
	for i := range encType.NumField() {
		field := encType.Field(i)
		if !field.IsExported() {
			continue
		}

		getter := decValue.MethodByName(field.Name)
		if !getter.IsValid() || getter.Type().NumIn() != 0 || getter.Type().NumOut() != 1 {
			continue
		}

		got := getter.Call(nil)[0]
		equal, comparable := valuesEqual(encValue.Field(i), got)
		if !comparable {
			continue
		}
		if !equal {
			t.Errorf("%s.%s round-trip mismatch", decValue.Type(), field.Name)
		}
	}
}

func valuesEqual(field, got reflect.Value) (equal, comparable bool) {
	if !field.CanInterface() {
		return false, false
	}

	// Compare byte sequences with bytes.Equal so a nil slice and an empty
	// slice are treated as equal.
	if fieldBytes, ok := bytesOf(field); ok {
		gotBytes, ok := bytesOf(got)
		if !ok {
			return false, false
		}
		return bytes.Equal(fieldBytes, gotBytes), true
	}

	if field.Type() == got.Type() {
		return reflect.DeepEqual(field.Interface(), got.Interface()), true
	}

	if field.Kind() == reflect.Array && field.Type().Elem().Kind() == reflect.Uint8 {
		if gotBytes, ok := bytesOf(got); ok {
			fieldBytes := make([]byte, field.Len())
			reflect.Copy(reflect.ValueOf(fieldBytes), field)
			return bytes.Equal(fieldBytes, gotBytes), true
		}
	}

	if field.Kind() == reflect.Ptr && field.IsNil() {
		return false, false
	}

	// Named types that implement Encoder (e.g. *Filetime, Encoder interface
	// fields, and named slices such as NegotiateContexts) round-trip through
	// their own Encode, which accounts for alignment and framing.
	if enc, ok := field.Interface().(Encoder); ok {
		if gotBytes, ok := bytesOf(got); ok {
			encoded := make([]byte, enc.Size())
			enc.Encode(encoded)
			return bytes.Equal(encoded, gotBytes), true
		}
	}

	// A slice of concrete Encoder elements without framing (e.g. []LockElement)
	// round-trips to the concatenation of the encoded elements. If the decoder
	// exposes padding between elements the lengths differ and the comparison is
	// skipped rather than reported as a mismatch.
	if field.Kind() == reflect.Slice {
		if fieldBytes, ok := encodeElements(field); ok {
			if gotBytes, ok := bytesOf(got); ok && len(fieldBytes) == len(gotBytes) {
				return bytes.Equal(fieldBytes, gotBytes), true
			}
		}
	}

	return false, false
}

func bytesOf(v reflect.Value) ([]byte, bool) {
	if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
		return v.Bytes(), true
	}
	return nil, false
}

// encodeElements encodes every element of a slice whose element type
// implements Encoder and returns their concatenation.
func encodeElements(v reflect.Value) ([]byte, bool) {
	if v.Kind() != reflect.Slice || v.Len() == 0 {
		return nil, false
	}
	// Concrete Encoder element slices (e.g. []LockElement) concatenate to the
	// wire form. Framed lists such as CreateContexts are handled by their own
	// Encoder branch in valuesEqual before reaching here.
	elemType := v.Type().Elem()
	if !elemType.Implements(encoderInterfaceType) {
		return nil, false
	}

	var encoded []byte
	for i := range v.Len() {
		elem := v.Index(i)
		if elem.Kind() == reflect.Ptr && elem.IsNil() {
			return nil, false
		}
		enc, ok := elem.Interface().(Encoder)
		if !ok {
			return nil, false
		}
		b := make([]byte, enc.Size())
		enc.Encode(b)
		encoded = append(encoded, b...)
	}
	return encoded, true
}

type mockEncoder struct {
	data []byte
}

func (e *mockEncoder) Encode(dst []byte) {
	copy(dst, e.data)
}

func (e *mockEncoder) Size() int {
	return len(e.data)
}

func testHeaderSettersAndCodec(
	t *testing.T,
	pkt Packet,
	expectedCmd Command, expectedCreditCharge uint16,
	msgId, sessionId uint64,
	treeId, nextCmd uint32,
	creditReq uint16,
	flags uint32,
) {
	pkt.SetMessageId(msgId)
	pkt.SetSessionId(sessionId)
	pkt.SetTreeId(treeId)
	pkt.SetNextCommand(nextCmd)
	pkt.SetCreditRequestResponse(creditReq)
	pkt.SetFlags(flags)

	if pkt.Command() != expectedCmd {
		t.Fatalf("Command mismatch: expected %d, got %d", expectedCmd, pkt.Command())
	}
	if pkt.CreditCharge() != expectedCreditCharge {
		t.Fatalf("CreditCharge mismatch: expected %d, got %d", expectedCreditCharge, pkt.CreditCharge())
	}

	buf := make([]byte, pkt.Size())
	pkt.Encode(buf)

	p := PacketCodec(buf)
	if p.Command() != expectedCmd {
		t.Fatalf("Header Command mismatch: expected %d, got %d", expectedCmd, p.Command())
	}
	if p.CreditCharge() != expectedCreditCharge {
		t.Fatalf("Header CreditCharge mismatch: expected %d, got %d", expectedCreditCharge, p.CreditCharge())
	}
	if p.MessageId() != msgId {
		t.Fatalf("Header MessageId mismatch: expected %d, got %d", msgId, p.MessageId())
	}
	if p.SessionId() != sessionId {
		t.Fatalf("Header SessionId mismatch: expected %d, got %d", sessionId, p.SessionId())
	}
	if p.TreeId() != treeId {
		t.Fatalf("Header TreeId mismatch: expected %d, got %d", treeId, p.TreeId())
	}
	if p.NextCommand() != nextCmd {
		t.Fatalf("Header NextCommand mismatch: expected %d, got %d", nextCmd, p.NextCommand())
	}
	if p.CreditRequest() != creditReq {
		t.Fatalf("Header CreditRequest mismatch: expected %d, got %d", creditReq, p.CreditRequest())
	}
	if p.Flags() != flags {
		t.Fatalf("Header Flags mismatch: expected %d, got %d", flags, p.Flags())
	}
}
