package v5

import (
	"encoding/binary"
	"fmt"
	encoder "github.com/hirochachacha/go-smb2/encode"
	"github.com/hirochachacha/go-smb2/internal/msrpc"
	"github.com/hirochachacha/go-smb2/internal/utf16le"
)

var (
	WINREG_UUID          = []byte("01d08c334422f131aaaa900038001003")
	WINREG_VERSION       = 1
	WINREG_VERSION_MINOR = 0
)

const (
	// Opnums
	OpenClassesRoot = iota
	OpenCurrentUser
	OpenLocalMachine // openHKLM
	OpenPerformanceData
	OpenUsers
	BaseRegCloseKey
	BaseRegCreateKey
	BaseRegDeleteKey
	BaseRegDeleteValue
	BaseRegEnumKey
	BaseRegEnumValue
	BaseRegFlushKey
	BaseRegGetKeySecurity
	BaseRegLoadKey
	Opnum14NotImplemented
	BaseRegOpenKey
	BaseRegQueryInfoKey
	BaseRegQueryValue
	BaseRegReplaceKey
	BaseRegRestoreKey
	BaseRegSaveKey
	BaseRegSetKeySecurity
	BaseRegSetValue
	BaseRegUnLoadKey
	Opnum24NotImplemented
	Opnum25NotImplemented
	BaseRegGetVersion
	OpenCurrentConfig
	Opnum28NotImplemented
	BaseRegQueryMultipleValues
	Opnum30NotImplemented
	BaseRegSaveKeyEx
	OpenPerformanceText
	OpenPerformanceNlsText
	BaseRegQueryMultipleValues2
	BaseRegDeleteKeyEx
)

type RegSam = uint32

type RpcHKey struct {
	ContextHandle []byte `smb:"fixed:20"`
}

type UnicodeString struct {
	ReferentID  uint32
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
	RegString   []byte `smb:"align:4"`
}

func (u *UnicodeString) Len() int {
	if u != nil {
		return 16 + roundup(int(u.ActualCount*2), 4)
	}
	return 4
}

func NewUnicodeString(s string, ref uint32) *UnicodeString {
	if s == "" {
		return nil
	}
	l := utf16le.EncodedStringLen(s)/2 + 1
	reg := make([]byte, roundup(l*2, 4))
	copy(reg, utf16le.EncodeStringToBytes(s))
	return &UnicodeString{
		ReferentID:  ref,
		MaxCount:    uint32(l),
		Offset:      0,
		ActualCount: uint32(l),
		RegString:   reg,
	}
}

type RegString struct {
	ReferentId    []byte
	Length        uint16
	MaximumLength uint16 // size
	UnicodeString *UnicodeString
}

func roundup(x, align int) int {
	return (x + (align - 1)) &^ (align - 1)
}

func (s *RegString) GetRefId() uint32 {
	if s.UnicodeString != nil {
		return s.UnicodeString.ReferentID
	}
	return binary.LittleEndian.Uint32(s.ReferentId)
}

func GenerateRegString(s string, ref ...uint32) RegString {
	if len(s) == 0 {
		return RegString{}
	} else {
		l := utf16le.EncodedStringLen(s)/2 + 1

		var ReferentId []byte
		var refId uint32
		if len(ref) == 0 || ref[0] == 0 {
			refId = 0x20000
		} else {
			refId = ref[0] + 0x4
			binary.LittleEndian.PutUint32(ReferentId, ref[0])
		}

		return RegString{
			ReferentId,
			uint16(l * 2),
			uint16(l * 2),
			NewUnicodeString(s, refId),
		}
	}
}

func (s *RegString) SetRef(r uint32) {
	if s.UnicodeString != nil {
		s.UnicodeString.ReferentID = r
	}
}

func (s *RegString) Len() int {
	if s.UnicodeString != nil {
		return 4 + len(s.ReferentId) + s.UnicodeString.Len()
	}
	return 4 + 4
}

// OpenHKLMRequest Equal to OpenLocalMachine
type OpenHKLMRequest struct {
	msrpc.MSRPCHeaderStruct

	ServerName *UnicodeString
	AccessMask RegSam
}

func (o OpenHKLMRequest) Size() int {
	return 24 + o.ServerName.Len() + 4
}

func (o OpenHKLMRequest) Encode(b []byte) {
	o.FragLength = uint16(o.Size())
	a, err := encoder.Marshal(o)
	if err != nil {
		fmt.Println(err)
		return
	}
	copy(b, a)
}

func NewOpenHKLMRequest() *OpenHKLMRequest {
	nh := msrpc.NewMSRPCHeader()
	nh.OpNum = OpenLocalMachine
	nh.ContextId = 0
	nh.AllocHint = 8
	nh.PacketFlags = 3

	return &OpenHKLMRequest{
		MSRPCHeaderStruct: nh,
	}
}

type OpenKeyRequest struct {
	msrpc.MSRPCHeaderStruct

	RpcHKey
	KeyName    RegString // lpSubKey
	Options    uint32
	AccessMask RegSam // samDesired
}

func (s OpenKeyRequest) Size() int {
	return 24 + 20 + s.KeyName.Len() + 4 + 4
}

func (s OpenKeyRequest) Encode(b []byte) {
	s.FragLength = uint16(s.Size())
	a, err := encoder.Marshal(s)
	if err != nil {
		fmt.Println(err)
		return
	}
	copy(b, a)
}

func NewOpenKeyRequest(handle []byte, key string) OpenKeyRequest {
	nh := msrpc.NewMSRPCHeader()
	nh.OpNum = BaseRegOpenKey
	nh.ContextId = 0
	nh.PacketFlags = 3
	nh.AllocHint = 212
	ns := GenerateRegString(key)
	return OpenKeyRequest{
		MSRPCHeaderStruct: nh,
		RpcHKey:           RpcHKey{handle},
		KeyName:           ns,
		Options:           0,
		AccessMask:        0x00020019,
	}
}

type OpenKeyResponse struct {
	msrpc.DCEHeader
	RpcHKey RpcHKey `smb:"fixed:20"`
	ErrCode uint32
}

type OpenHKLMResponse struct {
	msrpc.DCEHeader
	RpcHKey
	ErrCode uint32
}

type CloseKeyRequest struct {
	msrpc.MSRPCHeaderStruct
	RpcHKey
}

type CloseKeyResponse struct {
	msrpc.DCEHeader
	RpcHKey
	ErrCode uint32
}

type FileTime = uint64

type EnumKeyRequest struct {
	msrpc.MSRPCHeaderStruct

	RpcHKey
	Index         uint32
	Name          RegString
	KeyClass      RegString
	LastWriteTime LastChangedTime
}

func (e *EnumKeyRequest) Size() int {
	return 24 + 20 + 4 + e.Name.Len() + e.KeyClass.Len() + 12
}

func (e *EnumKeyRequest) Encode(b []byte) {
	e.FragLength = uint16(e.Size())
	a, err := encoder.Marshal(e)
	if err != nil {
		fmt.Println(err)
		return
	}
	copy(b, a)
}

func NewEnumKeyRequest(index uint32, name, keyClass string, handle []byte, lastWriteTime uint64) EnumKeyRequest {
	ns1 := GenerateRegString(name)
	refId := ns1.GetRefId()
	ns2 := GenerateRegString(keyClass, refId+4)
	return EnumKeyRequest{
		RpcHKey:       RpcHKey{handle},
		Index:         index,
		Name:          ns1,
		KeyClass:      ns2,
		LastWriteTime: LastChangedTime{ns2.GetRefId() + 4, lastWriteTime},
	}
}

type LastChangedTime struct {
	ReferentId uint32 `smb:"offset:LastChangedTime"`
	FileTime
}

type EnumKeyResponse struct {
	msrpc.DCEHeader
	Name            RegString
	KeyClass        RegString
	LastChangedTime LastChangedTime
	ErrCode         uint32
}

type QueryInfoKeyRequest struct {
	msrpc.MSRPCHeaderStruct
	RpcHKey
	ClassName RegString
}

func (q QueryInfoKeyRequest) Size() int {
	return 24 + 20 + q.ClassName.Len()
}

func (q QueryInfoKeyRequest) Encode(b []byte) {
	q.FragLength = uint16(q.Size())
	a, err := encoder.Marshal(q)
	if err != nil {
		fmt.Println(err)
		return
	}
	copy(b, a)
}

func NewQueryInfoKeyRequest(handle []byte, className string) QueryInfoKeyRequest {
	nh := msrpc.NewMSRPCHeader()
	nh.OpNum = BaseRegQueryInfoKey
	nh.ContextId = 0
	nh.PacketFlags = 3
	ns := GenerateRegString(className)
	return QueryInfoKeyRequest{
		MSRPCHeaderStruct: nh,
		RpcHKey:           RpcHKey{handle},
		ClassName:         ns,
	}
}

type QueryInfoKeyInfo struct {
	PSubKey             uint32
	PMaxSubKeyLen       uint32
	PMaxClassLen        uint32
	PValues             uint32
	PMaxValueNameLen    uint32
	PMaxValueLen        uint32
	PSecurityDescriptor uint32
	PLastChangedTime    uint64
}

type QueryInfoKeyResponse struct {
	msrpc.DCEHeader
	QueryInfoKeyInfo
	ErrCode uint32
}

type PUint32 struct {
	ReferentId uint32
	uint32
}

func (p PUint32) Len() int {
	return 8
}

type PByteArray struct {
	ReferentId  uint32
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
	Byte        []byte
}

func (p PByteArray) Len() int {
	return 16 + len(p.Byte)
}

type EnumValueRequest struct {
	msrpc.MSRPCHeaderStruct

	RpcHKey
	Index     uint32
	ValueName RegString
	Type      PUint32
	Data      *UnicodeString
	PSize     PUint32
	PLen      PUint32
}

func (e *EnumValueRequest) Size() int {
	return 24 + 20 + 4 + e.ValueName.Len() + e.Type.Len() + e.Data.Len() + e.PLen.Len() + e.PSize.Len()
}

func (e *EnumValueRequest) Encode(b []byte) {
	e.FragLength = uint16(e.Size())
	a, err := encoder.Marshal(e)
	if err != nil {
		fmt.Println(err)
		return
	}
	copy(b, a)
}

type EnumValueResponse struct {
	msrpc.DCEHeader

	ValueName RegString
	Type      PUint32
	Data      *UnicodeString
	PSize     PUint32
	PLen      PUint32
}
