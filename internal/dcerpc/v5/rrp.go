package v5

import (
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
	String      []byte
}

type String struct {
	Length        uint16
	MaximumLength uint16 // size
	UnicodeString *UnicodeString
	Rdp           []byte
}

func roundup(x, align int) int {
	return (x + (align - 1)) &^ (align - 1)
}

func GenerateString(s string) String {
	if len(s) == 0 {
		return String{}
	} else {
		l := utf16le.EncodedStringLen(s)/2 + 1
		t := utf16le.EncodeStringToBytes(s)
		if l*2 != len(t) {
			nt := make([]byte, len(t)+2)
			copy(nt, t)
			t = nt
		}
		var r []byte
		if roundup(l*2, 4) != l*2 {
			r = []byte{0, 0}
		}
		return String{
			uint16(l * 2),
			uint16(l * 2),
			&UnicodeString{
				0,
				uint32(l),
				0,
				uint32(l),
				t,
			},
			r,
		}
	}
}

func (s *String) SetRef(r uint32) {
	if s.UnicodeString != nil {
		s.UnicodeString.ReferentID = r
	}
}

func (s *String) Len() int {
	if s.UnicodeString != nil {
		return 4 + 16 + roundup(int(s.Length), 4)
	}
	return 4 + 4
}

type ServerName struct {
	ReferentID  uint32 `smb:"offset:ServerName"`
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
	String      []byte
}

// OpenHKLMRequest Equal to OpenLocalMachine
type OpenHKLMRequest struct {
	msrpc.MSRPCHeaderStruct

	ServerName String
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
	KeyName    String // lpSubKey
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
	ns := GenerateString(key)
	ns.SetRef(0x20000)
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

type FileTime struct {
	Time uint64
}

type EnumKeyRequest struct {
	RpcHKey
	Index         uint32
	Name          UnicodeString
	KeyClass      KeyClass
	LastWriteTime LastChangedTime
}

type KeyClass struct {
	ReferentId uint32 `smb:"offset:KeyClass"`
	String
}

type LastChangedTime struct {
	ReferentId uint32 `smb:"offset:LastChangedTime"`
	FileTime
}

type EnumKeyResponse struct {
	msrpc.DCEHeader
	Name            String
	KeyClass        KeyClass
	LastChangedTime LastChangedTime
	ErrCode         uint32
}

type QueryInfoKeyRequest struct {
	msrpc.MSRPCHeaderStruct
	RpcHKey
	ClassName String
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
	ns := GenerateString(className)
	ns.SetRef(0x20000)
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
