package v5

import (
	"fmt"
	encoder "github.com/hirochachacha/go-smb2/encode"
	"github.com/hirochachacha/go-smb2/internal/msrpc"
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
}

func (s String) Len() int {
	if s.UnicodeString != nil {
		return 4 + 16 + len(s.UnicodeString.String)
	}
	return 4
}

type ServerName struct {
	ReferentID  uint32 `smb:"offset:ServerName"`
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
	String      []byte
}

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

func (s *OpenKeyRequest) Size() int {
	return 24 + 20 + s.KeyName.Len() + 4 + 4
}

func NewOpenKeyRequest() *OpenKeyRequest {
	nh := msrpc.NewMSRPCHeader()
	nh.OpNum = BaseRegOpenKey
	nh.ContextId = 0

	return &OpenKeyRequest{
		MSRPCHeaderStruct: nh,
		RpcHKey:           RpcHKey{},
		KeyName:           String{},
		Options:           0,
		AccessMask:        0,
	}
}
