package v5

import (
	encoder "github.com/hirochachacha/go-smb2/encode"
	"github.com/hirochachacha/go-smb2/internal/msrpc"
)

var (
	SVCCTL_UUID          = []byte("81bb7a364498f135ad3298f038001003")
	SVCCTL_VERSION       = 2
	SVCCTL_VERSION_MINOR = 0
)

const (
	RCloseServiceHandle = iota
	RControlService
	RDeleteService
	RLockServiceDatabase
	RQueryServiceObjectSecurity
	RSetServiceObjectSecurity
	RQueryServiceStatus
	RSetServiceStatus
	RUnlockServiceDatabase
	RNotifyBootConfigStatus
	Opnum10NotUsedOnWire
	RChangeServiceConfigW
	RCreateServiceW
	REnumDependentServicesW
	REnumServicesStatusW
	ROpenSCManagerW
	ROpenServiceW
	RQueryServiceConfigW
	RQueryServiceLockStatusW
	RStartServiceW
	RGetServiceDisplayNameW
	RGetServiceKeyNameW
	Opnum22NotUsedOnWire
	RChangeServiceConfigA
	RCreateServiceA
	REnumDependentServicesA
	REnumServicesStatusA
	ROpenSCManagerA
	ROpenServiceA
	RQueryServiceConfigA
	RQueryServiceLockStatusA
	RStartServiceA
	RGetServiceDisplayNameA
	RGetServiceKeyNameA
	Opnum34NotUsedOnWire
	REnumServiceGroupW
	RChangeServiceConfig2A
	RChangeServiceConfig2W
	RQueryServiceConfig2A
	RQueryServiceConfig2W
	RQueryServiceStatusEx
	REnumServicesStatusExA
	REnumServicesStatusExW
	Opnum43NotUsedOnWire
	RCreateServiceWOW64A
	RCreateServiceWOW64W
	Opnum46NotUsedOnWire
	RNotifyServiceStatusChange
	RGetNotifyResults
	RCloseNotifyHandle
	RControlServiceExA
	RControlServiceExW
	Opnum52NotUsedOnWire
	Opnum53NotUsedOnWire
	Opnum54NotUsedOnWire
	Opnum55NotUsedOnWire
	RQueryServiceConfigEx
	Opnum57NotUsedOnWire
	Opnum58NotUsedOnWire
	Opnum59NotUsedOnWire
	RCreateWowService
	Opnum61NotUsedOnWire
	Opnum62NotUsedOnWire
	Opnum63NotUsedOnWire
	ROpenSCManager2
)

type ROpenSCManagerWRequest struct {
	msrpc.MSRPCHeaderStruct

	MachineName  *UnicodeString
	DatabaseName *UnicodeString

	AccessMask uint32
}

func (r ROpenSCManagerWRequest) Size() int {
	return 24 + r.MachineName.Len() + r.DatabaseName.Len() + 4
}

func (r ROpenSCManagerWRequest) Encode(b []byte) {
	r.FragLength = uint16(r.Size())
	a, err := encoder.Marshal(r)
	if err != nil {
		return
	}
	copy(b, a)
}

func NewROpenSCManagerWRequest(machineName, databaseName string) ROpenSCManagerWRequest {
	ms := msrpc.NewMSRPCHeader()
	ms.OpNum = ROpenSCManagerW
	ms.ContextId = 0
	ms.AllocHint = 52
	ms.PacketFlags = 3
	return ROpenSCManagerWRequest{
		MSRPCHeaderStruct: ms,
		MachineName:       NewUnicodeString(machineName, 0x20000),
		DatabaseName:      NewUnicodeString(databaseName, 0x20004),
	}
}

type ROpenSCManagerWResponse struct {
	msrpc.DCEHeader
	RpcHKey
}

type RCreateServiceWRequest struct {
	msrpc.MSRPCHeaderStruct

	RpcHKey
	ServiceName *UnicodeString
	DisplayName *UnicodeString

	Access           uint32
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinPath          *UnicodeString
	OrderGroup       *UnicodeString
	TagId            *PUint32
	Dependencies     *PByteArray
	DependSize       uint32
	ServiceStartName *UnicodeString
	Password         *PByteArray
	PwSize           uint32
}

func (R RCreateServiceWRequest) Size() int {
	return 24 + 20 + R.ServiceName.Len() + R.DisplayName.Len() + 16 + R.BinPath.Len() + R.OrderGroup.Len() + R.TagId.Len() + R.Dependencies.Len() + 4 + R.ServiceStartName.Len() + R.Password.Len() + 4
}

func (R RCreateServiceWRequest) Encode(b []byte) {
	R.FragLength = uint16(R.Size())
	a, err := encoder.Marshal(R)
	if err != nil {
		return
	}
	copy(b, a)
}

func NewRCreateServiceWRequest(handle []byte, serviceName, display, binPath string) RCreateServiceWRequest {
	ms := msrpc.NewMSRPCHeader()
	ms.OpNum = RCreateServiceW
	ms.AllocHint = 208
	ms.PacketType = msrpc.RPC_TYPE_REQUEST
	return RCreateServiceWRequest{
		MSRPCHeaderStruct: ms,
		RpcHKey:           RpcHKey{handle},
		ServiceName:       NewUnicodeString(serviceName, 0),
		DisplayName:       NewUnicodeString(display, 0x20000),
		Access:            0xf01ff,
		ServiceType:       0x10,
		StartType:         0x3,
		ErrorControl:      0x1,
		BinPath:           NewUnicodeString(binPath, 0),
		OrderGroup:        nil,
		TagId:             nil,
		Dependencies:      nil,
		DependSize:        0,
		ServiceStartName:  nil,
		Password:          nil,
		PwSize:            0,
	}
}

type RCreateServiceWResp struct {
	msrpc.DCEHeader
	TagId uint32
	RpcHKey
	Code uint32
}

type RDeleteServiceRequest struct {
	msrpc.MSRPCHeaderStruct

	RpcHKey
}

func (R RDeleteServiceRequest) Size() int {
	return 24 + 20
}

func (R RDeleteServiceRequest) Encode(b []byte) {
	R.FragLength = uint16(R.Size())
	a, err := encoder.Marshal(R)
	if err != nil {
		return
	}
	copy(b, a)
}

func NewRDeleteServiceRequest(handle []byte) RDeleteServiceRequest {
	ms := msrpc.NewMSRPCHeader()
	ms.OpNum = RDeleteService
	ms.PacketFlags = 0x3
	return RDeleteServiceRequest{
		MSRPCHeaderStruct: ms,
		RpcHKey:           RpcHKey{handle},
	}
}

type RDeleteServiceResp struct {
	msrpc.DCEHeader

	Code uint32
}

type ROpenServiceWRequest struct {
	msrpc.MSRPCHeaderStruct

	RpcHKey
	ServiceName *UnicodeString
	Access      uint32
}

func (R ROpenServiceWRequest) Size() int {
	return 24 + 20 + R.ServiceName.Len() + 4
}

func (R ROpenServiceWRequest) Encode(b []byte) {
	R.FragLength = uint16(R.Size())
	a, err := encoder.Marshal(R)
	if err != nil {
		return
	}
	copy(b, a)
}

func NewROpenServiceWRequest(handle []byte, serviceName string) ROpenServiceWRequest {
	ms := msrpc.NewMSRPCHeader()
	ms.OpNum = ROpenServiceW
	ms.PacketFlags = 0x3
	return ROpenServiceWRequest{
		MSRPCHeaderStruct: ms,
		RpcHKey:           RpcHKey{handle},
		ServiceName:       NewUnicodeString(serviceName, 0),
		Access:            0x10,
	}
}

type ROpenServiceWResponse struct {
	msrpc.DCEHeader

	RpcHKey

	Code uint32
}

type RCloseServiceHandleRequest struct {
	msrpc.MSRPCHeaderStruct

	RpcHKey
}

func (R RCloseServiceHandleRequest) Size() int {
	return 24 + 20
}

func (R RCloseServiceHandleRequest) Encode(b []byte) {
	R.FragLength = uint16(R.Size())
	a, err := encoder.Marshal(R)
	if err != nil {
		return
	}
	copy(b, a)
}

func NewRCloseServiceHandleRequest(handle []byte) RCloseServiceHandleRequest {
	ms := msrpc.NewMSRPCHeader()
	ms.OpNum = RCloseServiceHandle
	ms.PacketFlags = 0x3
	return RCloseServiceHandleRequest{
		MSRPCHeaderStruct: ms,
		RpcHKey:           RpcHKey{handle},
	}
}

type RCloseServiceHandleResp struct {
	msrpc.DCEHeader

	RpcHKey
	Code uint32
}

type RStartServiceWRequest struct {
	msrpc.MSRPCHeaderStruct

	RpcHKey

	Argc uint32
	Argv *UnicodeString
}

func (R RStartServiceWRequest) Size() int {
	return 24 + 20 + 4 + R.Argv.Len()
}

func (R RStartServiceWRequest) Encode(b []byte) {
	R.FragLength = uint16(R.Size())
	a, err := encoder.Marshal(R)
	if err != nil {
		return
	}
	copy(b, a)
}

func NewRStartServiceWRequest(handle []byte) RStartServiceWRequest {
	ms := msrpc.NewMSRPCHeader()
	ms.OpNum = RStartServiceW
	ms.PacketFlags = 0x3

	return RStartServiceWRequest{
		MSRPCHeaderStruct: ms,
		RpcHKey:           RpcHKey{handle},
	}
}

type RQueryServiceStatusRequest struct {
	msrpc.MSRPCHeaderStruct

	RpcHKey
}

func (R RQueryServiceStatusRequest) Size() int {
	return 24 + 20

}

func (R RQueryServiceStatusRequest) Encode(b []byte) {
	R.FragLength = uint16(R.Size())
	a, err := encoder.Marshal(R)
	if err != nil {
		return
	}
	copy(b, a)
}

func NewRQueryServiceStatusRequest(handle []byte) RQueryServiceStatusRequest {
	ms := msrpc.NewMSRPCHeader()
	ms.OpNum = RQueryServiceStatus
	ms.PacketFlags = 0x3

	return RQueryServiceStatusRequest{
		MSRPCHeaderStruct: ms,
		RpcHKey:           RpcHKey{handle},
	}
}

type RStartServiceWResp RDeleteServiceResp
type RQueryServiceStatusResp struct {
	msrpc.DCEHeader

	ServiceType             uint32
	CurrentState            uint32
	CtlAccepted             uint32
	ExitCode                uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}
