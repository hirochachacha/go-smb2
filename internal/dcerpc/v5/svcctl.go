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

func (r *ROpenSCManagerWRequest) Size() int {
	return 24 + r.MachineName.Len() + r.DatabaseName.Len() + 4
}

func (r *ROpenSCManagerWRequest) Encode(b []byte) {
	r.FragLength = uint16(r.Size())
	a, err := encoder.Marshal(r)
	if err != nil {
		return
	}
	copy(b, a)
}
