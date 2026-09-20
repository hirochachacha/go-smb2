package smb2

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hirochachacha/go-smb2/v2/internal/erref"
	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/x/protocol"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

type (
	SecurityDescriptor  = security.Descriptor
	SecurityInformation = security.Information
	SID                 = security.SID
	ACL                 = security.ACL
	ACE                 = security.ACE
)

const (
	OWNER_SECURITY_INFORMATION = security.Owner
	GROUP_SECURITY_INFORMATION = security.Group
	DACL_SECURITY_INFORMATION  = security.DACL
	SACL_SECURITY_INFORMATION  = security.SACL

	ACCESS_ALLOWED = security.AccessAllowed
	ACCESS_DENIED  = security.AccessDenied
	SYSTEM_AUDIT   = security.SystemAudit

	SE_SELF_RELATIVE  uint16 = 0x8000
	SE_DACL_PRESENT   uint16 = 0x0004
	SE_SACL_PRESENT   uint16 = 0x0010
	SE_DACL_PROTECTED uint16 = 0x1000
	SE_SACL_PROTECTED uint16 = 0x2000
)

var decodeSecurityDescriptor = security.DecodeDescriptor

func testSID() *security.SID {
	return &security.SID{Revision: 1, IdentifierAuthority: 5, SubAuthority: []uint32{32, 544}}
}

func encodeSecurityDescriptorForTest(t *testing.T, descriptor *security.Descriptor, _ ...security.Information) []byte {
	t.Helper()
	data, err := descriptor.Encode()
	if err != nil {
		t.Fatalf("descriptor.Encode() error = %v", err)
	}
	return data
}

func TestSecurityDescriptorRoundTripPreservesACLDetails(t *testing.T) {
	t.Parallel()
	raw := []byte{0x42, 0x07, 0x04, 0x00}
	descriptor := &SecurityDescriptor{
		Owner: testSID(),
		Group: testSID(),
		DACL: &ACL{Revision: 2, ACEs: []ACE{
			{Type: ACCESS_DENIED, Flags: 3, Mask: 0x10, SID: testSID()},
			{Type: 0x42, Flags: 7, Raw: raw},
		}},
		SACL: &ACL{Revision: 2, ACEs: []ACE{
			{Type: SYSTEM_AUDIT, Flags: 1, Mask: 0x20, SID: testSID()},
		}},
	}

	wireBytes := encodeSecurityDescriptorForTest(t, descriptor, OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	decoded, err := decodeSecurityDescriptor(wireBytes, OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("decodeSecurityDescriptor() error = %v", err)
	}
	if decoded.DACL == nil || len(decoded.DACL.ACEs) != 2 || !bytes.Equal(decoded.DACL.ACEs[1].Raw, raw) {
		t.Fatalf("DACL details were not preserved: %#v", decoded.DACL)
	}
	if decoded.SACL == nil || len(decoded.SACL.ACEs) != 1 || decoded.SACL.ACEs[0].SID == nil {
		t.Fatalf("SACL details were not preserved: %#v", decoded.SACL)
	}
}

func TestSecurityDescriptorDistinguishesNullAndEmptyACL(t *testing.T) {
	t.Parallel()
	descriptor := &SecurityDescriptor{
		DACL: security.NullACL,
		SACL: &ACL{Revision: 2},
	}
	wireBytes := encodeSecurityDescriptorForTest(t, descriptor, DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	decoded, err := decodeSecurityDescriptor(wireBytes, DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("decodeSecurityDescriptor() error = %v", err)
	}
	if decoded.DACL != security.NullACL {
		t.Fatalf("NULL DACL became an ACL: %#v", decoded.DACL)
	}
	if decoded.SACL == nil || len(decoded.SACL.ACEs) != 0 {
		t.Fatalf("empty SACL was not preserved: %#v", decoded.SACL)
	}
}

func TestSecurityDescriptorSetValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		descriptor *SecurityDescriptor
	}{
		{"no selected component", &SecurityDescriptor{}},
		{"invalid ACL", &SecurityDescriptor{DACL: &ACL{ACEs: []ACE{{}}}}},
		{"authority too wide", &SecurityDescriptor{Owner: &SID{Revision: 1, IdentifierAuthority: 1 << 48}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.descriptor.Encode(); err == nil {
				t.Fatal("invalid security descriptor was accepted")
			}
		})
	}
}

func TestSecurityDescriptorRejectsKnownACEInWrongACLEvenAsRaw(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		selection SecurityInformation
		acl       *ACL
	}{
		{
			name:      "audit ACE in DACL",
			selection: DACL_SECURITY_INFORMATION,
			acl:       &ACL{Revision: 2, ACEs: []ACE{{Type: SYSTEM_AUDIT, Raw: []byte{byte(SYSTEM_AUDIT), 0, 4, 0}}}},
		},
		{
			name:      "object audit ACE in DACL",
			selection: DACL_SECURITY_INFORMATION,
			acl:       &ACL{Revision: 4, ACEs: []ACE{{Type: 0x07, Raw: []byte{0x07, 0, 4, 0}}}},
		},
		{
			name:      "allow ACE in SACL",
			selection: SACL_SECURITY_INFORMATION,
			acl:       &ACL{Revision: 2, ACEs: []ACE{{Type: ACCESS_ALLOWED, Raw: []byte{byte(ACCESS_ALLOWED), 0, 4, 0}}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := &SecurityDescriptor{}
			if test.selection == DACL_SECURITY_INFORMATION {
				descriptor.DACL = test.acl
			} else {
				descriptor.SACL = test.acl
			}
			if _, err := descriptor.Encode(); err == nil {
				t.Fatal("known ACE was accepted in the wrong ACL")
			}
		})
	}
}

func TestSecurityDescriptorRejectsTruncatedAndOversizedACL(t *testing.T) {
	t.Parallel()
	valid := encodeSecurityDescriptorForTest(t, &SecurityDescriptor{
		DACL: &ACL{Revision: 2},
	}, DACL_SECURITY_INFORMATION)
	for _, data := range [][]byte{
		valid[:19],
		func() []byte {
			data := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(data[16:20], uint32(len(data)-4))
			return data
		}(),
	} {
		if _, err := decodeSecurityDescriptor(data, DACL_SECURITY_INFORMATION); err == nil {
			t.Fatalf("malformed descriptor of length %d was accepted", len(data))
		}
	}

	bad := append([]byte(nil), valid...)
	// Keep the ACL offset but claim an ACL larger than the descriptor.
	daclOffset := binary.LittleEndian.Uint32(bad[16:20])
	binary.LittleEndian.PutUint16(bad[daclOffset+2:daclOffset+4], 0xffff)
	if _, err := decodeSecurityDescriptor(bad, DACL_SECURITY_INFORMATION); err == nil {
		t.Fatal("oversized ACL was accepted")
	}
}

func TestSecurityDescriptorSharedSIDAndAbsentACL(t *testing.T) {
	t.Parallel()
	// Owner and Group can reference the same SID, with neither ACL present.
	wireBytes := []byte{
		1, 0, 0, 0x80, 20, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0,
	}
	sd, err := decodeSecurityDescriptor(wireBytes, securityInformationComponents)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Owner == nil || sd.Group == nil || sd.Owner.SubAuthority[1] != 544 || sd.Group.SubAuthority[1] != 544 {
		t.Fatalf("shared SID decoded incorrectly: %#v", sd)
	}
	if sd.DACL != security.NullACL || sd.SACL != security.NullACL {
		t.Fatal("absent requested ACLs were not normalized to NULL ACLs")
	}
	clear(wireBytes)
	sd.Owner.SubAuthority[1] = 1
	if sd.Group.SubAuthority[1] != 544 {
		t.Fatal("decoded SIDs alias input or each other")
	}
}

func TestSecurityDescriptorPreservesMixedACERevisions(t *testing.T) {
	t.Parallel()
	// A non-object callback ACE is opaque to this API, including its condition.
	raw := []byte{9, 0, 24, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 7, 8, 9, 10}
	for _, revision := range []uint8{2, 4} {
		sd := &SecurityDescriptor{DACL: &ACL{Revision: revision, ACEs: []ACE{
			{Type: ACCESS_ALLOWED, SID: testSID(), Mask: 1}, {Type: 9, Raw: raw},
		}}}
		wireBytes := encodeSecurityDescriptorForTest(t, sd, DACL_SECURITY_INFORMATION)
		decoded, err := decodeSecurityDescriptor(wireBytes, DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.DACL.Revision != revision || !bytes.Equal(decoded.DACL.ACEs[1].Raw, raw) {
			t.Fatal("ACE or ACL revision changed")
		}
		clear(wireBytes)
		if !bytes.Equal(decoded.DACL.ACEs[1].Raw, raw) {
			t.Fatal("raw ACE aliases receive buffer")
		}
	}
}

func TestSecurityDescriptorProtectionAndSelection(t *testing.T) {
	t.Parallel()
	sd := &SecurityDescriptor{
		DACL: &ACL{Protected: true},
	}
	wireBytes, err := sd.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if sd.Information() != DACL_SECURITY_INFORMATION {
		t.Fatalf("selection = %#x, want DACL only", sd.Information())
	}
	if binary.LittleEndian.Uint16(wireBytes[2:4]) != SE_SELF_RELATIVE|SE_DACL_PRESENT|SE_DACL_PROTECTED {
		t.Fatal("DACL protection was not reflected in control")
	}
	if !bytes.Equal(wireBytes[4:16], make([]byte, 12)) || binary.LittleEndian.Uint32(wireBytes[16:20]) == 0 {
		t.Fatal("unselected components were transmitted")
	}
	sd.DACL.Protected = false
	wireBytes = encodeSecurityDescriptorForTest(t, sd)
	if binary.LittleEndian.Uint16(wireBytes[2:4])&SE_DACL_PROTECTED != 0 {
		t.Fatal("unprotect was ignored")
	}
}

func TestSecurityDescriptorMalformedComponentBounds(t *testing.T) {
	t.Parallel()
	valid := encodeSecurityDescriptorForTest(t, &SecurityDescriptor{
		DACL: &ACL{Revision: 2, ACEs: []ACE{{Type: ACCESS_ALLOWED, SID: testSID()}}},
	}, DACL_SECURITY_INFORMATION)
	for _, mutate := range []func([]byte){
		func(w []byte) { binary.LittleEndian.PutUint32(w[16:20], 0xfffffffc) },
		func(w []byte) { binary.LittleEndian.PutUint32(w[16:20], 21) },
		func(w []byte) { binary.LittleEndian.PutUint16(w[24:26], 0xffff) },
		func(w []byte) { binary.LittleEndian.PutUint16(w[30:32], 0xffff) },
		func(w []byte) { w[37] = 16 },
		func(w []byte) { w[36] = 2 },
	} {
		wireBytes := append([]byte(nil), valid...)
		mutate(wireBytes)
		if _, err := decodeSecurityDescriptor(wireBytes, DACL_SECURITY_INFORMATION); err == nil {
			t.Fatalf("malformed descriptor accepted: %x", wireBytes)
		}
	}
}

func TestSecurityDescriptorValidatesBeforeSending(t *testing.T) {
	t.Parallel()
	fs, _ := newTestShare(t, testServerOptions{maxTransactSize: 65536})
	// Both ACLs individually fit their uint16 AclSize; the combined descriptor
	// exceeds this connection's negotiated transaction size.
	raw := make([]byte, 40000)
	raw[0] = 0x42
	binary.LittleEndian.PutUint16(raw[2:4], uint16(len(raw)))
	acl := &ACL{Revision: 2, ACEs: []ACE{{Type: 0x42, Raw: raw}}}
	sd := &SecurityDescriptor{DACL: acl, SACL: acl}
	require.ErrorIs(t, fs.SetSecurityDescriptor(context.Background(), "test.txt", sd), os.ErrInvalid)
	require.ErrorIs(t, fs.SetSecurityDescriptor(context.Background(), "test.txt", nil), os.ErrInvalid)
	_, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", security.Information(0x80000000))
	require.ErrorIs(t, err, os.ErrInvalid)
	_, err = fs.GetSecurityDescriptor(context.Background(), "test.txt", 0)
	require.ErrorIs(t, err, os.ErrInvalid)
}

func TestShareSecurityDescriptor(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn
	targetFileId := &wire.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}
	selection := OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	descriptor := &SecurityDescriptor{
		Owner: testSID(),
		DACL:  &ACL{Revision: 2},
	}
	wireBytes := encodeSecurityDescriptorForTest(t, descriptor, selection)

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 1. Compound CREATE + QUERY_INFO + CLOSE for GetSecurityDescriptor
		req, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		for {
			p := wire.PacketCodec(req)
			switch p.Command() {
			case wire.SMB2_CREATE:
				create := wire.CreateRequestDecoder(p.Body())
				require.EqualValues(t, wire.READ_CONTROL, create.DesiredAccess())
				sendTestResponse(dt, req, &wire.CreateResponse{
					FileId:         targetFileId,
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_QUERY_INFO:
				query := wire.QueryInfoRequestDecoder(p.Body())
				require.EqualValues(t, maxSingleCreditPayloadSize, query.OutputBufferLength())
				sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(wireBytes)}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_CLOSE:
				sendTestResponse(dt, req, &wire.CloseResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			}
			if next := p.NextCommand(); next != 0 {
				req = req[next:]
			} else {
				break
			}
		}

		// 2. Compound CREATE + SET_INFO + CLOSE for SetSecurityDescriptor
		req, err = readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		for {
			p := wire.PacketCodec(req)
			switch p.Command() {
			case wire.SMB2_CREATE:
				create := wire.CreateRequestDecoder(p.Body())
				require.EqualValues(t, wire.WRITE_DAC|wire.WRITE_OWNER, create.DesiredAccess())
				sendTestResponse(dt, req, &wire.CreateResponse{
					FileId:         targetFileId,
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_SET_INFO:
				set := wire.SetInfoRequestDecoder(p.Body())
				require.EqualValues(t, selection, set.AdditionalInformation())
				sendTestResponse(dt, req, &wire.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_CLOSE:
				sendTestResponse(dt, req, &wire.CloseResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			}
			if next := p.NextCommand(); next != 0 {
				req = req[next:]
			} else {
				break
			}
		}
	}()

	got, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", selection)
	require.NoError(t, err)
	require.NotNil(t, got)

	err = fs.SetSecurityDescriptor(context.Background(), "test.txt", got)
	require.NoError(t, err)
	<-done
}

func TestGetSecurityDescriptorSACLOnly(t *testing.T) {
	t.Parallel()
	fs, serverConn := newTestShare(t)
	dt := serverConn
	targetFileID := &wire.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}
	wireBytes := encodeSecurityDescriptorForTest(t, &SecurityDescriptor{SACL: &ACL{Revision: 2}})

	done := make(chan struct{})
	go func() {
		defer close(done)
		req, err := readMsg(dt)
		if err != nil {
			t.Error(err)
			return
		}
		for {
			packet := wire.PacketCodec(req)
			switch packet.Command() {
			case wire.SMB2_CREATE:
				create := wire.CreateRequestDecoder(packet.Body())
				require.EqualValues(t, wire.ACCESS_SYSTEM_SECURITY, create.DesiredAccess())
				sendTestResponse(dt, req, &wire.CreateResponse{
					FileId:         targetFileID,
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_QUERY_INFO:
				query := wire.QueryInfoRequestDecoder(packet.Body())
				require.EqualValues(t, SACL_SECURITY_INFORMATION, query.AdditionalInformation())
				sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(wireBytes)}, uint32(erref.STATUS_SUCCESS))
			case wire.SMB2_CLOSE:
				sendTestResponse(dt, req, &wire.CloseResponse{
					CreationTime:   &wire.Filetime{},
					LastAccessTime: &wire.Filetime{},
					LastWriteTime:  &wire.Filetime{},
					ChangeTime:     &wire.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			}
			if next := packet.NextCommand(); next != 0 {
				req = req[next:]
			} else {
				break
			}
		}
	}()

	descriptor, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", SACL_SECURITY_INFORMATION)
	require.NoError(t, err)
	require.NotNil(t, descriptor.SACL)
	require.Nil(t, descriptor.Owner)
	require.Nil(t, descriptor.Group)
	require.Nil(t, descriptor.DACL)
	<-done
}

func TestGetSecurityDescriptor_BufferTooSmallRetry(t *testing.T) {
	t.Parallel()
	t.Run("SuccessAfterRetry", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		dt := serverConn
		targetFileId := &wire.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}
		selection := OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
		descriptor := &SecurityDescriptor{
			Owner: testSID(),
			DACL:  &ACL{Revision: 2},
		}
		wireBytes := encodeSecurityDescriptorForTest(t, descriptor, selection)

		const requiredLen = 70 * 1024 // larger than 64KB, fits within max limit

		done := make(chan struct{})
		go func() {
			defer close(done)
			// Attempt 1: Initial query with 64KB buffer -> server fails with STATUS_BUFFER_TOO_SMALL
			req, err := readMsg(dt)
			if err != nil {
				t.Error(err)
				return
			}
			for {
				p := wire.PacketCodec(req)
				switch p.Command() {
				case wire.SMB2_CREATE:
					sendTestResponse(dt, req, &wire.CreateResponse{
						FileId:         targetFileId,
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_QUERY_INFO:
					query := wire.QueryInfoRequestDecoder(p.Body())
					require.EqualValues(t, maxSingleCreditPayloadSize, query.OutputBufferLength())
					errData := make([]byte, 4)
					le.PutUint32(errData, uint32(requiredLen))
					errRes := &wire.ErrorResponse{
						CommandCode: wire.SMB2_QUERY_INFO,
						ErrorData:   rawEncoder(errData),
					}
					sendTestResponse(dt, req, errRes, uint32(erref.STATUS_BUFFER_TOO_SMALL))
				case wire.SMB2_CLOSE:
					sendTestResponse(dt, req, &wire.CloseResponse{
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				}
				if next := p.NextCommand(); next != 0 {
					req = req[next:]
				} else {
					break
				}
			}

			// Attempt 2: Retried query with requiredLen buffer -> server succeeds
			req, err = readMsg(dt)
			if err != nil {
				t.Error(err)
				return
			}
			for {
				p := wire.PacketCodec(req)
				switch p.Command() {
				case wire.SMB2_CREATE:
					sendTestResponse(dt, req, &wire.CreateResponse{
						FileId:         targetFileId,
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_QUERY_INFO:
					query := wire.QueryInfoRequestDecoder(p.Body())
					require.EqualValues(t, requiredLen, query.OutputBufferLength())
					sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(wireBytes)}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_CLOSE:
					sendTestResponse(dt, req, &wire.CloseResponse{
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				}
				if next := p.NextCommand(); next != 0 {
					req = req[next:]
				} else {
					break
				}
			}
		}()

		got, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", selection)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, descriptor.Owner, got.Owner)
		require.NotNil(t, got.DACL)
		require.NotEqual(t, security.NullACL, got.DACL)
		<-done
	})

	t.Run("SuccessAtEffectiveLimit", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		dt := serverConn
		targetFileId := &wire.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}
		selection := OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
		descriptor := &SecurityDescriptor{
			Owner: testSID(),
			DACL:  &ACL{Revision: 2},
		}
		wireBytes := encodeSecurityDescriptorForTest(t, descriptor, selection)

		// Exactly the largest query buffer this connection may send: the retry
		// is still permitted because it does not exceed the effective limit.
		requiredLen := fs.maxTransactSize(2)
		require.Greater(t, requiredLen, maxSingleCreditPayloadSize)

		done := make(chan struct{})
		go func() {
			defer close(done)
			// Attempt 1: initial query with 64KB buffer -> server fails with
			// STATUS_BUFFER_TOO_SMALL, reporting the effective limit.
			req, err := readMsg(dt)
			if err != nil {
				t.Error(err)
				return
			}
			for {
				p := wire.PacketCodec(req)
				switch p.Command() {
				case wire.SMB2_CREATE:
					sendTestResponse(dt, req, &wire.CreateResponse{
						FileId:         targetFileId,
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_QUERY_INFO:
					query := wire.QueryInfoRequestDecoder(p.Body())
					require.EqualValues(t, maxSingleCreditPayloadSize, query.OutputBufferLength())
					errData := make([]byte, 4)
					le.PutUint32(errData, uint32(requiredLen))
					sendTestResponse(dt, req, &wire.ErrorResponse{
						CommandCode: wire.SMB2_QUERY_INFO,
						ErrorData:   rawEncoder(errData),
					}, uint32(erref.STATUS_BUFFER_TOO_SMALL))
				case wire.SMB2_CLOSE:
					sendTestResponse(dt, req, &wire.CloseResponse{
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				}
				if next := p.NextCommand(); next != 0 {
					req = req[next:]
				} else {
					break
				}
			}

			// Attempt 2: retried query at the effective limit -> server succeeds.
			req, err = readMsg(dt)
			if err != nil {
				t.Error(err)
				return
			}
			for {
				p := wire.PacketCodec(req)
				switch p.Command() {
				case wire.SMB2_CREATE:
					sendTestResponse(dt, req, &wire.CreateResponse{
						FileId:         targetFileId,
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_QUERY_INFO:
					query := wire.QueryInfoRequestDecoder(p.Body())
					require.EqualValues(t, requiredLen, query.OutputBufferLength())
					sendTestResponse(dt, req, &wire.QueryInfoResponse{Output: rawEncoder(wireBytes)}, uint32(erref.STATUS_SUCCESS))
				case wire.SMB2_CLOSE:
					sendTestResponse(dt, req, &wire.CloseResponse{
						CreationTime:   &wire.Filetime{},
						LastAccessTime: &wire.Filetime{},
						LastWriteTime:  &wire.Filetime{},
						ChangeTime:     &wire.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				}
				if next := p.NextCommand(); next != 0 {
					req = req[next:]
				} else {
					break
				}
			}
		}()

		got, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", selection)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, descriptor.Owner, got.Owner)
		require.NotNil(t, got.DACL)
		require.NotEqual(t, security.NullACL, got.DACL)
		<-done
	})
}

// TestGetSecurityDescriptor_BufferTooSmallOversizedRequired verifies that a
// server-reported required length above the connection's sendable limit is not
// retried. [MS-SMB2] 3.3.5.20 says the server SHOULD reject an
// OutputBufferLength greater than Connection.MaxTransactSize with
// STATUS_INVALID_PARAMETER, so the original response error must be preserved
// instead of exposing a local credit or internal error.
func TestGetSecurityDescriptor_BufferTooSmallOversizedRequired(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		requiredLen uint32
		options     testServerOptions
	}{
		{
			name:        "exceeds negotiated max transact size",
			requiredLen: 256 * 1024,
			options:     testServerOptions{maxTransactSize: 128 * 1024},
		},
		{
			name:        "exceeds credit derived effective size",
			requiredLen: 70 * 1024,
			options:     testServerOptions{credits: 1, singleCredit: true},
		},
		{
			name:        "huge required length",
			requiredLen: 0x7FFF0000,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fs, serverConn := newTestShare(t, test.options)
			dt := serverConn
			targetFileId := &wire.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}

			var queryCount atomic.Int32
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					req, err := readMsg(dt)
					if err != nil {
						return
					}
					for {
						p := wire.PacketCodec(req)
						switch p.Command() {
						case wire.SMB2_CREATE:
							sendTestResponse(dt, req, &wire.CreateResponse{
								FileId:         targetFileId,
								CreationTime:   &wire.Filetime{},
								LastAccessTime: &wire.Filetime{},
								LastWriteTime:  &wire.Filetime{},
								ChangeTime:     &wire.Filetime{},
							}, uint32(erref.STATUS_SUCCESS))
						case wire.SMB2_QUERY_INFO:
							queryCount.Add(1)
							errData := make([]byte, 4)
							le.PutUint32(errData, test.requiredLen)
							sendTestResponse(dt, req, &wire.ErrorResponse{
								CommandCode: wire.SMB2_QUERY_INFO,
								ErrorData:   rawEncoder(errData),
							}, uint32(erref.STATUS_BUFFER_TOO_SMALL))
						case wire.SMB2_CLOSE:
							sendTestResponse(dt, req, &wire.CloseResponse{
								CreationTime:   &wire.Filetime{},
								LastAccessTime: &wire.Filetime{},
								LastWriteTime:  &wire.Filetime{},
								ChangeTime:     &wire.Filetime{},
							}, uint32(erref.STATUS_SUCCESS))
						}
						if next := p.NextCommand(); next != 0 {
							req = req[next:]
						} else {
							break
						}
					}
				}
			}()

			got, err := fs.GetSecurityDescriptor(context.Background(), "test.txt", OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION)
			require.Nil(t, got)
			var pathErr *os.PathError
			require.ErrorAs(t, err, &pathErr)
			// The original response status must survive instead of being
			// replaced by a retry failure.
			require.ErrorIs(t, err, erref.STATUS_BUFFER_TOO_SMALL)
			var internalErr *protocol.InternalError
			require.NotErrorAs(t, err, &internalErr)

			// No retry may be sent; unblock and finish the pseudo server.
			require.NoError(t, serverConn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
			<-done
			require.EqualValues(t, 1, queryCount.Load())
		})
	}
}
