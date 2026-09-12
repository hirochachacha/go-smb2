package smb2

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hirochachacha/go-smb2/internal/erref"
	"github.com/hirochachacha/go-smb2/internal/smb2"
)


func testSID() *SID {
	return &SID{Revision: 1, IdentifierAuthority: 5, SubAuthorities: []uint32{32, 544}}
}

func encodeSecurityDescriptorForTest(t *testing.T, descriptor *SecurityDescriptor, selection SecurityInformation) []byte {
	t.Helper()
	internalDescriptor, err := descriptor.internal(selection)
	if err != nil {
		t.Fatalf("descriptor.internal() error = %v", err)
	}
	data := make([]byte, internalDescriptor.Size())
	internalDescriptor.Encode(data)
	return data
}

func TestSecurityDescriptorRoundTripPreservesACLDetails(t *testing.T) {
	raw := []byte{0x42, 0x07, 0x04, 0x00}
	descriptor := &SecurityDescriptor{
		Control:                SE_RM_CONTROL_VALID | SE_DACL_PRESENT | SE_SACL_PRESENT,
		ResourceManagerControl: 0x5a,
		Owner:                  testSID(),
		Group:                  testSID(),
		DACL: &ACL{Revision: 2, ACEs: []ACE{
			{Type: ACCESS_DENIED, Flags: 3, Mask: 0x10, SID: testSID()},
			{Type: 0x42, Flags: 7, Raw: raw},
		}},
		SACL: &ACL{Revision: 2, ACEs: []ACE{
			{Type: SYSTEM_AUDIT, Flags: 1, Mask: 0x20, SID: testSID()},
		}},
	}

	wire := encodeSecurityDescriptorForTest(t, descriptor, OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	decoded, err := decodeSecurityDescriptor(wire, OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("decodeSecurityDescriptor() error = %v", err)
	}
	if decoded.Control != descriptor.Control|SE_SELF_RELATIVE || decoded.ResourceManagerControl != descriptor.ResourceManagerControl {
		t.Fatalf("control fields = %#x/%#x, want %#x/%#x", decoded.Control, decoded.ResourceManagerControl, descriptor.Control|SE_SELF_RELATIVE, descriptor.ResourceManagerControl)
	}
	if decoded.DACL == nil || len(decoded.DACL.ACEs) != 2 || !bytes.Equal(decoded.DACL.ACEs[1].Raw, raw) {
		t.Fatalf("DACL details were not preserved: %#v", decoded.DACL)
	}
	if decoded.SACL == nil || len(decoded.SACL.ACEs) != 1 || decoded.SACL.ACEs[0].SID == nil {
		t.Fatalf("SACL details were not preserved: %#v", decoded.SACL)
	}
}

func TestSecurityDescriptorDistinguishesNullAndEmptyACL(t *testing.T) {
	descriptor := &SecurityDescriptor{
		Control: SE_DACL_PRESENT | SE_SACL_PRESENT,
		DACL:    nil,
		SACL:    &ACL{Revision: 2},
	}
	wire := encodeSecurityDescriptorForTest(t, descriptor, DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	decoded, err := decodeSecurityDescriptor(wire, DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("decodeSecurityDescriptor() error = %v", err)
	}
	if decoded.DACL != nil {
		t.Fatalf("NULL DACL became an ACL: %#v", decoded.DACL)
	}
	if decoded.SACL == nil || len(decoded.SACL.ACEs) != 0 {
		t.Fatalf("empty SACL was not preserved: %#v", decoded.SACL)
	}
}

func TestSecurityDescriptorSetValidation(t *testing.T) {
	tests := []struct {
		name       string
		selection  SecurityInformation
		descriptor *SecurityDescriptor
	}{
		{"missing DACL PRESENT", DACL_SECURITY_INFORMATION, &SecurityDescriptor{}},
		{"protection without DACL", PROTECTED_DACL_SECURITY_INFORMATION, &SecurityDescriptor{}},
		{"conflicting DACL protection", DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, &SecurityDescriptor{Control: SE_DACL_PRESENT}},
		{"authority too wide", OWNER_SECURITY_INFORMATION, &SecurityDescriptor{Owner: &SID{Revision: 1, IdentifierAuthority: 1 << 48}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.descriptor.internal(test.selection); err == nil {
				t.Fatal("invalid security descriptor was accepted")
			}
		})
	}
}

func TestSecurityDescriptorRejectsKnownACEInWrongACLEvenAsRaw(t *testing.T) {
	tests := []struct {
		name      string
		selection SecurityInformation
		control   uint16
		acl       *ACL
	}{
		{
			name:      "audit ACE in DACL",
			selection: DACL_SECURITY_INFORMATION,
			control:   SE_DACL_PRESENT,
			acl:       &ACL{Revision: 2, ACEs: []ACE{{Type: SYSTEM_AUDIT, Raw: []byte{SYSTEM_AUDIT, 0, 4, 0}}}},
		},
		{
			name:      "object audit ACE in DACL",
			selection: DACL_SECURITY_INFORMATION,
			control:   SE_DACL_PRESENT,
			acl:       &ACL{Revision: 4, ACEs: []ACE{{Type: 0x07, Raw: []byte{0x07, 0, 4, 0}}}},
		},
		{
			name:      "allow ACE in SACL",
			selection: SACL_SECURITY_INFORMATION,
			control:   SE_SACL_PRESENT,
			acl:       &ACL{Revision: 2, ACEs: []ACE{{Type: ACCESS_ALLOWED, Raw: []byte{ACCESS_ALLOWED, 0, 4, 0}}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			descriptor := &SecurityDescriptor{Control: test.control}
			if test.selection == DACL_SECURITY_INFORMATION {
				descriptor.DACL = test.acl
			} else {
				descriptor.SACL = test.acl
			}
			if _, err := descriptor.internal(test.selection); err == nil {
				t.Fatal("known ACE was accepted in the wrong ACL")
			}
		})
	}
}

func TestSecurityDescriptorRejectsTruncatedAndOversizedACL(t *testing.T) {
	valid := encodeSecurityDescriptorForTest(t, &SecurityDescriptor{
		Control: SE_DACL_PRESENT,
		DACL:    &ACL{Revision: 2},
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
	// Owner and Group can reference the same SID, with neither ACL present.
	wire := []byte{1, 0, 0, 0x80, 20, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0}
	sd, err := decodeSecurityDescriptor(wire, securityInformationComponents)
	if err != nil {
		t.Fatal(err)
	}
	if sd.Owner == nil || sd.Group == nil || sd.Owner.SubAuthorities[1] != 544 || sd.Group.SubAuthorities[1] != 544 {
		t.Fatalf("shared SID decoded incorrectly: %#v", sd)
	}
	if sd.Control&(SE_DACL_PRESENT|SE_SACL_PRESENT) != 0 || sd.DACL != nil || sd.SACL != nil {
		t.Fatal("absent ACLs were not retained")
	}
	clear(wire)
	sd.Owner.SubAuthorities[1] = 1
	if sd.Group.SubAuthorities[1] != 544 {
		t.Fatal("decoded SIDs alias input or each other")
	}
}

func TestSecurityDescriptorPreservesMixedACERevisions(t *testing.T) {
	// A non-object callback ACE is opaque to this API, including its condition.
	raw := []byte{9, 0, 24, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 7, 8, 9, 10}
	for _, revision := range []uint8{2, 4} {
		sd := &SecurityDescriptor{Control: SE_DACL_PRESENT, DACL: &ACL{Revision: revision, ACEs: []ACE{
			{Type: ACCESS_ALLOWED, SID: testSID(), Mask: 1}, {Type: 9, Raw: raw},
		}}}
		wire := encodeSecurityDescriptorForTest(t, sd, DACL_SECURITY_INFORMATION)
		decoded, err := decodeSecurityDescriptor(wire, DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.DACL.Revision != revision || !bytes.Equal(decoded.DACL.ACEs[1].Raw, raw) {
			t.Fatal("ACE or ACL revision changed")
		}
		clear(wire)
		if !bytes.Equal(decoded.DACL.ACEs[1].Raw, raw) {
			t.Fatal("raw ACE aliases receive buffer")
		}
	}
}

func TestSecurityDescriptorProtectionAndSelection(t *testing.T) {
	sd := &SecurityDescriptor{Control: SE_DACL_PRESENT | SE_SACL_PRESENT | SE_SACL_PROTECTED,
		Owner: testSID(), Group: testSID(), SACL: &ACL{Revision: 2}}
	wire := encodeSecurityDescriptorForTest(t, sd, DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION)
	if binary.LittleEndian.Uint16(wire[2:4]) != SE_SELF_RELATIVE|SE_DACL_PRESENT|SE_DACL_PROTECTED {
		t.Fatal("protection selection was not reflected in control")
	}
	if !bytes.Equal(wire[4:20], make([]byte, 16)) {
		t.Fatal("unselected components were transmitted")
	}
	sd.Control |= SE_DACL_PROTECTED
	wire = encodeSecurityDescriptorForTest(t, sd, DACL_SECURITY_INFORMATION|UNPROTECTED_DACL_SECURITY_INFORMATION)
	if binary.LittleEndian.Uint16(wire[2:4])&SE_DACL_PROTECTED != 0 {
		t.Fatal("unprotect was ignored")
	}
}

func TestSecurityDescriptorMalformedComponentBounds(t *testing.T) {
	valid := encodeSecurityDescriptorForTest(t, &SecurityDescriptor{Control: SE_DACL_PRESENT,
		DACL: &ACL{Revision: 2, ACEs: []ACE{{Type: ACCESS_ALLOWED, SID: testSID()}}}}, DACL_SECURITY_INFORMATION)
	for _, mutate := range []func([]byte){
		func(w []byte) { binary.LittleEndian.PutUint32(w[16:20], 0xfffffffc) },
		func(w []byte) { binary.LittleEndian.PutUint32(w[16:20], 21) },
		func(w []byte) { binary.LittleEndian.PutUint16(w[24:26], 0xffff) },
		func(w []byte) { binary.LittleEndian.PutUint16(w[30:32], 0xffff) },
		func(w []byte) { w[37] = 16 },
		func(w []byte) { w[36] = 2 },
	} {
		wire := append([]byte(nil), valid...)
		mutate(wire)
		if _, err := decodeSecurityDescriptor(wire, DACL_SECURITY_INFORMATION); err == nil {
			t.Fatalf("malformed descriptor accepted: %x", wire)
		}
	}
}

func TestSecurityDescriptorValidatesBeforeSending(t *testing.T) {
	fs, _ := newTestShare(t)
	// Both ACLs individually fit their uint16 AclSize; the combined descriptor
	// exceeds this connection's negotiated transaction size.
	fs.conn.maxTransactSize = 65536
	raw := make([]byte, 40000)
	raw[0] = 0x42
	binary.LittleEndian.PutUint16(raw[2:4], uint16(len(raw)))
	acl := &ACL{Revision: 2, ACEs: []ACE{{Type: 0x42, Raw: raw}}}
	sd := &SecurityDescriptor{Control: SE_DACL_PRESENT | SE_SACL_PRESENT, DACL: acl, SACL: acl}
	require.ErrorIs(t, fs.SetSecurityDescriptor("test.txt", DACL_SECURITY_INFORMATION|SACL_SECURITY_INFORMATION, sd), os.ErrInvalid)
	require.ErrorIs(t, fs.SetSecurityDescriptor("test.txt", OWNER_SECURITY_INFORMATION, nil), os.ErrInvalid)
	_, err := fs.GetSecurityDescriptor("test.txt", PROTECTED_DACL_SECURITY_INFORMATION)
	require.ErrorIs(t, err, os.ErrInvalid)
	_, err = fs.GetSecurityDescriptor("test.txt", 0)
	require.ErrorIs(t, err, os.ErrInvalid)
}

func TestShareSecurityDescriptor(t *testing.T) {
	fs, serverConn := newTestShare(t)
	dt := direct(serverConn)
	targetFileId := &smb2.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}
	selection := OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
	descriptor := &SecurityDescriptor{
		Control: SE_DACL_PRESENT,
		Owner:   testSID(),
		DACL:    &ACL{Revision: 2},
	}
	wire := encodeSecurityDescriptorForTest(t, descriptor, selection)

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
			p := smb2.PacketCodec(req)
			switch p.Command() {
			case smb2.SMB2_CREATE:
				create := smb2.CreateRequestDecoder(p.Body())
				require.EqualValues(t, smb2.READ_CONTROL, create.DesiredAccess())
				sendTestResponse(dt, req, &smb2.CreateResponse{
					FileId:         targetFileId,
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			case smb2.SMB2_QUERY_INFO:
				query := smb2.QueryInfoRequestDecoder(p.Body())
				require.EqualValues(t, singleCreditMaxPayloadSize, query.OutputBufferLength())
				sendTestResponse(dt, req, &smb2.QueryInfoResponse{Output: rawEncoder(wire)}, uint32(erref.STATUS_SUCCESS))
			case smb2.SMB2_CLOSE:
				sendTestResponse(dt, req, &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
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
			p := smb2.PacketCodec(req)
			switch p.Command() {
			case smb2.SMB2_CREATE:
				create := smb2.CreateRequestDecoder(p.Body())
				require.EqualValues(t, smb2.WRITE_DAC|smb2.WRITE_OWNER, create.DesiredAccess())
				sendTestResponse(dt, req, &smb2.CreateResponse{
					FileId:         targetFileId,
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			case smb2.SMB2_SET_INFO:
				sendTestResponse(dt, req, &smb2.SetInfoResponse{}, uint32(erref.STATUS_SUCCESS))
			case smb2.SMB2_CLOSE:
				sendTestResponse(dt, req, &smb2.CloseResponse{
					CreationTime:   &smb2.Filetime{},
					LastAccessTime: &smb2.Filetime{},
					LastWriteTime:  &smb2.Filetime{},
					ChangeTime:     &smb2.Filetime{},
				}, uint32(erref.STATUS_SUCCESS))
			}
			if next := p.NextCommand(); next != 0 {
				req = req[next:]
			} else {
				break
			}
		}
	}()

	got, err := fs.GetSecurityDescriptor("test.txt", selection)
	require.NoError(t, err)
	require.NotNil(t, got)

	err = fs.SetSecurityDescriptor("test.txt", selection, got)
	require.NoError(t, err)
	<-done
}

func TestGetSecurityDescriptor_BufferTooSmallRetry(t *testing.T) {
	t.Run("SuccessAfterRetry", func(t *testing.T) {
		fs, serverConn := newTestShare(t)
		dt := direct(serverConn)
		targetFileId := &smb2.FileId{Persistent: [8]byte{0x11}, Volatile: [8]byte{0x22}}
		selection := OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
		descriptor := &SecurityDescriptor{
			Control: SE_DACL_PRESENT,
			Owner:   testSID(),
			DACL:    &ACL{Revision: 2},
		}
		wire := encodeSecurityDescriptorForTest(t, descriptor, selection)

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
				p := smb2.PacketCodec(req)
				switch p.Command() {
				case smb2.SMB2_CREATE:
					sendTestResponse(dt, req, &smb2.CreateResponse{
						FileId:         targetFileId,
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				case smb2.SMB2_QUERY_INFO:
					query := smb2.QueryInfoRequestDecoder(p.Body())
					require.EqualValues(t, singleCreditMaxPayloadSize, query.OutputBufferLength())
					errData := make([]byte, 4)
					le.PutUint32(errData, uint32(requiredLen))
					errRes := &smb2.ErrorResponse{
						CommandCode: smb2.SMB2_QUERY_INFO,
						ErrorData:   rawEncoder(errData),
					}
					sendTestResponse(dt, req, errRes, uint32(erref.STATUS_BUFFER_TOO_SMALL))
				case smb2.SMB2_CLOSE:
					sendTestResponse(dt, req, &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
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
				p := smb2.PacketCodec(req)
				switch p.Command() {
				case smb2.SMB2_CREATE:
					sendTestResponse(dt, req, &smb2.CreateResponse{
						FileId:         targetFileId,
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				case smb2.SMB2_QUERY_INFO:
					query := smb2.QueryInfoRequestDecoder(p.Body())
					require.EqualValues(t, requiredLen, query.OutputBufferLength())
					sendTestResponse(dt, req, &smb2.QueryInfoResponse{Output: rawEncoder(wire)}, uint32(erref.STATUS_SUCCESS))
				case smb2.SMB2_CLOSE:
					sendTestResponse(dt, req, &smb2.CloseResponse{
						CreationTime:   &smb2.Filetime{},
						LastAccessTime: &smb2.Filetime{},
						LastWriteTime:  &smb2.Filetime{},
						ChangeTime:     &smb2.Filetime{},
					}, uint32(erref.STATUS_SUCCESS))
				}
				if next := p.NextCommand(); next != 0 {
					req = req[next:]
				} else {
					break
				}
			}
		}()

		got, err := fs.GetSecurityDescriptor("test.txt", selection)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Equal(t, SE_DACL_PRESENT|SE_SELF_RELATIVE, got.Control)
		require.Equal(t, descriptor.Owner, got.Owner)
		<-done
	})
}

