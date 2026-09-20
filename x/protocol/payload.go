package protocol

import (
	"fmt"

	"github.com/hirochachacha/go-smb2/v2/security"
	"github.com/hirochachacha/go-smb2/v2/x/wire"
)

// payloadRequest retains only the selectors needed to interpret an output.
// It is copied at send time, so reusing a Request cannot change an old response.
type payloadRequest struct {
	command        wire.Command
	infoType       uint8
	infoClass      uint8
	additionalInfo uint32
	ctlCode        uint32
}

func describePayloadRequest(packet wire.Packet) payloadRequest {
	switch req := packet.(type) {
	case *wire.QueryInfoRequest:
		return payloadRequest{command: req.Command(), infoType: req.InfoType, infoClass: req.FileInfoClass, additionalInfo: req.AdditionalInformation}
	case *wire.QueryDirectoryRequest:
		return payloadRequest{command: req.Command(), infoClass: req.FileInfoClass}
	case *wire.IoctlRequest:
		return payloadRequest{command: req.Command(), ctlCode: req.CtlCode}
	}
	return payloadRequest{}
}

func decodePayload[D responseDecoder](output []byte, description string) (D, error) {
	decoded := D(output)
	if decoded.IsInvalid() {
		return nil, &InvalidResponseError{"broken " + description}
	}
	return decoded, nil
}

// QueryInfoResponse interprets QUERY_INFO output using the original request.
// Typed accessors validate on access and return read-only views valid until
// Response.Close. RawOutput does not validate the nested payload.
type QueryInfoResponse struct {
	decoded wire.QueryInfoResponseDecoder
	request payloadRequest
}

func (r *QueryInfoResponse) RawOutput() []byte {
	if r == nil || r.decoded == nil {
		return nil
	}
	return r.decoded.Output()
}

func (r *QueryInfoResponse) requireClass(infoType, infoClass uint8) error {
	if r == nil || r.decoded == nil || r.request.command != wire.SMB2_QUERY_INFO || r.request.infoType != infoType || r.request.infoClass != infoClass {
		return &InternalError{"payload accessor does not match QUERY_INFO request"}
	}
	return nil
}

// SecurityDescriptor validates and decodes the security fields requested by
// QUERY_INFO. The returned descriptor owns its data independently of Response.
func (r *QueryInfoResponse) SecurityDescriptor() (*security.Descriptor, error) {
	if err := r.requireClass(wire.SMB2_0_INFO_SECURITY, 0); err != nil {
		return nil, err
	}
	descriptor, err := security.DecodeDescriptor(r.RawOutput(), security.Information(r.request.additionalInfo))
	if err != nil {
		return nil, &InvalidResponseError{fmt.Sprintf("broken security descriptor: %v", err)}
	}
	return descriptor, nil
}

// QueryDirectoryResponse interprets directory entries using the requested class.
// Typed accessors validate the entire chain before returning any entries.
type QueryDirectoryResponse struct {
	decoded wire.QueryDirectoryResponseDecoder
	request payloadRequest
}

func (r *QueryDirectoryResponse) RawOutput() []byte {
	if r == nil || r.decoded == nil {
		return nil
	}
	return r.decoded.Output()
}

// FileIdBothDirectoryInformation returns validated, read-only directory entries.
// The entries remain valid until the owning Response is closed.
func (r *QueryDirectoryResponse) FileIdBothDirectoryInformation() ([]wire.FileIdBothDirectoryInformationDecoder, error) {
	if r == nil || r.decoded == nil || r.request.command != wire.SMB2_QUERY_DIRECTORY || r.request.infoClass != wire.FileIdBothDirectoryInformation {
		return nil, &InternalError{"payload accessor does not match QUERY_DIRECTORY request"}
	}
	output := r.RawOutput()
	entries := make([]wire.FileIdBothDirectoryInformationDecoder, 0, len(output)/128)
	for len(output) != 0 {
		entry, err := decodePayload[wire.FileIdBothDirectoryInformationDecoder](output, "query directory response format")
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
		next := entry.NextEntryOffset()
		if next == 0 {
			break
		}
		output = output[next:]
	}
	return entries, nil
}

// IoctlResponse interprets output using the requested control code. Typed
// accessors validate on access and return read-only views valid until Close.
type IoctlResponse struct {
	decoded wire.IoctlResponseDecoder
	request payloadRequest
}

func (r *IoctlResponse) RawOutput() []byte {
	if r == nil || r.decoded == nil {
		return nil
	}
	return r.decoded.Output()
}

func (r *IoctlResponse) OutputCount() uint32 {
	if r == nil || r.decoded == nil {
		return 0
	}
	return r.decoded.OutputCount()
}

func (r *IoctlResponse) CtlCode() uint32 {
	if r == nil || r.decoded == nil {
		return 0
	}
	return r.decoded.CtlCode()
}

func (r *IoctlResponse) requireCode(codes ...uint32) error {
	if r != nil && r.decoded != nil && r.request.command == wire.SMB2_IOCTL {
		for _, code := range codes {
			if r.request.ctlCode == code {
				return nil
			}
		}
	}
	return &InternalError{"payload accessor does not match IOCTL request"}
}

// FileStandardInformation returns a validated, read-only payload decoder valid until Close.
func (r *QueryInfoResponse) FileStandardInformation() (wire.FileStandardInformationDecoder, error) {
	if err := r.requireClass(wire.SMB2_0_INFO_FILE, wire.FileStandardInformation); err != nil {
		return nil, err
	}
	return decodePayload[wire.FileStandardInformationDecoder](r.RawOutput(), "query info response format")
}

// FileBasicInformation returns a validated, read-only payload decoder valid until Close.
func (r *QueryInfoResponse) FileBasicInformation() (wire.FileBasicInformationDecoder, error) {
	if err := r.requireClass(wire.SMB2_0_INFO_FILE, wire.FileBasicInformation); err != nil {
		return nil, err
	}
	return decodePayload[wire.FileBasicInformationDecoder](r.RawOutput(), "query info response format")
}

// FileNetworkOpenInformation returns a validated, read-only payload decoder valid until Close.
func (r *QueryInfoResponse) FileNetworkOpenInformation() (wire.FileNetworkOpenInformationDecoder, error) {
	if err := r.requireClass(wire.SMB2_0_INFO_FILE, wire.FileNetworkOpenInformation); err != nil {
		return nil, err
	}
	return decodePayload[wire.FileNetworkOpenInformationDecoder](r.RawOutput(), "query info response format")
}

// FileFsFullSizeInformation returns a validated, read-only payload decoder valid until Close.
func (r *QueryInfoResponse) FileFsFullSizeInformation() (wire.FileFsFullSizeInformationDecoder, error) {
	if err := r.requireClass(wire.SMB2_0_INFO_FILESYSTEM, wire.FileFsFullSizeInformation); err != nil {
		return nil, err
	}
	return decodePayload[wire.FileFsFullSizeInformationDecoder](r.RawOutput(), "query info response format")
}

// SymbolicLinkReparseData returns a validated, read-only payload decoder valid until Close.
func (r *IoctlResponse) SymbolicLinkReparseData() (wire.SymbolicLinkReparseDataBufferDecoder, error) {
	if err := r.requireCode(wire.FSCTL_GET_REPARSE_POINT); err != nil {
		return nil, err
	}
	return decodePayload[wire.SymbolicLinkReparseDataBufferDecoder](r.RawOutput(), "symbolic link response data buffer format")
}

// SrvRequestResumeKey returns a validated, read-only payload decoder valid until Close.
func (r *IoctlResponse) SrvRequestResumeKey() (wire.SrvRequestResumeKeyResponseDecoder, error) {
	if err := r.requireCode(wire.FSCTL_SRV_REQUEST_RESUME_KEY); err != nil {
		return nil, err
	}
	return decodePayload[wire.SrvRequestResumeKeyResponseDecoder](r.RawOutput(), "srv request resume key response format")
}

// SrvCopychunk returns a validated, read-only payload decoder valid until Close.
func (r *IoctlResponse) SrvCopychunk() (wire.SrvCopychunkResponseDecoder, error) {
	if err := r.requireCode(wire.FSCTL_SRV_COPYCHUNK, wire.FSCTL_SRV_COPYCHUNK_WRITE); err != nil {
		return nil, err
	}
	return decodePayload[wire.SrvCopychunkResponseDecoder](r.RawOutput(), "srv copy chunk response format")
}
