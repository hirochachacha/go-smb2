package msrpc

import (
	"fmt"
	"io"
)

// InvalidResponseError identifies RPC decoding failures, separately from
// errors returned by the underlying pipe reader.
type InvalidResponseError struct{ Message string }

func (e *InvalidResponseError) Error() string {
	if e == nil {
		return "empty RPC response error"
	}
	return e.Message
}

// ValidateBindAck checks the response to the requested bind, including the
// accepted transfer syntax. The transport remains owned by its caller.
func ValidateBindAck(packet []byte, callID uint32) error {
	ack := BindAckDecoder(packet)
	if ack.IsInvalid() || ack.CallId() != callID {
		return &InvalidResponseError{"broken bind ack response format"}
	}
	if !ack.AcceptsNDR() {
		return &InvalidResponseError{"bind ack did not accept NDR v2"}
	}
	return nil
}

// ReadShareNames assembles RPC response fragments and decodes the resulting
// NetrShareEnum stub. read must fill at least minimum bytes of buffer or return
// an error; it may return additional bytes up to len(buffer). A negative limit
// disables the aggregate stub-size limit. Pipe errors are returned unchanged.
func ReadShareNames(initial []byte, callID uint32, limit int, read func(buffer []byte, minimum int) (int, error)) ([]string, error) {
	scratch := make([]byte, DefaultMaxFragmentSize)
	remaining := initial
	var output []byte
	first := true
	for {
		packet := remaining
		fill := func(minimum int) error {
			n, err := read(scratch, minimum)
			if err != nil {
				return err
			}
			if n < minimum || n > len(scratch) {
				return io.ErrUnexpectedEOF
			}
			packet = append(packet, scratch[:n]...)
			return nil
		}
		if len(packet) < HeaderSize {
			if err := fill(HeaderSize - len(packet)); err != nil {
				return nil, err
			}
		}
		header := ResponseHeaderDecoder(packet)
		if header.IsInvalid() || header.CallId() != callID {
			return nil, &InvalidResponseError{"broken net share enum response format"}
		}
		length := int(header.FragLength())
		if len(packet) < length {
			if err := fill(length - len(packet)); err != nil {
				return nil, err
			}
		}
		fragment := ResponseFragmentDecoder(packet[:length])
		if fragment.IsInvalid() {
			return nil, &InvalidResponseError{"broken net share enum response format"}
		}
		remaining = packet[length:]
		chunk := fragment.Stub()
		if !first && len(chunk) == 0 {
			return nil, &InvalidResponseError{"empty net share enum response fragment"}
		}
		if limit >= 0 && len(chunk) > limit-len(output) {
			return nil, &InvalidResponseError{"net share enum response exceeds maximum size"}
		}
		output = append(output, chunk...)
		if fragment.Header().PacketFlags()&RPC_PACKET_FLAG_LAST != 0 {
			if len(remaining) != 0 {
				return nil, &InvalidResponseError{"broken net share enum response format"}
			}
			break
		}
		first = false
	}
	names, err := NetShareEnumAllResponseDecoder(output).Sharenames()
	if err != nil {
		return nil, &InvalidResponseError{fmt.Sprintf("broken net share enum response format: %v", err)}
	}
	return names, nil
}
