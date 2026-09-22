# macOS SMB COPYCHUNK uses the source offset as the destination offset

Draft for an Apple bug report. Not submitted.

## Summary

The tested macOS SMB server reads the requested source range correctly, but
writes it at `SourceOffset` in the destination instead of at `TargetOffset`.
This is observed behavior; the server implementation has not been inspected.
The server returns success and accurate chunk/byte counts despite the incorrect
destination contents. This can silently overwrite unrelated destination bytes.

The earlier observation that copying always started at destination offset zero
was incomplete: those requests all had `SourceOffset=0`.

## Environment

- Server: macOS 26.6.2, build 25G83 (server-side `sw_vers` supplied by the user).
- Hardware and backing filesystem: not yet recorded.
- Client: go-smb2, runtime revision `4c2beab`; Go 1.27.1, linux/arm64.
- Transport to the macOS environment: TCP, NTLM authentication; dialect selected
  automatically. The negotiated dialect was not recorded.
- Source and destination are different files in the same share and session.
- Source opened for `GENERIC_READ`; destination for `GENERIC_READ|GENERIC_WRITE`.
- Neither `O_APPEND` nor Seek nor concurrent file modification is used.

## Protocol sequence

1. Create a source file containing ASCII `AAAABBBBCCCC` (12 bytes).
2. Create a destination file containing ASCII `0123456789abcdef` (16 bytes).
3. Open both files normally and obtain the source resume key with
   `FSCTL_SRV_REQUEST_RESUME_KEY`.
4. Send `FSCTL_SRV_COPYCHUNK` (`0x001440f2`) on the destination handle:
   `SMB2_0_IOCTL_IS_FSCTL`, `MaxOutputResponse=24`, and the resume key from step 3.
5. For the minimal nonzero-source reproduction, send one chunk with
   `SourceOffset=4`, `TargetOffset=0`, `Length=4`, `Reserved=0`.
6. Close the destination handle, reopen/read its contents, and compare them with
   the expected result. Each test case starts from a freshly initialized file.

The serialized 24-byte chunk in step 5 is:

```text
04 00 00 00 00 00 00 00  # SourceOffset = 4
00 00 00 00 00 00 00 00  # TargetOffset = 0
04 00 00 00              # Length = 4
00 00 00 00              # Reserved = 0
```

These are the encoded request input bytes, not a packet-capture trace. The
resume key, file IDs, addresses, share names, and credentials are omitted.

Expected destination: `BBBB456789abcdef`.
Actual destination: `0123BBBB89abcdef`.

This demonstrates that the source offset is honored (`BBBB` is read), while
those bytes are written at destination offset 4 rather than the requested 0.

## Results on the tested macOS server

All rows returned `STATUS_SUCCESS`. All response counts matched the requested
chunk count and total length, with `ChunkBytesWritten=0`.

| Source offset | Target offset | Length | Expected destination | Actual destination |
|---:|---:|---:|---|---|
| 0 | 0 | 4 | `AAAA456789abcdef` | `AAAA456789abcdef` |
| 4 | 4 | 4 | `0123BBBB89abcdef` | `0123BBBB89abcdef` |
| 4 | 0 | 4 | `BBBB456789abcdef` | `0123BBBB89abcdef` |
| 0 | 6 | 4 | `012345AAAAabcdef` | `AAAA456789abcdef` |
| 4 | 6 | 4 | `012345BBBBabcdef` | `0123BBBB89abcdef` |
| 3 | 5 | 3 | `01234ABB89abcdef` | `012ABB6789abcdef` |
| 8 | 16 | 4 | `0123456789abcdefCCCC` | `01234567CCCCcdef` |
| 0 | 0 | 12 | `AAAABBBBCCCCcdef` | `AAAABBBBCCCCcdef` |

A two-chunk request `(SourceOffset=4, TargetOffset=2, Length=4)` followed by
`(SourceOffset=8, TargetOffset=10, Length=4)` should produce
`01BBBB6789CCCCef`. It instead produces `0123BBBBCCCCcdef`. The response reports
`ChunksWritten=2`, `ChunkBytesWritten=0`, and `TotalBytesWritten=8`.

The source file remained unchanged. An additional probe of
`FSCTL_SRV_COPYCHUNK_WRITE` (`0x001480f2`) returned `STATUS_NOT_SUPPORTED` on this
macOS environment; it provides no evidence about that control's offset handling.

## Comparison runs

The same serialized request construction passed all nine cases for both
FSCTL_SRV_COPYCHUNK and FSCTL_SRV_COPYCHUNK_WRITE on one Windows and six Samba
transport/auth/share configurations (126 passing case executions). macOS had
three passing and six failing COPYCHUNK cases, and nine unsupported-control
skips for COPYCHUNK_WRITE. One additional configured connection was refused.
Specialized DFS/Kerberos matrices were not selected.

All test-directory cleanup completed without reported failures. The short unit
suite passed. The live test command returned failure because of the six macOS
content mismatches; those failures are the reproduction, not successful checks.
No runtime source was changed during this investigation.

## Specification and reproduction

MS-SMB2 section 2.2.31.1.1 defines SourceOffset and TargetOffset as independent
byte offsets from the starts of their respective files, and Length as the byte
count to copy. Section 3.3.5.15.6 defines server-side copy processing and the
success response. The observed writes do not respect TargetOffset.

The repository test is `TestServerSideCopyOffsets` in
[copy_offsets_integration_test.go](copy_offsets_integration_test.go). Configure
`client_conf.json` locally, then run:

```sh
go test -run '^TestServerSideCopyOffsets$' -count=1 -v -timeout=5m .
```

The test intentionally fails on incorrect contents. Unsupported copy controls
are skipped explicitly. It creates uniquely named directories and removes its
own files afterward. `go test -short ./...` skips these network tests.

Before submitting, fill in the server's hardware/filesystem and ideally the
negotiated SMB dialect. No claim is made about other macOS
versions. A packet capture and reproduction with an independent SMB client
have not yet been obtained.

## Library mitigation

The File API now selects server-side copy only when source and destination
positions match. Unequal positions use ordinary reads/writes. This applies to
append and non-append destinations alike and needs no server OS detection.
`TestFileCopyOffsets` covers that mitigation; `TestServerSideCopyOffsets` above
intentionally calls the raw protocol API to keep the server defect reproducible.
The mitigation does not change the server's behavior or the recorded results.
