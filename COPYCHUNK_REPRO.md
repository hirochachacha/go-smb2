# macOS SMB COPYCHUNK writes at SourceOffset instead of TargetOffset

Draft for an Apple bug report. Not submitted.

## Problem

The macOS SMB server returns success for a server-side copy but writes the
bytes at the wrong destination offset, silently overwriting unrelated bytes.

Minimal case: source `AAAABBBBCCCC`, destination `0123456789abcdef`.
Copy four bytes from source offset **4** to destination offset **0** using
`FSCTL_SRV_COPYCHUNK` (`0x001440f2`).

- Expected destination: `BBBB456789abcdef`.
- Observed with Impacket 0.13.1: `0123BBBB89abcdef`.
- Response: `STATUS_SUCCESS`, `ChunksWritten=1`, `ChunkBytesWritten=0`,
  `TotalBytesWritten=4`.

The source range is correct (`BBBB`), but the destination position is 4, not 0.
MS-SMB2 sections 2.2.31.1 and 2.2.31.1.1 specify separate source and target
byte offsets. Both reserved fields in this request are zero.

## Environment

- Server: macOS 26.6.2, build 25G83 (`sw_vers` supplied by the user).
- Transport: TCP, NTLM authentication; separate files in the same share.
- No append mode, seek calls, or concurrent writers.
- Hardware and backing filesystem: fill in before submission.
- Original observation: go-smb2 revision `4c2beab`, Go 1.27.1, linux/arm64.
- Independent reproduction below: Impacket 0.13.1, SMB 2.1 (0x0210),
  verified against the same server.

## Minimal reproduction with Impacket

This uses [Fortra Impacket](https://github.com/fortra/impacket), with no Go
code or dependency on go-smb2. Its [SMBConnection API](https://github.com/fortra/impacket/blob/master/impacket/smbconnection.py)
creates and reads the files; its [SMB3 ioctl API](https://github.com/fortra/impacket/blob/master/impacket/smb3.py)
sends the resume-key and copy requests.

Install in a temporary Python environment, save the code below as `repro.py`,
and run it against a writable share. The password is prompted, not passed on
the command line. The script creates a unique directory and removes its own
files afterward, including when the content check fails.

```sh
python3 -m venv /tmp/copychunk-venv
/tmp/copychunk-venv/bin/pip install impacket==0.13.1
/tmp/copychunk-venv/bin/python repro.py SERVER SHARE USER [DOMAIN] [PORT]
```

```python
import getpass
import struct
import sys
import uuid
from contextlib import ExitStack
from importlib.metadata import version

from impacket.smbconnection import SMBConnection
from impacket.smb3structs import (
    FILE_CREATE, GENERIC_READ, GENERIC_WRITE, SMB2_DIALECT_21,
    SMB2_0_IOCTL_IS_FSCTL,
)

host, share, user = sys.argv[1:4]
domain = sys.argv[4] if len(sys.argv) > 4 else ""
port = int(sys.argv[5]) if len(sys.argv) > 5 else 445
password = getpass.getpass()

with ExitStack() as cleanup:
    client = SMBConnection(host, host, sess_port=port,
                           preferredDialect=SMB2_DIALECT_21)
    cleanup.callback(client.close)
    client.login(user, password, domain)
    tree = client.connectTree(share)
    print("Impacket", version("impacket"), "dialect", hex(client.getDialect()))
    directory = "copychunk-" + uuid.uuid4().hex
    client.createDirectory(share, directory)
    cleanup.callback(client.deleteDirectory, share, directory)

    handles = []
    for name, contents in [("source", b"AAAABBBBCCCC"),
                           ("destination", b"0123456789abcdef")]:
        path = directory + "\\" + name
        handle = client.createFile(
            tree, path, desiredAccess=GENERIC_READ | GENERIC_WRITE,
            creationDisposition=FILE_CREATE,
        )
        cleanup.callback(client.deleteFile, share, path)
        cleanup.callback(client.closeFile, tree, handle)
        assert client.writeFile(tree, handle, contents) == len(contents)
        handles.append(handle)

    smb = client.getSMBServer()
    resume = smb.ioctl(tree, handles[0], ctlCode=0x00140078,
                       flags=SMB2_0_IOCTL_IS_FSCTL, inputBlob=b"",
                       maxInputResponse=0, maxOutputResponse=32)
    assert len(resume) >= 24
    # SourceKey, ChunkCount=1, Reserved=0; Source=4, Target=0, Length=4.
    request = resume[:24] + struct.pack("<IIQQII", 1, 0, 4, 0, 4, 0)
    response = smb.ioctl(tree, handles[1], ctlCode=0x001440f2,
                         flags=SMB2_0_IOCTL_IS_FSCTL, inputBlob=request,
                         maxInputResponse=0, maxOutputResponse=24)
    print("STATUS_SUCCESS; counts:", struct.unpack("<III", response))
    actual = client.readFile(tree, handles[1], offset=0, bytesToRead=16)
    expected = b"BBBB456789abcdef"
    print("expected:", expected)
    print("actual:  ", actual)
    assert actual == expected, "COPYCHUNK wrote at the wrong destination offset"
```

The script fixes the dialect to SMB 2.1 to make negotiation reproducible.
Both handles have ordinary read/write access. A content assertion failure
with `actual: b'0123BBBB89abcdef'` reproduces the defect. Authentication,
connection, or unsupported-control errors do not establish reproduction.

## Verified result

Running the code above against the configured macOS server produced:

```text
Impacket 0.13.1 dialect 0x210
STATUS_SUCCESS; counts: (1, 0, 4)
expected: b'BBBB456789abcdef'
actual:   b'0123BBBB89abcdef'
AssertionError: COPYCHUNK wrote at the wrong destination offset
```

The process exited with status 1 because of the content assertion. Cleanup
completed without errors. This independently reproduces the go-smb2 finding.

## Supporting observations

The original go-smb2 investigation also tested other offsets and multiple
chunks: macOS consistently used SourceOffset as the destination offset.
Equal offsets passed. Windows and six Samba configurations honored both
offsets. These broader results were obtained with go-smb2, not this script.

The library now uses server-side copy only for equal file positions and
ordinary reads/writes otherwise. `TestServerSideCopyOffsets` verifies that
mitigation through the File API; it does not deliberately trigger the server
bug. The server defect reproducer is kept only in this document.
