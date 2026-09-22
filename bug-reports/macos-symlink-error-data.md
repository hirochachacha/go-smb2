# macOS SMB omits required data for STATUS_STOPPED_ON_SYMLINK

Draft for an Apple bug report. Not submitted.

## Problem and environment

On macOS 26.6.2 (25G83), opening a symbolic link through SMB returns
`STATUS_STOPPED_ON_SYMLINK` (`0x8000002d`) without the required Symbolic Link
Error Response. Independently reproduced with Impacket 0.13.1 over SMB 2.1,
TCP and NTLM, using a relative link and an existing target in the same share.

## Minimal reproduction

1. In a writable share, create `target.txt` and a relative symlink `link`
   pointing to `target.txt`. The Impacket probe created the link using
   `FSCTL_SET_REPARSE_POINT` with `IO_REPARSE_TAG_SYMLINK` and the relative flag.
2. Send an ordinary `SMB2 CREATE` for `link`: `DesiredAccess=GENERIC_READ`,
   `CreateDisposition=FILE_OPEN`, `CreateOptions=FILE_NON_DIRECTORY_FILE`.
   Do not set `FILE_OPEN_REPARSE_POINT` or automatically retry the error.
3. Inspect the error response. Impacket's `SMBConnection.openFile` raises
   `SessionError`; `getErrorPacket()['Data']` contains the error body.

Save as `repro.py` and run against a writable share. The password is prompted.
The script creates a unique directory and removes its files even when the
assertion fails. Cleanup opens the symlink itself, without following it.

```sh
python3 -m venv /tmp/symlink-venv
/tmp/symlink-venv/bin/pip install impacket==0.13.1
/tmp/symlink-venv/bin/python repro.py SERVER SHARE USER [DOMAIN] [PORT]
```

```python
import getpass
import struct
import sys
import uuid
from contextlib import ExitStack
from importlib.metadata import version

from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import (
    DELETE, FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
    GENERIC_READ, GENERIC_WRITE, SMB2_DIALECT_21,
    SMB2_0_IOCTL_IS_FSCTL, SMB2_FILE_DISPOSITION_INFO,
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
    smb = client.getSMBServer()
    print("Impacket", version("impacket"), "dialect", hex(client.getDialect()))
    directory = "symlink-error-" + uuid.uuid4().hex
    client.createDirectory(share, directory)
    cleanup.callback(client.deleteDirectory, share, directory)

    def remove_file(path):
        handle = client.openFile(
            tree, path, desiredAccess=DELETE,
            creationOption=FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE,
        )
        try:
            smb.setInfo(tree, handle, inputBlob=b"\x01",
                        fileInfoClass=SMB2_FILE_DISPOSITION_INFO)
        finally:
            client.closeFile(tree, handle)

    for name in ("target.txt", "link"):
        path = directory + "\\" + name
        handle = client.createFile(tree, path,
                                   desiredAccess=GENERIC_READ | GENERIC_WRITE,
                                   creationDisposition=FILE_CREATE)
        cleanup.callback(remove_file, path)
        try:
            if name == "target.txt":
                client.writeFile(tree, handle, b"target")
            else:
                target = "target.txt".encode("utf-16-le")
                # SubstituteName, PrintName, SYMLINK_FLAG_RELATIVE=1.
                body = struct.pack("<HHHHI", 0, len(target), len(target),
                                   len(target), 1) + target + target
                reparse = struct.pack("<IHH", 0xA000000C, len(body), 0) + body
                smb.ioctl(tree, handle, ctlCode=0x000900A4,
                          flags=SMB2_0_IOCTL_IS_FSCTL, inputBlob=reparse,
                          maxInputResponse=0, maxOutputResponse=0)
        finally:
            client.closeFile(tree, handle)

    try:
        handle = client.openFile(tree, directory + "\\link",
                                 desiredAccess=GENERIC_READ,
                                 creationOption=FILE_NON_DIRECTORY_FILE)
    except SessionError as error:
        if error.getErrorCode() != 0x8000002D:
            raise
        raw = error.getErrorPacket()["Data"]
        byte_count = struct.unpack_from("<I", raw, 4)[0]
        print("Status:", hex(error.getErrorCode()))
        print("Error body:", raw.hex(" "))
        print("ByteCount:", byte_count)
        assert byte_count > 0, "Missing Symbolic Link Error Response"
    else:
        client.closeFile(tree, handle)
        print("CREATE succeeded; missing-error-data defect not reproduced")
```

Verified with the code above: the assertion failed with ByteCount=0, and
cleanup completed without errors. Other connection or SMB errors do not
establish reproduction.

Observed response (SMB header excluded):

```text
Status:        0x8000002d (STATUS_STOPPED_ON_SYMLINK)
Error body:    09 00 00 00 00 00 00 00 00
StructureSize: 9
ByteCount:     0
```

The trailing zero byte supplies no symbolic-link payload.

## Expected behavior and impact

MS-SMB2 section 2.2.2.2 requires ErrorData to contain the Symbolic Link Error
Response defined in section 2.2.2.2.1 when this status is returned. That
structure provides the target name, relative/absolute flags, and unparsed
path length needed to continue path resolution.

Without it, clients cannot resolve the link from the CREATE response.
go-smb2 works around this by opening the link with `FILE_OPEN_REPARSE_POINT`
and querying `FSCTL_GET_REPARSE_POINT`, requiring extra requests. Returning
the required error data would remove the need for this workaround.
