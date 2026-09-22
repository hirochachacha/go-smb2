# Samba fails to traverse an SMB-created symlink in an intermediate path component

Draft for a Samba bug report.

## Problem and environment

A relative symlink created over SMB can be read with `readlink`, but opening
a file beneath that link fails with `NT_STATUS_OBJECT_PATH_NOT_FOUND`.
Direct access to the target file succeeds.

Tested with Samba server and `smbclient` 4.24.6 on Linux
(package `2:4.24.6+linuxschools-1~noble1`). The share has
`follow symlinks = yes` and `wide links = no`; the target is inside the share.

## Minimal reproduction with smbclient

Create a local file in a temporary working directory and connect to a writable
share. Use a fresh `repro` directory for this test:

```sh
printf 'hello\n' > child.txt
smbclient //server/share -U username -m SMB3 --option='client min protocol=SMB2'
```

Run these commands in `smbclient` without enabling POSIX mode:

```text
mkdir repro
mkdir repro\real-dir
put child.txt repro\real-dir\child
symlink real-dir repro\link
readlink repro\link
get repro\real-dir\child direct.txt
get repro\link\child indirect.txt
```

## Observed and expected behavior

Symlink creation succeeds, `readlink` returns `real-dir`, and the direct
`get` succeeds. The final command fails:

```text
NT_STATUS_OBJECT_PATH_NOT_FOUND opening remote file \repro\link\child
```

Expected: access through the symlink succeeds. If client-side resolution is
required, the server should return `STATUS_STOPPED_ON_SYMLINK` with the
symlink information.

## Supporting observations

`smbclient` creates this link using CREATE and FSCTL_SET_REPARSE_POINT.
Samba stores the reparse data on a regular file. The suspected cause is that
intermediate-component traversal does not recognize this stored reparse
point, although final-component handling does. Relevant code is in
`source3/modules/util_reparse.c`, `source3/smbd/files.c`, and
`source3/smbd/smb2_create.c`.

As a control, a native symlink created with `ln -s real-dir native-link`
on the server was successfully traversed over SMB in a separate test.

## Cleanup

Remove the test files and directories in `smbclient`:

```text
del repro\link
del repro\real-dir\child
rmdir repro\real-dir
rmdir repro
```

Remove the local `child.txt`, `direct.txt`, and any `indirect.txt` created
by the reproduction after inspecting the results.
