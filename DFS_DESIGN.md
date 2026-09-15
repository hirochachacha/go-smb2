# Separating the SMB Session API from the DFS Layer

Status: Design direction agreed. The API examples below are proposals and are not yet implemented.

See [DFS_IMPLEMENTATION_PLAN.md](DFS_IMPLEMENTATION_PLAN.md) for implementation order,
public types, completion criteria, and agent task templates.

## Goals

Separate explicit ownership of connections and authenticated sessions from a convenient
API that provides transparent DFS access. Preserve the current configuration options
and the Credentials / TransportDialer factory interfaces.

The dependency direction must be `dfs → smb2`. smb2 must not depend on dfs.
Do not retain compatibility flags, aliases, or parallel behavior paths for the old API.

## smb2: Explicit Session Management

```go
dialer := &smb2.Dialer{
    Credentials:     credentials,
    TransportDialer: transportDialer,
}

session, err := dialer.Dial(ctx, "server")
if err != nil {
    return err
}
defer session.Close()

share, err := session.Mount(ctx, "share")
if err != nil {
    return err
}
defer share.Unmount(ctx)
```

- Move the current ClientConfig options directly into public fields on Dialer.
  Construct it with a struct literal; do not provide DialerConfig or NewDialer.
- Dialer holds configuration and creates connections. It does not cache or own sessions.
- Dial returns configuration errors rather than panicking.
- Concurrent Dial calls are supported. Callers must not modify the Dialer or referenced
  configuration, including slices, while it is in use (including by dfs.Client).
- Each Dial creates an independent Session and transfers ownership to the caller.
- Session owns one authenticated SMB session and its connection.
- Session.Close terminates the session and connection.
- Session.Mount accepts a share name on that server and returns a Share.
- Share represents a single TreeConnect. Its path operations accept paths relative to the share.
- Session.ListShareNames(ctx) enumerates shares on that server.
- Replace the current smb2.Client and Client.Mount with this API.
- Preserve the lower-level Share operations and its WithContext / io/fs support.

### DFS Wire Handling

The logic for constructing correct DFS requests remains in smb2.

- Store the share's DFS attribute from SMB2_SHARE_CAP_DFS in the TREE_CONNECT response's Capabilities.
- Set SMB2_FLAGS_DFS_OPERATIONS and a DFS-formatted path on CREATE requests to DFS shares.
- Do not base this decision on SMB2_SHAREFLAG_DFS / SMB2_SHAREFLAG_DFS_ROOT in ShareFlags.
- Return STATUS_PATH_NOT_COVERED to the upper layer as a public error carrying the actual
  UNC of the CREATE that stopped. Preserve path changes made while following symlinks within
  the same share. Distinguish this path from the original user-facing UNC, and do not
  automatically connect to referral targets.
- Do not unconditionally set DFS flags for ordinary shares.

### Retrieving Referrals

The public method is `Session.GetDFSReferrals(ctx, path)`.

Accept a full UNC for ROOT/LINK referrals, an empty string for DOMAIN referrals, and a
path containing only the domain name (`\domain` / `\\domain`) for DC referrals.
Supporting these low-level request forms does not imply automatic domain classification
or DC discovery.

- Perform one referral retrieval against the connected server.
  Handle necessary wire-level details internally, such as retrying with a larger response buffer.
- Return the referral type, matched path portion, TTL, and ordered target list.
- Also provide each target's access path with the unresolved suffix applied.
- Preserve information needed by the upper layer, including referral types and target set boundaries.
- Parse responses and validate path boundaries in smb2.
- Do not recursively follow referrals or connect to another server.
- Lazily create and reuse a dedicated IPC$ TreeConnect owned by Session for these queries.
  Do not borrow a caller-owned Share or create a lifetime race with Share.Unmount.
  Close the dedicated tree in Session.Close. Canceling an individual query must not close Session.
- Represent DOMAIN/DC name-list responses directly. Do not synthesize a storage prefix
  or a target path with an appended suffix for them.
- Finalize concrete return type and field names during implementation according to this contract.

## dfs: Transparent Access

```go
client := dfs.New(dialer)
defer client.Close()

file, err := client.Open(ctx, `\\server\share\folder\file.txt`)
if err != nil {
    return err
}
defer file.Close(ctx)
```

- dfs.Client uses Dialer and owns the Sessions and Shares it creates.
- Support both ordinary and DFS shares.
- Handle UNC resolution, referral retrieval, path rewriting, and referral target selection and traversal.
- Cache referrals according to their TTL and reuse connections and TreeConnects.
- Retain sessions until Client.Close, including those used only for intermediate referral queries.
  Replacing sessions with broken connections is separate from this retention policy.
- Do not initially add idle timeouts, connection limits, or early release of intermediate sessions.
- Express the choice of DFS support through the package. No AutoResolveDFS toggle is needed.
- Apply cycle detection and traversal limits to both referrals and symbolic links.

### Paths and File

- Path operations require absolute UNC paths containing server and share names.
- Rename accepts both paths as UNCs.
- Symlink's target is an exception: it is the content stored in the link, so relative paths are allowed.
- Open operations return the existing `*smb2.File`.
- Bind File to the tree where it was actually opened. Read / Write and similar operations use that tree.
- File.Name and user-facing path errors use the original UNC, rather than the resolved target.
- Keep the display path separate from the path used for actual operations.
- Do not initially add WithContext or an io/fs adapter to dfs.Client.
  Pass context and UNC to each operation. The existing File.WithContext remains usable.

### Public Path Operations

Provide Open, OpenFile, Create, Stat, Lstat, ReadDir, ReadFile, WriteFile, Mkdir,
Remove, Rename, Symlink, Readlink, Truncate, Chmod, Chtimes, and Statfs.

Define each operation explicitly and delegate to its resolved target; do not embed Share.

Do not initially expose Mount / Unmount, RemoveAll, or MkdirAll on dfs.Client.
Preserve RemoveAll / MkdirAll on the lower-level smb2.Share.

### Removal and Rename

- Rename across resolved shares must return an error that callers can identify.
  Do not emulate it with copy and delete.
- Reject Remove of a DFS link itself or a share root.
- Allow removal of an explicitly specified ordinary file or empty directory beneath a DFS link.
- Never delete a referral target's share or directory when the requested object is the DFS link itself.
  Preserve and check whether the original target is the link itself, even when using cached referrals.
- Do not provide namespace administration operations such as creating, deleting, or moving DFS links.
  These are MS-DFSNM administration operations, distinct from ordinary Symlink operations.

### Ordinary Symbolic Links

- Expose Symlink / Readlink in the initial implementation.
- Support relative links and absolute UNC links, without a same-server restriction.
- Symlink creates a link at the specified location. Do not connect to its target to create it.
- Readlink returns the stored target without connecting to it.
- For Open and similar operations, interpret STATUS_STOPPED_ON_SYMLINK responses and follow
  UNC links to other servers. If the target is DFS, continue with DFS resolution.
- Resolve relative links from the directory containing the link and carry forward the unparsed suffix.
- Do not rewrite the contents of relative links to match DFS referral targets.
- Lstat / Readlink / Remove operate on the final ordinary symbolic link itself.
- Evaluation of links to local drives is unsupported. Do not automatically access the client's local files.
- Automatic traversal in the lower-level smb2.Share is limited to the current TreeConnect.
  Do not internally obtain another share's TreeConnect, even on the same server.
- If a UNC link matches the current server and share names, convert it to a share-relative path
  and retry on the current tree. For a DFS share, rebuild the DFS path when constructing CREATE.
  Do not treat server aliases as the same endpoint solely because DNS or IP addresses match.
- Do not send a UNC targeting another share/server, or a relative link escaping the current tree,
  as a relative path on the same tree. Return a public error identifiable with errors.As to indicate
  that traversal requires the upper layer.
- This error must carry validated link information and a continuation path including the unparsed suffix.
  Preserve the distinction between the original operation path and the actual share/path where the
  link was encountered. The upper layer must neither append the suffix twice nor interpret a relative
  link against the unresolved namespace.
- dfs.Client receives this error and sends the continuation UNC back through ordinary path resolution.
  Obtain the necessary Session / Share and construct CREATE for that target share.
  Direct users of the lower-level Share can also explicitly connect and continue using the public error.
- Maintain exploration state for the entire operation so that limits remain effective when alternating
  between symbolic links and DFS referrals. Do not reset limits at layer boundaries.
- Retry traversal only after confirming that CREATE stopped at a link.
  Check results of subsequent operations in compound requests as well; do not repeat completed mutations.

### Domain-Based Paths

- Do not initially implement domain classification or DC discovery.
- Treat names in inputs and referral targets as connection endpoints, and return connection or referral failures.
- Do not distinguish domains from servers by the appearance of their names.
- Domain resolution is out of scope both at the initial entry point and during referral traversal.
- Future changes may extend dfs internals or configuration while retaining the same Open and other
  operation signatures. External DC discovery can be integrated if needed.
- Do not add speculative DC discovery interfaces or configuration in the initial implementation.
- GetDFSReferrals remains available as a low-level API exposing the retrieved referrals.

### Cancellation, Close, and Retry

- Canceling an individual operation affects only that operation. Do not close the shared connection.
- For callers waiting on shared connection establishment, cancellation of one caller must not disrupt others.
- For direct receives, prevent late writes into the caller's buffer after cancellation returns.
- dfs.Client.Close stops new operations and cancels connection/authentication in progress.
  Start closing existing Sessions to release blocked communication before waiting for in-progress
  operations and shutdown to finish. Do not defer Session shutdown until Mount and similar work finish.
- At the Session shutdown deadline, close the transport without being blocked by the send mutex,
  releasing synchronous I/O. Restrict this path to Session/Client shutdown and aborting an unpublished Dial.
- When Close returns, no connections owned by that Client may remain.
  Credentials / TransportDialer implementations must also cooperate with context cancellation.
- Close terminates connections even if Files remain open. Those Files become unusable.
- Switch referral candidates only for conditions deemed retryable, such as an unavailable endpoint.
- Do not automatically repeat permission failures or writes with unknown outcomes against another candidate.
- Do not transparently replace an open File with a File on another referral target.
- Implement and verify cache TTLs, candidate ordering and sets, and concrete retryable statuses
  against Microsoft specifications and the contracts above.

## Differences from the Current Implementation

The change already made is the simplification that retains current Client sessions until Close.
The public Dialer / Session API and separation into a dfs subpackage are not yet implemented.

The current Share.Symlink does not prohibit a UNC target on another server.
However, it has no dedicated branch converting an ordinary UNC into `\??\UNC\...` form.
Current symbolic link traversal also replaces the name and retries on the same Share;
it must not be treated as supporting correct reconnection to another server.
Verify UNC encoding during creation and connection switching during traversal separately
when implementing the new design.

## Implementation Verification

- Ownership of independent Dial results and Close races with connection/authentication.
- Sharing connections to the same server while isolating cancellation of individual operations.
- SHARE_CAP_DFS detection and CREATE flag/path construction.
- Referral boundaries, suffix handling, TTL, multiple candidates, interlinks, cycles, and limits.
- Rejecting Remove of DFS links themselves while allowing ordinary objects beneath them.
- Rejecting cross-share Rename.
- Relative and UNC symbolic links, traversal to other servers, and operations that do not follow the final link.
- Original UNC display in File.Name / errors, separate from the File's actual connection target.
- Preserving lower-level Share functionality while removing the old Client API.

## Specification References

- [MS-SMB2: Receiving a TREE_CONNECT Response (3.2.5.5)](.agents/skills/ms-specs/specs/MS-SMB2/3-protocol-details/3.2.5.5-receiving-an-smb2-tree-connect-response.md)
- [MS-SMB2: Generating a TREE_CONNECT Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/652e0c14-5014-4470-999d-b174d7b2da87)
- [MS-SMB2: Opening a File](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/448cb979-7321-4598-89df-e5c97135b566)
- [MS-SMB2: Obtaining DFS Referrals](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/81da0080-7f42-486e-932d-64f14f24ebcf)
- [MS-DFSC: Referral Responses](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/bd1a7a9d-dfee-4dc6-ba37-bfeb329a7bfa)
- [MS-DFSC: Resolving UNC Paths](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsc/1ff7d611-ba19-49fb-95f4-7c5358b86834)
- [MS-SMB2: Symbolic Link Response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/f15ae37d-a787-4bf2-9940-025a8c9c0022)
- [MS-SMB2: Evaluating Symbolic Links](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a8da655c-8b0b-415a-b726-16dc33fa5827)
- [MS-DFSNM: Removing a DFS Link](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dfsnm/89a016c8-3484-49e6-bb48-30cdfd5f8f58)
