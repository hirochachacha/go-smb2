# Coding & Design Guidelines

## Protocol Safety & Error Handling
- Strictly adhere to Microsoft specifications (such as MS-SMB2, MS-FSCC, MS-SRVS, ...). Refer to the `ms-specs` skill (`.agents/skills/ms-specs/SKILL.md`) for specification lookup and search instructions.
- Always validate slice bounds, fragment lengths, and payload boundaries when parsing wire protocol packets to prevent integer overflow and panics.
- Keep external dependencies minimal; prefer the Go standard library.

## Connection & Request Lifecycle
- Never close the shared connection (`conn.close`) in response to an individual request's context cancellation or timeout. Canceling a request must only send `SMB2 CANCEL` and affect that specific request; concurrent requests and sessions sharing the connection must not be disrupted.
- For zero-copy / direct reads where the transport writes directly into the caller's buffer, wait for in-flight transport reception to complete on cancellation so the caller buffer is safe from late writes without aborting the shared connection.
