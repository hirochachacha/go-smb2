# Coding & Design Guidelines

## Protocol Safety & Error Handling
- Strictly adhere to Microsoft specifications (such as MS-SMB2, MS-FSCC, MS-SRVS, ...). Refer to the `ms-specs` skill (`.agents/skills/ms-specs/SKILL.md`) for specification lookup and search instructions.
- Always validate slice bounds, fragment lengths, and payload boundaries when parsing wire protocol packets to prevent integer overflow and panics.
- Keep external dependencies minimal; prefer the Go standard library.

## Security Policy: Input Validation
- Distinguish validation of API arguments used for encoding from validation of encoded input being decoded. Decoding requires stricter validation, regardless of who supplies the encoded input.
- Keep validation of caller-provided API arguments used for encoding minimal, focused on preventing simple, common usage mistakes. Do not require exhaustive protocol validation of these arguments: generating a nonconforming request that the server rejects is not, by itself, a security finding and is outside the scope of security audits.
- Public APIs must not panic for any input, except when passed a nil `context.Context`. Invalid `Dialer` configuration must return an error from `Dial`. Validation needed to uphold this guarantee is allowed and remains within the scope of security audits.
- Treat all input being decoded as untrusted, including server responses and caller-provided encoded input. Validate it strictly against the applicable Microsoft specifications, including structural constraints and semantic correctness; detect and reject malformed or semantically invalid input. Missing or incorrect decoding validation is within the scope of security audits.

## Connection & Request Lifecycle
- Never close the shared connection (`conn.close`) in response to an individual request's context cancellation or timeout. Canceling a request must only send `SMB2 CANCEL` and affect that specific request; concurrent requests and sessions sharing the connection must not be disrupted.
- For zero-copy / direct reads where the transport writes directly into the caller's buffer, wait for in-flight transport reception to complete on cancellation so the caller buffer is safe from late writes without aborting the shared connection.

## File API Semantics
- File API behavior must conform to the semantics of the standard library `os` package, except for context handling.
- Do not use `os.Is*` (e.g., `os.IsNotExist`, `os.IsPermission`); use `errors.Is` instead.
