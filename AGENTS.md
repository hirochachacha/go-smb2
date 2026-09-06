# Agent Guidelines for go-smb2

This document provides instructions and context for AI coding agents working on the `go-smb2` codebase.

## Project Overview

`go-smb2` is an SMB2/SMB3 client library implementation for Go (`github.com/hirochachacha/go-smb2`). It implements the SMB2 and SMB3 wire protocols along with NTLM/SPNEGO authentication and MSRPC helpers (such as share enumeration).

## Codebase Architecture

```
.
├── client.go, conn.go, session.go, tree_conn.go  # Core SMB client, connection, session, and tree connection management
├── client_fs.go, filepath.go, path.go            # File system interfaces (io/fs support, path resolution)
├── credit.go                                     # Credit balance tracking and grant management
├── initiator.go, spnego.go                       # Authentication initiator interface & SPNEGO handshake
├── internal/
│   ├── smb2/                                     # SMB2 packet structures, encoders, and decoders
│   ├── msrpc/                                    # MSRPC protocol framing and NetShareEnumAll decoder
│   ├── ntlm/                                     # NTLM authentication implementation
│   ├── spnego/                                   # SPNEGO GSS-API token exchange wrapper
│   ├── crypto/                                   # Cryptographic primitives (CMAC, CCM) for signing/encryption
│   ├── erref/                                    # NTSTATUS error codes
│   └── utf16le/                                  # UTF-16LE conversion helpers
```

## Build & Test Instructions

- Run all unit tests:
  ```bash
  go test ./...
  ```
- Run tests with race detection:
  ```bash
  go test -race ./...
  ```
- Run tests for a specific package:
  ```bash
  go test -v ./internal/smb2
  ```
- Integration testing:
  - Integration tests in `client_test.go` require a running SMB server configured via `client_conf.json`.
  - CI environment configuration example can be found in `.github/workflows/go.yml`.

## Coding & Design Guidelines

### Protocol Safety & Error Handling
- Strictly adhere to Microsoft specifications (MS-SMB2, MS-FSCC, MS-SRVS). Refer to the `ms-specs` skill (`.agents/skills/ms-specs/SKILL.md`) for specification lookup and search instructions.
- Always validate slice bounds, fragment lengths, and payload boundaries when parsing wire protocol packets to prevent integer overflow and panics.
- Keep external dependencies minimal; prefer the Go standard library.
