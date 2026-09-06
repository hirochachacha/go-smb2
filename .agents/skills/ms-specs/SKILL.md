---
name: ms-specs
description: >-
  Lookup and search Microsoft Open Specifications used in go-smb2 (including [MS-SMB2], [MS-FSCC], [MS-DTYP] and [MS-SRVS]). Use whenever implementing or debugging SMB2/SMB3 wire formats, packet
  structures, file information classes, FSCTL codes, negotiate contexts, signing, credits,
  encryption, session setup, or verifying compliance with Microsoft specifications.
---

# Microsoft Open Specifications (`.agents/skills/ms-specs/specs/`)

Specifications are located under `.agents/skills/ms-specs/specs/` as section-numbered Markdown files, indexed by `qmd`.

## Setup (One-time or when specs are missing)

On a fresh clone or if the specifications/index have not been built yet, run:
```bash
qmd init
python3 .agents/skills/ms-specs/scripts/setup_specs.py
```
This extracts Markdown files from `.agents/skills/ms-specs/docx/` into `.agents/skills/ms-specs/specs/` and automatically registers the `ms-specs` QMD collection.

## Retrieval Workflow

Search using `qmd` and retrieve the matching section using `qmd get`.
Files are modularly chunked (~30–150 lines per subsection), so `qmd get "#<docid>"` returns the exact target section without cluttering context.

### 1. Search (Primary)

#### Keyword Search (BM25)
Best for constants, struct names, error codes, command names, and flags:
```bash
qmd search "SMB2_FLAGS_RELATED_OPERATIONS" -c ms-specs
```

#### Hybrid / Semantic Query
Best for conceptual questions, protocol behavior, or when exact keywords are unknown:
```bash
qmd query "how are compounded related requests handled" -c ms-specs
```
Or for vector similarity search only:
```bash
qmd vsearch "preauth integrity hash negotiation" -c ms-specs
```

### 2. Read Results (`qmd get`)

Use the `#docid` (or path) from search results to read the full section:
```bash
qmd get "#<docid>"
```
Optionally specify line ranges:
```bash
qmd get "#<docid>:from:count"
```

### 3. Direct File Access (Shortcut)

When following explicit cross-references or when the section path is already known:
Files follow `.agents/skills/ms-specs/specs/<SPEC>/<chapter>/<section>-<slug>.md`:
- `.agents/skills/ms-specs/specs/MS-SMB2/2-messages/2.2.3-smb2-negotiate-request.md`
- `.agents/skills/ms-specs/specs/MS-SMB2/3-protocol-details/3.2.4.1.4-sending-compounded-requests.md`
- `.agents/skills/ms-specs/specs/MS-FSCC/2-structures/2.4.7-filebasicinformation.md`
Check [`INDEX.md`](file:///Users/hiro/d/go-smb2/.agents/skills/ms-specs/specs/INDEX.md) for table of contents.
