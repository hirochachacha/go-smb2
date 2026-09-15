# Agent Execution Workflow for DFS Separation

## How to Start

Use this repository as the working directory and give the parent agent this instruction:

> Start implementing DFS separation according to DFS_EXECUTION_WORKFLOW.md.
> Delegate implementation to sub-agents and conduct independent reviews. Proceed autonomously
> through fixes and re-verification of findings. Do not commit, push, or create a PR.

Creating, consulting, or reviewing this document alone does not initiate implementation.
An agent receiving the execution request above must follow the instructions below.
If sub-agent capabilities are unavailable, report that limitation instead of claiming to have used them.
Continue investigation, implementation, and verification that can be done alone, but explicitly
report that independent review has not been performed.

## Execution Instructions

You are the parent agent responsible for integration. Complete implementation and verification
according to the documents below; do not stop after explaining a plan.

Required reading:

1. [AGENTS.md](AGENTS.md) and any additional applicable instructions.
2. [DFS_DESIGN.md](DFS_DESIGN.md): agreed functionality, ownership, and exclusions.
3. [DFS_IMPLEMENTATION_PLAN.md](DFS_IMPLEMENTATION_PLAN.md): public APIs, phases, and verification criteria.
4. This document: delegation, review, fixes, resumption, and completion procedures.

This document explicitly requests sub-agent work. Assign useful independent tasks within the
available capabilities and higher-priority instructions. Do not introduce external services
or plugins merely to run this workflow.

### Shared Rules

- Do not ask the user to approve already agreed requirements again.
- Resolve clear defects and gaps in the plan autonomously while preserving the agreed contracts.
- Ask only when a change to agreed functionality, ownership, or destructive-operation semantics is needed.
  While waiting for an answer, continue work that does not depend on that decision.
- Preserve existing working-tree changes. Do not stop merely because uncommitted changes exist.
- Do not commit, push, create a PR, publish, or send messages to external parties.
- Use the ms-specs skill for specification checks. Neither the plan nor existing code replaces the specification.
- The parent must inspect diffs and test output rather than taking an implementer's completion claim on trust.
- Do not repeat tests without purpose for areas unaffected by review changes.
- Give the user regular brief updates on progress, findings, and remaining issues.

## 0. Baseline and Progress Record

- Inspect the working directory, branch, HEAD, git status, and existing diff.
- Save a snapshot of the implementation baseline, including modified and untracked files, in a work area
  and record its location. Do not paste secrets into reports or prompts.
- Do not treat the entire diff against HEAD as the changes from this implementation task.
- Inspect existing API callers and the test structure.
- Create `DFS_IMPLEMENTATION_STATUS.md`, or read and update it if it already exists.

Record the following in the status file:

- The baseline and snapshot location.
- Each phase's state: not started / implementing / reviewing / fixing / complete.
- Each agent's assignment, edit scope, and handoff notes.
- Frozen API contracts and evidence supporting plan corrections.
- Test commands, results, and skipped checks with reasons.
- Finding IDs, severity, evidence, fixes, and re-review results.
- The next concrete action.

When resuming, reconcile the documents with actual code. Do not restart completed phases.
If code has changed since review or testing, recheck the parts relevant to those changes.

## 1. Pre-Implementation Review

Start an independent sub-agent with this read-only assignment:

> Read the design, implementation plan, and current code. Identify contradictions that block
> implementation. Focus on whether the public API can support the upper layer, ownership,
> Close, continuation information, and deletion boundaries. Read previous findings and the
> correction record as well. Support conclusions with specifications and code; give concrete
> triggering conditions and proposed fixes for any findings. Do not edit code or documents.
> If you run tests, state exactly what was tested.

In parallel, the parent records the baseline and inventories migration targets and tests.
Do not treat a previous review approval as approval of the current working tree. However,
do not repeatedly investigate unchanged, already verified points without a reason.

Triage findings. The parent fixes document issues that can be resolved within the agreements.
Proceed to step 2 once implementation-blocking findings are resolved.

## 2. Lower-Level API Implementation

Assign implementation plan phases 1–2 to an implementation sub-agent:

- Separate Dialer / Session / single-tree responsibilities.
- Use a directly configured Dialer struct, with configuration errors returned by Dial and safe
  concurrent Dial calls. Do not introduce DialerConfig or NewDialer; configuration must remain
  unchanged while the Dialer is in use, including by dfs.Client.
- Referral retrieval, DFSReferralError, and SymlinkError.
- Symlink creation and lower-level traversal, and original UNC display.
- Lower-level Close and synchronous I/O shutdown paths.

Do not allow owners to change public types or shared contracts such as internal/smbpath
unilaterally. In parallel, the parent checks external-package usability, migration targets,
and test conditions.

If replacing the lower-level API breaks compilation of existing tests or callers, do not leave
that until the final phase. Bring necessary migration work into this phase or group tightly
coupled changes into the same work unit. Do not pass by adding compatibility aliases or deleting tests.

After implementation, give a different reviewer the lower-level diff and focused test results.
Resolve findings, recheck fixes, and freeze the API between layers before proceeding.

## 3. Upper DFS Layer Implementation

Assign implementation plan phases 3–5 to implementation sub-agents in dependency order:

1. Session / Share sharing, creation, and Client.Close.
2. Referral caching, path resolution, and symlink continuation integration.
3. Agreed path operations and Remove / Rename protections.

Do not allow concurrent edits to shared lower-level files. If an out-of-scope edit is needed,
the owner must notify the parent, who assigns responsibility. Do not force work into multiple
assignments when one owner is simpler.

Once phase completion criteria are met, independently review the ownership and resolution
boundaries. Pause edits to reviewed files or provide an immutable diff snapshot.
While awaiting review, the parent works on non-overlapping tasks such as documentation and examples.

## 4. Overall Verification and Final Review

The parent checks the integrated result and completes implementation plan phase 6 and its
verification checklist. Run race tests across all packages and external API tests.
Record real-environment test results and any checks not performed.

For final review, start an independent reviewer with fresh context. Provide the following
evidence rather than presenting the implementer's self-assessment as the conclusion:

- AGENTS.md, the design, and the implementation plan.
- The implementation baseline and the distinction between existing changes and implementation changes.
- Current code, relevant files, test commands, and actual results.
- Resolved findings and changed locations. Prior approval must not be used as a reason to skip verification.

Review assignment:

> Independently review the implementation without changing code. Treat the design and plan as
> potentially fallible and check actual code and Microsoft specifications. Beyond plan adherence,
> focus on failure paths, cancellation/Close races, requests sent to the wrong share, alternating
> DFS/symlink traversal, mistaken deletion targets, duplicate execution of compound requests,
> original UNC display, and manual continuation through the public API. For each finding, provide
> an ID, severity, file/line, triggering conditions, impact, evidence, and a proposed fix.
> Separate unverified concerns from confirmed issues and report review coverage and limitations.

## 5. Fix Loop

- The parent checks each finding's evidence and gives the implementer a concrete fix scope and verification criteria.
- After each fix, ask the reviewer to recheck the fix and related code.
- Do not accept unsupported findings unconditionally. Record evidence when rejecting a finding.
- Lowering severity does not resolve a finding.
- Do not stop reviewing solely because a fixed number of rounds has elapsed.
  Resolve defects, regressions, and missing implementation within the agreed scope.
- If the same issue recurs, the parent clarifies reproduction conditions and contracts in the assignment.
- When user judgment is truly needed, briefly ask about the specific decision and its consequences.

## Information Required for Every Delegation

At minimum, give each implementation owner:

- Required documents and assigned implementation phase numbers.
- Editable files/scope and files currently being edited by other owners.
- Frozen APIs and the state of prerequisite changes.
- Completion criteria and focused tests to run for this assignment.
- Instructions to report unresolved decisions to the parent and not edit outside scope, commit, or publish.
- Required return information: changes, verification evidence, unverified items, issues, and handoff notes.

Use the models currently available; this document does not prescribe model names.
Respect the environment's concurrency limit. Do not omit independent review when that capability is available.

## Completion Criteria

Declare implementation complete only when all of the following are satisfied:

- The design's public API and functional scope are implemented, with no old API or unnecessary compatibility paths.
- Dependency direction and ownership between the lower SMB layer and upper DFS layer match the design.
- Required implementation-plan tests have run, and functional defects and regressions are resolved.
- Independent review and rechecking of fixes are complete, with no substantiated unresolved findings.
- Test and review results correspond to the final code and are recorded.
- The design, plan, status record, and implementation agree.

If real-environment tests are unavailable, leave them explicitly unverified. Distinguish
"implementation and local verification complete; real-environment verification incomplete."
Likewise, do not claim full verification if sub-agents or tests could not be run.

The final response must briefly state key changes, test results, independent review results,
unverified items and limitations, and links to relevant documents.
Do not commit, push, or create a PR unless separately requested.
