#!/usr/bin/env bash
#
# orchestrate_refactor.sh
#
# Autonomous code improvement orchestration:
# 1. AUDITOR -p: Inspect codebase, propose bug fixes and refactorings.
# 2. REVIEWER -p: Review proposals against project standards, classify into:
#    - Pending human review (recorded in PENDING_REVIEWS.md)
#    - Approved (auto-executable minimal changes with Conventional Commit messages)
# 3. DEVELOPER -p: Execute changes, run tests, and auto-commit if green.
#

set -euo pipefail

# Configuration / Defaults
OUTPUT_DIR="${OUTPUT_DIR:-.orchestration}"
PENDING_FILE="${PENDING_FILE:-PENDING_REVIEWS.md}"
TEST_CMD="${TEST_CMD:-go test ./...}"

AUDITOR="${AUDITOR-pi}"
REVIEWER="${REVIEWER-agy --dangerously-skip-permissions}"
DEVELOPER="${DEVELOPER-pi}"

LOOP_MODE=0
TARGET_PATH="."

for arg in "$@"; do
  case "$arg" in
    --loop)
      LOOP_MODE=1
      ;;
    -h|--help)
      echo "Usage: [AUDITOR=cmd] [REVIEWER=cmd] [DEVELOPER=cmd] $0 [--loop] [TARGET_PATH]"
      echo ""
      echo "Options:"
      echo "  --loop         Run iteratively until all improvements are applied or quota is exhausted"
      echo "  TARGET_PATH    Target directory/file to inspect (default: .)"
      echo ""
      echo "Environment variables:"
      echo "  AUDITOR        Investigation tool"
      echo "  REVIEWER       Review/planning tool"
      echo "  DEVELOPER      Execution/implementation tool"
      echo "  TEST_CMD       Test command to verify changes (default: 'go test ./...')"
      exit 0
      ;;
    *)
      TARGET_PATH="$arg"
      ;;
  esac
done

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check for API quota / rate limit / credit exhaustion in output
is_quota_exhausted() {
  local log_file="$1"
  if [[ ! -f "$log_file" ]]; then
    return 1
  fi
  if grep -iE "(quota.*exceeded|exceeded.*quota|rate.*limit|too many requests|insufficient.*quota|insufficient.*credit|insufficient_quota|resource.*exhausted|usage.*limit|out of credits|billing.*error|429)" "$log_file" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

# 1. Preflight checks
log_info "Running preflight checks..."

for var_name in AUDITOR REVIEWER DEVELOPER; do
  val="${!var_name}"
  if [[ -z "${val// }" ]]; then
    log_error "Environment variable $var_name cannot be empty. Please specify a valid command."
    exit 1
  fi
done

AUDITOR_BIN="${AUDITOR%% *}"
REVIEWER_BIN="${REVIEWER%% *}"
DEVELOPER_BIN="${DEVELOPER%% *}"

for cmd in git jq python3 "$AUDITOR_BIN" "$REVIEWER_BIN" "$DEVELOPER_BIN"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_error "Missing required command: $cmd"
    exit 1
  fi
done

# Ensure git working tree is clean
if [[ -n "$(git status --porcelain)" ]]; then
  log_error "Git working tree is not clean. Commit or stash your changes before running orchestration."
  git status --short
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Clean up on interrupt
cleanup_on_interrupt() {
  echo ""
  log_warn "Interrupted! Restoring git working tree..."
  git reset --hard HEAD >/dev/null 2>&1 || true
  git clean -fd >/dev/null 2>&1 || true
  exit 130
}
trap cleanup_on_interrupt INT TERM

ITERATION=0
TOTAL_COMMITS=0
TOTAL_PENDING=0
QUOTA_EXHAUSTED=0

while true; do
  ITERATION=$((ITERATION + 1))
  TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
  RUN_DIR="$OUTPUT_DIR/run_${TIMESTAMP}_iter${ITERATION}"
  mkdir -p "$RUN_DIR"

  PROPOSALS_FILE="$RUN_DIR/phase1_proposals.md"
  PLANS_FILE="$RUN_DIR/phase2_plans.json"
  ROUND_COMMITTED=0

  if [[ "$LOOP_MODE" -eq 1 ]]; then
    echo ""
    log_info "========================================================"
    log_info "Loop Iteration #$ITERATION (Target: '$TARGET_PATH')"
    log_info "========================================================"
  else
    log_ok "Workspace clean. Run directory: $RUN_DIR"
  fi

  # 2. Phase 1: Exploration & Proposals (auditor)
  log_info "Phase 1: Starting code investigation with auditor ($AUDITOR, target: '$TARGET_PATH')..."

  AUDITOR_PROMPT="You are a code auditor for an SMB2/SMB3 Go library.
Analyze the code in '$TARGET_PATH' for:
1. Real bugs, edge cases, unchecked errors, or potential panics.
2. Inefficiencies or code quality issues.
3. Safe refactoring opportunities.

Requirements & Safety Rules:
- Only suggest concrete, valuable changes. Do not invent speculative changes.
- Do NOT modify any files or execute commands with side effects (read-only inspection commands like git, grep, go vet, and ms-specs search commands like bunx @tobilu/qmd are permitted if needed to examine code).
- Provide a structured report with:
  - Proposal ID (e.g. PROP-1)
  - Title
  - Target files and line references
  - Nature of change (Bug Fix / Safe Refactor / Architectural or Speculative)
  - Detailed issue explanation and proposed solution
  - Trade-offs or potential risks (if any)"

  AUDITOR_RAW_LOG="$RUN_DIR/phase1_raw.log"
  AUDITOR_EXIT=0
  $AUDITOR -p "$AUDITOR_PROMPT" > "$PROPOSALS_FILE" 2> "$AUDITOR_RAW_LOG" || AUDITOR_EXIT=$?

  if is_quota_exhausted "$PROPOSALS_FILE" || is_quota_exhausted "$AUDITOR_RAW_LOG"; then
    log_error "API quota / credit limit exhausted in auditor (Phase 1). Terminating."
    QUOTA_EXHAUSTED=1
    break
  fi

  if [[ $AUDITOR_EXIT -ne 0 ]]; then
    log_error "auditor investigation failed with exit code $AUDITOR_EXIT. Check $AUDITOR_RAW_LOG"
    break
  fi

  if [[ ! -s "$PROPOSALS_FILE" ]]; then
    log_info "auditor generated an empty proposal report. Reached a clean state."
    break
  fi

  log_ok "Phase 1 complete. Proposals saved to $PROPOSALS_FILE"

  # 3. Phase 2: Review, Classification & Plan Generation (reviewer)
  log_info "Phase 2: Reviewing proposals and generating implementation plans with reviewer ($REVIEWER)..."

  REVIEWER_INSTRUCTIONS="$(cat << 'PROMPT_EOF'
You are a senior reviewer and project architect.
Review the following proposals generated by an automated investigation tool.

Review rules:
1. Project Rules:
   - Deliver the smallest change that satisfies the goal.
   - Conventional Commits for commit messages (concise subject: fix/refactor, body with bullet points).
   - Prefer simplicity over speculative or future-proof additions.
   - For Go code, maintain protocol safety and slice boundary checks.
   - Strictly adhere to Microsoft specifications (MS-SMB2, MS-FSCC, MS-SRVS). You can consult docs/specs/ and use the ms-specs skill and its commands (`bunx @tobilu/qmd search/vsearch/get ... -c ms-specs`) to verify protocol compliance.
   - Follow Test-Driven Development (TDD):
     In approved plans, instructions must specify a TDD flow:
     1. RED: Write or update a focused unit test in *_test.go first reproducing the issue or asserting expected behavior.
     2. GREEN: Implement the minimal change in target code to make the test pass.
     3. REFACTOR/VERIFY: Verify tests pass with go test.

2. Classification Criteria:
   - "approved_plans": ONLY for changes that are clearly worth doing, low-risk, minimal, do NOT change public APIs or architecture, do NOT require human design decisions, and are safe to apply automatically.
   - "pending_reviews": For changes that require HUMAN JUDGMENT (architectural decisions, trade-offs, potential breaking changes, ambiguous requirements, or subjective style preferences).
   - "rejected": For proposals that are speculative, unnecessary, over-engineered, or violate simplicity.

3. Execution & Output Rules:
   - Do NOT modify any files or execute commands with side effects (read-only inspection commands like git, grep, go vet, and ms-specs search commands like bunx @tobilu/qmd are permitted if needed to verify context).
   - Output ONLY valid JSON (no surrounding markdown code blocks, no backticks, no commentary before or after).
   JSON structure:
   {
     "summary": "Brief summary of the review",
     "pending_reviews": [
       {
         "id": "PROP-X",
         "title": "Short title",
         "target_files": ["file1.go"],
         "reason_for_review": "Why human decision is needed",
         "proposal_summary": "Summary of what was proposed",
         "trade_offs": "Key trade-offs or risks"
       }
     ],
     "approved_plans": [
       {
         "id": "PROP-Y",
         "title": "Short title",
         "target_files": ["file2.go", "file2_test.go"],
         "commit_message": "fix: concise subject\n\n- detail 1\n- detail 2",
         "instructions": "Step-by-step TDD instructions for developer: 1) write/update failing test in *_test.go, 2) apply minimal implementation to pass, 3) verify"
       }
     ]
   }

Here are the proposals:
PROMPT_EOF
)"

  REVIEWER_PROMPT="${REVIEWER_INSTRUCTIONS}

$(cat "$PROPOSALS_FILE")"

  REVIEWER_RAW_LOG="$RUN_DIR/phase2_raw.log"
  REVIEWER_EXIT=0
  $REVIEWER -p "$REVIEWER_PROMPT" > "$RUN_DIR/raw_review.txt" 2> "$REVIEWER_RAW_LOG" || REVIEWER_EXIT=$?

  if is_quota_exhausted "$RUN_DIR/raw_review.txt" || is_quota_exhausted "$REVIEWER_RAW_LOG"; then
    log_error "API quota / credit limit exhausted in reviewer (Phase 2). Terminating."
    QUOTA_EXHAUSTED=1
    break
  fi

  if [[ $REVIEWER_EXIT -ne 0 ]]; then
    log_error "reviewer failed with exit code $REVIEWER_EXIT. Check $REVIEWER_RAW_LOG"
    break
  fi

  if [[ ! -s "$RUN_DIR/raw_review.txt" ]]; then
    log_error "reviewer produced empty output. Check $REVIEWER_RAW_LOG"
    break
  fi

  # Extract valid JSON from reviewer response (stripping code fences if any)
  PARSE_EXIT=0
  python3 - "$RUN_DIR/raw_review.txt" "$PLANS_FILE" << 'PY_EOF' || PARSE_EXIT=$?
import sys, re, json

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    text = f.read()

text_trimmed = text.strip()
json_obj = None

# If wrapped in markdown code blocks
fence_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text_trimmed)
if fence_match:
    try:
        json_obj = json.loads(fence_match.group(1))
    except Exception:
        pass

if json_obj is None:
    first_brace = text_trimmed.find('{')
    last_brace = text_trimmed.rfind('}')
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            json_obj = json.loads(text_trimmed[first_brace:last_brace+1])
        except Exception:
            pass

if json_obj is None:
    print("Error: Failed to parse valid JSON from reviewer output.", file=sys.stderr)
    sys.exit(1)

with open(sys.argv[2], 'w', encoding='utf-8') as out:
    json.dump(json_obj, out, indent=2)
PY_EOF

  if [[ $PARSE_EXIT -ne 0 ]]; then
    log_error "Failed to parse JSON plan from reviewer output. Check $RUN_DIR/raw_review.txt and $REVIEWER_RAW_LOG"
    break
  fi

  log_ok "Phase 2 complete. Plans parsed to $PLANS_FILE"

  # 4. Handle Pending Reviews (Human decision needed)
  NUM_PENDING=$(jq '.pending_reviews | length' "$PLANS_FILE")
  log_info "Pending items requiring human judgment: $NUM_PENDING"

  if [[ "$NUM_PENDING" -gt 0 ]]; then
    if [[ ! -f "$PENDING_FILE" ]]; then
      cat << 'HDR' > "$PENDING_FILE"
# Pending Code Reviews

This document records code improvements and refactoring proposals that require human design decisions, architectural considerations, or manual inspection before applying.
HDR
    fi
    {
      echo ""
      echo "## Run: $TIMESTAMP (Target: \`$TARGET_PATH\`, Iteration: #$ITERATION)"
      echo ""
      jq -r '.pending_reviews[] | "### [\(.id)] \(.title)\n- **Files**: `\(.target_files | join(", "))`\n- **Human Decision Required**: \(.reason_for_review)\n- **Proposal**: \(.proposal_summary)\n- **Trade-offs / Risks**: \(.trade_offs // "N/A")\n"' "$PLANS_FILE"
    } >> "$PENDING_FILE"
    TOTAL_PENDING=$((TOTAL_PENDING + NUM_PENDING))
    log_ok "Recorded $NUM_PENDING item(s) to $PENDING_FILE for manual review."
  fi

  # 5. Phase 3: Execute Approved Plans (developer session per plan)
  NUM_APPROVED=$(jq '.approved_plans | length' "$PLANS_FILE")
  log_info "Approved items for automatic execution: $NUM_APPROVED"

  if [[ "$NUM_APPROVED" -eq 0 ]]; then
    log_info "No approved plans in this round. Codebase is in expected state."
    if [[ "$LOOP_MODE" -eq 1 ]]; then
      break
    fi
    exit 0
  fi

  for i in $(seq 0 $((NUM_APPROVED - 1))); do
    PLAN_ID=$(jq -r ".approved_plans[$i].id" "$PLANS_FILE")
    PLAN_TITLE=$(jq -r ".approved_plans[$i].title" "$PLANS_FILE")
    PLAN_FILES=$(jq -r ".approved_plans[$i].target_files | join(\", \")" "$PLANS_FILE")
    PLAN_COMMIT_MSG=$(jq -r ".approved_plans[$i].commit_message" "$PLANS_FILE")
    PLAN_INSTRUCTIONS=$(jq -r ".approved_plans[$i].instructions" "$PLANS_FILE")

    echo ""
    log_info "========================================================"
    log_info "Executing [$((i+1))/$NUM_APPROVED] with developer ($DEVELOPER): $PLAN_ID - $PLAN_TITLE"
    log_info "Target files: $PLAN_FILES"
    log_info "========================================================"

    DEVELOPER_PROMPT="You are executing an approved code improvement task.
Task: $PLAN_TITLE
Target files: $PLAN_FILES

Instructions:
$PLAN_INSTRUCTIONS

Rules:
- Strictly follow Test-Driven Development (TDD):
  1. RED: Write or update a focused unit test in *_test.go first that reproduces the issue or asserts the required behavior. Run the test to confirm it fails as expected.
  2. GREEN: Implement the minimal code change in the target file to make the test pass.
  3. REFACTOR & VERIFY: Run the test suite to confirm the fix passes and introduces no regressions.
- Apply ONLY the requested change for the assigned task; keep it minimal and precise.
- Do NOT touch or modify any unrelated files.
- Follow existing codebase style and project rules (maintain protocol safety, slice boundary checks).
- Both implementation code and test code must be clean and complete before finishing."

    DEVELOPER_EXEC_LOG="$RUN_DIR/phase3_exec_${PLAN_ID}.log"
    DEVELOPER_EXEC_EXIT=0
    $DEVELOPER -p "$DEVELOPER_PROMPT" > "$DEVELOPER_EXEC_LOG" 2>&1 || DEVELOPER_EXEC_EXIT=$?

    if is_quota_exhausted "$DEVELOPER_EXEC_LOG"; then
      log_error "API quota / credit limit exhausted in developer during implementation. Reverting uncommitted changes and stopping."
      git reset --hard HEAD >/dev/null 2>&1 || true
      git clean -fd >/dev/null 2>&1 || true
      QUOTA_EXHAUSTED=1
      break
    fi

    # Check if any changes were made
    if [[ -z "$(git status --porcelain)" ]]; then
      log_warn "No files modified for plan $PLAN_ID. Skipping."
      continue
    fi

    # Run test suite
    log_info "Running tests: $TEST_CMD"
    if eval "$TEST_CMD"; then
      log_ok "Tests passed! Committing changes..."
      git add -A
      git commit -m "$PLAN_COMMIT_MSG"
      ROUND_COMMITTED=$((ROUND_COMMITTED + 1))
      TOTAL_COMMITS=$((TOTAL_COMMITS + 1))
      log_ok "Committed: $(git rev-parse --short HEAD) - $PLAN_TITLE"
    else
      log_error "Tests failed for plan $PLAN_ID! Reverting changes..."
      git reset --hard HEAD >/dev/null 2>&1 || true
      git clean -fd >/dev/null 2>&1 || true

      {
        echo ""
        echo "### [FAILED-EXECUTION: $PLAN_ID] $PLAN_TITLE"
        echo "- **Files**: \`$PLAN_FILES\`"
        echo "- **Status**: Automated execution attempted, but '$TEST_CMD' failed."
        echo "- **Action**: Requires human review and debugging."
      } >> "$PENDING_FILE"
      TOTAL_PENDING=$((TOTAL_PENDING + 1))
    fi
  done

  if [[ "$QUOTA_EXHAUSTED" -eq 1 ]]; then
    break
  fi

  if [[ "$LOOP_MODE" -eq 0 ]]; then
    break
  fi

  if [[ "$ROUND_COMMITTED" -eq 0 ]]; then
    log_info "No changes were committed in iteration #$ITERATION. Ending loop."
    break
  fi

  log_ok "Iteration #$ITERATION finished with $ROUND_COMMITTED commit(s). Continuing loop..."
done

# 6. Final Summary
echo ""
log_info "========================================================"
log_info "Orchestration Run Summary"
log_info "========================================================"
log_info "Total Iterations:         $ITERATION"
log_ok   "Total Auto-Committed:     $TOTAL_COMMITS"
log_warn "Total Pending Review:     $TOTAL_PENDING (see $PENDING_FILE)"
if [[ "$QUOTA_EXHAUSTED" -eq 1 ]]; then
  log_error "Execution Status:         Stopped due to quota / credit exhaustion."
else
  log_ok   "Execution Status:         Completed successfully."
fi
log_info "Detailed logs preserved in $OUTPUT_DIR"

