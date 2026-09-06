#!/usr/bin/env bun
//
// refactor.ts
//
// Autonomous code improvement orchestration:
// 1. AUDITOR: Inspect codebase, propose bug fixes and refactorings.
// 2. PLANNER: Review proposals, filter out risky changes, and plan TDD instructions.
// 3. DEVELOPER: Execute approved plans concurrently across isolated git worktrees.
// 4. REVIEWER: Review actual commit diffs from each worktree, verify safety, and merge.
//

import { mkdir, readdir, rm, stat } from "node:fs/promises";
import { join, basename, resolve, dirname } from "node:path";
import { homedir } from "node:os";

async function dirExists(p: string): Promise<boolean> {
  try {
    const s = await stat(p);
    return s.isDirectory();
  } catch {
    return false;
  }
}

// --- Configuration & Types ---

interface Proposal {
  id: string;
  title: string;
  status: "approved" | "pending_review" | "rejected";
  issue?: string;
  decision_reason?: string;
  reason?: string;
  target_files?: string[];
  commit_message?: string;
  instructions?: string;
  trade_offs?: string;
}

interface PlansData {
  summary: string;
  proposals: Proposal[];
  approved_plans?: Proposal[];
  pending_reviews?: Proposal[];
  rejected?: Proposal[];
}

interface PlanExecutionState {
  status: string;
  commit?: string;
  branch?: string;
  worktree?: string;
  failure_reason?: string;
}

interface ReviewResult {
  status: "implemented" | "merge_rejected" | "conflict" | "failed";
  commit?: string;
  reason?: string;
  failure_reason?: string;
}

interface ParsedProposalDetails {
  title: string;
  issue: string;
  nature?: string;
  solution?: string;
  tradeOffs?: string;
}

function parseProposalsMd(content: string): Map<string, ParsedProposalDetails> {
  const map = new Map<string, ParsedProposalDetails>();
  const sections = content.split(/^##\s+/m);
  for (const s of sections) {
    const headerMatch = s.match(/^(PROP-\d+)(?:\s*[—–\-:]\s*(.*))?$/m);
    if (!headerMatch) continue;
    const id = headerMatch[1];
    const rawTitle = headerMatch[2] ? headerMatch[2].trim() : "";

    const issueMatch = s.match(/\*\*Issue\*\*\s*([\s\S]*?)(?=\n\*\*(?:Proposed solution|Trade-offs\/risks|Target files|Nature)\*\*|\n---|\n##|$)/i);
    const natureMatch = s.match(/\*\*Nature:\*\*\s*(.*)/i);
    const solutionMatch = s.match(/\*\*Proposed solution\*\*\s*([\s\S]*?)(?=\n\*\*(?:Trade-offs\/risks|Issue|Target files|Nature)\*\*|\n---|\n##|$)/i);
    const tradeOffsMatch = s.match(/\*\*Trade-offs\/risks\*\*\s*([\s\S]*?)(?=\n\*\*(?:Proposed solution|Issue|Target files|Nature)\*\*|\n---|\n##|$)/i);

    let issue = issueMatch ? issueMatch[1].trim() : "";
    if (issue) {
      issue = issue
        .replace(/```[\s\S]*?```/g, "")
        .replace(/`([^`]+)`/g, "$1")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)
        .join(" ")
        .replace(/\s+/g, " ")
        .trim();
      if (issue.length > 250) {
        issue = issue.slice(0, 247) + "...";
      }
    }

    map.set(id, {
      title: rawTitle,
      issue,
      nature: natureMatch ? natureMatch[1].trim() : "",
      solution: solutionMatch ? solutionMatch[1].trim() : "",
      tradeOffs: tradeOffsMatch ? tradeOffsMatch[1].trim() : "",
    });
  }
  return map;
}

interface IterationState {
  run_id: string;
  iteration: number;
  target_path: string;
  lang?: "en" | "ja";
  status: "running" | "completed" | "failed" | "stopped";
  start_time: string;
  end_time?: string;
  phase1?: { status: string };
  phase2?: { status: string };
  phase3?: {
    plans: Record<string, PlanExecutionState>;
  };
  phase4?: {
    reviews: Record<string, ReviewResult>;
  };
}

const OUTPUT_DIR = resolve(process.env.OUTPUT_DIR || ".orchestration");
const TEST_CMD = process.env.TEST_CMD || "go test ./...";
const PARALLEL_JOBS = parseInt(process.env.PARALLEL_JOBS || "3", 10);
const MAX_DEV_ATTEMPTS = parseInt(process.env.MAX_DEV_ATTEMPTS || "3", 10);

const AUDITOR = process.env.AUDITOR || "";
const PLANNER = process.env.PLANNER || "";
const DEVELOPER = process.env.DEVELOPER || "";
const REVIEWER = process.env.REVIEWER || "";

const CURRENT_TASK_FILE = join(OUTPUT_DIR, "current_task.json");
const CURRENT_LOG_LINK = join(OUTPUT_DIR, "current.log");

// Terminal Colors
const RED = "\x1b[0;31m";
const GREEN = "\x1b[0;32m";
const YELLOW = "\x1b[1;33m";
const BLUE = "\x1b[0;34m";
const CYAN = "\x1b[0;36m";
const MAGENTA = "\x1b[0;35m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const NC = "\x1b[0m";

function logInfo(...args: unknown[]) { console.log(`${BLUE}[INFO]${NC}`, ...args); }
function logOk(...args: unknown[]) { console.log(`${GREEN}[OK]${NC}`, ...args); }
function logWarn(...args: unknown[]) { console.log(`${YELLOW}[WARN]${NC}`, ...args); }
function logError(...args: unknown[]) { console.error(`${RED}[ERROR]${NC}`, ...args); }

function isQuotaExhausted(text: string): boolean {
  return /(quota.*exceeded|exceeded.*quota|rate.*limit|too many requests|insufficient.*quota|insufficient.*api.*credit|insufficient_quota|resource.*exhausted|usage.*limit|out of (?:api )?credits|billing.*error|\b429\b)/i.test(text);
}

function extractJson(raw: string): any {
  if (!raw) return null;
  const codeBlockRegex = /```(?:json)?\s*([\s\S]*?)\s*```/g;
  let match;
  while ((match = codeBlockRegex.exec(raw)) !== null) {
    try {
      const parsed = JSON.parse(match[1].trim());
      if (parsed && typeof parsed === "object") return parsed;
    } catch {}
  }
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start !== -1 && end > start) {
    try {
      const parsed = JSON.parse(raw.slice(start, end + 1));
      if (parsed && typeof parsed === "object") return parsed;
    } catch {}
  }
  return null;
}

// --- Shell Helpers ---

async function runCmd(cmd: string, cwd?: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const proc = Bun.spawn(["bash", "-c", cmd], {
    cwd: cwd || process.cwd(),
    stdout: "pipe",
    stderr: "pipe",
  });
  const stdout = await new Response(proc.stdout).text();
  const stderr = await new Response(proc.stderr).text();
  const exitCode = await proc.exited;
  return { stdout, stderr, exitCode };
}

// Run an interactive/background streaming command writing stdout and stderr to a file
async function runToolToFile(
  toolCmd: string,
  prompt: string,
  outputFile: string,
  cwd?: string,
  onPid?: (pid: number) => Promise<void> | void
): Promise<number> {
  const absOutputFile = resolve(outputFile);
  await mkdir(dirname(absOutputFile), { recursive: true });
  const escapedPrompt = prompt.replace(/'/g, "'\\''");
  const fullCmd = `exec ${toolCmd} -p '${escapedPrompt}' > "${absOutputFile}" 2>&1`;
  const proc = Bun.spawn(["bash", "-c", fullCmd], {
    cwd: cwd || process.cwd(),
    stdout: "ignore",
    stderr: "ignore",
  });
  if (onPid) {
    try {
      await onPid(proc.pid);
    } catch {}
  }
  return await proc.exited;
}

// Set active task pointer for real-time tracking
async function setCurrentTask(
  runId: string,
  iteration: number,
  phase: string,
  taskName: string,
  logFile: string,
  status = "running",
  worktreeDir?: string,
  pid?: number
) {
  await mkdir(OUTPUT_DIR, { recursive: true });
  const absLog = resolve(logFile);
  const data: Record<string, any> = {
    run_id: runId,
    iteration,
    phase,
    task_name: taskName,
    log_file: absLog,
    status,
    updated_at: new Date().toISOString(),
  };
  if (worktreeDir) {
    data.worktree_dir = resolve(worktreeDir);
  }
  if (pid) {
    data.pid = pid;
  }
  await Bun.write(CURRENT_TASK_FILE, JSON.stringify(data, null, 2));
  try {
    await rm(CURRENT_LOG_LINK, { force: true });
    await runCmd(`ln -sfn "${absLog}" "${CURRENT_LOG_LINK}"`);
  } catch {}
}

async function clearCurrentTask(status = "completed") {
  const taskFile = Bun.file(CURRENT_TASK_FILE);
  if (await taskFile.exists()) {
    try {
      const data = await taskFile.json();
      data.status = status;
      data.updated_at = new Date().toISOString();
      await Bun.write(CURRENT_TASK_FILE, JSON.stringify(data, null, 2));
    } catch {
      // Corrupted task file: self-recover by rewriting clean final status
      await Bun.write(CURRENT_TASK_FILE, JSON.stringify({ status, updated_at: new Date().toISOString() }, null, 2));
    }
  }
}

// Update state.json inside RUN_DIR atomically
async function updateRunState(runDir: string, updates: Partial<IterationState> | Record<string, any>) {
  const statePath = join(runDir, "state.json");
  const stateFile = Bun.file(statePath);
  let state: Record<string, any> = {};
  if (await stateFile.exists()) {
    try {
      state = await stateFile.json();
    } catch (err) {
      logError(`Failed to parse existing state file at ${statePath}: ${err}`);
      throw err;
    }
  }
  function deepMerge(target: any, source: any) {
    for (const key of Object.keys(source)) {
      if (source[key] && typeof source[key] === "object" && !Array.isArray(source[key])) {
        if (!target[key] || typeof target[key] !== "object") target[key] = {};
        deepMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  deepMerge(state, updates);
  await Bun.write(stateFile, JSON.stringify(state, null, 2));
}

// Get numeric sort key for iteration directories (e.g. iter-1 -> 1, iter-10 -> 10)
function getRunSortKey(name: string): number {
  const m = name.match(/\d+/);
  return m ? parseInt(m[0], 10) : 99999;
}

async function getIterationDirs(): Promise<string[]> {
  if (!(await dirExists(OUTPUT_DIR))) return [];
  const entries = await readdir(OUTPUT_DIR);
  const dirs: string[] = [];
  for (const d of entries) {
    if (d.startsWith("iter-") || d.startsWith("run_")) {
      try {
        const s = await stat(join(OUTPUT_DIR, d));
        if (s.isDirectory()) dirs.push(d);
      } catch {}
    }
  }
  return dirs.sort((a, b) => getRunSortKey(a) - getRunSortKey(b));
}

async function getNextIterationInfo(): Promise<{ iteration: number; runDir: string }> {
  const dirs = await getIterationDirs();
  let maxNum = 0;
  for (const d of dirs) {
    const num = getRunSortKey(d);
    if (num > maxNum) maxNum = num;
  }
  const nextNum = maxNum + 1;
  return { iteration: nextNum, runDir: join(OUTPUT_DIR, `iter-${nextNum}`) };
}

// Clean temporary worktrees and branches
async function cleanupWorktrees(runDir: string, iter: number) {
  const wtDir = join(runDir, "worktrees");
  if (await dirExists(wtDir)) {
    const entries = await readdir(wtDir);
    for (const e of entries) {
      const p = join(wtDir, e);
      try {
        const s = await stat(p);
        if (s.isDirectory()) {
          await runCmd(`git worktree remove --force "${p}" 2>/dev/null || rm -rf "${p}"`);
        }
      } catch {}
    }
  }
  await runCmd("git worktree prune >/dev/null 2>&1");
  const { stdout } = await runCmd(`git branch --list "refactor/iter-${iter}/*"`);
  for (const line of stdout.split("\n")) {
    const b = line.replace("*", "").trim();
    if (!b) continue;
    // Check if the branch has any commits not yet merged into HEAD
    const unmerged = await runCmd(`git log HEAD..${b} --oneline`);
    if (unmerged.stdout.trim().length > 0) {
      logInfo(`Preserving branch with unmerged commits: ${b}`);
    } else {
      await runCmd(`git branch -D "${b}" >/dev/null 2>&1`);
    }
  }
}

// Concurrency pool helper: runs fn over items with max `limit` in parallel
async function asyncPool<T, R>(limit: number, items: T[], fn: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let index = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (index < items.length) {
      const current = index++;
      results[current] = await fn(items[current], current);
    }
  });
  await Promise.all(workers);
  return results;
}

// --- Subcommands ---

// Command: status
async function cmdStatus(targetRun?: string, summaryOnly = false) {
  if (!(await dirExists(OUTPUT_DIR))) {
    logInfo(`No orchestration directory found at ${OUTPUT_DIR}`);
    return;
  }

  const allDirs = await getIterationDirs();
  let runs = allDirs;
  if (targetRun) {
    const matched = allDirs.filter((d) => d === targetRun || basename(d) === targetRun);
    if (matched.length === 0) {
      logError(`Iteration not found: ${targetRun}`);
      return;
    }
    runs = matched;
  }

  if (runs.length === 0) {
    console.log(`No iterations found in ${OUTPUT_DIR}. Run ./scripts/refactor.ts run to start.`);
    return;
  }

  if (!summaryOnly) {
    console.log(`${BOLD}Orchestration Status:${NC}`);
    console.log("======================================================================");
  }

  for (const r of runs) {
    const rDir = join(OUTPUT_DIR, r);
    const stateFile = Bun.file(join(rDir, "state.json"));
    let state: IterationState = {
      run_id: r,
      iteration: getRunSortKey(r),
      target_path: ".",
      status: "running",
      start_time: "",
    };
    let isCorrupted = false;
    if (await stateFile.exists()) {
      try {
        state = await stateFile.json();
      } catch (err) {
        logError(`[${r}] State file is corrupted (${stateFile.name}): ${err}`);
        isCorrupted = true;
      }
    }

    let timeStr = state.start_time ? state.start_time.slice(0, 19).replace("T", " ") : "";
    if (!timeStr) {
      try {
        const s = await stat(rDir);
        timeStr = s.mtime.toISOString().slice(0, 19).replace("T", " ");
      } catch {
        timeStr = "Unknown";
      }
    }

    let iterStatus = isCorrupted ? "CORRUPTED" : (state.status || "INCOMPLETE").toUpperCase();

    // Parse proposals and results
    const plansFile = Bun.file(join(rDir, "phase2_plans.json"));
    let proposals: Proposal[] = [];
    if (await plansFile.exists()) {
      try {
        const p2Data: PlansData = await plansFile.json();
        proposals = p2Data.proposals || [];
        if (proposals.length === 0) {
          for (const p of p2Data.approved_plans || []) proposals.push({ ...p, status: "approved" });
          for (const p of p2Data.pending_reviews || []) proposals.push({ ...p, status: "pending_review" });
          for (const p of p2Data.rejected || []) proposals.push({ ...p, status: "rejected" });
        }
      } catch (err) {
        logError(`[${r}] Plans file is corrupted (${plansFile.name}): ${err}`);
      }
    }

    const proposalsMdFile = Bun.file(join(rDir, "phase1_proposals.md"));
    let proposalsMdMap = new Map<string, ParsedProposalDetails>();
    if (await proposalsMdFile.exists()) {
      try {
        const mdText = await proposalsMdFile.text();
        proposalsMdMap = parseProposalsMd(mdText);
      } catch {}
    }

    proposals.sort((a, b) => {
      const numA = parseInt((a.id.match(/\d+/) || ["99999"])[0], 10);
      const numB = parseInt((b.id.match(/\d+/) || ["99999"])[0], 10);
      return numA - numB;
    });

    const phase3Plans = state.phase3?.plans || {};
    const phase4Reviews = state.phase4?.reviews || {};

    let mergedCount = 0;
    let builtCount = 0;
    let devCount = 0;
    let queuedCount = 0;
    let humanReviewCount = 0;
    let rejectedPlanningCount = 0;
    let rejectedReviewCount = 0;
    let unitTestFailedCount = 0;
    let integrationFailedCount = 0;
    let conflictCount = 0;
    let noChangesCount = 0;

    interface TaskRow {
      id: string;
      title: string;
      status:
        | "MERGED"
        | "BUILT (DEV PASS)"
        | "APPROVED (QUEUED)"
        | "DEVELOPING"
        | "NEEDS_HUMAN_REVIEW"
        | "REJECTED (PLANNING)"
        | "REJECTED (CODE REVIEW)"
        | "UNIT_TEST_FAILED"
        | "INTEGRATION_TEST_FAILED"
        | "MERGE_CONFLICT"
        | "NO_CHANGES";
      issue?: string;
      plannerDecision?: string;
      reviewerDecision?: string;
      failureDetail?: string;
      files: string[];
      commit: string;
      tradeOffs?: string;
      worktree?: string;
    }
    const taskRows: TaskRow[] = [];

    for (const p of proposals) {
      const pid = p.id;
      const reviewStatus = p.status;
      const mdDetails = proposalsMdMap.get(pid);

      const issue = p.issue || mdDetails?.issue || "";
      const plannerReason = p.decision_reason || p.reason || "";
      let plannerDecision = "";
      if (reviewStatus === "approved") {
        plannerDecision = `[Approved] ${plannerReason}`;
      } else if (reviewStatus === "pending_review") {
        plannerDecision = `[Needs Human Review] ${plannerReason}`;
      } else if (reviewStatus === "rejected") {
        plannerDecision = `[Rejected] ${plannerReason}`;
      }

      let taskStatus: TaskRow["status"] = "APPROVED (QUEUED)";
      let reviewerDecision = "";
      let failureDetail = "";
      let commitHash = "";
      let worktree = "";

      if (reviewStatus === "approved") {
        const p4 = phase4Reviews[pid];
        const p3 = phase3Plans[pid];
        if (p3 && p3.worktree) worktree = p3.worktree;

        if (p4) {
          if (p4.status === "implemented") {
            taskStatus = "MERGED";
            commitHash = p4.commit || "";
            reviewerDecision = `[Merge Approved] ${p4.reason || "Review passed and verified on main"}`;
            mergedCount++;
          } else if (p4.status === "merge_rejected") {
            taskStatus = "REJECTED (CODE REVIEW)";
            reviewerDecision = `[Merge Rejected] ${p4.reason || "Code review rejected diff"}`;
            rejectedReviewCount++;
          } else if (p4.status === "conflict") {
            taskStatus = "MERGE_CONFLICT";
            if (p4.reason) reviewerDecision = `[Merge Approved] ${p4.reason}`;
            failureDetail = p4.failure_reason || "Merge conflict during git cherry-pick with earlier changes";
            conflictCount++;
          } else {
            taskStatus = "INTEGRATION_TEST_FAILED";
            if (p4.reason) reviewerDecision = `[Merge Approved] ${p4.reason}`;
            failureDetail = p4.failure_reason || "Integration test on main failed after cherry-pick";
            integrationFailedCount++;
          }
        } else if (p3) {
          if (p3.status === "built") {
            taskStatus = "BUILT (DEV PASS)";
            commitHash = p3.commit || "";
            builtCount++;
          } else if (p3.status === "test_failed") {
            taskStatus = "UNIT_TEST_FAILED";
            failureDetail = p3.failure_reason || `Unit tests failed in worktree. Check ${basename(rDir)}/phase3_exec_${pid}.log`;
            unitTestFailedCount++;
          } else if (p3.status === "no_changes") {
            taskStatus = "NO_CHANGES";
            failureDetail = p3.failure_reason || "No code changes produced in target files";
            noChangesCount++;
          } else if (p3.status === "worktree_failed") {
            taskStatus = "UNIT_TEST_FAILED";
            failureDetail = p3.failure_reason || "Failed to create isolated git worktree";
            unitTestFailedCount++;
          } else if (p3.status === "running") {
            taskStatus = "DEVELOPING";
            devCount++;
          } else {
            taskStatus = "APPROVED (QUEUED)";
            queuedCount++;
          }
        } else {
          taskStatus = "APPROVED (QUEUED)";
          queuedCount++;
        }
      } else if (reviewStatus === "pending_review") {
        taskStatus = "NEEDS_HUMAN_REVIEW";
        humanReviewCount++;
      } else if (reviewStatus === "rejected") {
        taskStatus = "REJECTED (PLANNING)";
        rejectedPlanningCount++;
      }

      taskRows.push({
        id: pid,
        title: p.title || mdDetails?.title || pid,
        status: taskStatus,
        issue,
        plannerDecision,
        reviewerDecision,
        failureDetail,
        files: p.target_files || [],
        commit: commitHash,
        tradeOffs: p.trade_offs || mdDetails?.tradeOffs,
        worktree,
      });
    }

    const statusColor = iterStatus === "COMPLETED" ? GREEN : iterStatus === "RUNNING" ? BLUE : YELLOW;
    const summaryParts: string[] = [];
    if (mergedCount) summaryParts.push(`${GREEN}${mergedCount} merged${NC}`);
    if (builtCount) summaryParts.push(`${CYAN}${builtCount} built (dev pass)${NC}`);
    if (devCount) summaryParts.push(`${BLUE}${devCount} developing${NC}`);
    if (queuedCount) summaryParts.push(`${CYAN}${queuedCount} approved (queued)${NC}`);
    if (humanReviewCount) summaryParts.push(`${YELLOW}${humanReviewCount} needs human review${NC}`);
    if (rejectedPlanningCount) summaryParts.push(`${RED}${rejectedPlanningCount} rejected (planning)${NC}`);
    if (rejectedReviewCount) summaryParts.push(`${RED}${rejectedReviewCount} rejected (code review)${NC}`);
    if (unitTestFailedCount) summaryParts.push(`${MAGENTA}${unitTestFailedCount} unit test failed${NC}`);
    if (integrationFailedCount) summaryParts.push(`${MAGENTA}${integrationFailedCount} integration test failed${NC}`);
    if (conflictCount) summaryParts.push(`${YELLOW}${conflictCount} conflicts${NC}`);
    if (noChangesCount) summaryParts.push(`${DIM}${noChangesCount} no changes${NC}`);

    const summaryText = summaryParts.length > 0 ? summaryParts.join(", ") : "no tasks";

    if (summaryOnly) {
      logInfo(`Tasks Summary [${r} (${statusColor}${iterStatus}${NC})]: ${summaryText} (${taskRows.length} total)`);
      continue;
    }

    console.log(`\n${BOLD}[${r}] (${timeStr}) - ${statusColor}${iterStatus}${NC}`);
    console.log("----------------------------------------------------------------------");

    if (taskRows.length === 0) {
      console.log(`  ${DIM}(No tasks recorded for this iteration)${NC}`);
      continue;
    }

    for (const t of taskRows) {
      let badge = `  [${t.id}] ${t.status.padEnd(20)}`;
      if (t.status === "MERGED") badge = `${GREEN}✓ [${t.id}] MERGED               ${NC}`;
      else if (t.status === "BUILT (DEV PASS)") badge = `${CYAN}● [${t.id}] BUILT (DEV PASS)     ${NC}`;
      else if (t.status === "APPROVED (QUEUED)") badge = `${CYAN}○ [${t.id}] APPROVED (QUEUED)    ${NC}`;
      else if (t.status === "DEVELOPING") badge = `${BLUE}⚙ [${t.id}] DEVELOPING           ${NC}`;
      else if (t.status === "NEEDS_HUMAN_REVIEW") badge = `${YELLOW}? [${t.id}] NEEDS_HUMAN_REVIEW  ${NC}`;
      else if (t.status === "REJECTED (PLANNING)") badge = `${RED}✗ [${t.id}] REJECTED (PLANNING)  ${NC}`;
      else if (t.status === "REJECTED (CODE REVIEW)") badge = `${RED}✗ [${t.id}] REJECTED (CODE REV)  ${NC}`;
      else if (t.status === "UNIT_TEST_FAILED") badge = `${MAGENTA}✗ [${t.id}] UNIT_TEST_FAILED     ${NC}`;
      else if (t.status === "INTEGRATION_TEST_FAILED") badge = `${MAGENTA}✗ [${t.id}] INTEGRATION_FAILED   ${NC}`;
      else if (t.status === "MERGE_CONFLICT") badge = `${YELLOW}⚠ [${t.id}] MERGE_CONFLICT       ${NC}`;
      else if (t.status === "NO_CHANGES") badge = `${DIM}- [${t.id}] NO_CHANGES           ${NC}`;

      const commitStr = t.commit ? ` (commit: ${CYAN}${t.commit}${NC})` : "";
      console.log(`  ${badge} ${BOLD}${t.title}${NC}${commitStr}`);
      if (t.issue) console.log(`      • Issue / Goal:      ${t.issue}`);
      if (t.plannerDecision) console.log(`      • Planner Decision:  ${t.plannerDecision}`);
      if (t.reviewerDecision) console.log(`      • Reviewer Decision: ${t.reviewerDecision}`);
      if (t.failureDetail) console.log(`      • Failure Detail:    ${RED}${t.failureDetail}${NC}`);
      if (t.files.length > 0) console.log(`      • Target files:      ${t.files.join(", ")}`);
      if (t.worktree) console.log(`      • Worktree:          ${t.worktree}`);
      if (t.tradeOffs) console.log(`      • Trade-offs:        ${t.tradeOffs}`);
    }

    console.log(`\n  ${BOLD}Tasks Summary:${NC} ${summaryText} (${taskRows.length} total)`);
  }

  if (!summaryOnly) {
    console.log("\n======================================================================\n");
  }
}

// Remove worktrees, branches, and directory for an iteration
async function removeIterationResources(rDir: string, iterName: string): Promise<{ branches: string[]; worktrees: number }> {
  let worktreeCount = 0;
  const branchesRemoved: string[] = [];

  // 1. Remove git worktrees
  const wtDir = join(rDir, "worktrees");
  if (await dirExists(wtDir)) {
    try {
      const entries = await readdir(wtDir);
      for (const e of entries) {
        const p = join(wtDir, e);
        try {
          const s = await stat(p);
          if (s.isDirectory()) {
            await runCmd(`git worktree remove --force "${p}" 2>/dev/null || rm -rf "${p}"`);
            worktreeCount++;
          }
        } catch {}
      }
    } catch {}
  }
  await runCmd("git worktree prune >/dev/null 2>&1");

  // 2. Remove git branches associated with this iteration
  const iterNum = getRunSortKey(iterName);
  const patterns = new Set<string>();
  if (iterNum !== 99999) {
    patterns.add(`refactor/iter-${iterNum}/*`);
    patterns.add(`refactor/iter-${iterNum}`);
  }
  patterns.add(`refactor/${iterName}/*`);
  patterns.add(`refactor/${iterName}`);

  for (const pat of patterns) {
    const { stdout } = await runCmd(`git branch --list "${pat}"`);
    for (const line of stdout.split("\n")) {
      const b = line.replace("*", "").trim();
      if (!b) continue;
      const delRes = await runCmd(`git branch -D "${b}" 2>&1`);
      if (delRes.exitCode === 0) {
        branchesRemoved.push(b);
      }
    }
  }

  // 3. Remove iteration directory
  await rm(rDir, { recursive: true, force: true });

  return { branches: branchesRemoved, worktrees: worktreeCount };
}

// Command: remove
async function cmdRemove(targetRun?: string, force = false) {
  if (!(await dirExists(OUTPUT_DIR))) {
    logInfo(`No orchestration directory found at ${OUTPUT_DIR}`);
    return;
  }

  const allDirs = await getIterationDirs();
  if (targetRun) {
    const rDir = join(OUTPUT_DIR, targetRun);
    if (!(await dirExists(rDir))) {
      logError(`Iteration directory not found: ${targetRun}`);
      process.exit(1);
    }
    const stateFile = Bun.file(join(rDir, "state.json"));
    let isCompleted = false;
    if (await stateFile.exists()) {
      try {
        const s = await stateFile.json();
        if (s.status === "completed") isCompleted = true;
      } catch (err) {
        logError(`Iteration '${targetRun}' state file is corrupted: ${err}`);
        if (!force) {
          logError("Cannot verify completion status. Use --force to remove corrupted iteration.");
          process.exit(1);
        }
      }
    }
    if (!force && !isCompleted) {
      logWarn(`Iteration '${targetRun}' is not completed. Use --force to remove incomplete iteration.`);
      process.exit(1);
    }
    const { branches, worktrees } = await removeIterationResources(rDir, targetRun);
    const extras: string[] = [];
    if (worktrees > 0) extras.push(`${worktrees} worktree(s)`);
    if (branches.length > 0) extras.push(`branch(es): ${branches.join(", ")}`);
    const extraStr = extras.length > 0 ? ` (${extras.join(", ")})` : "";
    logOk(`Removed iteration: ${targetRun}${extraStr}`);
  } else {
    const removed: string[] = [];
    const skipped: string[] = [];
    const allBranches: string[] = [];
    let totalWorktrees = 0;
    for (const r of allDirs) {
      const rDir = join(OUTPUT_DIR, r);
      const stateFile = Bun.file(join(rDir, "state.json"));
      let isCompleted = false;
      if (await stateFile.exists()) {
        try {
          const s = await stateFile.json();
          if (s.status === "completed") isCompleted = true;
        } catch (err) {
          logError(`Iteration '${r}' state file is corrupted: ${err}`);
        }
      }
      if (isCompleted) {
        const { branches, worktrees } = await removeIterationResources(rDir, r);
        removed.push(r);
        allBranches.push(...branches);
        totalWorktrees += worktrees;
      } else {
        skipped.push(r);
      }
    }
    if (removed.length > 0) {
      const extras: string[] = [];
      if (totalWorktrees > 0) extras.push(`${totalWorktrees} worktree(s)`);
      if (allBranches.length > 0) extras.push(`branch(es): ${allBranches.join(", ")}`);
      const extraStr = extras.length > 0 ? ` (cleaned up ${extras.join(", ")})` : "";
      logOk(`Removed ${removed.length} completed iteration(s): ${removed.join(", ")}${extraStr}`);
    } else {
      console.log("No completed iterations found to remove.");
    }
    if (skipped.length > 0) logWarn(`Kept ${skipped.length} incomplete iteration(s): ${skipped.join(", ")}`);
  }
}

// Locate live session JSONL transcript for a task (pi, antigravity-cli / agy)
async function findSessionJsonl(info: {
  pid?: number;
  worktreeDir?: string;
}): Promise<string | null> {
  // 1. If PID is present, look up exact session opened by this process
  if (info.pid) {
    try {
      const { stdout, exitCode } = await runCmd(`lsof -p ${info.pid} 2>/dev/null`);
      if (exitCode === 0 && stdout) {
        // Antigravity-cli (agy): conversations/<UUID>.db
        const agyMatch = stdout.match(/conversations\/([0-9a-fA-F-]{36})\.db/);
        if (agyMatch) {
          const convId = agyMatch[1];
          const transcript = join(homedir(), ".gemini/antigravity-cli/brain", convId, ".system_generated/logs/transcript.jsonl");
          if (await Bun.file(transcript).exists()) return transcript;
        }

        // Direct .jsonl opened by process
        for (const line of stdout.split("\n")) {
          const parts = line.split(/\s+/);
          const last = parts[parts.length - 1];
          if (last && last.endsWith(".jsonl") && (await Bun.file(last).exists())) {
            return last;
          }
        }
      }
    } catch {}
  }

  // 2. Pi sessions directory lookup by working directory slug
  const targetCwd = info.worktreeDir || process.cwd();
  const slug = "--" + targetCwd.replace(/^\//, "").replace(/\//g, "-") + "--";
  const piDir = join(homedir(), ".pi/agent/sessions", slug);
  if (await dirExists(piDir)) {
    try {
      const files = await readdir(piDir);
      const jsonlFiles = files.filter((f) => f.endsWith(".jsonl"));
      if (jsonlFiles.length > 0) {
        let newest = "";
        let maxMtime = 0;
        const now = Date.now();
        for (const f of jsonlFiles) {
          const fullPath = join(piDir, f);
          const s = await stat(fullPath);
          // If watching main repo without specific worktree, only consider recent files (< 30 minutes)
          if (!info.worktreeDir && now - s.mtimeMs > 30 * 60 * 1000) continue;
          if (s.mtimeMs > maxMtime) {
            maxMtime = s.mtimeMs;
            newest = fullPath;
          }
        }
        if (newest) return newest;
      }
    } catch {}
  }

  return null;
}

// Format a single JSONL line for human-readable watch display
function formatJsonlLine(line: string): string | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  try {
    const obj = JSON.parse(trimmed);
    const results: string[] = [];

    // Format 1: pi
    if (obj.type === "message" && obj.message) {
      const msg = obj.message;
      if (msg.role === "assistant" && Array.isArray(msg.content)) {
        for (const item of msg.content) {
          if (item.type === "thinking" && item.thinking) {
            const firstLine = item.thinking.trim().split("\n")[0].slice(0, 95);
            results.push(`${CYAN}[THINK]${NC} ${firstLine}...`);
          } else if (item.type === "toolCall") {
            const args = item.arguments || item.input || {};
            let detail = JSON.stringify(args);
            if (item.name === "bash" && args.command) {
              detail = args.command;
            } else if ((item.name === "read" || item.name === "edit" || item.name === "write") && args.path) {
              detail = args.path;
            }
            results.push(`${YELLOW}[TOOL]${NC}  ${BOLD}${item.name}${NC}: ${detail.slice(0, 90)}`);
          } else if (item.type === "text" && item.text) {
            const firstLine = item.text.trim().split("\n")[0].slice(0, 95);
            results.push(`${GREEN}[MSG]${NC}   ${firstLine}`);
          }
        }
      } else if (msg.role === "toolResult") {
        const text = msg.content?.map((c: any) => c.text || "").join(" ").trim();
        if (text) {
          const firstLine = text.split("\n")[0].slice(0, 90);
          results.push(`${DIM}[RES]   ${msg.toolName || "tool"}: ${firstLine}${NC}`);
        }
      }
    }

    // Format 2: antigravity-cli / agy
    if (obj.thinking) {
      const firstLine = obj.thinking.trim().split("\n")[0].slice(0, 95);
      results.push(`${CYAN}[THINK]${NC} ${firstLine}...`);
    }
    if (Array.isArray(obj.tool_calls)) {
      for (const tc of obj.tool_calls) {
        const args = tc.arguments || tc.args || {};
        let detail = JSON.stringify(args);
        if (tc.name === "run_command" && (args.CommandLine || args.command)) {
          detail = args.CommandLine || args.command;
        } else if ((tc.name === "view_file" || tc.name === "edit_file" || tc.name === "write_to_file") && (args.AbsolutePath || args.TargetFile)) {
          detail = args.AbsolutePath || args.TargetFile;
        }
        results.push(`${YELLOW}[TOOL]${NC}  ${BOLD}${tc.name}${NC}: ${detail.slice(0, 90)}`);
      }
    }
    if (obj.source === "MODEL" && obj.content && typeof obj.content === "string") {
      const firstLine = obj.content.trim().split("\n")[0].slice(0, 95);
      if (obj.type === "PLANNER_RESPONSE") {
        results.push(`${GREEN}[MSG]${NC}   ${firstLine}`);
      } else if (obj.type === "GENERIC") {
        results.push(`${DIM}[RES]   ${firstLine}${NC}`);
      }
    }

    return results.length > 0 ? results.join("\n") : null;
  } catch {
    return null;
  }
}

// Command: watch
async function cmdWatch(targetTask?: string) {
  logInfo("Watching orchestration task log in real-time (Press Ctrl+C to stop)...");

  let currentWatchedTarget = "";
  let tailProc: ReturnType<typeof Bun.spawn> | null = null;

  process.on("SIGINT", () => {
    if (tailProc) tailProc.kill();
    console.log("");
    logInfo("Stopped watching.");
    process.exit(0);
  });

  while (true) {
    let logFile = "";
    let taskName = "";
    let runId = "";
    let phase = "";
    let worktreeDir = "";
    let pid: number | undefined;

    const allDirs = await getIterationDirs();
    const latestRun = allDirs.length > 0 ? join(OUTPUT_DIR, allDirs[allDirs.length - 1]) : "";

    if (targetTask) {
      if (latestRun) {
        const taskLogPath = join(latestRun, `phase3_exec_${targetTask}.log`);
        const taskLogFile = Bun.file(taskLogPath);
        if (await taskLogFile.exists()) {
          logFile = taskLogPath;
          taskName = `Task ${targetTask}`;
          runId = basename(latestRun);
          phase = "phase3";
          const targetWt = join(latestRun, "worktrees", targetTask);
          worktreeDir = targetWt;
        }
      }
    } else {
      const currentTaskFile = Bun.file(CURRENT_TASK_FILE);
      if (await currentTaskFile.exists()) {
        try {
          const info = await currentTaskFile.json();
          runId = info.run_id || "";
          phase = info.phase || "";
          taskName = info.task_name || "";
          logFile = info.log_file || "";
          worktreeDir = info.worktree_dir || "";
          pid = info.pid;
        } catch {}
      }
    }

    const sessionJsonl = await findSessionJsonl({ pid, worktreeDir });
    const targetSource = sessionJsonl || logFile;

    if (targetSource && targetSource !== currentWatchedTarget) {
      const targetFile = Bun.file(targetSource);
      if (await targetFile.exists()) {
        if (tailProc) {
          tailProc.kill();
          tailProc = null;
        }
        currentWatchedTarget = targetSource;

        console.log("");
        console.log(`${BLUE}================================================================${NC}`);
        console.log(`${GREEN}[WATCHING]${NC} Run: ${YELLOW}${runId}${NC} | Phase: ${YELLOW}${phase}${NC}`);
        console.log(`${GREEN}[TASK]${NC}     ${taskName}`);
        if (worktreeDir) {
          console.log(`${GREEN}[WORKTREE]${NC} ${worktreeDir}`);
        }
        if (sessionJsonl) {
          console.log(`${GREEN}[SESSION]${NC}  ${CYAN}${sessionJsonl}${NC} ${DIM}(Live structured stream)${NC}`);
        } else {
          console.log(`${GREEN}[LOG FILE]${NC} ${logFile}`);
        }
        console.log(`${BLUE}================================================================${NC}`);

        if (sessionJsonl) {
          const proc = Bun.spawn(["tail", "-n", "30", "-f", sessionJsonl], { stdout: "pipe" });
          tailProc = proc;
          (async () => {
            const reader = proc.stdout.getReader();
            const decoder = new TextDecoder();
            let buf = "";
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buf += decoder.decode(value, { stream: true });
                const lines = buf.split("\n");
                buf = lines.pop() || "";
                for (const line of lines) {
                  const formatted = formatJsonlLine(line);
                  if (formatted) console.log(formatted);
                }
              }
            } catch {}
          })();
        } else {
          tailProc = Bun.spawn(["tail", "-n", "25", "-f", logFile], { stdout: "inherit", stderr: "inherit" });
        }
      }
    }

    await new Promise((r) => setTimeout(r, 1000));
  }
}

// Find latest incomplete run directory
async function findLatestIncompleteRun(): Promise<string | null> {
  const allDirs = await getIterationDirs();
  for (let i = allDirs.length - 1; i >= 0; i--) {
    const rDir = join(OUTPUT_DIR, allDirs[i]);
    const stateFile = Bun.file(join(rDir, "state.json"));
    if (!(await stateFile.exists())) return rDir;
    try {
      const s = await stateFile.json();
      if (s.status !== "completed") return rDir;
    } catch (err) {
      logError(`Iteration '${allDirs[i]}' has corrupted state.json: ${err}. Skipping automatic resume for this iteration.`);
    }
  }
  return null;
}

// --- Main Orchestration Loop ---

function printUsage() {
  console.log(`Usage: ./scripts/refactor.ts <COMMAND> [OPTIONS] [TARGET_PATH]

Commands:
  run [OPTIONS] [TARGET_PATH]   Run refactoring orchestration (required to start)
  status [ITERATION] [--summary] Display task status per iteration
  resume [ITERATION] [--loop]   Resume an incomplete iteration (defaults to latest incomplete)
  watch [TASK_ID]               Watch the real-time conversation log (defaults to current active task)
  remove, rm [ITERATION] [-f]   Remove completed iteration(s) (removes all completed if omitted)

Options:
  --loop                        Run iteratively until all improvements are applied or quota is exhausted
  --ja, -j                      Instruct LLMs (Auditor, Planner, Reviewer) to output in Japanese
  TARGET_PATH                   Target directory/file to inspect (default: .)

Environment variables:
  AUDITOR                       Investigation tool (required)
  PLANNER                       Planning & screening tool (required)
  DEVELOPER                     Execution/implementation tool (required)
  REVIEWER                      Diff review & merge tool (required)
  PARALLEL_JOBS                 Concurrent worktree jobs for DEVELOPER (default: 3)
  REFACTOR_LANG                 Language for LLM generated output ('ja' for Japanese)
  TEST_CMD                      Test command to verify changes (default: 'go test ./...')`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    logError("No command specified. Use 'run' to start orchestration.");
    printUsage();
    process.exit(1);
  }

  const cmd = args[0];
  if (cmd === "-h" || cmd === "--help" || cmd === "help") {
    printUsage();
    return;
  }
  if (cmd === "status" || cmd === "--status") {
    const summaryOnly = args.includes("--summary") || args.includes("-s");
    const target = args.slice(1).find((a) => !a.startsWith("-"));
    await cmdStatus(target, summaryOnly);
    return;
  }
  if (cmd === "watch" || cmd === "tail" || cmd === "--watch") {
    await cmdWatch(args[1]);
    return;
  }
  if (cmd === "remove" || cmd === "rm" || cmd === "--remove") {
    const force = args.includes("-f") || args.includes("--force");
    const target = args.slice(1).find((a) => !a.startsWith("-"));
    await cmdRemove(target, force);
    return;
  }

  if (cmd !== "run" && cmd !== "resume") {
    logError(`Unknown or missing command: '${cmd}'. Use 'run' to start orchestration.`);
    printUsage();
    process.exit(1);
  }

  // Parse options for run / resume
  let loopMode = false;
  let resumeDir: string | null = null;
  let targetPath = ".";
  let isJa = args.includes("--ja") || args.includes("-j") || args.includes("--japanese") || process.env.REFACTOR_LANG === "ja";
  const subArgs = args.slice(1);

  if (cmd === "resume") {
    for (let i = 0; i < subArgs.length; i++) {
      const a = subArgs[i];
      if (a === "--loop") {
        loopMode = true;
      } else if (a === "--ja" || a === "-j" || a === "--japanese") {
        isJa = true;
      } else if (!a.startsWith("-")) {
        resumeDir = a.startsWith("/") || a.startsWith(".") ? a : join(OUTPUT_DIR, a);
      }
    }
    if (!resumeDir) {
      resumeDir = await findLatestIncompleteRun();
      if (!resumeDir) {
        logError(`No incomplete iteration found in ${OUTPUT_DIR} to resume.`);
        process.exit(1);
      }
    }
  } else {
    // cmd === "run"
    for (let i = 0; i < subArgs.length; i++) {
      const a = subArgs[i];
      if (a === "--loop") {
        loopMode = true;
      } else if (a === "--ja" || a === "-j" || a === "--japanese") {
        isJa = true;
      } else if (!a.startsWith("-")) {
        targetPath = a;
      }
    }
  }

  // Preflight checks
  logInfo("Running preflight checks...");
  const requiredTools = [
    { name: "AUDITOR", val: AUDITOR },
    { name: "PLANNER", val: PLANNER },
    { name: "DEVELOPER", val: DEVELOPER },
    { name: "REVIEWER", val: REVIEWER },
  ];

  for (const t of requiredTools) {
    if (!t.val.trim()) {
      logError(`Environment variable ${t.name} cannot be empty. Please specify a valid command.`);
      process.exit(1);
    }
    const bin = t.val.trim().split(" ")[0];
    const check = await runCmd(`command -v "${bin}"`);
    if (check.exitCode !== 0) {
      logError(`Missing required command for ${t.name}: ${bin}`);
      process.exit(1);
    }
  }

  const gitClean = await runCmd("git status --porcelain");
  if (gitClean.stdout.trim().length > 0) {
    logError("Git working tree is not clean. Commit or stash your changes before running orchestration.");
    console.log(gitClean.stdout);
    process.exit(1);
  }

  await mkdir(OUTPUT_DIR, { recursive: true });

  let activeRunDir = "";
  let activeIteration = 0;

  process.on("SIGINT", async () => {
    console.log("");
    logWarn("Interrupted! Preserving worktrees and branches for manual review or resume...");
    await clearCurrentTask("stopped");
    if (activeRunDir && (await dirExists(activeRunDir))) {
      await updateRunState(activeRunDir, { status: "stopped" });
    }
    await runCmd("git cherry-pick --abort >/dev/null 2>&1 || true");
    await runCmd("git reset --hard HEAD >/dev/null 2>&1 || true");
    process.exit(130);
  });

  let iteration = 0;
  let totalCommits = 0;
  let quotaExhausted = false;

  while (true) {
    let roundCommitted = 0;
    let runDir = "";

    if (resumeDir) {
      runDir = resolve(resumeDir);
      iteration = getRunSortKey(basename(runDir));
      resumeDir = null; // consume
      logInfo(`Resuming iteration #${iteration} from ${basename(runDir)}...`);
    } else {
      const next = await getNextIterationInfo();
      iteration = next.iteration;
      runDir = next.runDir;
      await mkdir(runDir, { recursive: true });
    }

    activeRunDir = runDir;
    activeIteration = iteration;

    const statePath = join(runDir, "state.json");
    const stateFile = Bun.file(statePath);
    let existingLang: "en" | "ja" | undefined;
    if (await stateFile.exists()) {
      try {
        const existingState: IterationState = await stateFile.json();
        existingLang = existingState.lang;
      } catch {}
    }
    const isIterJa = isJa || existingLang === "ja";
    const currentLang: "en" | "ja" = isIterJa ? "ja" : "en";

    const proposalsPath = join(runDir, "phase1_proposals.md");
    const plansPath = join(runDir, "phase2_plans.json");
    const reviewSummaryPath = join(runDir, "review_summary.md");

    await updateRunState(runDir, {
      run_id: basename(runDir),
      iteration,
      target_path: targetPath,
      lang: currentLang,
      status: "running",
      start_time: new Date().toISOString(),
    });

    if (loopMode) {
      console.log("");
      logInfo("========================================================");
      logInfo(`Iteration #${iteration} (Target: '${targetPath}')`);
      logInfo(`Run Directory: ${runDir}`);
      if (isIterJa) logInfo("Output Language: Japanese (LLMs instructed to generate in Japanese)");
      logInfo("========================================================");
    } else {
      logOk(`Run directory: ${runDir}`);
      if (isIterJa) logInfo("Output Language: Japanese (LLMs instructed to generate in Japanese)");
    }

    // --- Phase 1: Exploration & Proposals (AUDITOR) ---
    if ((await Bun.file(proposalsPath).exists()) && Bun.file(proposalsPath).size > 0) {
      logOk(`Phase 1: Existing proposals found in ${proposalsPath}. Skipping exploration.`);
    } else {
      logInfo(`Phase 1: Starting code investigation with AUDITOR (${AUDITOR}, target: '${targetPath}')...`);
      const auditorRawLog = join(runDir, "phase1_raw.log");
      await setCurrentTask(basename(runDir), iteration, "phase1", `Phase 1: Code audit with AUDITOR (${AUDITOR})`, proposalsPath);

      const auditorPrompt = `You are a code auditor for an SMB2/SMB3 Go library.
Analyze the code in '${targetPath}' for:
1. Real bugs, edge cases, unchecked errors, or potential panics.
2. Inefficiencies or code quality issues.
3. Safe refactoring opportunities.

Requirements & Safety Rules:
- Only suggest concrete, valuable changes. Do not invent speculative changes.
- Do NOT modify any files or execute commands with side effects (read-only inspection commands like git, grep, go vet, and qmd are permitted if needed to examine code).
- Provide a structured report with:
  - Proposal ID (e.g. PROP-1, PROP-2, ...)
  - Title
  - Target files and line references
  - Nature of change (Bug Fix / Safe Refactor / Architectural or Speculative)
  - Detailed issue explanation and proposed solution
  - Trade-offs or potential risks (if any)${isIterJa ? `\n\nLanguage Requirement:\n- Write all proposal titles, issue explanations, solutions, and trade-offs in Japanese (日本語で記述してください). Keep Proposal IDs (e.g. PROP-1), code symbols, and file paths in their original format.` : ""}`;

      const exitCode = await runToolToFile(AUDITOR, auditorPrompt, proposalsPath, undefined, async (pid) => {
        await setCurrentTask(basename(runDir), iteration, "phase1", `Phase 1: Code audit with AUDITOR (${AUDITOR})`, proposalsPath, "running", undefined, pid);
      });
      const outputText = (await Bun.file(proposalsPath).exists()) ? await Bun.file(proposalsPath).text() : "";

      if (isQuotaExhausted(outputText)) {
        logError("API quota / credit limit exhausted in AUDITOR (Phase 1). Terminating.");
        await updateRunState(runDir, { status: "failed" });
        quotaExhausted = true;
        break;
      }

      if (exitCode !== 0) {
        logError(`AUDITOR investigation failed with exit code ${exitCode}. Check ${proposalsPath}`);
        await updateRunState(runDir, { status: "failed" });
        break;
      }

      if (outputText.trim().length === 0) {
        logInfo("AUDITOR generated an empty proposal report. Reached a clean state.");
        await updateRunState(runDir, { status: "completed" });
        break;
      }

      logOk(`Phase 1 complete. Proposals saved to ${proposalsPath}`);
    }

    await updateRunState(runDir, { phase1: { status: "completed" } });

    // --- Phase 2: Planning & Screening (PLANNER) ---
    if ((await Bun.file(plansPath).exists()) && Bun.file(plansPath).size > 0) {
      logOk(`Phase 2: Existing plans found in ${plansPath}. Skipping planning.`);
    } else {
      logInfo(`Phase 2: Reviewing proposals and planning with PLANNER (${PLANNER})...`);
      const rawReviewPath = join(runDir, "raw_review.txt");
      await setCurrentTask(basename(runDir), iteration, "phase2", `Phase 2: Planning with PLANNER (${PLANNER})`, rawReviewPath);

      const proposalsText = await Bun.file(proposalsPath).text();
      const plannerPrompt = `You are a senior project architect and planner.
Review the proposals generated by the code auditor and plan their execution.

Rules:
1. Project Rules:
   - Deliver the smallest change that satisfies the goal.
   - Conventional Commits for commit messages (concise subject: fix/refactor, body with bullet points).
   - Prefer simplicity over speculative or future-proof additions.
   - Maintain protocol safety and slice boundary checks.
   - Strictly adhere to Microsoft specifications (MS-SMB2, MS-FSCC, MS-SRVS).
   - Follow Test-Driven Development (TDD) for approved items:
     1. RED: Write or update a focused unit test in *_test.go asserting expected behavior.
     2. GREEN: Implement minimal change in target code to make the test pass.
     3. REFACTOR/VERIFY: Verify tests pass with go test.

Requirements & Safety Rules:
- Only suggest concrete, valuable changes. Do not invent speculative changes.
- Do NOT modify any files or execute commands with side effects (read-only inspection commands like git, grep, go vet, and qmd are permitted if needed to examine code).

2. Classification Criteria:
   - "approved": ONLY for changes that are clearly worth doing, low-risk, minimal, do NOT change public APIs or architecture, do NOT require human design decisions, and are safe to apply automatically.
   - "pending_review": For changes that require HUMAN JUDGMENT (architectural decisions, trade-offs, potential breaking changes, ambiguous requirements, or subjective style preferences).
   - "rejected": For proposals that are speculative, unnecessary, over-engineered, or violate simplicity.

3. Output format:
   Output ONLY valid JSON (no markdown code blocks, no backticks, no commentary before or after).
   Every proposal from the auditor report MUST be planned in sequential order (PROP-1, PROP-2, PROP-3, ...).
   Every proposal must clearly state its status, the underlying issue/goal, and a concrete decision reason explaining WHY it is approved, pending_review, or rejected.

   JSON structure:
   {
     "summary": "Brief overall summary of the review and plan",
     "proposals": [
       {
         "id": "PROP-1",
         "title": "Short title",
         "issue": "Concise summary of the problem or bug being addressed",
         "status": "approved", // "approved" | "pending_review" | "rejected"
         "decision_reason": "Clear explanation of WHY this proposal is approved, pending_review, or rejected",
         "target_files": ["file1.go", "file1_test.go"],
         "commit_message": "fix: concise subject\\n\\n- detail 1\\n- detail 2", // required if approved
         "instructions": "Step-by-step TDD instructions: 1) failing test, 2) minimal fix, 3) verify", // required if approved
         "trade_offs": "Trade-offs or risks" // optional, recommended for pending_review
       }
     ]
   }${isIterJa ? `\n\nLanguage Requirement:\n- Write the "summary", proposal "title", "issue", "decision_reason", and "trade_offs" in Japanese (日本語で記述してください).\n- Keep JSON keys, "id" (e.g. PROP-1), "status" values ("approved", "pending_review", "rejected"), "target_files", and "commit_message" (Conventional Commits) in English.` : ""}

Here are the proposals:
${proposalsText}`;

      const exitCode = await runToolToFile(PLANNER, plannerPrompt, rawReviewPath, undefined, async (pid) => {
        await setCurrentTask(basename(runDir), iteration, "phase2", `Phase 2: Planning with PLANNER (${PLANNER})`, rawReviewPath, "running", undefined, pid);
      });
      const rawText = (await Bun.file(rawReviewPath).exists()) ? await Bun.file(rawReviewPath).text() : "";

      if (isQuotaExhausted(rawText)) {
        logError("API quota / credit limit exhausted in PLANNER (Phase 2). Terminating.");
        await updateRunState(runDir, { status: "failed" });
        quotaExhausted = true;
        break;
      }

      if (exitCode !== 0 || !rawText.trim()) {
        logError(`PLANNER failed with exit code ${exitCode}. Check ${rawReviewPath}`);
        await updateRunState(runDir, { status: "failed" });
        break;
      }

      // Parse and normalize JSON
      const jsonObj: any = extractJson(rawText);

      if (!jsonObj) {
        logError(`Failed to parse valid JSON from PLANNER output. Check ${rawReviewPath}`);
        await updateRunState(runDir, { status: "failed" });
        break;
      }

      const proposals: Proposal[] = jsonObj.proposals || [];
      if (proposals.length === 0) {
        for (const p of jsonObj.approved_plans || []) proposals.push({ ...p, status: "approved" });
        for (const p of jsonObj.pending_reviews || []) proposals.push({ ...p, status: "pending_review" });
        for (const p of jsonObj.rejected || []) proposals.push({ ...p, status: "rejected" });
      }

      for (const p of proposals) {
        if (!p.decision_reason && p.reason) p.decision_reason = p.reason;
        if (!p.reason && p.decision_reason) p.reason = p.decision_reason;
      }

      proposals.sort((a, b) => {
        const numA = parseInt((a.id.match(/\d+/) || ["99999"])[0], 10);
        const numB = parseInt((b.id.match(/\d+/) || ["99999"])[0], 10);
        return numA - numB;
      });

      jsonObj.proposals = proposals;
      jsonObj.approved_plans = proposals.filter((p) => p.status === "approved");
      jsonObj.pending_reviews = proposals.filter((p) => p.status === "pending_review");
      jsonObj.rejected = proposals.filter((p) => p.status === "rejected");

      await Bun.write(plansPath, JSON.stringify(jsonObj, null, 2));

      // Write summary markdown
      let summaryMd = `# Proposal Planning Summary\n\n`;
      if (jsonObj.summary) summaryMd += `${jsonObj.summary}\n\n`;
      for (const p of proposals) {
        summaryMd += `- **[${p.id}] ${p.status.toUpperCase()}**: ${p.title}\n`;
        if (p.issue) summaryMd += `  - **Issue/Goal**: ${p.issue}\n`;
        summaryMd += `  - **Planner Decision**: ${p.decision_reason || p.reason || "N/A"}\n`;
        if (p.target_files && p.target_files.length > 0) {
          summaryMd += `  - **Target files**: \`${p.target_files.join("`, `")}\`\n`;
        }
        if (p.trade_offs) summaryMd += `  - **Trade-offs**: ${p.trade_offs}\n`;
      }
      await Bun.write(reviewSummaryPath, summaryMd);

      logOk(`Phase 2 complete. Plans parsed to ${plansPath}`);
    }

    await updateRunState(runDir, { phase2: { status: "completed" } });

    // Show task status summary after planning
    await cmdStatus(basename(runDir), true);

    // --- Phase 3: Concurrent Execution with git worktree (DEVELOPER) ---
    const plansData: PlansData = await Bun.file(plansPath).json();
    const approvedPlans = plansData.approved_plans || [];
    logInfo(`Approved plans for execution: ${approvedPlans.length} (Concurrency: ${PARALLEL_JOBS})`);

    if (approvedPlans.length === 0) {
      logInfo("No approved plans in this round. Codebase is in clean state.");
      await updateRunState(runDir, { status: "completed", end_time: new Date().toISOString() });
      if (loopMode) break;
      return;
    }

    const wtBaseDir = join(runDir, "worktrees");
    await mkdir(wtBaseDir, { recursive: true });

    logInfo(`Launching DEVELOPER tasks concurrently across git worktrees (max ${PARALLEL_JOBS})...`);
    logInfo(`Worktree base directory: ${wtBaseDir}`);

    // Run each approved plan inside its isolated git worktree
    await asyncPool(PARALLEL_JOBS, approvedPlans, async (plan, idx) => {
      const planId = plan.id;
      const planTitle = plan.title;
      const branchName = `refactor/iter-${iteration}/${planId}`;
      const worktreeDir = join(wtBaseDir, planId);
      const execLogPath = join(runDir, `phase3_exec_${planId}.log`);

      const currentRunState: IterationState = await Bun.file(join(runDir, "state.json")).json().catch(() => ({}));
      const existingP3Plans = currentRunState.phase3?.plans || {};
      if (existingP3Plans[planId]?.status === "built") {
        const branchCheck = await runCmd(`git rev-parse "${branchName}"`);
        if (branchCheck.exitCode === 0) {
          logOk(`[DEVELOPER ${idx + 1}/${approvedPlans.length}] ${planId} is already built on ${branchName}. Skipping execution.`);
          return;
        }
      }

      logInfo(`[DEVELOPER ${idx + 1}/${approvedPlans.length}] Starting: ${planId} - ${planTitle}`);
      logInfo(`  • Worktree: ${worktreeDir}`);
      logInfo(`  • Branch:   ${branchName}`);
      logInfo(`  • Log:      ${execLogPath}`);
      await setCurrentTask(basename(runDir), iteration, "phase3", `DEVELOPER on ${planId}: ${planTitle}`, execLogPath, "running", worktreeDir);

      // Create isolated worktree
      if (await dirExists(worktreeDir)) await rm(worktreeDir, { recursive: true, force: true });
      await runCmd(`git branch -D "${branchName}" >/dev/null 2>&1 || true`);
      const wtRes = await runCmd(`git worktree add -B "${branchName}" "${worktreeDir}" HEAD`);
      if (wtRes.exitCode !== 0) {
        const wtErr = wtRes.stderr.trim() || "Failed to create isolated git worktree";
        logError(`Failed to create worktree for ${planId} at ${worktreeDir}: ${wtErr}`);
        await updateRunState(runDir, { phase3: { plans: { [planId]: { status: "worktree_failed", failure_reason: wtErr } } } });
        return;
      }

      const baseCommitRes = await runCmd("git rev-parse HEAD", worktreeDir);
      const baseCommit = baseCommitRes.stdout.trim();

      await updateRunState(runDir, { phase3: { plans: { [planId]: { status: "running", branch: branchName, worktree: worktreeDir } } } });

      const devPrompt = `You are executing an approved code improvement task.
Task: ${planTitle}
Target files: ${(plan.target_files || []).join(", ")}

Instructions:
${plan.instructions || ""}

Rules:
- Strictly follow Test-Driven Development (TDD):
  1. RED: Write or update a focused unit test in *_test.go first that reproduces the issue or asserts the required behavior. Confirm it fails as expected.
  2. GREEN: Implement the minimal code change in the target file to make the test pass.
  3. REFACTOR & VERIFY: Run the test suite to confirm the fix passes and introduces no regressions.
- Apply ONLY the requested change for the assigned task; keep it minimal and precise.
- Do NOT touch or modify any unrelated files.
- Follow existing codebase style and project rules (maintain protocol safety, slice boundary checks).
- Both implementation code and test code must be clean and complete before finishing.`;

      let testsPassed = false;
      let lastTestErr = "";

      for (let attempt = 1; attempt <= MAX_DEV_ATTEMPTS; attempt++) {
        const attemptPrompt = attempt === 1
          ? devPrompt
          : `You are continuing to work on the task: "${planTitle}".
The previous attempt failed the test suite in ${worktreeDir}.

Test command: ${TEST_CMD}
Failure output:
${lastTestErr}

Target files: ${(plan.target_files || []).join(", ")}
Original instructions:
${plan.instructions || ""}

Please analyze why the test failed and fix the implementation code or the test code accordingly.
Rules:
- Keep the fix minimal and precise to satisfy the task.
- Ensure all tests pass cleanly (${TEST_CMD}).
- Maintain protocol safety and codebase standards.`;

        const attemptLogPath = attempt === 1 ? execLogPath : join(runDir, `phase3_exec_${planId}_retry${attempt}.log`);
        const taskLabel = attempt === 1
          ? `DEVELOPER on ${planId}: ${planTitle}`
          : `DEVELOPER on ${planId} (Retry ${attempt - 1}/${MAX_DEV_ATTEMPTS - 1}): ${planTitle}`;

        const devExitCode = await runToolToFile(DEVELOPER, attemptPrompt, attemptLogPath, worktreeDir, async (pid) => {
          await setCurrentTask(basename(runDir), iteration, "phase3", taskLabel, attemptLogPath, "running", worktreeDir, pid);
        });
        if (devExitCode !== 0) {
          logWarn(`DEVELOPER process exited with code ${devExitCode} for ${planId} (Attempt ${attempt}/${MAX_DEV_ATTEMPTS}). Inspect logs at: ${attemptLogPath}`);
        }
        const logContent = (await Bun.file(attemptLogPath).exists()) ? await Bun.file(attemptLogPath).text() : "";

        if (isQuotaExhausted(logContent)) {
          logError(`Quota exhausted during ${planId}`);
          await updateRunState(runDir, { phase3: { plans: { [planId]: { status: "quota_exhausted", branch: branchName, worktree: worktreeDir } } } });
          quotaExhausted = true;
          return;
        }

        // If developer agent committed changes, soft reset back to baseCommit to collect all changes in index/working tree
        const curHeadRes = await runCmd("git rev-parse HEAD", worktreeDir);
        const curHead = curHeadRes.stdout.trim();
        if (curHead && curHead !== baseCommit) {
          await runCmd(`git reset --soft "${baseCommit}"`, worktreeDir);
        }

        // Run tests inside worktree
        const testRes = await runCmd(TEST_CMD, worktreeDir);
        if (testRes.exitCode === 0) {
          testsPassed = true;
          break;
        }
        lastTestErr = (testRes.stderr || testRes.stdout).trim();
        logWarn(`Tests failed inside worktree for ${planId} (Attempt ${attempt}/${MAX_DEV_ATTEMPTS}): ${lastTestErr.slice(0, 300)}`);
      }

      if (testsPassed) {
        // Stage ONLY target files
        await runCmd("git reset HEAD --quiet", worktreeDir);
        for (const f of plan.target_files || []) {
          const check = await runCmd(`test -e "${f}"`, worktreeDir);
          if (check.exitCode === 0) {
            await runCmd(`git add "${f}"`, worktreeDir);
          }
        }

        const diffCheck = await runCmd("git diff --cached --quiet", worktreeDir);
        if (diffCheck.exitCode === 0) {
          const statusCheck = await runCmd("git status --porcelain", worktreeDir);
          const noChangesReason = statusCheck.stdout.trim().length > 0
            ? `Changes were made, but none in target files: ${(plan.target_files || []).join(", ")}`
            : "No code changes produced in worktree";
          if (statusCheck.stdout.trim().length > 0) {
            logWarn(`Changes were made for ${planId} (${worktreeDir}), but none in target files [${(plan.target_files || []).join(", ")}]`);
          } else {
            logWarn(`No changes produced in worktree for ${planId} (${worktreeDir})`);
          }
          await updateRunState(runDir, {
            phase3: { plans: { [planId]: { status: "no_changes", branch: branchName, worktree: worktreeDir, failure_reason: noChangesReason } } },
          });
        } else {
          const commitMsg = plan.commit_message || `fix: ${planTitle}`;
          await runCmd(`git commit -m "${commitMsg.replace(/"/g, '\\"')}"`, worktreeDir);
          await runCmd("git reset --hard HEAD >/dev/null 2>&1 || true", worktreeDir);
          await runCmd("git clean -fd >/dev/null 2>&1 || true", worktreeDir);

          const commitHashRes = await runCmd("git rev-parse --short HEAD", worktreeDir);
          const commitHash = commitHashRes.stdout.trim();
          logOk(`Built ${planId} in worktree: ${commitHash} (${worktreeDir})`);
          await updateRunState(runDir, {
            phase3: { plans: { [planId]: { status: "built", commit: commitHash, branch: branchName, worktree: worktreeDir } } },
          });
        }
      } else {
        logError(`All ${MAX_DEV_ATTEMPTS} attempts failed unit tests for ${planId} (${worktreeDir}): ${lastTestErr}`);
        await updateRunState(runDir, {
          phase3: {
            plans: {
              [planId]: {
                status: "test_failed",
                branch: branchName,
                worktree: worktreeDir,
                failure_reason: lastTestErr.slice(0, 500) || "go test failed inside worktree",
              },
            },
          },
        });
      }
    });

    if (quotaExhausted) {
      await updateRunState(runDir, { status: "stopped" });
      await cleanupWorktrees(runDir, iteration);
      break;
    }

    await updateRunState(runDir, { phase3: { status: "completed" } });
    logOk("Phase 3 complete. All DEVELOPER worktree tasks finished.");

    // --- Phase 4: Diff Review & Merge (REVIEWER) ---
    logInfo(`Phase 4: Reviewing all candidate proposals and merging with REVIEWER (${REVIEWER})...`);

    const stateAfterP3: IterationState = await Bun.file(join(runDir, "state.json")).json();
    const p3Plans = stateAfterP3.phase3?.plans || {};

    const builtPlans = approvedPlans.filter((p) => {
      const p3 = p3Plans[p.id];
      return p3 && p3.status === "built" && (p3.commit || p3.branch);
    });

    if (builtPlans.length === 0) {
      logWarn("No built proposals from Phase 3 available for review and merge.");
    } else {
      const currentBranchRes = await runCmd("git rev-parse --abbrev-ref HEAD");
      const currentBranch = currentBranchRes.stdout.trim() || "HEAD";
      const headBeforeMergeRes = await runCmd("git rev-parse HEAD");
      const headBeforeMerge = headBeforeMergeRes.stdout.trim();

      const planSummaries: string[] = [];
      for (const plan of builtPlans) {
        const p3 = p3Plans[plan.id];
        const branchName = p3.branch || `refactor/iter-${iteration}/${plan.id}`;
        let commitHash = p3.commit || "";
        if (!commitHash) {
          const commitRes = await runCmd(`git rev-parse "${branchName}"`);
          commitHash = commitRes.stdout.trim();
        }
        const diffRes = await runCmd(`git show "${commitHash}" --stat -p`);
        const commitDiff = diffRes.stdout;

        planSummaries.push(`### Proposal: ${plan.id} - ${plan.title}
- Branch: ${branchName}
- Commit: ${commitHash}
- Target files: ${(plan.target_files || []).join(", ")}
- Instructions: ${plan.instructions || ""}

Diff:
\`\`\`diff
${commitDiff}
\`\`\``);
      }

      const reviewPrompt = `You are a senior reviewer and integrator responsible for reviewing all candidate refactoring proposals implemented by DEVELOPER and merging them into the current branch (${currentBranch}).

Here are the ${builtPlans.length} implemented proposals ready for review:

${planSummaries.join("\n\n---\n\n")}

Your Responsibilities:
1. Review all candidate proposals:
   - Verify minimal change: Does each diff apply ONLY the required minimal changes without scope creep or unrelated edits?
   - Verify correctness & protocol safety: Does the code adhere to Go idioms, project rules, and Microsoft protocol specifications?
2. Integrate safe and valuable proposals into the current branch (${currentBranch}):
   - You have access to bash and git tools in this repository.
   - Choose which proposals to merge and the optimal order to merge them (e.g. \`git cherry-pick <commit>\` or \`git merge <branch>\`).
   - If merge conflicts occur, resolve the conflicts cleanly, preserve intended logic, and complete the cherry-pick (\`git add ... && git cherry-pick --continue\`).
   - If a proposal is unsafe, inappropriate, or causes irreconcilable issues, reject/skip it (abort with \`git cherry-pick --abort\`).
3. Verify test suite:
   - Run \`${TEST_CMD}\` to verify that all tests pass cleanly after all merges are complete.
   - If minor integration issues arise, apply minimal fixes and commit them.
   - If any change breaks the repository and cannot be fixed, revert it cleanly.
4. Output format:
   Output a final JSON block summarizing your review and the outcome for EVERY proposal:
   \`\`\`json
   {
     "summary": "Overall summary of the review, merge decisions, and integration",
     "reviews": {
       "PROP-1": {
         "status": "implemented", // "implemented" | "merge_rejected" | "conflict"
         "reason": "Detailed explanation of why this was approved & merged, or rejected/skipped"
       },
       "PROP-2": {
         "status": "merge_rejected",
         "reason": "Explanation of rejection"
       }
     }
   }
   \`\`\`
${isIterJa ? `\nLanguage Requirement:\n- Write the "summary" and each "reason" in Japanese (日本語で記述してください).\n- Keep "status" values ("implemented", "merge_rejected", "conflict") strictly in English.` : ""}`;

      const reviewLogPath = join(runDir, "phase4_review.log");
      await runToolToFile(REVIEWER, reviewPrompt, reviewLogPath, undefined, async (pid) => {
        await setCurrentTask(basename(runDir), iteration, "phase4", `Phase 4: Reviewing all proposals & merging with REVIEWER (${REVIEWER})`, reviewLogPath, "running", undefined, pid);
      });
      const reviewText = (await Bun.file(reviewLogPath).exists()) ? await Bun.file(reviewLogPath).text() : "";

      // Cleanup any dangling cherry-pick or uncommitted state
      const inCherryPick = (await runCmd("git status")).stdout.includes("cherry-pick");
      if (inCherryPick) {
        logWarn("Cherry-pick was still in progress after REVIEWER finished. Aborting remaining cherry-pick...");
        await runCmd("git cherry-pick --abort >/dev/null 2>&1 || true");
      }

      // Verify test suite and git status on main
      logInfo(`Verifying integration tests on ${currentBranch}: ${TEST_CMD}`);
      const testMain = await runCmd(TEST_CMD);
      const gitClean = (await runCmd("git status --porcelain")).stdout.trim().length === 0;
      const finalHeadRes = await runCmd("git rev-parse HEAD");
      const finalHead = finalHeadRes.stdout.trim();

      let mergeSucceeded = false;

      if (testMain.exitCode === 0 && gitClean) {
        if (finalHead !== headBeforeMerge) {
          mergeSucceeded = true;
          const logRes = await runCmd(`git log --oneline ${headBeforeMerge}..${finalHead}`);
          const count = logRes.stdout.trim().split("\n").filter(Boolean).length;
          roundCommitted += count;
          totalCommits += count;
          logOk(`Phase 4 complete! ${count} commit(s) successfully merged into ${currentBranch}.`);
        } else {
          logInfo("REVIEWER did not merge any proposals into the current branch.");
        }
      } else {
        logError(`Integration tests failed or repository dirty after REVIEWER run. Resetting to pre-merge HEAD (${headBeforeMerge.slice(0, 8)})...`);
        await runCmd(`git reset --hard "${headBeforeMerge}"`);
        await runCmd("git clean -fd >/dev/null 2>&1 || true");
      }

      // Parse REVIEWER json report
      const parsedReview = extractJson(reviewText);
      const reviewsMap: Record<string, ReviewResult> = {};

      for (const plan of approvedPlans) {
        const p3Info = p3Plans[plan.id];
        if (!p3Info || p3Info.status !== "built") continue;

        const rep = parsedReview?.reviews?.[plan.id];
        let status: ReviewResult["status"] = "merge_rejected";
        let reason = rep?.reason || "No review details provided by REVIEWER";

        if (mergeSucceeded) {
          if (rep?.status === "implemented") {
            status = "implemented";
          } else if (rep?.status === "conflict") {
            status = "conflict";
          } else {
            status = "merge_rejected";
          }
        } else if (finalHead === headBeforeMerge) {
          status = rep?.status === "conflict" ? "conflict" : "merge_rejected";
          if (!rep?.reason) reason = "No changes merged";
        } else {
          status = "failed";
          reason = "Integration tests failed on main branch";
        }

        reviewsMap[plan.id] = {
          status,
          reason,
        };

        if (status === "implemented") {
          logOk(`[MERGED] ${plan.id} (${plan.title}): ${reason}`);
        } else {
          logWarn(`[NOT MERGED] ${plan.id} (${plan.title}) [${status}]: ${reason}`);
        }
      }

      await updateRunState(runDir, {
        phase4: {
          reviews: reviewsMap,
        },
      });
    }

    // Phase 5: Clean up all worktrees and temporary branches
    logInfo("Cleaning up worktrees and temporary branches...");
    await cleanupWorktrees(runDir, iteration);

    await updateRunState(runDir, { status: "completed", end_time: new Date().toISOString() });

    // Show updated status summary
    await cmdStatus(basename(runDir), true);

    if (!loopMode) break;
    if (roundCommitted === 0) {
      logInfo(`No changes were committed in iteration #${iteration}. Ending loop.`);
      break;
    }
    logOk(`Iteration #${iteration} finished with ${roundCommitted} commit(s). Continuing loop...`);
  }

  await clearCurrentTask("completed");

  console.log("");
  logInfo("========================================================");
  logInfo("Orchestration Run Summary");
  logInfo("========================================================");
  logInfo(`Total Iterations:         ${iteration}`);
  logOk(`Total Auto-Committed:     ${totalCommits}`);
  if (quotaExhausted) {
    logError("Execution Status:         Stopped due to quota / credit exhaustion.");
  } else {
    logOk("Execution Status:         Completed successfully.");
  }
  logInfo(`To view iteration task statuses: ./scripts/refactor.ts status`);
  logInfo(`Detailed logs preserved in       ${OUTPUT_DIR}`);
}

main().catch((err) => {
  logError("Fatal error:", err);
  process.exit(1);
});
