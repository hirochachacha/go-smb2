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
}

interface ReviewResult {
  status: "implemented" | "merge_rejected" | "conflict" | "failed";
  commit?: string;
  reason?: string;
}

interface IterationState {
  run_id: string;
  iteration: number;
  target_path: string;
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
  return /(quota.*exceeded|exceeded.*quota|rate.*limit|too many requests|insufficient.*quota|insufficient.*credit|insufficient_quota|resource.*exhausted|usage.*limit|out of credits|billing.*error|429)/i.test(text);
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
async function runToolToFile(toolCmd: string, prompt: string, outputFile: string, cwd?: string): Promise<number> {
  const absOutputFile = resolve(outputFile);
  await mkdir(dirname(absOutputFile), { recursive: true });
  const escapedPrompt = prompt.replace(/'/g, "'\\''");
  const fullCmd = `${toolCmd} -p '${escapedPrompt}' > "${absOutputFile}" 2>&1`;
  const res = await runCmd(fullCmd, cwd);
  return res.exitCode;
}

// Set active task pointer for real-time tracking
async function setCurrentTask(runId: string, iteration: number, phase: string, taskName: string, logFile: string, status = "running", worktreeDir?: string) {
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
  await Bun.write(CURRENT_TASK_FILE, JSON.stringify(data, null, 2));
  try {
    const logLink = Bun.file(CURRENT_LOG_LINK);
    if (await logLink.exists()) await rm(CURRENT_LOG_LINK, { force: true });
    Bun.spawn(["ln", "-sf", absLog, CURRENT_LOG_LINK]);
  } catch (err) {
    logWarn(`Failed to create current log symlink ${CURRENT_LOG_LINK}: ${err}`);
  }
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
    if (b) await runCmd(`git branch -D "${b}" >/dev/null 2>&1`);
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

    proposals.sort((a, b) => {
      const numA = parseInt((a.id.match(/\d+/) || ["99999"])[0], 10);
      const numB = parseInt((b.id.match(/\d+/) || ["99999"])[0], 10);
      return numA - numB;
    });

    const phase3Plans = state.phase3?.plans || {};
    const phase4Reviews = state.phase4?.reviews || {};

    let implementedCount = 0;
    let approvedCount = 0;
    let mergeRejectedCount = 0;
    let conflictCount = 0;
    let pendingCount = 0;
    let rejectedCount = 0;
    let failedCount = 0;

    interface TaskRow {
      id: string;
      title: string;
      status: string;
      reason: string;
      files: string[];
      commit: string;
      tradeOffs?: string;
      worktree?: string;
    }
    const taskRows: TaskRow[] = [];

    for (const p of proposals) {
      const pid = p.id;
      const reviewStatus = p.status;
      let taskStatus = reviewStatus.toUpperCase();
      let reason = p.reason || "";
      let commitHash = "";
      let worktree = "";

      if (reviewStatus === "approved") {
        const p4 = phase4Reviews[pid];
        const p3 = phase3Plans[pid];
        if (p3 && p3.worktree) worktree = p3.worktree;

        if (p4) {
          if (p4.status === "implemented") {
            taskStatus = "IMPLEMENTED";
            commitHash = p4.commit || "";
            reason = p4.reason || reason;
            implementedCount++;
          } else if (p4.status === "merge_rejected") {
            taskStatus = "MERGE_REJECTED";
            reason = p4.reason || reason;
            mergeRejectedCount++;
          } else if (p4.status === "conflict") {
            taskStatus = "MERGE_CONFLICT";
            reason = p4.reason || "Merge conflict during cherry-pick";
            conflictCount++;
          } else {
            taskStatus = "FAILED";
            reason = p4.reason || "Integration test failed";
            failedCount++;
          }
        } else if (p3) {
          if (p3.status === "built") {
            taskStatus = "BUILT";
            commitHash = p3.commit || "";
            approvedCount++;
          } else if (p3.status === "test_failed") {
            taskStatus = "FAILED";
            failedCount++;
          } else if (p3.status === "running") {
            taskStatus = "DEVELOPING";
          } else {
            taskStatus = "APPROVED";
            approvedCount++;
          }
        } else {
          taskStatus = "APPROVED";
          approvedCount++;
        }
      } else if (reviewStatus === "pending_review") {
        taskStatus = "PENDING_REVIEW";
        pendingCount++;
      } else if (reviewStatus === "rejected") {
        taskStatus = "REJECTED";
        rejectedCount++;
      }

      taskRows.push({
        id: pid,
        title: p.title,
        status: taskStatus,
        reason,
        files: p.target_files || [],
        commit: commitHash,
        tradeOffs: p.trade_offs,
        worktree,
      });
    }

    const statusColor = iterStatus === "COMPLETED" ? GREEN : iterStatus === "RUNNING" ? BLUE : YELLOW;
    const summaryParts: string[] = [];
    if (implementedCount) summaryParts.push(`${GREEN}${implementedCount} implemented${NC}`);
    if (approvedCount) summaryParts.push(`${CYAN}${approvedCount} approved${NC}`);
    if (mergeRejectedCount) summaryParts.push(`${RED}${mergeRejectedCount} merge-rejected${NC}`);
    if (conflictCount) summaryParts.push(`${YELLOW}${conflictCount} conflicts${NC}`);
    if (pendingCount) summaryParts.push(`${YELLOW}${pendingCount} pending review${NC}`);
    if (rejectedCount) summaryParts.push(`${RED}${rejectedCount} rejected${NC}`);
    if (failedCount) summaryParts.push(`${MAGENTA}${failedCount} failed${NC}`);

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
      let badge = `  [${t.id}] ${t.status.padEnd(14)}`;
      if (t.status === "IMPLEMENTED") badge = `${GREEN}✓ [${t.id}] IMPLEMENTED   ${NC}`;
      else if (t.status === "APPROVED") badge = `${CYAN}● [${t.id}] APPROVED      ${NC}`;
      else if (t.status === "BUILT") badge = `${CYAN}● [${t.id}] BUILT (DIFF OK)${NC}`;
      else if (t.status === "DEVELOPING") badge = `${BLUE}⚙ [${t.id}] DEVELOPING    ${NC}`;
      else if (t.status === "PENDING_REVIEW") badge = `${YELLOW}? [${t.id}] PENDING_REVIEW${NC}`;
      else if (t.status === "REJECTED") badge = `${RED}✗ [${t.id}] REJECTED      ${NC}`;
      else if (t.status === "MERGE_REJECTED") badge = `${RED}✗ [${t.id}] MERGE_REJECTED${NC}`;
      else if (t.status === "MERGE_CONFLICT") badge = `${YELLOW}⚠ [${t.id}] MERGE_CONFLICT${NC}`;
      else if (t.status === "FAILED") badge = `${MAGENTA}✗ [${t.id}] FAILED        ${NC}`;

      const commitStr = t.commit ? ` (commit: ${CYAN}${t.commit}${NC})` : "";
      console.log(`  ${badge} ${BOLD}${t.title}${NC}${commitStr}`);
      if (t.reason) console.log(`      • Reason: ${t.reason}`);
      if (t.files.length > 0) console.log(`      • Target files: ${t.files.join(", ")}`);
      if (t.worktree) console.log(`      • Worktree: ${t.worktree}`);
      if (t.tradeOffs) console.log(`      • Trade-offs: ${t.tradeOffs}`);
    }

    console.log(`\n  ${BOLD}Tasks Summary:${NC} ${summaryText} (${taskRows.length} total)`);
  }

  if (!summaryOnly) {
    console.log("\n======================================================================\n");
  }
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
    await rm(rDir, { recursive: true, force: true });
    logOk(`Removed iteration: ${targetRun}`);
  } else {
    const removed: string[] = [];
    const skipped: string[] = [];
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
        await rm(rDir, { recursive: true, force: true });
        removed.push(r);
      } else {
        skipped.push(r);
      }
    }
    if (removed.length > 0) logOk(`Removed ${removed.length} completed iteration(s): ${removed.join(", ")}`);
    else console.log("No completed iterations found to remove.");
    if (skipped.length > 0) logWarn(`Kept ${skipped.length} incomplete iteration(s): ${skipped.join(", ")}`);
  }
}

// Command: watch
async function cmdWatch(targetTask?: string) {
  logInfo("Watching orchestration task log in real-time (Press Ctrl+C to stop)...");

  let currentLog = "";
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

    const allDirs = await getIterationDirs();
    const latestRun = allDirs.length > 0 ? join(OUTPUT_DIR, allDirs[allDirs.length - 1]) : "";

    let worktreeDir = "";

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
          if (await dirExists(targetWt)) worktreeDir = targetWt;
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
        } catch {}
      }
    }

    if (logFile && logFile !== currentLog) {
      const targetLog = Bun.file(logFile);
      if (await targetLog.exists()) {
        if (tailProc) tailProc.kill();
        currentLog = logFile;
        console.log("");
        console.log(`${BLUE}================================================================${NC}`);
        console.log(`${GREEN}[WATCHING]${NC} Run: ${YELLOW}${runId}${NC} | Phase: ${YELLOW}${phase}${NC}`);
        console.log(`${GREEN}[TASK]${NC}     ${taskName}`);
        if (worktreeDir) {
          console.log(`${GREEN}[WORKTREE]${NC} ${worktreeDir}`);
        }
        console.log(`${GREEN}[LOG FILE]${NC} ${logFile}`);
        console.log(`${BLUE}================================================================${NC}`);

        tailProc = Bun.spawn(["tail", "-n", "25", "-f", logFile], { stdout: "inherit", stderr: "inherit" });
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
  TARGET_PATH                   Target directory/file to inspect (default: .)

Environment variables:
  AUDITOR                       Investigation tool (required)
  PLANNER                       Planning & screening tool (required)
  DEVELOPER                     Execution/implementation tool (required)
  REVIEWER                      Diff review & merge tool (required)
  PARALLEL_JOBS                 Concurrent worktree jobs for DEVELOPER (default: 3)
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
  const subArgs = args.slice(1);

  if (cmd === "resume") {
    for (let i = 0; i < subArgs.length; i++) {
      const a = subArgs[i];
      if (a === "--loop") {
        loopMode = true;
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
    logWarn("Interrupted! Cleaning up worktrees and restoring git working tree...");
    await clearCurrentTask("stopped");
    if (activeRunDir && (await dirExists(activeRunDir))) {
      await cleanupWorktrees(activeRunDir, activeIteration);
    }
    await runCmd("git reset --hard HEAD >/dev/null 2>&1 || true");
    await runCmd("git clean -fd >/dev/null 2>&1 || true");
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

    const proposalsPath = join(runDir, "phase1_proposals.md");
    const proposalsFile = Bun.file(proposalsPath);
    const plansPath = join(runDir, "phase2_plans.json");
    const plansFile = Bun.file(plansPath);
    const reviewSummaryPath = join(runDir, "review_summary.md");

    await updateRunState(runDir, {
      run_id: basename(runDir),
      iteration,
      target_path: targetPath,
      status: "running",
      start_time: new Date().toISOString(),
    });

    if (loopMode) {
      console.log("");
      logInfo("========================================================");
      logInfo(`Iteration #${iteration} (Target: '${targetPath}')`);
      logInfo(`Run Directory: ${runDir}`);
      logInfo("========================================================");
    } else {
      logOk(`Run directory: ${runDir}`);
    }

    // --- Phase 1: Exploration & Proposals (AUDITOR) ---
    if ((await proposalsFile.exists()) && proposalsFile.size > 0) {
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
  - Trade-offs or potential risks (if any)`;

      const exitCode = await runToolToFile(AUDITOR, auditorPrompt, proposalsPath);
      const outputText = (await proposalsFile.exists()) ? await proposalsFile.text() : "";

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
    if ((await plansFile.exists()) && plansFile.size > 0) {
      logOk(`Phase 2: Existing plans found in ${plansPath}. Skipping planning.`);
    } else {
      logInfo(`Phase 2: Reviewing proposals and planning with PLANNER (${PLANNER})...`);
      const rawReviewPath = join(runDir, "raw_review.txt");
      const rawReviewFile = Bun.file(rawReviewPath);
      await setCurrentTask(basename(runDir), iteration, "phase2", `Phase 2: Planning with PLANNER (${PLANNER})`, rawReviewPath);

      const proposalsText = await proposalsFile.text();
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
   Every proposal must clearly state its status and a concrete reason explaining WHY it is approved, pending_review, or rejected.

   JSON structure:
   {
     "summary": "Brief overall summary of the review and plan",
     "proposals": [
       {
         "id": "PROP-1",
         "title": "Short title",
         "status": "approved", // "approved" | "pending_review" | "rejected"
         "reason": "Clear explanation of WHY this proposal is approved, pending_review, or rejected",
         "target_files": ["file1.go", "file1_test.go"],
         "commit_message": "fix: concise subject\\n\\n- detail 1\\n- detail 2", // required if approved
         "instructions": "Step-by-step TDD instructions: 1) failing test, 2) minimal fix, 3) verify", // required if approved
         "trade_offs": "Trade-offs or risks" // optional, recommended for pending_review
       }
     ]
   }

Here are the proposals:
${proposalsText}`;

      const exitCode = await runToolToFile(PLANNER, plannerPrompt, rawReviewPath);
      const rawText = (await rawReviewFile.exists()) ? await rawReviewFile.text() : "";

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
        summaryMd += `  - **Reason**: ${p.reason || "N/A"}\n`;
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
    const plansData: PlansData = await plansFile.json();
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
      const execLogFile = Bun.file(execLogPath);

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
        logError(`Failed to create worktree for ${planId} at ${worktreeDir}: ${wtRes.stderr}`);
        await updateRunState(runDir, { phase3: { plans: { [planId]: { status: "worktree_failed" } } } });
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

      const devExitCode = await runToolToFile(DEVELOPER, devPrompt, execLogPath, worktreeDir);
      if (devExitCode !== 0) {
        logWarn(`DEVELOPER process exited with code ${devExitCode} for ${planId}. Inspect logs at: ${execLogPath}`);
      }
      const logContent = (await execLogFile.exists()) ? await execLogFile.text() : "";

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
          if (statusCheck.stdout.trim().length > 0) {
            logWarn(`Changes were made for ${planId} (${worktreeDir}), but none in target files [${(plan.target_files || []).join(", ")}]`);
          } else {
            logWarn(`No changes produced in worktree for ${planId} (${worktreeDir})`);
          }
          await updateRunState(runDir, { phase3: { plans: { [planId]: { status: "no_changes", branch: branchName, worktree: worktreeDir } } } });
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
        logError(`Tests failed inside worktree for ${planId} (${worktreeDir}): ${testRes.stderr || testRes.stdout}`);
        await updateRunState(runDir, { phase3: { plans: { [planId]: { status: "test_failed", branch: branchName, worktree: worktreeDir } } } });
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
    logInfo(`Phase 4: Starting diff reviews and merge verification with REVIEWER (${REVIEWER})...`);
    await setCurrentTask(basename(runDir), iteration, "phase4", `Phase 4: Diff review with REVIEWER (${REVIEWER})`, join(runDir, "phase4_raw.log"));

    const stateAfterP3: IterationState = await Bun.file(join(runDir, "state.json")).json();
    const p3Plans = stateAfterP3.phase3?.plans || {};

    for (const plan of approvedPlans) {
      const planId = plan.id;
      const planTitle = plan.title;
      const p3Info = p3Plans[planId];

      if (!p3Info || p3Info.status !== "built" || !p3Info.branch) {
        logWarn(`Plan ${planId} did not produce a clean commit. Skipping review & merge.`);
        continue;
      }

      const branchName = p3Info.branch;
      const commitRes = await runCmd(`git rev-parse "${branchName}"`);
      const commitHash = commitRes.stdout.trim();
      if (!commitHash) continue;

      const diffRes = await runCmd(`git show "${commitHash}" --stat -p`);
      const commitDiff = diffRes.stdout;

      console.log("");
      logInfo("========================================================");
      logInfo(`REVIEWER inspecting git diff for ${planId}: ${planTitle}`);
      logInfo("========================================================");

      const reviewPrompt = `You are a senior reviewer inspecting the actual git commit diff implemented by a developer.

Task: ${planTitle}
Target files: ${(plan.target_files || []).join(", ")}
Original Instructions:
${plan.instructions || ""}

Developer's actual commit diff:
${commitDiff}

Review rules:
1. Verify minimal change: Does the diff apply ONLY the required minimal changes without scope creep or unrelated edits?
2. Verify correctness: Does the code adhere to Go idioms, protocol safety, and project standards?
3. Decide whether this commit is safe and ready to merge into main.

Output format:
Output ONLY valid JSON (no markdown code blocks, no backticks, no commentary):
{
  "status": "merge_approved", // or "merge_rejected"
  "reason": "Concise explanation of why this change is approved to merge or rejected"
}`;

      const reviewLogPath = join(runDir, `phase4_review_${planId}.log`);
      const reviewLogFile = Bun.file(reviewLogPath);
      await runToolToFile(REVIEWER, reviewPrompt, reviewLogPath);
      const reviewText = (await reviewLogFile.exists()) ? await reviewLogFile.text() : "";

      let decisionStatus = "merge_rejected";
      let decisionReason = "Failed to parse reviewer judgment";

      const parsed = extractJson(reviewText);
      if (parsed) {
        decisionStatus = parsed.status || "merge_rejected";
        decisionReason = parsed.reason || "No reason specified";
      }

      const norm = (decisionStatus || "").toLowerCase();
      const isApproved = norm === "merge_approved" || norm === "approved";

      if (isApproved) {
        logOk(`REVIEWER approved merge for ${planId}! (${decisionReason})`);
        const currentBranchRes = await runCmd("git rev-parse --abbrev-ref HEAD");
        const currentBranch = currentBranchRes.stdout.trim() || "HEAD";
        logInfo(`Cherry-picking ${commitHash} into ${currentBranch}...`);

        const cpRes = await runCmd(`git cherry-pick "${commitHash}"`);
        if (cpRes.exitCode === 0) {
          // Re-verify test suite on main
          logInfo(`Verifying integration tests on ${currentBranch}: ${TEST_CMD}`);
          const testMain = await runCmd(TEST_CMD);
          if (testMain.exitCode === 0) {
            const newCommitRes = await runCmd("git rev-parse --short HEAD");
            const newCommit = newCommitRes.stdout.trim();
            logOk(`Successfully merged ${planId}! Commit: ${newCommit}`);
            roundCommitted++;
            totalCommits++;
            await updateRunState(runDir, {
              phase4: { reviews: { [planId]: { status: "implemented", commit: newCommit, reason: decisionReason } } },
            });
          } else {
            logError(`Integration tests failed after cherry-picking ${planId}! Reverting...`);
            await runCmd("git reset --hard HEAD~1");
            await updateRunState(runDir, {
              phase4: { reviews: { [planId]: { status: "failed", reason: "Integration test failed after cherry-pick" } } },
            });
          }
        } else {
          logWarn(`Merge conflict encountered while cherry-picking ${planId}! Aborting cherry-pick.`);
          await runCmd("git cherry-pick --abort >/dev/null 2>&1 || git reset --hard HEAD");
          await updateRunState(runDir, {
            phase4: { reviews: { [planId]: { status: "conflict", reason: "Merge conflict with earlier merged changes" } } },
          });
        }
      } else {
        logWarn(`REVIEWER rejected merge for ${planId}: ${decisionReason}`);
        await updateRunState(runDir, {
          phase4: { reviews: { [planId]: { status: "merge_rejected", reason: decisionReason } } },
        });
      }
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
