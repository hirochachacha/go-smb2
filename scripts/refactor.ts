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

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { join, basename, resolve } from "node:path";
import { spawn } from "node:child_process";

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

const OUTPUT_DIR = process.env.OUTPUT_DIR || ".orchestration";
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
  // Use temporary script or direct execution
  const escapedPrompt = prompt.replace(/'/g, "'\\''");
  const fullCmd = `${toolCmd} -p '${escapedPrompt}' > "${outputFile}" 2>&1`;
  const res = await runCmd(fullCmd, cwd);
  return res.exitCode;
}

// Set active task pointer for real-time tracking
function setCurrentTask(runId: string, iteration: number, phase: string, taskName: string, logFile: string, status = "running") {
  mkdirSync(OUTPUT_DIR, { recursive: true });
  const absLog = resolve(logFile);
  const data = {
    run_id: runId,
    iteration,
    phase,
    task_name: taskName,
    log_file: absLog,
    status,
    updated_at: new Date().toISOString(),
  };
  writeFileSync(CURRENT_TASK_FILE, JSON.stringify(data, null, 2));
  try {
    if (existsSync(CURRENT_LOG_LINK)) rmSync(CURRENT_LOG_LINK);
    Bun.spawnSync(["ln", "-sf", absLog, CURRENT_LOG_LINK]);
  } catch {}
}

function clearCurrentTask(status = "completed") {
  if (existsSync(CURRENT_TASK_FILE)) {
    try {
      const data = JSON.parse(readFileSync(CURRENT_TASK_FILE, "utf-8"));
      data.status = status;
      data.updated_at = new Date().toISOString();
      writeFileSync(CURRENT_TASK_FILE, JSON.stringify(data, null, 2));
    } catch {}
  }
}

// Update state.json inside RUN_DIR atomically
function updateRunState(runDir: string, updates: Partial<IterationState> | Record<string, any>) {
  const stateFile = join(runDir, "state.json");
  let state: Record<string, any> = {};
  if (existsSync(stateFile)) {
    try {
      state = JSON.parse(readFileSync(stateFile, "utf-8"));
    } catch {}
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
  writeFileSync(stateFile, JSON.stringify(state, null, 2));
}

// Get numeric sort key for iteration directories (e.g. iter-1 -> 1, iter-10 -> 10)
function getRunSortKey(name: string): number {
  const m = name.match(/\d+/);
  return m ? parseInt(m[0], 10) : 99999;
}

function getIterationDirs(): string[] {
  if (!existsSync(OUTPUT_DIR)) return [];
  const entries = readdirSync(OUTPUT_DIR);
  return entries
    .filter((d) => (d.startsWith("iter-") || d.startsWith("run_")) && statSync(join(OUTPUT_DIR, d)).isDirectory())
    .sort((a, b) => getRunSortKey(a) - getRunSortKey(b));
}

function getNextIterationInfo(): { iteration: number; runDir: string } {
  const dirs = getIterationDirs();
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
  if (existsSync(wtDir)) {
    const entries = readdirSync(wtDir);
    for (const e of entries) {
      const p = join(wtDir, e);
      if (statSync(p).isDirectory()) {
        await runCmd(`git worktree remove --force "${p}" 2>/dev/null || rm -rf "${p}"`);
      }
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
function cmdStatus(targetRun?: string) {
  if (!existsSync(OUTPUT_DIR)) {
    logInfo(`No orchestration directory found at ${OUTPUT_DIR}`);
    return;
  }

  const allDirs = getIterationDirs();
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

  console.log(`${BOLD}Orchestration Status:${NC}`);
  console.log("======================================================================");

  for (const r of runs) {
    const rDir = join(OUTPUT_DIR, r);
    const stateFile = join(rDir, "state.json");
    let state: IterationState = {
      run_id: r,
      iteration: getRunSortKey(r),
      target_path: ".",
      status: "running",
      start_time: "",
    };
    if (existsSync(stateFile)) {
      try {
        state = JSON.parse(readFileSync(stateFile, "utf-8"));
      } catch {}
    }

    let timeStr = state.start_time ? state.start_time.slice(0, 19).replace("T", " ") : "";
    if (!timeStr) {
      try {
        const mtime = statSync(rDir).mtime;
        timeStr = mtime.toISOString().slice(0, 19).replace("T", " ");
      } catch {
        timeStr = "Unknown";
      }
    }

    let iterStatus = (state.status || "INCOMPLETE").toUpperCase();

    // Parse proposals and results
    const plansFile = join(rDir, "phase2_plans.json");
    let proposals: Proposal[] = [];
    if (existsSync(plansFile)) {
      try {
        const p2Data: PlansData = JSON.parse(readFileSync(plansFile, "utf-8"));
        proposals = p2Data.proposals || [];
        if (proposals.length === 0) {
          for (const p of p2Data.approved_plans || []) proposals.push({ ...p, status: "approved" });
          for (const p of p2Data.pending_reviews || []) proposals.push({ ...p, status: "pending_review" });
          for (const p of p2Data.rejected || []) proposals.push({ ...p, status: "rejected" });
        }
      } catch {}
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
    }
    const taskRows: TaskRow[] = [];

    for (const p of proposals) {
      const pid = p.id;
      const reviewStatus = p.status;
      let taskStatus = reviewStatus.toUpperCase();
      let reason = p.reason || "";
      let commitHash = "";

      if (reviewStatus === "approved") {
        const p4 = phase4Reviews[pid];
        const p3 = phase3Plans[pid];

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
      });
    }

    const statusColor = iterStatus === "COMPLETED" ? GREEN : iterStatus === "RUNNING" ? BLUE : YELLOW;
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
      if (t.tradeOffs) console.log(`      • Trade-offs: ${t.tradeOffs}`);
    }

    const summaryParts: string[] = [];
    if (implementedCount) summaryParts.push(`${GREEN}${implementedCount} implemented${NC}`);
    if (approvedCount) summaryParts.push(`${CYAN}${approvedCount} approved${NC}`);
    if (mergeRejectedCount) summaryParts.push(`${RED}${mergeRejectedCount} merge-rejected${NC}`);
    if (conflictCount) summaryParts.push(`${YELLOW}${conflictCount} conflicts${NC}`);
    if (pendingCount) summaryParts.push(`${YELLOW}${pendingCount} pending review${NC}`);
    if (rejectedCount) summaryParts.push(`${RED}${rejectedCount} rejected${NC}`);
    if (failedCount) summaryParts.push(`${MAGENTA}${failedCount} failed${NC}`);

    console.log(`\n  ${BOLD}Tasks Summary:${NC} ${summaryParts.join(", ")} (${taskRows.length} total)`);
  }

  console.log("\n======================================================================\n");
}

// Command: remove
function cmdRemove(targetRun?: string, force = false) {
  if (!existsSync(OUTPUT_DIR)) {
    logInfo(`No orchestration directory found at ${OUTPUT_DIR}`);
    return;
  }

  const allDirs = getIterationDirs();
  if (targetRun) {
    const rDir = join(OUTPUT_DIR, targetRun);
    if (!existsSync(rDir)) {
      logError(`Iteration directory not found: ${targetRun}`);
      process.exit(1);
    }
    const stateFile = join(rDir, "state.json");
    let isCompleted = false;
    if (existsSync(stateFile)) {
      try {
        const s = JSON.parse(readFileSync(stateFile, "utf-8"));
        if (s.status === "completed") isCompleted = true;
      } catch {}
    }
    if (!force && !isCompleted) {
      logWarn(`Iteration '${targetRun}' is not completed. Use --force to remove incomplete iteration.`);
      process.exit(1);
    }
    rmSync(rDir, { recursive: true, force: true });
    logOk(`Removed iteration: ${targetRun}`);
  } else {
    const removed: string[] = [];
    const skipped: string[] = [];
    for (const r of allDirs) {
      const rDir = join(OUTPUT_DIR, r);
      const stateFile = join(rDir, "state.json");
      let isCompleted = false;
      if (existsSync(stateFile)) {
        try {
          const s = JSON.parse(readFileSync(stateFile, "utf-8"));
          if (s.status === "completed") isCompleted = true;
        } catch {}
      }
      if (isCompleted) {
        rmSync(rDir, { recursive: true, force: true });
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
  let tailProc: ReturnType<typeof spawn> | null = null;

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

    const allDirs = getIterationDirs();
    const latestRun = allDirs.length > 0 ? join(OUTPUT_DIR, allDirs[allDirs.length - 1]) : "";

    if (targetTask) {
      if (latestRun && existsSync(join(latestRun, `phase3_exec_${targetTask}.log`))) {
        logFile = join(latestRun, `phase3_exec_${targetTask}.log`);
        taskName = `Task ${targetTask}`;
        runId = basename(latestRun);
        phase = "phase3";
      }
    } else if (existsSync(CURRENT_TASK_FILE)) {
      try {
        const info = JSON.parse(readFileSync(CURRENT_TASK_FILE, "utf-8"));
        runId = info.run_id || "";
        phase = info.phase || "";
        taskName = info.task_name || "";
        logFile = info.log_file || "";
      } catch {}
    }

    if (logFile && logFile !== currentLog && existsSync(logFile)) {
      if (tailProc) tailProc.kill();
      currentLog = logFile;
      console.log("");
      console.log(`${BLUE}================================================================${NC}`);
      console.log(`${GREEN}[WATCHING]${NC} Run: ${YELLOW}${runId}${NC} | Phase: ${YELLOW}${phase}${NC}`);
      console.log(`${GREEN}[TASK]${NC}     ${taskName}`);
      console.log(`${GREEN}[LOG FILE]${NC} ${logFile}`);
      console.log(`${BLUE}================================================================${NC}`);

      tailProc = spawn("tail", ["-n", "25", "-f", logFile], { stdio: "inherit" });
    }

    await new Promise((r) => setTimeout(r, 1000));
  }
}

// Find latest incomplete run directory
function findLatestIncompleteRun(): string | null {
  const allDirs = getIterationDirs();
  for (let i = allDirs.length - 1; i >= 0; i--) {
    const rDir = join(OUTPUT_DIR, allDirs[i]);
    const stateFile = join(rDir, "state.json");
    if (!existsSync(stateFile)) return rDir;
    try {
      const s = JSON.parse(readFileSync(stateFile, "utf-8"));
      if (s.status !== "completed") return rDir;
    } catch {
      return rDir;
    }
  }
  return null;
}

// --- Main Orchestration Loop ---

async function main() {
  const args = process.argv.slice(2);

  // Subcommand dispatch
  if (args.length > 0) {
    const cmd = args[0];
    if (cmd === "status" || cmd === "--status") {
      cmdStatus(args[1]);
      return;
    }
    if (cmd === "watch" || cmd === "tail" || cmd === "--watch") {
      await cmdWatch(args[1]);
      return;
    }
    if (cmd === "remove" || cmd === "rm" || cmd === "--remove") {
      const force = args.includes("-f") || args.includes("--force");
      const target = args.slice(1).find((a) => !a.startsWith("-"));
      cmdRemove(target, force);
      return;
    }
    if (cmd === "-h" || cmd === "--help") {
      console.log(`Usage: ./scripts/refactor.ts [COMMAND] [OPTIONS] [TARGET_PATH]

Commands:
  run [OPTIONS] [TARGET_PATH]   Run refactoring orchestration
  status [ITERATION]            Display task status (implemented/approved/pending/rejected) per iteration
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
      return;
    }
  }

  // Parse options for run / resume
  let loopMode = false;
  let resumeDir: string | null = null;
  let targetPath = ".";

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "run") continue;
    if (a === "--loop") {
      loopMode = true;
    } else if (a === "resume" || a === "--resume") {
      const nextArg = args[i + 1];
      if (nextArg && !nextArg.startsWith("-")) {
        resumeDir = nextArg.startsWith("/") || nextArg.startsWith(".") ? nextArg : join(OUTPUT_DIR, nextArg);
        i++;
      } else {
        resumeDir = findLatestIncompleteRun();
        if (!resumeDir) {
          logError(`No incomplete iteration found in ${OUTPUT_DIR} to resume.`);
          process.exit(1);
        }
      }
    } else if (!a.startsWith("-")) {
      targetPath = a;
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

  mkdirSync(OUTPUT_DIR, { recursive: true });

  let activeRunDir = "";
  let activeIteration = 0;

  process.on("SIGINT", async () => {
    console.log("");
    logWarn("Interrupted! Cleaning up worktrees and restoring git working tree...");
    clearCurrentTask("stopped");
    if (activeRunDir && existsSync(activeRunDir)) {
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
      const next = getNextIterationInfo();
      iteration = next.iteration;
      runDir = next.runDir;
      mkdirSync(runDir, { recursive: true });
    }

    activeRunDir = runDir;
    activeIteration = iteration;

    const proposalsFile = join(runDir, "phase1_proposals.md");
    const plansFile = join(runDir, "phase2_plans.json");
    const reviewSummaryFile = join(runDir, "review_summary.md");

    updateRunState(runDir, {
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
    if (existsSync(proposalsFile) && statSync(proposalsFile).size > 0) {
      logOk(`Phase 1: Existing proposals found in ${proposalsFile}. Skipping exploration.`);
    } else {
      logInfo(`Phase 1: Starting code investigation with AUDITOR (${AUDITOR}, target: '${targetPath}')...`);
      const auditorRawLog = join(runDir, "phase1_raw.log");
      setCurrentTask(basename(runDir), iteration, "phase1", `Phase 1: Code audit with AUDITOR (${AUDITOR})`, proposalsFile);

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

      const exitCode = await runToolToFile(AUDITOR, auditorPrompt, proposalsFile);
      const outputText = existsSync(proposalsFile) ? readFileSync(proposalsFile, "utf-8") : "";

      if (isQuotaExhausted(outputText)) {
        logError("API quota / credit limit exhausted in AUDITOR (Phase 1). Terminating.");
        updateRunState(runDir, { status: "failed" });
        quotaExhausted = true;
        break;
      }

      if (exitCode !== 0) {
        logError(`AUDITOR investigation failed with exit code ${exitCode}. Check ${proposalsFile}`);
        updateRunState(runDir, { status: "failed" });
        break;
      }

      if (outputText.trim().length === 0) {
        logInfo("AUDITOR generated an empty proposal report. Reached a clean state.");
        updateRunState(runDir, { status: "completed" });
        break;
      }

      logOk(`Phase 1 complete. Proposals saved to ${proposalsFile}`);
    }

    updateRunState(runDir, { phase1: { status: "completed" } });

    // --- Phase 2: Planning & Screening (PLANNER) ---
    if (existsSync(plansFile) && statSync(plansFile).size > 0) {
      logOk(`Phase 2: Existing plans found in ${plansFile}. Skipping planning.`);
    } else {
      logInfo(`Phase 2: Reviewing proposals and planning with PLANNER (${PLANNER})...`);
      const rawReviewFile = join(runDir, "raw_review.txt");
      setCurrentTask(basename(runDir), iteration, "phase2", `Phase 2: Planning with PLANNER (${PLANNER})`, rawReviewFile);

      const proposalsText = readFileSync(proposalsFile, "utf-8");
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

      const exitCode = await runToolToFile(PLANNER, plannerPrompt, rawReviewFile);
      const rawText = existsSync(rawReviewFile) ? readFileSync(rawReviewFile, "utf-8") : "";

      if (isQuotaExhausted(rawText)) {
        logError("API quota / credit limit exhausted in PLANNER (Phase 2). Terminating.");
        updateRunState(runDir, { status: "failed" });
        quotaExhausted = true;
        break;
      }

      if (exitCode !== 0 || !rawText.trim()) {
        logError(`PLANNER failed with exit code ${exitCode}. Check ${rawReviewFile}`);
        updateRunState(runDir, { status: "failed" });
        break;
      }

      // Parse and normalize JSON
      let jsonObj: any = null;
      const fenceMatch = rawText.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
      if (fenceMatch) {
        try { jsonObj = JSON.parse(fenceMatch[1]); } catch {}
      }
      if (!jsonObj) {
        const fb = rawText.indexOf("{");
        const lb = rawText.lastIndexOf("}");
        if (fb !== -1 && lb > fb) {
          try { jsonObj = JSON.parse(rawText.slice(fb, lb + 1)); } catch {}
        }
      }

      if (!jsonObj) {
        logError(`Failed to parse valid JSON from PLANNER output. Check ${rawReviewFile}`);
        updateRunState(runDir, { status: "failed" });
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

      writeFileSync(plansFile, JSON.stringify(jsonObj, null, 2));

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
      writeFileSync(reviewSummaryFile, summaryMd);

      logOk(`Phase 2 complete. Plans parsed to ${plansFile}`);
    }

    updateRunState(runDir, { phase2: { status: "completed" } });

    // Show task status after planning
    cmdStatus(basename(runDir));

    // --- Phase 3: Concurrent Execution with git worktree (DEVELOPER) ---
    const plansData: PlansData = JSON.parse(readFileSync(plansFile, "utf-8"));
    const approvedPlans = plansData.approved_plans || [];
    logInfo(`Approved plans for execution: ${approvedPlans.length} (Concurrency: ${PARALLEL_JOBS})`);

    if (approvedPlans.length === 0) {
      logInfo("No approved plans in this round. Codebase is in clean state.");
      updateRunState(runDir, { status: "completed", end_time: new Date().toISOString() });
      if (loopMode) break;
      return;
    }

    const wtBaseDir = join(runDir, "worktrees");
    mkdirSync(wtBaseDir, { recursive: true });

    logInfo(`Launching DEVELOPER tasks concurrently across git worktrees (max ${PARALLEL_JOBS})...`);

    // Run each approved plan inside its isolated git worktree
    await asyncPool(PARALLEL_JOBS, approvedPlans, async (plan, idx) => {
      const planId = plan.id;
      const planTitle = plan.title;
      const branchName = `refactor/iter-${iteration}/${planId}`;
      const worktreeDir = join(wtBaseDir, planId);
      const execLog = join(runDir, `phase3_exec_${planId}.log`);

      logInfo(`[DEVELOPER ${idx + 1}/${approvedPlans.length}] Starting: ${planId} - ${planTitle}`);
      setCurrentTask(basename(runDir), iteration, "phase3", `DEVELOPER on ${planId}: ${planTitle}`, execLog);

      // Create isolated worktree
      if (existsSync(worktreeDir)) rmSync(worktreeDir, { recursive: true, force: true });
      await runCmd(`git branch -D "${branchName}" >/dev/null 2>&1 || true`);
      const wtRes = await runCmd(`git worktree add -B "${branchName}" "${worktreeDir}" HEAD`);
      if (wtRes.exitCode !== 0) {
        logError(`Failed to create worktree for ${planId}: ${wtRes.stderr}`);
        updateRunState(runDir, { phase3: { plans: { [planId]: { status: "worktree_failed" } } } });
        return;
      }

      updateRunState(runDir, { phase3: { plans: { [planId]: { status: "running" } } } });

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

      await runToolToFile(DEVELOPER, devPrompt, execLog, worktreeDir);
      const logContent = existsSync(execLog) ? readFileSync(execLog, "utf-8") : "";

      if (isQuotaExhausted(logContent)) {
        logError(`Quota exhausted during ${planId}`);
        updateRunState(runDir, { phase3: { plans: { [planId]: { status: "quota_exhausted" } } } });
        quotaExhausted = true;
        return;
      }

      // Run tests inside worktree
      const testRes = await runCmd(TEST_CMD, worktreeDir);
      if (testRes.exitCode === 0) {
        // Stage ONLY target files
        await runCmd("git reset HEAD --quiet", worktreeDir);
        for (const f of plan.target_files || []) {
          const check = await runCmd(`git ls-files --error-unmatch "${f}" 2>/dev/null || test -e "${f}"`, worktreeDir);
          if (check.exitCode === 0) {
            await runCmd(`git add "${f}"`, worktreeDir);
          }
        }

        const diffCheck = await runCmd("git diff --cached --quiet", worktreeDir);
        if (diffCheck.exitCode === 0) {
          logWarn(`No changes staged in target files for ${planId}`);
          updateRunState(runDir, { phase3: { plans: { [planId]: { status: "no_changes" } } } });
        } else {
          const commitMsg = plan.commit_message || `fix: ${planTitle}`;
          await runCmd(`git commit -m "${commitMsg.replace(/"/g, '\\"')}"`, worktreeDir);
          await runCmd("git reset --hard HEAD >/dev/null 2>&1 || true", worktreeDir);
          await runCmd("git clean -fd >/dev/null 2>&1 || true", worktreeDir);

          const commitHashRes = await runCmd("git rev-parse --short HEAD", worktreeDir);
          const commitHash = commitHashRes.stdout.trim();
          logOk(`Built ${planId} in worktree: ${commitHash}`);
          updateRunState(runDir, {
            phase3: { plans: { [planId]: { status: "built", commit: commitHash, branch: branchName } } },
          });
        }
      } else {
        logError(`Tests failed inside worktree for ${planId}`);
        updateRunState(runDir, { phase3: { plans: { [planId]: { status: "test_failed" } } } });
      }
    });

    if (quotaExhausted) {
      updateRunState(runDir, { status: "stopped" });
      await cleanupWorktrees(runDir, iteration);
      break;
    }

    updateRunState(runDir, { phase3: { status: "completed" } });
    logOk("Phase 3 complete. All DEVELOPER worktree tasks finished.");

    // --- Phase 4: Diff Review & Merge (REVIEWER) ---
    logInfo(`Phase 4: Starting diff reviews and merge verification with REVIEWER (${REVIEWER})...`);
    setCurrentTask(basename(runDir), iteration, "phase4", `Phase 4: Diff review with REVIEWER (${REVIEWER})`, join(runDir, "phase4_raw.log"));

    const stateAfterP3: IterationState = JSON.parse(readFileSync(join(runDir, "state.json"), "utf-8"));
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

      const reviewLog = join(runDir, `phase4_review_${planId}.log`);
      await runToolToFile(REVIEWER, reviewPrompt, reviewLog);
      const reviewText = existsSync(reviewLog) ? readFileSync(reviewLog, "utf-8") : "";

      let decisionStatus = "merge_rejected";
      let decisionReason = "Failed to parse reviewer judgment";

      try {
        const fm = reviewText.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
        const parsed = fm ? JSON.parse(fm[1]) : JSON.parse(reviewText.slice(reviewText.indexOf("{"), reviewText.lastIndexOf("}") + 1));
        decisionStatus = parsed.status || "merge_rejected";
        decisionReason = parsed.reason || "No reason specified";
      } catch {}

      if (decisionStatus === "merge_approved") {
        logOk(`REVIEWER approved merge for ${planId}! (${decisionReason})`);
        logInfo(`Cherry-picking ${p3Info.commit} into main branch...`);

        const cpRes = await runCmd(`git cherry-pick "${commitHash}"`);
        if (cpRes.exitCode === 0) {
          // Re-verify test suite on main
          logInfo(`Verifying integration tests on main: ${TEST_CMD}`);
          const testMain = await runCmd(TEST_CMD);
          if (testMain.exitCode === 0) {
            const newCommitRes = await runCmd("git rev-parse --short HEAD");
            const newCommit = newCommitRes.stdout.trim();
            logOk(`Successfully merged ${planId}! Commit: ${newCommit}`);
            roundCommitted++;
            totalCommits++;
            updateRunState(runDir, {
              phase4: { reviews: { [planId]: { status: "implemented", commit: newCommit, reason: decisionReason } } },
            });
          } else {
            logError(`Integration tests failed after cherry-picking ${planId}! Reverting...`);
            await runCmd("git reset --hard HEAD~1");
            updateRunState(runDir, {
              phase4: { reviews: { [planId]: { status: "failed", reason: "Integration test failed after cherry-pick" } } },
            });
          }
        } else {
          logWarn(`Merge conflict encountered while cherry-picking ${planId}! Aborting cherry-pick.`);
          await runCmd("git cherry-pick --abort");
          updateRunState(runDir, {
            phase4: { reviews: { [planId]: { status: "conflict", reason: "Merge conflict with earlier merged changes" } } },
          });
        }
      } else {
        logWarn(`REVIEWER rejected merge for ${planId}: ${decisionReason}`);
        updateRunState(runDir, {
          phase4: { reviews: { [planId]: { status: "merge_rejected", reason: decisionReason } } },
        });
      }
    }

    // Phase 5: Clean up all worktrees and temporary branches
    logInfo("Cleaning up worktrees and temporary branches...");
    await cleanupWorktrees(runDir, iteration);

    updateRunState(runDir, { status: "completed", end_time: new Date().toISOString() });

    // Show updated status
    cmdStatus(basename(runDir));

    if (!loopMode) break;
    if (roundCommitted === 0) {
      logInfo(`No changes were committed in iteration #${iteration}. Ending loop.`);
      break;
    }
    logOk(`Iteration #${iteration} finished with ${roundCommitted} commit(s). Continuing loop...`);
  }

  clearCurrentTask("completed");

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
