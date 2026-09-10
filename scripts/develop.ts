#!/usr/bin/env bun
//
// develop.ts
//
// Development workflow:
// audit: AUDITOR finds defects; VALIDATOR independently checks evidence.
// implement: Send the original request directly to DEVELOPER.
// 3. DEVELOPER: Execute approved plans concurrently across isolated git worktrees.
// 4. REVIEWER: Review actual commit diffs from each worktree, verify safety, and merge.
//

import { appendFile, mkdir, readdir, readlink, rename, rm, stat, symlink, unlink } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { join, basename, resolve, dirname } from "node:path";
import { homedir } from "node:os";
import tty from "node:tty";
import { createHash, randomUUID } from "node:crypto";

async function lockOwner(path: string): Promise<number | null> {
  try {
    const pid = Number((await readlink(path)).split(":")[0]);
    if (!Number.isSafeInteger(pid) || pid <= 0) throw new Error(`Invalid lock owner: ${path}`);
    return pid;
  } catch (err: any) {
    if (err.code === "ENOENT") return null;
    throw err;
  }
}

// Atomic symlink creation publishes ownership without a partially written PID file.
// Never steal locks: after an unclean process death an operator must remove the
// stale lock, since a check-then-unlink takeover can delete a new owner's lock.
async function acquireLock(path: string, wait = true): Promise<() => Promise<void>> {
  await mkdir(dirname(path), { recursive: true });
  const owner = `${process.pid}:${randomUUID()}`;
  for (;;) {
    try {
      await symlink(owner, path);
      break;
    } catch (err: any) {
      if (err.code !== "EEXIST") throw err;
      const pid = await lockOwner(path);
      if (pid === null) continue;
      try { process.kill(pid, 0); } catch (err: any) {
        if (err.code === "ESRCH") throw new Error(`Stale lock from exited process ${pid}: ${path}. Remove this lock before retrying.`);
        if (err.code !== "EPERM") throw err;
      }
      if (!wait) throw new Error(`Run is already active (PID ${pid}): ${path}`);
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  return async () => {
    try {
      if (await readlink(path) === owner) await unlink(path);
    } catch (err: any) {
      if (err.code !== "ENOENT") throw err;
    }
  };
}

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
  target_files?: string[];
  instructions?: string;
  trade_offs?: string;
  acceptance_criteria?: string[];
  evidence?: string[];
}

interface AuditFinding {
  id: string;
  title: string;
  target_files: string[];
  defect: string;
  evidence: string[];
  reproduction: string[];
  acceptance_criteria: string[];
  non_goals?: string[];
}

interface AuditReport {
  findings: AuditFinding[];
}

interface ValidationDecision {
  id: string;
  status: Proposal["status"];
  reason: string;
  target_files?: string[];
  evidence?: string[];
  instructions?: string;
  acceptance_criteria?: string[];
  trade_offs?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isNonemptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isNonemptyStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.every(isNonemptyString);
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(isNonemptyString);
}

function parseAuditReport(text: string): AuditReport {
  const value: unknown = JSON.parse(text);
  if (!isRecord(value) || !Array.isArray(value.findings)) {
    throw new Error("Audit report must contain findings");
  }
  if (value.findings.length > 3) throw new Error("Audit report must contain at most three findings");
  for (const [index, candidate] of value.findings.entries()) {
    if (!isRecord(candidate) || candidate.id !== `PROP-${index + 1}`) {
      throw new Error("Audit finding IDs must be sequential from PROP-1");
    }
    if (!isNonemptyString(candidate.title) || !isNonemptyString(candidate.defect)) {
      throw new Error(`Audit finding ${candidate.id} requires title and defect`);
    }
    for (const field of ["target_files", "evidence", "reproduction", "acceptance_criteria"]) {
      if (!isNonemptyStringList(candidate[field])) {
        throw new Error(`Audit finding ${candidate.id} requires nonempty ${field}`);
      }
    }
    if (candidate.non_goals !== undefined && !isStringList(candidate.non_goals)) {
      throw new Error(`Audit finding ${candidate.id} has invalid non_goals`);
    }
  }
  return value as unknown as AuditReport;
}

function parseValidationReport(text: string, findings: AuditFinding[]): ValidationDecision[] {
  const value: unknown = JSON.parse(text);
  if (!isRecord(value) || !Array.isArray(value.decisions) || value.decisions.length !== findings.length) {
    throw new Error("Validation report must contain one decision per finding");
  }
  for (const [index, candidate] of value.decisions.entries()) {
    if (!isRecord(candidate) || candidate.id !== findings[index].id
      || !isNonemptyString(candidate.reason)
      || !["approved", "pending_review", "rejected"].includes(String(candidate.status))) {
      throw new Error(`Validation decision ${findings[index].id} is incomplete`);
    }
    if (candidate.status === "approved" && (!isNonemptyStringList(candidate.evidence)
      || !isNonemptyStringList(candidate.target_files) || !isNonemptyString(candidate.instructions)
      || !isNonemptyStringList(candidate.acceptance_criteria))) {
      throw new Error(`Approved proposal ${candidate.id} lacks an execution contract`);
    }
    for (const field of ["target_files", "evidence", "acceptance_criteria"]) {
      if (candidate[field] !== undefined && !isNonemptyStringList(candidate[field])) {
        throw new Error(`Validation decision ${candidate.id} has invalid ${field}`);
      }
    }
    for (const field of ["instructions", "trade_offs"]) {
      if (candidate[field] !== undefined && !isNonemptyString(candidate[field])) {
        throw new Error(`Validation decision ${candidate.id} has invalid ${field}`);
      }
    }
  }
  return value.decisions as ValidationDecision[];
}

export type WorkInput =
  | { mode: "discover"; target_path: string }
  | { mode: "request"; target_path: string; request: string };

// Persist the input itself, not a path to a request file that can change on resume.
export async function parseWorkInput(command: string, args: string[]): Promise<{ input: WorkInput; loop: boolean }> {
  if (!["audit", "implement"].includes(command)) throw new Error(`Unknown command: ${command}`);
  let target = ".";
  let request: string | undefined;
  let requestFile: string | undefined;
  let loop = false;
  let positional: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--loop") loop = true;
    else if (["--ja", "-j", "--japanese"].includes(arg)) continue;
    else if (arg === "--target" || arg === "--file") {
      const value = args[++i];
      if (!value || value.startsWith("--")) throw new Error(`${arg} requires a value`);
      if (arg === "--target") target = value;
      else requestFile = value;
    } else if (arg.startsWith("-")) throw new Error(`Unknown option: ${arg}`);
    else if (positional !== undefined) throw new Error("Use a single quoted request or target path");
    else positional = arg;
  }
  if (command === "implement") {
    if (loop) throw new Error("--loop is only available for audit");
    if (requestFile && positional !== undefined) throw new Error("Use either request text or --file, not both");
    request = requestFile ? await Bun.file(requestFile).text() : positional;
    if (!request?.trim()) throw new Error("implement requires non-empty text or --file <path>");
    return { input: { mode: "request", target_path: target, request }, loop };
  }
  if (requestFile) throw new Error("--file is only available for implement");
  return { input: { mode: "discover", target_path: positional ?? target }, loop };
}

function workContext(input: WorkInput): string {
  return input.mode === "request"
    ? `Original user request (the source of truth; do not replace it with the design):\n${input.request}\n\nTarget scope: ${input.target_path}`
    : `Work source: automatic discovery in ${input.target_path}. Only implement justified improvements.`;
}

export function validateRequestPlan(input: WorkInput, proposals: Proposal[]): void {
  if (input.mode !== "request") return;
  if (proposals.length !== 1) throw new Error("A user request must have exactly one end-to-end plan");
  const plan = proposals[0];
  if (!["approved", "pending_review", "rejected"].includes(plan.status)) throw new Error("Invalid plan status");
  if (plan.status !== "approved") return;
  if (!Array.isArray(plan.acceptance_criteria) || !plan.acceptance_criteria.length ||
      plan.acceptance_criteria.some((criterion) => typeof criterion !== "string" || !criterion.trim())) {
    throw new Error("An approved user request requires concrete acceptance_criteria");
  }
  if (!plan.instructions?.trim() || !plan.target_files?.length) {
    throw new Error("An approved user request requires instructions and target_files");
  }
}

interface PlansData {
  proposals: Proposal[];
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

function stripDecisionTags(text: string): string {
  if (!text) return "";
  return text.replace(/^\[(Approved|Merge Approved|Merge Rejected|Needs Human Review|Rejected(\s*\([^)]+\))?)\]\s*/i, "").trim();
}

interface IterationState {
  run_id: string;
  iteration: number;
  target_path: string;
  input?: WorkInput;
  branch_prefix?: string;
  target_branch?: string;
  target_root?: string;
  base_commit?: string;
  lang?: "en" | "ja";
  status: "running" | "completed" | "failed" | "stopped";
  start_time: string;
  end_time?: string;
  phase1?: { status: string };
  phase2?: { status: string };
  phase3?: {
    status?: string;
    plans: Record<string, PlanExecutionState>;
  };
  phase4?: {
    status?: string;
    reviews: Record<string, ReviewResult>;
  };
}

const OUTPUT_DIR = resolve(process.env.OUTPUT_DIR || ".orchestration");
const TEST_CMD = process.env.TEST_CMD || "go test ./...";
const PARALLEL_JOBS = parseInt(process.env.PARALLEL_JOBS || "8", 10);

const AUDITOR = process.env.AUDITOR || "";
const VALIDATOR = process.env.VALIDATOR || "";
const DEVELOPER = process.env.DEVELOPER || "";
const REVIEWER = process.env.REVIEWER || "";

let trackingDir = OUTPUT_DIR;
let commandCwd = process.cwd();
let lockDirectory = "";
let stopping = false;
const activeProcesses = new Set<ReturnType<typeof Bun.spawn>>();
const heldLocks = new Set<() => Promise<void>>();
let processShutdown: Promise<void> | undefined;

function quote(value: string): string { return `'${value.replace(/'/g, "'\\''")}'`; }

async function holdLock(path: string, wait = true) {
  const release = await acquireLock(path, wait);
  const unlock = async () => { await release(); heldLocks.delete(unlock); };
  heldLocks.add(unlock);
  return unlock;
}

async function initializeLocks() {
  const common = await runCmd("git rev-parse --path-format=absolute --git-common-dir");
  if (common.exitCode !== 0) throw new Error(common.stderr);
  lockDirectory = join(common.stdout.trim(), "development-locks");
}

function runLockPath(runDir: string) {
  return join(lockDirectory, `run-${createHash("sha256").update(realpathSync(runDir)).digest("hex")}.lock`);
}

function stopProcesses(): Promise<void> {
  if (processShutdown) return processShutdown;
  processShutdown = (async () => {
    const children = [...activeProcesses];
    for (const child of children) {
      try { process.kill(-child.pid, "SIGTERM"); } catch {}
    }
    await Promise.race([
      Promise.all(children.map((child) => child.exited)),
      new Promise((resolve) => setTimeout(resolve, 3000)),
    ]);
    for (const child of children) {
      // The process group may still contain grandchildren after the leader exits.
      try { process.kill(-child.pid, "SIGKILL"); } catch {}
    }
    await Promise.all(children.map((child) => child.exited));
  })();
  return processShutdown;
}

// Terminal Colors
const RED = "\x1b[0;31m";
const GREEN = "\x1b[0;32m";
const YELLOW = "\x1b[1;33m";
const BLUE = "\x1b[0;34m";
const CYAN = "\x1b[0;36m";
const MAGENTA = "\x1b[0;35m";
const WHITE = "\x1b[38;5;251m";
const GRAY = "\x1b[90m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const NC = "\x1b[0m";

function logInfo(...args: unknown[]) { console.log(`${BLUE}[INFO]${NC}`, ...args); }
function logOk(...args: unknown[]) { console.log(`${GREEN}[OK]${NC}`, ...args); }
function logWarn(...args: unknown[]) { console.log(`${YELLOW}[WARN]${NC}`, ...args); }
function logError(...args: unknown[]) { console.error(`${RED}[ERROR]${NC}`, ...args); }

const textSegmenter = new Intl.Segmenter("ja", { granularity: "word" });

function stringWidth(str: string): number {
  const clean = str.replace(/\x1b\[[0-9;]*m/g, "");
  let width = 0;
  for (const char of clean) {
    const code = char.codePointAt(0) || 0;
    if (
      (code >= 0x1100 && code <= 0x115f) ||
      (code >= 0x2e80 && code <= 0xa4cf && code !== 0x303f) ||
      (code >= 0xac00 && code <= 0xd7a3) ||
      (code >= 0xf900 && code <= 0xfaff) ||
      (code >= 0xfe10 && code <= 0xfe19) ||
      (code >= 0xfe30 && code <= 0xfe6f) ||
      (code >= 0xff00 && code <= 0xff60) ||
      (code >= 0xffe0 && code <= 0xffe6) ||
      (code >= 0x20000 && code <= 0x2fffd) ||
      (code >= 0x30000 && code <= 0x3fffd)
    ) {
      width += 2;
    } else {
      width += 1;
    }
  }
  return width;
}

function getTerminalWidth(): number {
  let cols: number | undefined;
  if (tty.isatty(1)) {
    cols = process.stdout.columns;
  } else if (tty.isatty(2)) {
    cols = process.stderr.columns;
  }
  const effectiveCols = cols || parseInt(process.env.COLUMNS || "90", 10);
  const maxWrap = parseInt(process.env.STATUS_WRAP_WIDTH || "90", 10);
  return Math.max(50, Math.min(effectiveCols, maxWrap));
}

const kinsokuChars = new Set(["、", "。", "，", "．", "）", ")", "]", "}", "・", "！", "？", "!", "?", "：", ":", "；", ";"]);

function wrapText(text: string, maxWidth: number, indent = "    ", lineSuffix = ""): string {
  if (!text) return "";
  const indentWidth = stringWidth(indent);
  const targetWidth = Math.max(30, maxWidth - indentWidth);
  const lines: string[] = [];
  const paragraphs = text.split("\n");

  for (const para of paragraphs) {
    if (!para.trim()) {
      lines.push("");
      continue;
    }

    const isBullet = /^\s*(?:[-*]|\d+\.)\s+/.test(para);
    const subIndent = isBullet ? indent + "  " : indent;

    let currentLine = "";
    let currentWidth = 0;
    let isFirstLine = true;

    for (const { segment } of textSegmenter.segment(para)) {
      const segW = stringWidth(segment);

      if (currentWidth === 0 && segment.trim() === "") {
        continue;
      }

      if (currentWidth + segW > targetWidth && !kinsokuChars.has(segment)) {
        if (currentLine) {
          lines.push((isFirstLine ? indent : subIndent) + currentLine + lineSuffix);
          isFirstLine = false;
        }
        currentLine = segment.trimStart();
        currentWidth = stringWidth(currentLine);
      } else {
        currentLine += segment;
        currentWidth += segW;
      }
    }

    if (currentLine.trim()) {
      lines.push((isFirstLine ? indent : subIndent) + currentLine + lineSuffix);
    }
  }

  return lines.join("\n");
}

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
  if (stopping) throw new Error("Execution interrupted");
  const proc = Bun.spawn(["bash", "-c", cmd], {
    cwd: cwd || commandCwd,
    detached: true,
    stdout: "pipe",
    stderr: "pipe",
  });
  activeProcesses.add(proc);
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited,
  ]);
  activeProcesses.delete(proc);
  if (stopping) throw new Error("Execution interrupted");
  return { stdout, stderr, exitCode };
}

// Run an interactive/background streaming command writing stdout and stderr to a file
function validateReview(report: any, plans: Proposal[]): boolean {
  return plans.every(plan => {
    const review = report?.reviews?.[plan.id];
    return ["implemented", "merge_rejected", "conflict"].includes(review?.status)
      && typeof review.reason === "string" && review.reason.trim().length > 0;
  });
}

export async function runToolToFile(
  toolCmd: string,
  prompt: string,
  outputFile: string,
  cwd?: string,
  onPid?: (pid: number) => Promise<void> | void
): Promise<number> {
  if (stopping) throw new Error("Execution interrupted");
  const absOutputFile = resolve(outputFile);
  await mkdir(dirname(absOutputFile), { recursive: true });
  const transcriptFile = `${absOutputFile}.transcript.log`;
  const fullCmd = `exec ${toolCmd} "$1" > "$2" 2> "$3"`;
  const proc = Bun.spawn(["bash", "-c", fullCmd, "develop", prompt, absOutputFile, transcriptFile], {
    cwd: cwd || commandCwd,
    detached: true,
    stdin: "ignore",
    stdout: "ignore",
    stderr: "ignore",
  });
  activeProcesses.add(proc);
  if (onPid) {
    try {
      await onPid(proc.pid);
    } catch {}
  }
  const exitCode = await proc.exited;
  activeProcesses.delete(proc);
  if (stopping) throw new Error("Execution interrupted");
  if (exitCode !== 0) {
    // Keep failure diagnostics available to the workflow's error/quota checks.
    await appendFile(absOutputFile, await Bun.file(transcriptFile).text());
  }
  return exitCode;
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
  data.worktree_dir = resolve(worktreeDir || commandCwd);
  if (pid) {
    data.pid = pid;
  }
  await Bun.write(join(trackingDir, "current_task.json"), JSON.stringify(data, null, 2));
  try {
    await rm(join(trackingDir, "current.log"), { force: true });
    await symlink(absLog, join(trackingDir, "current.log"));
  } catch {}
}

async function clearCurrentTask(status = "completed") {
  const taskFile = Bun.file(join(trackingDir, "current_task.json"));
  if (await taskFile.exists()) {
    try {
      const data = await taskFile.json();
      data.status = status;
      data.updated_at = new Date().toISOString();
      await Bun.write(join(trackingDir, "current_task.json"), JSON.stringify(data, null, 2));
    } catch {
      // Corrupted task file: self-recover by rewriting clean final status
      await Bun.write(join(trackingDir, "current_task.json"), JSON.stringify({ status, updated_at: new Date().toISOString() }, null, 2));
    }
  }
}

let stateLock = Promise.resolve();

// Update state.json inside RUN_DIR atomically
async function updateRunState(runDir: string, updates: Partial<IterationState> | Record<string, any>) {
  const unlock = stateLock;
  let release: () => void;
  stateLock = new Promise<void>((r) => { release = r; });
  await unlock;
  try {
    const statePath = join(runDir, "state.json");
    const stateFile = Bun.file(statePath);
    let state: Record<string, any> = {};
    if (await stateFile.exists()) {
      try {
        state = await stateFile.json();
      } catch (err) {
        logWarn(`Failed to parse existing state file at ${statePath} (${err}). Attempting recovery...`);
        state = {
          run_id: basename(runDir),
          iteration: getRunSortKey(basename(runDir)),
          target_path: ".",
          status: "running",
          start_time: new Date().toISOString(),
        };
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
    const tmpPath = `${statePath}.tmp.${Date.now()}.${Math.random().toString(36).slice(2)}`;
    await Bun.write(tmpPath, JSON.stringify(state, null, 2));
    await rename(tmpPath, statePath);
  } finally {
    release!();
  }
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
  // Reserve the directory atomically; another process may choose the same number.
  for (let nextNum = maxNum + 1; ; nextNum++) {
    const runDir = join(OUTPUT_DIR, `iter-${nextNum}`);
    try {
      await mkdir(runDir);
      return { iteration: nextNum, runDir };
    } catch (err: any) {
      if (err.code !== "EEXIST") throw err;
    }
  }
}

// Clean temporary worktrees and branches
async function cleanupWorktrees(runDir: string, iter: number) {
  const wtDir = join(runDir, "worktrees");
  const stateFile = Bun.file(join(runDir, "state.json"));
  let p3Plans: Record<string, PlanExecutionState> = {};
  let branchPrefix = "refactor";
  let targetRef = "HEAD";
  if (await stateFile.exists()) {
    try {
      const s = await stateFile.json();
      p3Plans = s.phase3?.plans || {};
      branchPrefix = s.branch_prefix || branchPrefix;
      targetRef = s.target_branch ? `refs/heads/${s.target_branch}` : targetRef;
    } catch {}
  }

  if (await dirExists(wtDir)) {
    const entries = await readdir(wtDir);
    for (const e of entries) {
      const p = join(wtDir, e);
      try {
        const s = await stat(p);
        if (s.isDirectory()) {
          // Preserve worktree for pending human review
          const p3Info = p3Plans[e];
          if (p3Info?.status === "pending_review") {
            logInfo(`Preserving worktree for human review: ${p}`);
            continue;
          }
          // Check if there are uncommitted changes
          const statusRes = await runCmd("git status --porcelain", p);
          if (statusRes.stdout.trim().length > 0) {
            logInfo(`Preserving worktree with uncommitted changes: ${p}`);
            continue;
          }
          await runCmd(`git worktree remove --force "${p}" 2>/dev/null || rm -rf "${p}"`);
        }
      } catch {}
    }
  }
  await runCmd("git worktree prune >/dev/null 2>&1");
  const { stdout } = await runCmd(`git branch --list ${quote(`${branchPrefix}/iter-${iter}/*`)}`);
  for (const line of stdout.split("\n")) {
    const b = line.replace("*", "").trim();
    if (!b) continue;
    // Cherry-picks onto a newer target have different hashes but equivalent patches.
    const unmerged = await runCmd(`git cherry ${quote(targetRef)} ${quote(b)}`);
    if (unmerged.exitCode !== 0 || unmerged.stdout.split("\n").some((line) => line.startsWith("+"))) {
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

function matchesStatus(taskStatus: string, filter: string): boolean {
  const norm = (s: string) => s.toUpperCase().replace(/[\s_\-()]+/g, "");
  return norm(taskStatus).includes(norm(filter));
}

// Command: status
async function cmdStatus(targetRun?: string, summaryOnly = false, statusFilter?: string) {
  if (!(await dirExists(OUTPUT_DIR))) {
    logInfo(`No orchestration directory found at ${OUTPUT_DIR}`);
    return;
  }

  const allDirs = await getIterationDirs();
  let runs = allDirs;
  if (targetRun) {
    const normalizedTarget = /^\d+$/.test(targetRun) ? `iter-${targetRun}` : targetRun;
    const matched = allDirs.filter((d) => d === normalizedTarget || basename(d) === normalizedTarget);
    if (matched.length === 0) {
      if (!statusFilter && !targetRun.startsWith("iter-") && !targetRun.startsWith("run_")) {
        statusFilter = targetRun;
        targetRun = undefined;
      } else {
        logError(`Iteration not found: ${targetRun}`);
        return;
      }
    } else {
      runs = matched;
    }
  }

  if (runs.length === 0) {
    console.log(`No iterations found in ${OUTPUT_DIR}. Run ./scripts/develop.ts run to start.`);
    return;
  }

  if (!summaryOnly) {
    const filterInfo = statusFilter ? ` (Filter: ${statusFilter.toUpperCase()})` : "";
    console.log(`\n${BOLD}${CYAN}#${NC} ${BOLD}${WHITE}Orchestration Status${filterInfo}${NC}`);
  }

  let totalMatched = 0;

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

    let iterStatus = isCorrupted ? "CORRUPTED" : state.status === "running" && state.phase4?.status === "waiting"
      ? "WAITING FOR MERGE" : (state.status || "INCOMPLETE").toUpperCase();

    // Parse proposals and results
    const plansFile = Bun.file(join(rDir, "phase2_plans.json"));
    let proposals: Proposal[] = [];
    if (await plansFile.exists()) {
      try {
        const p2Data: PlansData = await plansFile.json();
        proposals = p2Data.proposals || [];
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
      proposal?: string;
      proposalReview?: string;
      codeReview?: string;
      failureDetail?: string;
      files: string[];
      commit: string;
      worktree?: string;
    }
    const taskRows: TaskRow[] = [];

    for (const p of proposals) {
      const pid = p.id;
      const reviewStatus = p.status;

      const issue = p.issue || "";
      const proposal = p.instructions || "";

      const validationReason = stripDecisionTags(p.decision_reason || "");
      const tradeOffs = stripDecisionTags(p.trade_offs || "");
      let proposalReview = validationReason;
      const isNone = (s: string) => !s || /^(なし|none)[\s.。]*$/i.test(s.trim());
      if (!isNone(tradeOffs) && tradeOffs !== validationReason) {
        proposalReview = proposalReview ? `${proposalReview}\n\nTrade-offs: ${tradeOffs}` : tradeOffs;
      }

      let taskStatus: TaskRow["status"] = "APPROVED (QUEUED)";
      let codeReview = "";
      let failureDetail = "";
      const p3 = phase3Plans[pid];
      const p4 = phase4Reviews[pid];
      let commitHash = (p4 && p4.commit) || (p3 && p3.commit) || "";
      let worktree = (p3 && p3.worktree) || "";

      if (reviewStatus === "approved") {
        if (p4) {
          if (p4.status === "implemented") {
            taskStatus = "MERGED";
            codeReview = stripDecisionTags(p4.reason || "Review passed and verified on main");
            mergedCount++;
          } else if (p4.status === "merge_rejected") {
            taskStatus = "REJECTED (CODE REVIEW)";
            codeReview = stripDecisionTags(p4.reason || "Code review rejected diff");
            rejectedReviewCount++;
          } else if (p4.status === "conflict") {
            taskStatus = "MERGE_CONFLICT";
            if (p4.reason) codeReview = stripDecisionTags(p4.reason);
            failureDetail = p4.failure_reason || "REVIEWER reported an integration conflict";
            conflictCount++;
          } else {
            taskStatus = "INTEGRATION_TEST_FAILED";
            if (p4.reason) codeReview = stripDecisionTags(p4.reason);
            failureDetail = p4.failure_reason || "REVIEWER integration failed";
            integrationFailedCount++;
          }
        } else if (p3) {
          if (p3.status === "built") {
            taskStatus = "BUILT (DEV PASS)";
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
        proposal,
        proposalReview,
        codeReview,
        failureDetail,
        files: p.target_files || [],
        commit: commitHash,
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

    const visibleTasks = statusFilter
      ? taskRows.filter((t) => matchesStatus(t.status, statusFilter))
      : taskRows;

    totalMatched += visibleTasks.length;

    if (summaryOnly) {
      if (statusFilter && visibleTasks.length === 0) {
        continue;
      }
      const matchText = statusFilter ? ` [${visibleTasks.length} matching "${statusFilter.toUpperCase()}"]` : "";
      logInfo(`Tasks Summary [${r} (${statusColor}${iterStatus}${NC})]: ${summaryText} (${taskRows.length} total)${matchText}`);
      continue;
    }

    if (statusFilter && visibleTasks.length === 0) {
      if (targetRun) {
        console.log(`\n${BOLD}${BLUE}##${NC} ${BOLD}${WHITE}Iteration: ${r}${NC} ${DIM}(${timeStr})${NC} — ${statusColor}${BOLD}${iterStatus}${NC}\n`);
        console.log(`  ${DIM}(No tasks matching status "${statusFilter}" found in this iteration)${NC}\n`);
      }
      continue;
    }

    console.log(`\n${BOLD}${BLUE}##${NC} ${BOLD}${WHITE}Iteration: ${r}${NC} ${DIM}(${timeStr})${NC} — ${statusColor}${BOLD}${iterStatus}${NC}\n`);
    console.log(`${GRAY}----------------------------------------------------------------------${NC}\n`);

    if (visibleTasks.length === 0) {
      console.log(`  ${DIM}(No tasks recorded for this iteration)${NC}\n`);
      continue;
    }

    const termWidth = getTerminalWidth();

    for (const t of visibleTasks) {
      let icon = "•";
      let badgeColor = CYAN;
      if (t.status === "MERGED") { icon = "✔"; badgeColor = GREEN; }
      else if (t.status === "BUILT (DEV PASS)") { icon = "●"; badgeColor = CYAN; }
      else if (t.status === "APPROVED (QUEUED)") { icon = "○"; badgeColor = CYAN; }
      else if (t.status === "DEVELOPING") { icon = "⚙"; badgeColor = BLUE; }
      else if (t.status === "NEEDS_HUMAN_REVIEW") { icon = "?"; badgeColor = YELLOW; }
      else if (t.status === "REJECTED (PLANNING)") { icon = "✗"; badgeColor = RED; }
      else if (t.status === "REJECTED (CODE REVIEW)") { icon = "✗"; badgeColor = RED; }
      else if (t.status === "UNIT_TEST_FAILED") { icon = "✗"; badgeColor = MAGENTA; }
      else if (t.status === "INTEGRATION_TEST_FAILED") { icon = "✗"; badgeColor = MAGENTA; }
      else if (t.status === "MERGE_CONFLICT") { icon = "⚠"; badgeColor = YELLOW; }
      else if (t.status === "NO_CHANGES") { icon = "-"; badgeColor = DIM; }

      const commitStr = t.commit ? ` ${DIM}(commit: ${CYAN}\`${t.commit}\`${DIM})${NC}` : "";
      console.log(`${BOLD}${badgeColor}### ${icon} [${t.id}] ${t.status}${NC}: ${BOLD}${WHITE}${t.title}${NC}${commitStr}\n`);

      if (t.files.length > 0) {
        const fileBadges = t.files.map((f) => `${CYAN}\`${f}\`${NC}`).join(", ");
        console.log(`  - ${BOLD}${WHITE}Target files:${NC}\n    ${fileBadges}\n`);
      }
      if (t.issue) {
        console.log(`  - ${BOLD}${WHITE}Issue:${NC}\n${wrapText(t.issue, termWidth, `    ${WHITE}`, NC)}\n`);
      }
      if (t.proposal) {
        console.log(`  - ${BOLD}${WHITE}Proposal:${NC}\n${wrapText(t.proposal, termWidth, `    ${WHITE}`, NC)}\n`);
      }
      if (t.proposalReview) {
        console.log(`  - ${BOLD}${WHITE}Proposal Review:${NC}\n${wrapText(t.proposalReview, termWidth, `    ${WHITE}`, NC)}\n`);
      }
      if (t.codeReview) {
        console.log(`  - ${BOLD}${WHITE}Code Review:${NC}\n${wrapText(t.codeReview, termWidth, `    ${WHITE}`, NC)}\n`);
      }
      if (t.failureDetail) {
        console.log(`  - ${BOLD}${RED}Failure Detail:${NC}\n${wrapText(t.failureDetail, termWidth, `    ${RED}`, NC)}\n`);
      }
      if (t.worktree) {
        console.log(`  - ${BOLD}${WHITE}Worktree:${NC}\n    ${DIM}\`${t.worktree}\`${NC}\n`);
      }
    }

    console.log(`${GRAY}---${NC}`);
    if (statusFilter) {
      console.log(`${BOLD}${WHITE}**Matching Tasks [${r}]**:${NC} ${visibleTasks.length} matching "${statusFilter.toUpperCase()}" (${taskRows.length} total)\n`);
    } else {
      console.log(`${BOLD}${WHITE}**Tasks Summary [${r}]**:${NC} ${summaryText} (${taskRows.length} total)\n`);
    }
  }

  if (statusFilter && totalMatched === 0 && !summaryOnly) {
    console.log(`\n${YELLOW}No tasks found matching status "${statusFilter}".${NC}\n`);
  }

  if (!summaryOnly) {
    console.log(`${GRAY}======================================================================${NC}\n`);
  }
}

// Remove worktrees, branches, and directory for an iteration
async function removeIterationResources(rDir: string, iterName: string): Promise<{ branches: string[]; worktrees: number }> {
  const lock = runLockPath(rDir);
  const owner = await lockOwner(lock);
  if (owner !== null && owner !== process.pid) {
    logInfo(`Stopping ${iterName} (PID ${owner}) before removal...`);
    try { process.kill(owner, "SIGTERM"); } catch (err: any) { if (err.code !== "ESRCH") throw err; }
  }
  const releaseRun = await holdLock(lock);
  try {
    const releaseIntegration = await holdLock(join(lockDirectory, "integration.lock"));
    try { return await removeIterationFiles(rDir, iterName); }
    finally { await releaseIntegration(); }
  } finally { await releaseRun(); }
}

async function removeIterationFiles(rDir: string, iterName: string): Promise<{ branches: string[]; worktrees: number }> {
  let worktreeCount = 0;
  const branchesRemoved: string[] = [];
  const state = await Bun.file(join(rDir, "state.json")).json().catch(() => ({}));

  for (const name of ["workspace", "integration"]) {
    const path = join(rDir, name);
    if (await dirExists(path)) {
      const removed = await runCmd(`git worktree remove --force ${quote(path)}`);
      if (removed.exitCode !== 0) throw new Error(removed.stderr);
      worktreeCount++;
    }
  }

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
  if (state.branch_prefix) {
    patterns.add(`${state.branch_prefix}/iter-${iterNum}/*`);
  } else {
  if (iterNum !== 99999) {
    patterns.add(`refactor/iter-${iterNum}/*`);
    patterns.add(`refactor/iter-${iterNum}`);
  }
  patterns.add(`refactor/${iterName}/*`);
  patterns.add(`refactor/${iterName}`);
  if (iterNum !== 99999) patterns.add(`develop/iter-${iterNum}/*`);
  patterns.add(`develop/${iterName}/*`);
  }

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
async function cmdRemove(targetRun?: string) {
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
    const { branches, worktrees } = await removeIterationResources(rDir, targetRun);
    const extras: string[] = [];
    if (worktrees > 0) extras.push(`${worktrees} worktree(s)`);
    if (branches.length > 0) extras.push(`branch(es): ${branches.join(", ")}`);
    const extraStr = extras.length > 0 ? ` (${extras.join(", ")})` : "";
    logOk(`Removed iteration: ${targetRun}${extraStr}`);
  } else {
    const removed: string[] = [];
    const allBranches: string[] = [];
    let totalWorktrees = 0;
    for (const r of allDirs) {
      const rDir = join(OUTPUT_DIR, r);
      const { branches, worktrees } = await removeIterationResources(rDir, r);
      removed.push(r);
      allBranches.push(...branches);
      totalWorktrees += worktrees;
    }
    if (removed.length > 0) {
      const extras: string[] = [];
      if (totalWorktrees > 0) extras.push(`${totalWorktrees} worktree(s)`);
      if (allBranches.length > 0) extras.push(`branch(es): ${allBranches.join(", ")}`);
      const extraStr = extras.length > 0 ? ` (cleaned up ${extras.join(", ")})` : "";
      logOk(`Removed ${removed.length} iteration(s): ${removed.join(", ")}${extraStr}`);
    } else {
      console.log("No iterations found to remove.");
    }
  }
}

// Locate the transcript opened by the task or a launcher child process.
export async function findSessionJsonl(info: {
  pid?: number;
  worktreeDir?: string;
}): Promise<string | null> {
  // 1. If PID is present, look up exact session opened by this process
  if (info.pid && Number.isSafeInteger(info.pid) && info.pid > 0) {
    try {
      const pids = new Set([info.pid]);
      const processes = await runCmd("ps -axo pid=,ppid=");
      const parents = processes.stdout.trim().split("\n").map(line => line.trim().split(/\s+/).map(Number));
      let previousSize = 0;
      while (pids.size !== previousSize) {
        previousSize = pids.size;
        for (const [pid, parent] of parents) {
          if (pid && parent && pids.has(parent)) pids.add(pid);
        }
      }
      const { stdout, exitCode } = await runCmd(`lsof -a -p ${[...pids].join(",")} -Fn 2>/dev/null`);
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
          const path = line.startsWith("n") ? line.slice(1) : "";
          if (path.endsWith(".jsonl") && (await Bun.file(path).exists())) {
            return path;
          }
        }
      }
    } catch {}
  }

  // A known process must not attach to another task's old session while starting.
  if (info.pid) return null;

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

function formatWatchBlock(content: string): string {
  const lines = content.trim().split("\n");
  const visible = lines.slice(0, 20).join("\n");
  const shortened = visible.slice(0, 6000);
  const omitted = lines.length > 20 || shortened.length < visible.length;
  return "\n" + shortened.split("\n").map(line => `        ${line}`).join("\n")
    + (omitted ? "\n        … (truncated)" : "");
}

function formatWatchOutput(value: any): string {
  if (Array.isArray(value)) return value.map(part => formatWatchOutput(part.text ?? part)).filter(Boolean).join("\n");
  if (value && typeof value === "object") {
    if (typeof value.output === "string") {
      const status = [
        value.exit_code != null ? `exit ${value.exit_code}` : "",
        value.session_id != null ? `session ${value.session_id}` : "",
      ].filter(Boolean).join(" | ");
      return [status, formatWatchOutput(value.output)].filter(Boolean).join("\n");
    }
    if (Array.isArray(value.content)) return formatWatchOutput(value.content);
    return JSON.stringify(value, null, 2);
  }
  if (typeof value !== "string") return "";
  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === "object") return formatWatchOutput(parsed);
  } catch {}
  // functions.exec wraps the actual tool result in a script execution envelope.
  if (/^Script (completed|running)\b/.test(value)) {
    const outputStart = value.indexOf("\nOutput:\n");
    if (outputStart >= 0 && value.slice(outputStart + 9).trim()) {
      return formatWatchOutput(value.slice(outputStart + 9));
    }
  }
  return value;
}

function formatWatchArguments(value: any): string {
  if (typeof value === "string") {
    try { value = JSON.parse(value); } catch { return value; }
  }
  return JSON.stringify(value, null, 2) ?? "";
}

// Format a single JSONL line for human-readable watch display
export function formatJsonlLine(line: string, previousOutput = ""): string | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  try {
    const obj = JSON.parse(trimmed);
    const results: string[] = [];
    const contentText = (value: any): string => typeof value === "string" ? value
      : Array.isArray(value) ? value.map(part => part.text || "").join("\n") : "";
    const preview = (value: string) => value.trim().split("\n")[0].slice(0, 95);

    // task_complete.last_agent_message repeats the final response item.
    if (obj.type === "event_msg" && obj.payload?.type === "task_complete") return null;

    if (obj.type === "event_msg" && obj.payload?.type === "item_completed") {
      const item = obj.payload.item;
      if (item?.type === "AgentMessage") {
        const content = contentText(item.content);
        if (content.trim()) results.push(`${GREEN}[MSG]${NC}${formatWatchBlock(content)}`);
      }
    }

    // Older transcripts store the same kinds of records as response items.
    if (obj.type === "response_item" && obj.payload) {
      const item = obj.payload;
      if (item.type === "message" && item.role === "assistant") {
        const content = contentText(item.content);
        if (content.trim()) results.push(`${GREEN}[MSG]${NC}${formatWatchBlock(content)}`);
      } else if (item.type === "reasoning") {
        const content = contentText(item.summary);
        if (content.trim()) results.push(`${CYAN}[THINK]${NC} ${preview(content)}`);
      } else if (item.type === "function_call" || item.type === "custom_tool_call") {
        results.push(`${YELLOW}[TOOL]${NC}  ${BOLD}${item.name}${NC}${formatWatchBlock(formatWatchArguments(item.arguments ?? item.input ?? ""))}`);
      } else if (item.type === "function_call_output" || item.type === "custom_tool_call_output") {
        const content = formatWatchOutput(item.output);
        if (content.trim()) results.push(`${DIM}[RES]${formatWatchBlock(content)}${NC}`);
      }
    }

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
            results.push(`${YELLOW}[TOOL]${NC}  ${BOLD}${item.name}${NC}${formatWatchBlock(detail)}`);
          } else if (item.type === "text" && item.text) {
            const firstLine = item.text.trim().split("\n")[0].slice(0, 95);
            results.push(`${GREEN}[MSG]${NC}   ${firstLine}`);
          }
        }
      } else if (msg.role === "toolResult") {
        const text = msg.content?.map((c: any) => c.text || "").join(" ").trim();
        if (text) {
          results.push(`${DIM}[RES]   ${msg.toolName || "tool"}${formatWatchBlock(formatWatchOutput(text))}${NC}`);
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
        results.push(`${YELLOW}[TOOL]${NC}  ${BOLD}${tc.name}${NC}${formatWatchBlock(detail)}`);
      }
    }
    if (obj.source === "MODEL" && obj.content && typeof obj.content === "string") {
      const firstLine = obj.content.trim().split("\n")[0].slice(0, 95);
      if (obj.type === "VALIDATOR_RESPONSE") {
        results.push(`${GREEN}[MSG]${NC}   ${firstLine}`);
      } else if (obj.type === "GENERIC") {
        results.push(`${DIM}[RES]${formatWatchBlock(formatWatchOutput(obj.content))}${NC}`);
      }
    }

    const output = results.join("\n");
    return output && output !== previousOutput ? output : null;
  } catch {
    return null;
  }
}

// Command: watch
async function cmdWatch(targetRun?: string, targetTask?: string) {
  if (targetRun?.startsWith("PROP-")) { targetTask = targetRun; targetRun = undefined; }
  if (targetRun && /^\d+$/.test(targetRun)) targetRun = `iter-${targetRun}`;
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

    const allDirs = (await getIterationDirs()).filter((name) => !targetRun || name === targetRun);
    const latestRun = allDirs.length > 0 ? join(OUTPUT_DIR, allDirs[allDirs.length - 1]) : "";
    const taskPointer = join(latestRun || OUTPUT_DIR, "current_task.json");

    if (targetTask) {
      // Check current task first if it matches
      const currentTaskFile = Bun.file(taskPointer);
      if (await currentTaskFile.exists()) {
        try {
          const info = await currentTaskFile.json();
          if (
            (info.task_name && info.task_name.includes(targetTask)) ||
            (info.worktree_dir && info.worktree_dir.includes(targetTask)) ||
            (info.log_file && info.log_file.includes(targetTask))
          ) {
            runId = info.run_id || "";
            phase = info.phase || "";
            taskName = info.task_name || `Task ${targetTask}`;
            logFile = info.log_file || "";
            worktreeDir = info.worktree_dir || "";
            pid = info.pid;
          }
        } catch {}
      }

      // If not active in current_task.json, search all iterations in reverse
      if (!logFile) {
        for (const dirName of allDirs.slice().reverse()) {
          const iterDir = join(OUTPUT_DIR, dirName);
          const taskLogPath = join(iterDir, `phase3_exec_${targetTask}.log`);
          const taskLogFile = Bun.file(taskLogPath);
          if (await taskLogFile.exists()) {
            logFile = taskLogPath;
            taskName = `Task ${targetTask}`;
            runId = dirName;
            phase = "phase3";
            const targetWt = join(iterDir, "worktrees", targetTask);
            worktreeDir = targetWt;
            break;
          }
        }
      }
    } else {
      const currentTaskFile = Bun.file(taskPointer);
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

    // Do not fall back to repo root if specific task was requested but not found
    const sessionJsonl = (targetTask && !worktreeDir && !pid)
      ? null
      : await findSessionJsonl({ pid, worktreeDir });
    const transcriptFile = `${logFile}.transcript.log`;
    const hasTranscript = logFile && await Bun.file(transcriptFile).exists() && (await stat(transcriptFile)).size > 0;
    const targetSource = sessionJsonl || (hasTranscript ? transcriptFile : logFile);

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
          console.log(`${GREEN}[LOG FILE]${NC} ${targetSource}`);
        }
        console.log(`${BLUE}================================================================${NC}`);

        if (sessionJsonl) {
          const proc = Bun.spawn(["tail", "-n", "30", "-f", sessionJsonl], { stdout: "pipe" });
          tailProc = proc;
          (async () => {
            const reader = proc.stdout.getReader();
            const decoder = new TextDecoder();
            let buf = "";
            let previousOutput = "";
            try {
              while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                buf += decoder.decode(value, { stream: true });
                const lines = buf.split("\n");
                buf = lines.pop() || "";
                for (const line of lines) {
                  const formatted = formatJsonlLine(line, previousOutput);
                  if (formatted) {
                    console.log(formatted);
                    previousOutput = formatted;
                  }
                }
              }
            } catch {}
          })();
        } else {
          tailProc = Bun.spawn(["tail", "-n", "25", "-f", targetSource], { stdout: "inherit", stderr: "inherit" });
        }
      }
    }

    await new Promise((r) => setTimeout(r, 1000));
  }
}

// Find latest incomplete run directory
async function findLatestIncompleteRun(): Promise<string | null> {
  if (!lockDirectory) await initializeLocks();
  const allDirs = await getIterationDirs();
  for (let i = allDirs.length - 1; i >= 0; i--) {
    const rDir = join(OUTPUT_DIR, allDirs[i]);
    if (await lockOwner(runLockPath(rDir)) !== null) continue;
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
  console.log(`Usage: ./scripts/develop.ts <COMMAND> [OPTIONS] [TARGET_PATH]

Commands:
  audit [OPTIONS] [TARGET_PATH]     Audit, validate findings, and implement verified fixes
  implement [OPTIONS] "TEXT"        Implement a user request, then review
  implement [OPTIONS] --file PATH   Read a user request from a UTF-8 file
  status [ITERATION] [OPTIONS]  Display task status per iteration
  resume [ITERATION] [--loop]   Resume an incomplete iteration (defaults to latest incomplete)
  watch [ITERATION] [TASK_ID]    Watch a run's conversation log (defaults to latest run)
  remove, rm [ITERATION]       Force-remove iteration(s), including incomplete ones (all if omitted)

Status Options:
  --filter, -f <STATUS>         Filter tasks by status (e.g. NEEDS_HUMAN_REVIEW, MERGED, REJECTED)
  --summary, -s                 Show one-line summary per iteration only

Options:
  --loop                        Repeat auditing until stopped or quota is exhausted (audit only)
  --target PATH                 Scope to inspect (default: .)
  --ja, -j                      Generate agent reports in Japanese; system logs stay English
  TARGET_PATH                   Target directory/file to inspect (default: .)

Environment variables:
  AUDITOR                       Code audit command (required for audit)
  VALIDATOR                     Independent specification validation command (required for audit)
  DEVELOPER                     Implementation command
  REVIEWER                      Acceptance review & merge command
  PARALLEL_JOBS                 Concurrent worktree jobs for DEVELOPER (default: 8)
  WORKFLOW_LANG                 Language for generated output ('ja' for Japanese)
  OUTPUT_DIR                    Saved inputs, plans and logs (default: .orchestration)
  TEST_CMD                      Test command to verify changes (default: 'go test ./...')

Codex example (authenticate with codex login first):
  AUDITOR='codex exec --sandbox read-only' \\
  VALIDATOR='codex exec --sandbox read-only' \\
  DEVELOPER='codex exec --sandbox workspace-write' \\
  REVIEWER='codex exec --sandbox workspace-write' \\
  ./scripts/develop.ts audit

  implement calls DEVELOPER and REVIEWER only; audit also requires AUDITOR and VALIDATOR.
  Unverified audit findings are pending_review; implement reports essential ambiguities through DEVELOPER.
  Request text is saved in state.json and reused by resume.
  Multiple audit/implement processes may run concurrently. Each run owns its
  worktrees and logs; review, tests and automatic integration are serialized.
  rm stops an active run and its child processes before deleting its resources.

  Specify each complete command, including its non-interactive options:
  e.g. AUDITOR='pi -p', VALIDATOR='claude -p', or DEVELOPER='codex exec --sandbox workspace-write'.
  The prompt is appended as the final argument; -p and exec are not added automatically.
  Commands must write their final answer to stdout and diagnostics to stderr.
  stderr is preserved as <output>.transcript.log; no tool-specific flags are added.`);
}

export async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    logError("No command specified. Use 'audit' or 'implement'.");
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
    let statusFilter: string | undefined;
    const positional: string[] = [];

    for (let i = 1; i < args.length; i++) {
      const a = args[i];
      if (a === "--summary" || a === "-s") {
        continue;
      }
      if (a.startsWith("--filter=")) {
        statusFilter = a.slice("--filter=".length);
      } else if (a.startsWith("--status=")) {
        statusFilter = a.slice("--status=".length);
      } else if (a === "--filter" || a === "-f" || a === "--status") {
        if (i + 1 < args.length) {
          statusFilter = args[++i];
        }
      } else if (!a.startsWith("-")) {
        positional.push(a);
      }
    }

    let target: string | undefined;
    if (positional.length === 1) {
      const arg = positional[0];
      if (arg.startsWith("iter-") || arg.startsWith("run_") || /^\d+$/.test(arg)) {
        target = arg;
      } else if (!statusFilter) {
        statusFilter = arg;
      } else {
        target = arg;
      }
    } else if (positional.length >= 2) {
      target = positional[0];
      if (!statusFilter) {
        statusFilter = positional[1];
      }
    }

    await cmdStatus(target, summaryOnly, statusFilter);
    return;
  }
  if (cmd === "watch" || cmd === "tail" || cmd === "--watch") {
    await cmdWatch(args[1], args[2]);
    return;
  }
  if (cmd === "remove" || cmd === "rm" || cmd === "--remove") {
    await initializeLocks();
    const target = args.slice(1).find((a) => !a.startsWith("-"));
    await cmdRemove(target);
    return;
  }

  if (!["audit", "implement", "resume"].includes(cmd)) {
    logError(`Unknown command: '${cmd}'. Use 'audit' or 'implement'.`);
    printUsage();
    process.exit(1);
  }

  // Audit validates findings first; implement goes directly to development and review.
  let loopMode = false;
  let resumeDir: string | null = null;
  let input: WorkInput = { mode: "discover", target_path: "." };
  let isJa = args.includes("--ja") || args.includes("-j") || args.includes("--japanese") ||
    process.env.WORKFLOW_LANG === "ja";
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
    const parsed = await parseWorkInput(cmd, subArgs);
    input = parsed.input;
    loopMode = parsed.loop;
  }

  logInfo("Workflow environment (configured -> effective):");
  const environment = {
    AUDITOR,
    VALIDATOR,
    DEVELOPER,
    REVIEWER,
    OUTPUT_DIR,
    TEST_CMD,
    PARALLEL_JOBS,
    WORKFLOW_LANG: process.env.WORKFLOW_LANG || "en",
  };
  for (const [name, effective] of Object.entries(environment)) {
    logInfo(`  ${name} = ${JSON.stringify(effective)}`);
  }

  if (resumeDir) {
    const saved: IterationState = await Bun.file(join(resumeDir, "state.json")).json();
    input = saved.input || { mode: "discover", target_path: saved.target_path || "." };
  }

  // Preflight checks
  logInfo("Running preflight checks...");
  const requiredTools = [
    ...(input.mode === "discover" ? [
      { name: "AUDITOR", val: AUDITOR },
      { name: "VALIDATOR", val: VALIDATOR },
    ] : []),
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

  let activeRunDir = "";
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    console.log("");
    logWarn("Interrupted! Preserving worktrees and branches for manual review or resume...");
    await stopProcesses();
    if (activeRunDir && (await dirExists(activeRunDir))) {
      await clearCurrentTask("stopped");
      await updateRunState(activeRunDir, { status: "stopped" });
    }
    for (const release of [...heldLocks].reverse()) await release();
    process.exit(130);
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  await initializeLocks();
  const sourceRoot = (await runCmd("git rev-parse --show-toplevel")).stdout.trim();
  const releaseStartup = await holdLock(join(lockDirectory, "checkout.lock"));
  let initialBranch: string;
  try {
    const branch = await runCmd("git symbolic-ref --quiet --short HEAD", sourceRoot);
    if (branch.exitCode !== 0) throw new Error("Start development from a named branch, not a detached HEAD");
    initialBranch = branch.stdout.trim();
    const gitClean = await runCmd("git status --porcelain", sourceRoot);
    if (gitClean.stdout.trim().length > 0) {
      throw new Error(`Git working tree is not clean. Commit or stash your changes before running orchestration.\n${gitClean.stdout}`);
    }
  } finally { await releaseStartup(); }

  await mkdir(OUTPUT_DIR, { recursive: true });

  let iteration = 0;
  let totalCommits = 0;
  let quotaExhausted = false;
  let lastState: IterationState;

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
    }

    const releaseRun = await holdLock(runLockPath(runDir), false);
    try {
    if (!(await dirExists(runDir))) throw new Error(`Run was removed: ${runDir}`);
    activeRunDir = runDir;
    trackingDir = runDir;

    const statePath = join(runDir, "state.json");
    const stateFile = Bun.file(statePath);
    let existingLang: "en" | "ja" | undefined;
    let designCompleted = false;
    let branchPrefix = `develop/${randomUUID()}`;
    let targetBranch = initialBranch;
    let targetRoot = sourceRoot;
    let baseCommit = "";
    let startTime = new Date().toISOString();
    if (await stateFile.exists()) {
      const existingState: IterationState = await stateFile.json();
      if (existingState.status === "completed") {
        const reviews = existingState.phase4?.reviews || {};
        const hasUnmergedCandidate = Object.entries(existingState.phase3?.plans || {})
          .some(([id, plan]) => plan.status === "built" && reviews[id]?.status !== "implemented");
        if (!hasUnmergedCandidate) {
          logInfo(`${basename(runDir)} is already completed; nothing to resume.`);
          return;
        }
        logWarn(`${basename(runDir)} was marked completed with an unmerged candidate; resuming integration.`);
      }
      existingLang = existingState.lang;
      designCompleted = existingState.phase1?.status === "completed";
      input = existingState.input || { mode: "discover", target_path: existingState.target_path || "." };
      branchPrefix = existingState.branch_prefix || "refactor";
      targetBranch = existingState.target_branch || targetBranch;
      targetRoot = existingState.target_root || targetRoot;
      baseCommit = existingState.base_commit || "";
      startTime = existingState.start_time || startTime;
    }
    if (input.mode === "request" && loopMode) throw new Error("--loop is only available for audit");
    const targetPath = input.target_path;
    const context = workContext(input);
    const isIterJa = isJa || existingLang === "ja";
    const currentLang: "en" | "ja" = isIterJa ? "ja" : "en";
    const logWorkflowStep = (message: string) => logInfo(`[${basename(runDir)}] ${message}`);

    const findingsPath = join(runDir, "phase1_findings.json");
    const plansPath = join(runDir, "phase2_plans.json");

    if (!baseCommit) {
      const base = await runCmd(`git rev-parse ${quote(`refs/heads/${targetBranch}`)}`, sourceRoot);
      if (base.exitCode !== 0) throw new Error(base.stderr);
      baseCommit = base.stdout.trim();
    }

    await updateRunState(runDir, {
      run_id: basename(runDir),
      iteration,
      target_path: targetPath,
      input,
      branch_prefix: branchPrefix,
      target_branch: targetBranch,
      target_root: targetRoot,
      base_commit: baseCommit,
      lang: currentLang,
      status: "running",
      start_time: startTime,
    });

    const workspace = join(runDir, "workspace");
    if (!(await dirExists(workspace))) {
      const created = await runCmd(`git worktree add --detach ${quote(workspace)} ${quote(baseCommit)}`, sourceRoot);
      if (created.exitCode !== 0) throw new Error(created.stderr);
    }
    commandCwd = workspace;

    if (loopMode) {
      console.log("");
      logInfo("========================================================");
      logInfo(`Iteration #${iteration} (Target: '${targetPath}')`);
      logInfo(`Run Directory: ${runDir}`);
      if (isIterJa) logInfo("Output Language: Japanese (LLMs instructed to generate in Japanese)");
      logInfo("========================================================");
    } else {
      logOk(`Run directory: ${runDir} (${input.mode})`);
      if (isIterJa) logInfo("Output Language: Japanese (LLMs instructed to generate in Japanese)");
    }

    if (input.mode === "request") {
      if (!(await Bun.file(plansPath).exists())) {
        const task: Proposal = {
          id: "PROP-1", title: input.request.split("\n")[0].slice(0, 100),
          status: "approved", issue: input.request,
          decision_reason: "Explicit user request; implementation goes directly to DEVELOPER.",
          target_files: [targetPath],
          instructions: "Read the original request and existing code. Decide the implementation approach and focused tests, then implement the smallest complete change. If essential requirements are ambiguous, explain the question and stop without claiming completion.",
          acceptance_criteria: [input.request],
        };
        await Bun.write(plansPath, JSON.stringify({ proposals: [task] }, null, 2));
      }
      await updateRunState(runDir, { phase1: { status: "skipped" }, phase2: { status: "skipped" } });
      logWorkflowStep("implement: starting DEVELOPER directly; AUDITOR and VALIDATOR are not called.");
    } else {
    // --- Phase 1: Structured Findings (AUDITOR) ---
    if (designCompleted && (await Bun.file(findingsPath).exists()) && Bun.file(findingsPath).size > 0) {
      logOk(`Phase 1: Existing findings found in ${findingsPath}. Skipping exploration.`);
    } else {
      logInfo(`Phase 1: audit with AUDITOR (${AUDITOR}, target: '${targetPath}')...`);
      await setCurrentTask(basename(runDir), iteration, "phase1", `Phase 1: audit with AUDITOR (${AUDITOR})`, findingsPath);

      const auditPrompt = `You are a code auditor. Read AGENTS.md and inspect '${targetPath}'.
${context}

Return at most three independent, reproducible defects. Trace the relevant code, verify protocol claims with the ms-specs skill, and reproduce uncertain claims. Stay within the auditor role: investigate and report; do not implement fixes or audit unrelated code.

Output only JSON. Use sequential IDs and {"findings":[]} when nothing strong exists:
{"findings":[{"id":"PROP-1","title":"...","target_files":["file.go","file_test.go"],"defect":"Concrete failure and impact","evidence":["file:line or specification section and what it proves"],"reproduction":["Given/when/observed"],"acceptance_criteria":["Required observable behavior"],"non_goals":["Related work excluded"]}]}
${isIterJa ? "Write descriptive values in Japanese; keep JSON keys, IDs, code symbols, and paths unchanged." : ""}`;

      const exitCode = await runToolToFile(AUDITOR, auditPrompt, findingsPath, undefined, async (pid) => {
        await setCurrentTask(basename(runDir), iteration, "phase1", `Phase 1: audit with AUDITOR (${AUDITOR})`, findingsPath, "running", undefined, pid);
      });
      const outputText = (await Bun.file(findingsPath).exists()) ? await Bun.file(findingsPath).text() : "";

      if (isQuotaExhausted(outputText)) {
        logError("API quota / credit limit exhausted in AUDITOR (Phase 1). Terminating.");
        await updateRunState(runDir, { status: "failed" });
        quotaExhausted = true;
        break;
      }

      if (exitCode !== 0) {
        logError(`AUDITOR investigation failed with exit code ${exitCode}. Check ${findingsPath}`);
        await updateRunState(runDir, { status: "failed" });
        break;
      }

      let auditReport: AuditReport;
      try {
        auditReport = parseAuditReport(outputText);
        await Bun.write(findingsPath, JSON.stringify(auditReport, null, 2));
      } catch (err) {
        logError(`AUDITOR returned an invalid JSON report: ${err}. Check ${findingsPath}`);
        await updateRunState(runDir, { status: "failed" });
        break;
      }

      if (auditReport.findings.length === 0) {
        logInfo("AUDITOR reported no strong findings. Reached a clean state.");
        await updateRunState(runDir, {
          phase1: { status: "completed" },
          status: "completed",
          end_time: new Date().toISOString(),
        });
        if (loopMode) {
          logInfo("Loop mode remains active; starting another audit iteration.");
          continue;
        }
        break;
      }

      logOk(`Phase 1 complete. Findings saved to ${findingsPath}`);
    }

    await updateRunState(runDir, { phase1: { status: "completed" } });

    // --- Phase 2: Planning & Screening (VALIDATOR) ---
    if ((await Bun.file(plansPath).exists()) && Bun.file(plansPath).size > 0) {
      logOk(`Phase 2: Existing plans found in ${plansPath}. Skipping validation.`);
    } else {
      logInfo(`Phase 2: Independently validating findings with VALIDATOR (${VALIDATOR})...`);
      const validationPath = join(runDir, "phase2_validation.json");
      await setCurrentTask(basename(runDir), iteration, "phase2", `Phase 2: Validating findings with VALIDATOR (${VALIDATOR})`, validationPath);

      const findingsText = await Bun.file(findingsPath).text();
      const validationPrompt = `You are an independent specification validator. Read AGENTS.md.
${context}

Validate every finding below against its cited source and relevant code; try to disprove it through existing checks, valid counterexamples, or reproduction. Do not repeat the broad audit or inspect unrelated defects. Use approved only for a verified, minimal fix; pending_review for unresolved requirements or human trade-offs; rejected otherwise. For approved items, preserve decisive evidence and supply concise constraints and regression criteria. Stay within the validator role: decide and plan; do not implement fixes.

Output only JSON:
{"decisions":[{"id":"PROP-1","status":"approved|pending_review|rejected","reason":"...","target_files":["..."],"evidence":["..."],"instructions":"Constraints and non-goals","acceptance_criteria":["Observable regression case"],"trade_offs":"Optional"}]}
For approved items, every shown field except trade_offs is required. For other statuses, require only id, status, reason, and optional trade_offs. Preserve input order and IDs. Leave code-level choices to DEVELOPER.
${isIterJa ? "Write descriptive values in Japanese; keep keys, IDs, status values, and paths unchanged." : ""}

Audit findings:
${findingsText}`;

      const exitCode = await runToolToFile(VALIDATOR, validationPrompt, validationPath, undefined, async (pid) => {
        await setCurrentTask(basename(runDir), iteration, "phase2", `Phase 2: Validating findings with VALIDATOR (${VALIDATOR})`, validationPath, "running", undefined, pid);
      });
      const rawText = (await Bun.file(validationPath).exists()) ? await Bun.file(validationPath).text() : "";

      if (isQuotaExhausted(rawText)) {
        logError("API quota / credit limit exhausted in VALIDATOR (Phase 2). Terminating.");
        await updateRunState(runDir, { status: "failed" });
        quotaExhausted = true;
        break;
      }

      if (exitCode !== 0 || !rawText.trim()) {
        logError(`VALIDATOR failed with exit code ${exitCode}. Check ${validationPath}`);
        await updateRunState(runDir, { status: "failed" });
        break;
      }

      const findings = parseAuditReport(findingsText).findings;
      let decisions: ValidationDecision[];
      try {
        decisions = parseValidationReport(rawText, findings);
      } catch (err) {
        logError(`VALIDATOR returned an invalid JSON report: ${err}. Check ${validationPath}`);
        await updateRunState(runDir, { status: "failed" });
        break;
      }
      const proposals: Proposal[] = decisions.map((decision, index) => ({
        id: decision.id,
        title: findings[index].title,
        status: decision.status,
        issue: findings[index].defect,
        decision_reason: decision.reason,
        target_files: decision.target_files,
        evidence: decision.evidence,
        instructions: decision.instructions,
        acceptance_criteria: decision.acceptance_criteria,
        trade_offs: decision.trade_offs,
      }));
      const plansData: PlansData = { proposals };

      try {
        validateRequestPlan(input, proposals);
      } catch (err) {
        await updateRunState(runDir, { status: "failed" });
        throw err;
      }
      await Bun.write(plansPath, JSON.stringify(plansData, null, 2));

      logOk(`Phase 2 complete. Plans parsed to ${plansPath}`);
    }

    await updateRunState(runDir, { phase2: { status: "completed" } });

    // Show task status summary after planning
    await cmdStatus(basename(runDir), true);

    }

    // --- Phase 3: Concurrent Execution with git worktree (DEVELOPER) ---
    const plansData: PlansData = await Bun.file(plansPath).json();
    const plannedProposals = plansData.proposals;
    try {
      validateRequestPlan(input, plannedProposals);
    } catch (err) {
      await updateRunState(runDir, { status: "failed" });
      throw err;
    }
    const approvedPlans = plannedProposals.filter((plan) => plan.status === "approved");
    const pendingPlans = plannedProposals.filter((plan) => plan.status === "pending_review");
    logInfo(`Approved plans for execution: ${approvedPlans.length} (Concurrency: ${PARALLEL_JOBS})`);

    const wtBaseDir = join(runDir, "worktrees");
    await mkdir(wtBaseDir, { recursive: true });
    await runCmd("git worktree prune >/dev/null 2>&1 || true");

    let worktreeLock = Promise.resolve();
    async function createIsolatedWorktree(wDir: string, bName: string): Promise<{ success: boolean; error?: string }> {
      const unlock = worktreeLock;
      let release: () => void;
      worktreeLock = new Promise<void>((r) => { release = r; });
      await unlock;
      try {
        await runCmd(`git worktree remove --force "${wDir}" >/dev/null 2>&1 || true`);
        if (await dirExists(wDir)) {
          await rm(wDir, { recursive: true, force: true });
        }
        await runCmd("git worktree prune >/dev/null 2>&1 || true");
        await runCmd(`git branch -D "${bName}" >/dev/null 2>&1 || true`);
        const res = await runCmd(`git worktree add -B "${bName}" "${wDir}" HEAD`);
        if (res.exitCode !== 0) {
          return { success: false, error: res.stderr.trim() || "Failed to create isolated git worktree" };
        }
        return { success: true };
      } finally {
        release!();
      }
    }

    // Provision worktrees for pending human review proposals so maintainers can develop in parallel
    if (pendingPlans.length > 0) {
      logInfo(`Provisioning ${pendingPlans.length} worktree(s) for pending human review proposal(s)...`);
      for (const p of pendingPlans) {
        const branchName = `${branchPrefix}/iter-${iteration}/${p.id}`;
        const worktreeDir = join(wtBaseDir, p.id);
        const currentRunState: IterationState = await Bun.file(join(runDir, "state.json")).json().catch(() => ({}));
        const existingP3Plans = currentRunState.phase3?.plans || {};

        // If worktree already exists on disk, keep it
        if (existingP3Plans[p.id]?.worktree && (await dirExists(worktreeDir))) {
          continue;
        }

        const wtRes = await createIsolatedWorktree(worktreeDir, branchName);
        if (wtRes.success) {
          await updateRunState(runDir, {
            phase3: {
              plans: {
                [p.id]: {
                  status: "pending_review",
                  branch: branchName,
                  worktree: worktreeDir,
                },
              },
            },
          });
          logOk(`  • [${p.id}] Worktree ready at: ${worktreeDir}`);
        } else {
          logWarn(`  • [${p.id}] Failed to create worktree: ${wtRes.error}`);
        }
      }
    }

    if (approvedPlans.length === 0) {
      logInfo("No approved plans in this round.");
      if (pendingPlans.length > 0) {
        logInfo(`Worktrees for ${pendingPlans.length} pending human review proposal(s) are ready in: ${wtBaseDir}`);
      }
      const status = input.mode === "request" || pendingPlans.length > 0 ? "stopped" : "completed";
      await updateRunState(runDir, { status, end_time: new Date().toISOString() });
      if (loopMode && status === "completed") {
        logInfo("Loop mode remains active; starting another audit iteration.");
        continue;
      }
      break;
    }

    logInfo(`Launching DEVELOPER tasks concurrently across git worktrees (max ${PARALLEL_JOBS})...`);
    logInfo(`Worktree base directory: ${wtBaseDir}`);

    // Run each approved plan inside its isolated git worktree
    await asyncPool(PARALLEL_JOBS, approvedPlans, async (plan, idx) => {
      const planId = plan.id;
      const planTitle = plan.title;
      const branchName = `${branchPrefix}/iter-${iteration}/${planId}`;
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
      const wtRes = await createIsolatedWorktree(worktreeDir, branchName);
      if (!wtRes.success) {
        const wtErr = wtRes.error || "Failed to create isolated git worktree";
        logError(`Failed to create worktree for ${planId} at ${worktreeDir}: ${wtErr}`);
        await updateRunState(runDir, { phase3: { plans: { [planId]: { status: "worktree_failed", failure_reason: wtErr } } } });
        return;
      }

      await updateRunState(runDir, { phase3: { plans: { [planId]: { status: "running", branch: branchName, worktree: worktreeDir } } } });

      const devPrompt = `You are executing an approved development task. Read AGENTS.md.
${context}
Task: ${planTitle}
Target files: ${(plan.target_files || []).join(", ")}
Evidence: ${(plan.evidence || []).join("; ")}
Acceptance: ${(plan.acceptance_criteria || []).join("; ")}
Constraints: ${plan.instructions || ""}

Inspect the relevant code and callers, implement the smallest complete change, run ${TEST_CMD}, and commit the finished work on this branch. Keep all fixes in one clean commit and do not broaden the task.`;

      const devExitCode = await runToolToFile(DEVELOPER, devPrompt, execLogPath, worktreeDir, async pid => {
        await setCurrentTask(basename(runDir), iteration, "phase3", `DEVELOPER on ${planId}: ${planTitle}`, execLogPath, "running", worktreeDir, pid);
      });
      const logContent = (await Bun.file(execLogPath).exists()) ? await Bun.file(execLogPath).text() : "";
      if (isQuotaExhausted(logContent)) {
        quotaExhausted = true;
        await updateRunState(runDir, { phase3: { plans: { [planId]: { status: "quota_exhausted", branch: branchName, worktree: worktreeDir } } } });
      } else if (devExitCode !== 0) {
        await updateRunState(runDir, { phase3: { plans: { [planId]: {
          status: "test_failed", branch: branchName, worktree: worktreeDir,
          failure_reason: `DEVELOPER exited with code ${devExitCode}`,
        } } } });
      } else {
        logOk(`Built ${planId} on ${branchName}.`);
        await updateRunState(runDir, { phase3: { plans: { [planId]: { status: "built", branch: branchName, worktree: worktreeDir } } } });
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

    const candidatePlans = [...approvedPlans, ...pendingPlans];
    const builtPlans: Proposal[] = [];
    for (const p of candidatePlans) {
      const p3 = p3Plans[p.id];
      if (p3 && p3.status === "built" && (p3.commit || p3.branch)) {
        builtPlans.push(p);
      }
    }

    if (builtPlans.length === 0) {
      logWarn("No built proposals from Phase 3 available for review and merge.");
    } else {
      logInfo(`Waiting for REVIEWER to integrate ${basename(runDir)} into ${targetBranch}...`);
      await updateRunState(runDir, { phase4: { status: "waiting" } });
      const reviewLogPath = join(runDir, "phase4_review.log");
      await setCurrentTask(basename(runDir), iteration, "phase4", `Waiting to integrate into ${targetBranch}`, reviewLogPath, "waiting", workspace);
      const releaseIntegration = await holdLock(join(lockDirectory, "integration.lock"));
      try {
        await updateRunState(runDir, { phase4: { status: "running" } });
        const candidates = builtPlans.map(plan => ({
          id: plan.id,
          branch: p3Plans[plan.id].branch,
          target_files: plan.target_files || [],
          instructions: plan.instructions || "",
          acceptance_criteria: plan.acceptance_criteria || [],
        }));
        const reviewPrompt = `You are the reviewer and integrator. Read AGENTS.md.
${context}
Target checkout: ${targetRoot}
Target branch: ${targetBranch}
Candidates: ${JSON.stringify(candidates)}

Review and integrate accepted candidates into the target checkout. Resolve conflicts, fix issues, run ${TEST_CMD}, and leave a clean target with one new non-merge commit. Write an English Conventional Commit message. Do not start another audit.
Output only JSON for every proposal:
{"reviews":{"PROP-1":{"status":"implemented|merge_rejected|conflict","reason":"..."}}}
${isIterJa ? "Write summary and reasons in Japanese; keep status values in English." : ""}`;

        logWorkflowStep(`REVIEWER is reviewing and integrating the candidates. Log: ${reviewLogPath}`);
        const reviewExitCode = await runToolToFile(REVIEWER, reviewPrompt, reviewLogPath, workspace, async pid => {
          await setCurrentTask(basename(runDir), iteration, "phase4", "Review and integration", reviewLogPath, "running", workspace, pid);
        });
        const reviewText = await Bun.file(reviewLogPath).text().catch(() => "");
        const parsedReview = extractJson(reviewText);
        const valid = reviewExitCode === 0 && validateReview(parsedReview, builtPlans);
        const implemented = valid && builtPlans.some(plan => parsedReview.reviews[plan.id].status === "implemented");
        const defaultReason = reviewExitCode !== 0
          ? `REVIEWER exited with code ${reviewExitCode}`
          : "REVIEWER returned an invalid report";
        const reviewsMap: Record<string, ReviewResult> = {};
        for (const plan of builtPlans) {
          const review = parsedReview?.reviews?.[plan.id];
          const status: ReviewResult["status"] = valid
            ? review.status === "implemented" ? "implemented"
            : review.status === "conflict" ? "conflict" : "merge_rejected"
            : "failed";
          const reason = valid ? review.reason : defaultReason;
          reviewsMap[plan.id] = { status, reason, commit: p3Plans[plan.id].commit };
          logWorkflowStep(`${plan.id}: ${status}. ${reason.replace(/\s+/g, " ").slice(0, 300)}`);
        }
        if (valid && implemented) {
          roundCommitted = 1;
          totalCommits++;
          logOk(`REVIEWER integrated the candidates into ${targetBranch}.`);
        } else if (!valid) {
          logError(defaultReason);
        }
        await updateRunState(runDir, {
          phase4: {
            status: valid ? "completed" : "failed",
            reviews: reviewsMap,
          },
        });
      } finally {
        commandCwd = workspace;
        await releaseIntegration();
      }
    }

    // Phase 5: Clean up all worktrees and temporary branches
    if (input.mode !== "request") {
      logInfo("Cleaning up worktrees and temporary branches...");
      await cleanupWorktrees(runDir, iteration);
    } else {
      logInfo(`Preserving the request worktree for inspection and resume. Use rm ${basename(runDir)} to remove it.`);
    }

    const finalState: IterationState = await Bun.file(statePath).json();
    const runComplete = approvedPlans.every((plan) => finalState.phase4?.reviews[plan.id]?.status === "implemented");
    await updateRunState(runDir, { status: runComplete ? "completed" : "failed", end_time: new Date().toISOString() });

    // Show updated status summary
    await cmdStatus(basename(runDir), true);

    if (!loopMode) break;
    if (!runComplete) {
      logInfo(`Iteration #${iteration} did not complete successfully. Ending loop for inspection or resume.`);
      break;
    }
    logOk(`Iteration #${iteration} finished with ${roundCommitted} commit(s). Continuing loop...`);
    } catch (err) {
      if (!stopping && await dirExists(runDir)) {
        await updateRunState(runDir, { status: "failed" });
        await clearCurrentTask("failed");
      }
      throw err;
    } finally {
      if (stopping) await stopProcesses();
      commandCwd = sourceRoot;
      if (await Bun.file(join(runDir, "state.json")).exists()) {
        lastState = await Bun.file(join(runDir, "state.json")).json();
        await clearCurrentTask(lastState.status);
      }
      await releaseRun();
    }
  }

  const endState = lastState!;
  if (endState.status !== "completed") process.exitCode = 1;

  console.log("");
  logInfo("========================================================");
  logInfo("Orchestration Run Summary");
  logInfo("========================================================");
  logInfo(`Total Iterations:         ${iteration}`);
  logOk(`Total Auto-Committed:     ${totalCommits}`);
  if (quotaExhausted) {
    logError("Execution Status:         Stopped due to quota / credit exhaustion.");
  } else if (endState.status === "completed") {
    logOk("Execution Status:         Completed successfully.");
  } else {
    logWarn(`Execution Status:         ${endState.status}. Inspect status and saved plans before resuming.`);
  }
  logInfo(`To view iteration task statuses: ./scripts/develop.ts status`);
  logInfo(`Detailed logs preserved in       ${OUTPUT_DIR}`);
}

if (import.meta.main) {
  main().catch(async (err) => {
    if (stopping) return;
    await stopProcesses();
    for (const release of [...heldLocks].reverse()) await release();
    logError("Fatal error:", err);
    process.exit(1);
  });
}
