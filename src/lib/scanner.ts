/**
 * Trivy wrapper.
 *
 * Two hard lessons baked in here:
 *   1. NEVER download the vuln DB inside a tool call. First-run DB pulls from
 *      ghcr.io can take minutes (or stall on locked-down networks) and blow the
 *      MCP client timeout. The .mcpb ships a pre-downloaded DB; at runtime we
 *      pass --skip-db-update and a bundled --cache-dir, so scans are offline and
 *      fast.
 *   2. NEVER scan `/`. `trivy rootfs /` walks the entire disk — catastrophic on
 *      macOS. Host OS-package scanning is a Linux capability; everywhere else we
 *      scan a bounded target directory or a container image.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import zlib from "node:zlib";
import { pipeline } from "node:stream/promises";
import { detectPlatform, type OsFamily } from "./platform.js";

const pexecFile = promisify(execFile);

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type Scope = "os" | "packages" | "containers" | "all";

export interface Finding {
  cve_id: string;
  package: string;
  installed_version: string;
  fixed_version: string | null;
  severity: Severity;
  cvss_score: number | null;
  epss_score: number | null;
  description: string;
  published: string | null;
  pkg_manager: string | null;
}

export interface ScanResult {
  scanned_at: string;
  host: string;
  os: string;
  scanner: { name: "trivy"; version: string };
  scope: Scope;
  target: string;
  findings: Finding[];
}

/** A recoverable, user-facing condition (wrong platform, missing target). */
export class ScanGuidance extends Error {
  constructor(public code: string, message: string, public suggestion?: string) {
    super(message);
    this.name = "ScanGuidance";
  }
}

/** Resolve the trivy binary: env override (with Windows .exe fallback), then PATH. */
export function trivyPath(): string {
  const configured = process.env.VULNMCP_TRIVY_PATH;
  if (!configured) return "trivy";
  if (process.platform === "win32" && !/\.exe$/i.test(configured)) {
    if (!fs.existsSync(configured) && fs.existsSync(`${configured}.exe`)) {
      return `${configured}.exe`;
    }
  }
  return configured;
}

// The resolved, ready-to-use cache dir (writable, holds an extracted trivy.db),
// computed once by prepareDbCache(). `undefined` = not resolved yet; `null` =
// resolved to "no usable cache".
let resolvedCache: string | null | undefined;
let preparing: Promise<string | null> | null = null;

/** Stable identity for the bundled DB so a newer bundle triggers re-extraction. */
function dbIdentity(metaPath: string): string {
  try {
    const m = JSON.parse(fs.readFileSync(metaPath, "utf8"));
    return String(m.UpdatedAt ?? m.DownloadedAt ?? m.Version ?? "");
  } catch {
    try {
      return String(fs.statSync(metaPath).mtimeMs);
    } catch {
      return "";
    }
  }
}

/**
 * Materialize the offline Trivy DB cache, once.
 *
 * The .mcpb ships the DB gzipped (db/trivy.db.gz) because the raw BoltDB is
 * ~1GB and exceeds the bundle's 512MB-per-file limit. The bundle dir may also
 * be read-only, so we decompress into a per-user writable cache and point
 * --cache-dir there. Keyed by the DB's UpdatedAt: a reinstalled/newer bundle
 * re-extracts; an unchanged one is reused. Dev/source runs that already have a
 * raw trivy.db are used in place.
 *
 * Run at server startup (not inside a tool call) so decompression never counts
 * against the MCP request timeout. Idempotent and memoized.
 */
export function prepareDbCache(): Promise<string | null> {
  if (preparing) return preparing;
  preparing = (async () => {
    const bundled = process.env.VULNMCP_TRIVY_CACHE;
    if (!bundled || !fs.existsSync(bundled)) return (resolvedCache = null);

    // Already-usable raw cache (dev / source runs): use as-is.
    if (fs.existsSync(path.join(bundled, "db", "trivy.db"))) return (resolvedCache = bundled);

    const gz = path.join(bundled, "db", "trivy.db.gz");
    if (!fs.existsSync(gz)) return (resolvedCache = null); // nothing usable bundled

    const meta = path.join(bundled, "db", "metadata.json");
    const work = path.join(os.homedir(), ".vulnmcp", "trivy-cache");
    const workDbDir = path.join(work, "db");
    const outDb = path.join(workDbDir, "trivy.db");
    const marker = path.join(work, ".db-version");

    const want = dbIdentity(meta);
    const have =
      fs.existsSync(outDb) && fs.existsSync(marker) ? fs.readFileSync(marker, "utf8").trim() : null;

    if (have !== want) {
      fs.mkdirSync(workDbDir, { recursive: true });
      const tmp = `${outDb}.tmp`;
      await pipeline(fs.createReadStream(gz), zlib.createGunzip(), fs.createWriteStream(tmp));
      fs.renameSync(tmp, outDb); // atomic publish
      if (fs.existsSync(meta)) fs.copyFileSync(meta, path.join(workDbDir, "metadata.json"));
      fs.writeFileSync(marker, want);
    }
    return (resolvedCache = work);
  })().catch((err: unknown) => {
    // A broken cache must not wedge the server — fall back to no offline DB.
    process.stderr.write(`vulnmcp: DB cache prep failed: ${(err as Error)?.message}\n`);
    return (resolvedCache = null);
  });
  return preparing;
}

/**
 * The cache dir to pass to trivy. Returns the prepared cache once resolved;
 * before then (e.g. a direct unit-test call) only a ready-to-use raw cache is
 * honored — never a gz-only bundle, which trivy can't read.
 */
function cacheDir(): string | null {
  if (resolvedCache !== undefined) return resolvedCache;
  const dir = process.env.VULNMCP_TRIVY_CACHE;
  return dir && fs.existsSync(path.join(dir, "db", "trivy.db")) ? dir : null;
}

export async function trivyVersion(): Promise<string> {
  const args = ["--version", "--format", "json"];
  const cache = cacheDir();
  if (cache) args.push("--cache-dir", cache);
  const { stdout } = await pexecFile(trivyPath(), args, { timeout: 10_000, windowsHide: true });
  try {
    return JSON.parse(stdout).Version ?? "unknown";
  } catch {
    const m = stdout.match(/Version:\s*([\w.\-]+)/);
    return m ? m[1] : "unknown";
  }
}

const SEVERITY_SET = new Set<Severity>(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]);
function normSeverity(s: string | undefined): Severity {
  const up = (s ?? "UNKNOWN").toUpperCase();
  return (SEVERITY_SET.has(up as Severity) ? up : "UNKNOWN") as Severity;
}

function bestCvss(vuln: any): number | null {
  const cvss = vuln?.CVSS;
  if (!cvss || typeof cvss !== "object") return null;
  let best: number | null = null;
  for (const src of Object.values<any>(cvss)) {
    const score = src?.V3Score ?? src?.V40Score ?? src?.V2Score;
    if (typeof score === "number" && (best === null || score > best)) best = score;
  }
  return best;
}

function mapResults(raw: any): Finding[] {
  const out: Finding[] = [];
  const results = Array.isArray(raw?.Results) ? raw.Results : [];
  for (const result of results) {
    const vulns = Array.isArray(result?.Vulnerabilities) ? result.Vulnerabilities : [];
    for (const v of vulns) {
      out.push({
        cve_id: v.VulnerabilityID ?? "UNKNOWN",
        package: v.PkgName ?? "unknown",
        installed_version: v.InstalledVersion ?? "",
        fixed_version: v.FixedVersion || null,
        severity: normSeverity(v.Severity),
        cvss_score: bestCvss(v),
        epss_score:
          typeof v.Epss?.Score === "number"
            ? v.Epss.Score
            : typeof v.EPSS?.Score === "number"
            ? v.EPSS.Score
            : null,
        description: v.Description ?? v.Title ?? "",
        published: v.PublishedDate || null,
        pkg_manager: result.Type ?? null,
      });
    }
  }
  return out;
}

// Directories that are huge, volatile, or irrelevant to package scanning.
const SKIP_DIRS_POSIX = ["/proc", "/sys", "/dev", "/run", "/var/lib/docker", "/var/lib/containerd"];

export interface ScanOptions {
  scope?: Scope;
  /** Directory to scan for installed/declared packages (required off-Linux). */
  target?: string;
  /** Container image reference (for scope=containers). */
  image?: string;
  timeoutMs?: number;
}

interface BuiltScan {
  args: string[];
  /** Human label for what was scanned. */
  target: string;
}

/**
 * Build the trivy argv. Throws ScanGuidance for conditions the user must
 * resolve (no target on macOS/Windows, OS scope off Linux, missing image).
 */
function buildScan(scope: Scope, family: OsFamily, opts: ScanOptions, trivySecs: number): BuiltScan {
  const common = ["--quiet", "--format", "json", "--scanners", "vuln", "--timeout", `${trivySecs}s`];
  const cache = cacheDir();
  if (cache) {
    // Offline-first: use the bundled DB, never reach the network.
    common.push("--cache-dir", cache, "--skip-db-update", "--skip-java-db-update", "--offline-scan");
  }

  const validTarget = (t?: string): string | null => {
    if (!t) return null;
    if (!fs.existsSync(t)) throw new ScanGuidance("bad_target", `target path does not exist: ${t}`);
    return t;
  };

  if (scope === "containers") {
    if (!opts.image) {
      throw new ScanGuidance(
        "needs_image",
        "scope=containers requires an `image` reference.",
        "Ask the user which container image to scan, e.g. nginx:1.27."
      );
    }
    return { args: ["image", ...common, opts.image], target: opts.image };
  }

  const target = validTarget(opts.target);

  if (scope === "packages") {
    if (!target) {
      throw new ScanGuidance(
        "needs_target",
        "scope=packages requires a `target` directory to scan for dependency vulnerabilities.",
        "Ask the user for a project directory (where package-lock.json, requirements.txt, go.mod, etc. live)."
      );
    }
    return { args: ["fs", ...common, "--pkg-types", "library", target], target };
  }

  if (scope === "os") {
    if (family !== "linux") {
      throw new ScanGuidance(
        "os_unsupported",
        `OS-package scanning isn't supported on ${family} (Trivy enumerates installed OS packages on Linux only).`,
        "On macOS/Windows, scan a project directory with scope=packages and a target path, or a container image with scope=containers."
      );
    }
    const skip = SKIP_DIRS_POSIX.flatMap((d) => ["--skip-dirs", d]);
    return { args: ["rootfs", ...common, "--pkg-types", "os", ...skip, "/"], target: "/ (OS packages)" };
  }

  // scope === "all"
  if (target) {
    // A bounded directory: scan both OS-ish and library packages within it.
    return { args: ["fs", ...common, target], target };
  }
  if (family === "linux") {
    const skip = SKIP_DIRS_POSIX.flatMap((d) => ["--skip-dirs", d]);
    return { args: ["rootfs", ...common, "--pkg-types", "os", ...skip, "/"], target: "/ (OS packages)" };
  }
  throw new ScanGuidance(
    "needs_target",
    "On macOS/Windows there's no whole-system package scan; provide a `target` directory or use scope=containers with an `image`.",
    "Ask the user which project directory (or container image) to scan."
  );
}

export async function runScan(opts: ScanOptions = {}): Promise<ScanResult> {
  const scope = opts.scope ?? "all";
  await prepareDbCache(); // ensure the offline DB is extracted before trivy runs
  const platform = await detectPlatform();
  const budgetMs = opts.timeoutMs ?? 90_000;
  const trivySecs = Math.max(15, Math.floor(budgetMs / 1000) - 5);

  const { args, target } = buildScan(scope, platform.family, opts, trivySecs);

  const [version, exec] = await Promise.all([
    trivyVersion().catch(() => "unknown"),
    pexecFile(trivyPath(), args, {
      timeout: budgetMs,
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
    }),
  ]);

  let raw: any;
  try {
    raw = JSON.parse(exec.stdout);
  } catch (err) {
    throw new Error(`Failed to parse trivy output as JSON: ${(err as Error).message}`);
  }

  return {
    scanned_at: new Date().toISOString(),
    host: platform.hostname,
    os: platform.pretty,
    scanner: { name: "trivy", version },
    scope,
    target,
    findings: mapResults(raw),
  };
}

/** Surface a friendly error if trivy isn't installed/bundled. */
export async function ensureScannerAvailable(): Promise<void> {
  try {
    await prepareDbCache();
    await trivyVersion();
  } catch (err: any) {
    if (err?.code === "ENOENT") {
      throw new Error(
        "Trivy binary not found. VulnMCP bundles trivy in its .mcpb package; " +
          "if running from source, install trivy (https://trivy.dev) or set VULNMCP_TRIVY_PATH."
      );
    }
    throw err;
  }
}
