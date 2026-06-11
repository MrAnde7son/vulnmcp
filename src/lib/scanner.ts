/**
 * Trivy wrapper.
 *
 * Runs the local Trivy binary in offline/local-fs mode and normalizes its JSON
 * into VulnMCP's finding schema. The model never sees raw scanner noise — only
 * the structured findings defined here.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs";
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
  /** Which package manager owns this package, if Trivy reports it. */
  pkg_manager: string | null;
}

export interface ScanResult {
  scanned_at: string;
  host: string;
  os: string;
  scanner: { name: "trivy"; version: string };
  scope: Scope;
  findings: Finding[];
}

/**
 * Resolve the trivy binary: env override (with Windows .exe fallback), then PATH.
 * The .mcpb manifest passes a platform-agnostic bin/trivy path; on Windows the
 * bundled file is trivy.exe, so we append the extension when needed.
 */
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

export async function trivyVersion(): Promise<string> {
  const { stdout } = await pexecFile(trivyPath(), ["--version", "--format", "json"], {
    timeout: 10_000,
    windowsHide: true,
  });
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

/** Pull the highest available CVSS score across vendor sources. */
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

function mapResults(raw: any, scope: Scope): Finding[] {
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
        pkg_manager: result.Class === "lang-pkgs" ? result.Type ?? null : result.Type ?? null,
      });
    }
  }
  return out;
}

/** Build the trivy argv for a given scope and OS. */
function buildArgs(scope: Scope, family: OsFamily): string[] {
  // `rootfs /` enumerates OS + installed packages on the host.
  // `fs .` covers language dependencies in the working tree.
  const base = ["--quiet", "--format", "json", "--scanners", "vuln"];
  const target = family === "windows" ? "C:\\" : "/";
  switch (scope) {
    case "packages":
      return ["fs", ...base, "--pkg-types", "library", "."];
    case "containers":
      // Container image scanning is invoked with an explicit image elsewhere;
      // for a host scan we fall back to rootfs.
      return ["rootfs", ...base, target];
    case "os":
      return ["rootfs", ...base, "--pkg-types", "os", target];
    case "all":
    default:
      return ["rootfs", ...base, target];
  }
}

export interface ScanOptions {
  scope?: Scope;
  /** Use only the local vuln DB; never hit the network. */
  offline?: boolean;
  timeoutMs?: number;
}

export async function runScan(opts: ScanOptions = {}): Promise<ScanResult> {
  const scope = opts.scope ?? "all";
  const platform = await detectPlatform();
  const args = buildArgs(scope, platform.family);
  if (opts.offline) args.push("--skip-db-update", "--offline-scan");

  const [version, exec] = await Promise.all([
    trivyVersion().catch(() => "unknown"),
    pexecFile(trivyPath(), args, {
      timeout: opts.timeoutMs ?? 180_000,
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
    findings: mapResults(raw, scope),
  };
}

/** Surface a friendly error if trivy isn't installed/bundled. */
export async function ensureScannerAvailable(): Promise<void> {
  try {
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
