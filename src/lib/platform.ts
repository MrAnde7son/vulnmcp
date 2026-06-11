/**
 * Platform & privilege detection.
 *
 * This is the cross-platform heart of VulnMCP. The recipe schema is written in
 * terms of an abstract `elevated` flag; this module decides what "elevated"
 * concretely means on the host (sudo on POSIX, an admin check on Windows) and
 * which package managers are actually available.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";

const pexecFile = promisify(execFile);

export type OsFamily = "linux" | "darwin" | "windows";

export type PackageManager =
  | "apt"
  | "dnf"
  | "yum"
  | "apk"
  | "pacman"
  | "brew"
  | "npm"
  | "pip"
  | "winget"
  | "choco"
  | "scoop";

/** Probe table: how to detect each manager and its OS affinity. */
const MANAGER_PROBES: Record<
  PackageManager,
  { families: OsFamily[]; check: string; checkArgs: string[] }
> = {
  apt: { families: ["linux"], check: "apt-get", checkArgs: ["--version"] },
  dnf: { families: ["linux"], check: "dnf", checkArgs: ["--version"] },
  yum: { families: ["linux"], check: "yum", checkArgs: ["--version"] },
  apk: { families: ["linux"], check: "apk", checkArgs: ["--version"] },
  pacman: { families: ["linux"], check: "pacman", checkArgs: ["--version"] },
  brew: { families: ["darwin", "linux"], check: "brew", checkArgs: ["--version"] },
  npm: { families: ["linux", "darwin", "windows"], check: "npm", checkArgs: ["--version"] },
  pip: { families: ["linux", "darwin", "windows"], check: "pip", checkArgs: ["--version"] },
  winget: { families: ["windows"], check: "winget", checkArgs: ["--version"] },
  choco: { families: ["windows"], check: "choco", checkArgs: ["--version"] },
  scoop: { families: ["windows"], check: "scoop", checkArgs: ["--version"] },
};

export interface PlatformInfo {
  family: OsFamily;
  release: string;
  pretty: string;
  arch: string;
  hostname: string;
  /** Package managers that are actually installed and on PATH. */
  packageManagers: PackageManager[];
  /** How privilege escalation works on this host. */
  elevation: "sudo" | "admin" | "none";
}

export function osFamily(): OsFamily {
  switch (process.platform) {
    case "win32":
      return "windows";
    case "darwin":
      return "darwin";
    default:
      return "linux";
  }
}

/** Best-effort human-readable OS string. */
async function prettyOs(family: OsFamily): Promise<string> {
  try {
    if (family === "darwin") {
      const { stdout } = await pexecFile("sw_vers", ["-productVersion"]);
      return `macOS ${stdout.trim()}`;
    }
    if (family === "linux") {
      // /etc/os-release is the standard; fall back to kernel release.
      const fs = await import("node:fs/promises");
      const data = await fs.readFile("/etc/os-release", "utf8").catch(() => "");
      const m = data.match(/^PRETTY_NAME="?(.+?)"?$/m);
      if (m) return m[1];
      return `Linux ${os.release()}`;
    }
    // windows
    const { stdout } = await pexecFile("cmd", ["/c", "ver"]);
    return stdout.trim() || `Windows ${os.release()}`;
  } catch {
    return `${family} ${os.release()}`;
  }
}

/** Is a binary resolvable on PATH? */
async function hasBinary(cmd: string, args: string[]): Promise<boolean> {
  try {
    await pexecFile(cmd, args, { timeout: 4000, windowsHide: true });
    return true;
  } catch (err: any) {
    // ENOENT => not installed. Non-zero exit but present still counts.
    return err?.code !== "ENOENT";
  }
}

async function detectManagers(family: OsFamily): Promise<PackageManager[]> {
  const candidates = (Object.entries(MANAGER_PROBES) as [
    PackageManager,
    (typeof MANAGER_PROBES)[PackageManager]
  ][]).filter(([, p]) => p.families.includes(family));

  const results = await Promise.all(
    candidates.map(async ([name, probe]) => {
      const present = await hasBinary(probe.check, probe.checkArgs);
      return present ? name : null;
    })
  );
  return results.filter((x): x is PackageManager => x !== null);
}

/** Are we already running with the privilege needed to mutate system packages? */
export async function isElevated(family: OsFamily): Promise<boolean> {
  if (family === "windows") {
    // `net session` only succeeds for an elevated (admin) token.
    try {
      await pexecFile("net", ["session"], { timeout: 4000, windowsHide: true });
      return true;
    } catch {
      return false;
    }
  }
  // POSIX: uid 0 is root.
  return typeof process.getuid === "function" && process.getuid() === 0;
}

let cached: PlatformInfo | null = null;

export async function detectPlatform(force = false): Promise<PlatformInfo> {
  if (cached && !force) return cached;
  const family = osFamily();
  const [pretty, packageManagers] = await Promise.all([
    prettyOs(family),
    detectManagers(family),
  ]);
  cached = {
    family,
    release: os.release(),
    pretty,
    arch: process.arch,
    hostname: os.hostname(),
    packageManagers,
    elevation: family === "windows" ? "admin" : "sudo",
  };
  return cached;
}

/**
 * Wrap a command with the platform's elevation mechanism.
 * On POSIX we prefix `sudo`. On Windows there is no inline sudo; we surface the
 * requirement so the apply layer can verify the process is already elevated and
 * refuse otherwise (rather than silently failing mid-recipe).
 */
export function elevatedInvocation(
  family: OsFamily,
  command: string,
  args: string[]
): { command: string; args: string[]; needsPreElevatedProcess: boolean } {
  if (family === "windows") {
    return { command, args, needsPreElevatedProcess: true };
  }
  return { command: "sudo", args: [command, ...args], needsPreElevatedProcess: false };
}
