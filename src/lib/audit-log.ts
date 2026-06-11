/**
 * Append-only audit log at ~/.vulnmcp/audit.log.
 *
 * Every apply (and every rejected apply) is recorded. The log is local-only and
 * is never transmitted by telemetry. Format is a single human-readable line plus
 * a structured JSONL mirror (audit.jsonl) for tooling.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { configDir } from "./config.js";

export interface AuditEntry {
  ts: string;
  action: "APPLIED" | "REJECTED" | "DRY_RUN" | "FAILED";
  cve_id: string;
  package: string;
  from_version?: string;
  to_version?: string;
  package_manager: string;
  result: string;
  user: string;
}

function auditTextPath(): string {
  return path.join(configDir(), "audit.log");
}
function auditJsonlPath(): string {
  return path.join(configDir(), "audit.jsonl");
}

function currentUser(): string {
  try {
    return os.userInfo().username;
  } catch {
    return process.env.USER || process.env.USERNAME || "unknown";
  }
}

function formatLine(e: AuditEntry): string {
  const ver =
    e.from_version && e.to_version ? `${e.from_version}→${e.to_version}` : e.to_version ?? "-";
  return `${e.ts}  ${e.action.padEnd(8)} ${e.cve_id}  ${e.package}  ${ver}  user=${e.user}  result=${e.result}`;
}

export function appendAudit(
  entry: Omit<AuditEntry, "ts" | "user"> & Partial<Pick<AuditEntry, "ts" | "user">>
): AuditEntry {
  const full: AuditEntry = {
    ts: entry.ts ?? new Date().toISOString(),
    user: entry.user ?? currentUser(),
    ...entry,
  } as AuditEntry;

  fs.mkdirSync(configDir(), { recursive: true });
  // Append-only; never rewrite existing content.
  fs.appendFileSync(auditTextPath(), formatLine(full) + "\n", { mode: 0o600 });
  fs.appendFileSync(auditJsonlPath(), JSON.stringify(full) + "\n", { mode: 0o600 });
  return full;
}

export function readAudit(limit = 100): string[] {
  try {
    const lines = fs.readFileSync(auditTextPath(), "utf8").trimEnd().split("\n");
    return lines.slice(-limit);
  } catch {
    return [];
  }
}
