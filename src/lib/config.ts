/**
 * Local config + anonymous install id.
 *
 * Lives at ~/.vulnmcp/config.json. Holds the telemetry opt-in flag and a random
 * install id used only to deduplicate anonymous events. No host data here.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";

export interface VulnMcpConfig {
  telemetry_enabled: boolean;
  install_id: string;
  /** Schema version for forward-compat migrations. */
  version: 1;
}

export function configDir(): string {
  return process.env.VULNMCP_HOME || path.join(os.homedir(), ".vulnmcp");
}

export function configPath(): string {
  return path.join(configDir(), "config.json");
}

function ensureDir(): void {
  fs.mkdirSync(configDir(), { recursive: true });
}

function defaults(): VulnMcpConfig {
  return {
    // Opt-in: telemetry is OFF until the user explicitly enables it.
    telemetry_enabled: false,
    install_id: crypto.randomUUID(),
    version: 1,
  };
}

export function loadConfig(): VulnMcpConfig {
  try {
    const raw = fs.readFileSync(configPath(), "utf8");
    const parsed = JSON.parse(raw) as Partial<VulnMcpConfig>;
    return { ...defaults(), ...parsed, version: 1 };
  } catch {
    // First run: persist defaults so install_id is stable across launches.
    const d = defaults();
    saveConfig(d);
    return d;
  }
}

export function saveConfig(cfg: VulnMcpConfig): void {
  ensureDir();
  fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
}

/**
 * Effective telemetry state. An env var can force it on/off for CI or for
 * privacy-conscious users, overriding the stored config either way.
 *   VULNMCP_TELEMETRY=1 -> on, =0 -> off
 */
export function telemetryEnabled(cfg: VulnMcpConfig = loadConfig()): boolean {
  const env = process.env.VULNMCP_TELEMETRY;
  if (env === "1" || env?.toLowerCase() === "true") return true;
  if (env === "0" || env?.toLowerCase() === "false") return false;
  return cfg.telemetry_enabled;
}

export function setTelemetry(enabled: boolean): VulnMcpConfig {
  const cfg = loadConfig();
  cfg.telemetry_enabled = enabled;
  saveConfig(cfg);
  return cfg;
}
