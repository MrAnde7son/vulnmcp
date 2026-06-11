/**
 * Opt-in, privacy-preserving telemetry via PostHog.
 *
 * Design constraints (this is a security tool — get this right or get roasted):
 *   - OFF by default. Nothing is sent until the user runs `vulnmcp telemetry on`
 *     or sets VULNMCP_TELEMETRY=1.
 *   - No CVE ids, no package names, no hostnames, no file paths, no IPs.
 *     Only aggregate shapes: counts, severities, durations, os family, manager.
 *   - distinct_id is a random install id, never anything host-identifying.
 *   - Fully non-blocking and failure-tolerant: telemetry must never break a scan.
 *
 * The PostHog project key is a write-only ingest key and is safe to ship in OSS.
 */
import { PostHog } from "posthog-node";
import { loadConfig, telemetryEnabled, type VulnMcpConfig } from "./config.js";
import type { Severity } from "./scanner.js";

// Public, write-only ingest key. Override at build time via VULNMCP_POSTHOG_KEY.
const DEFAULT_POSTHOG_KEY = process.env.VULNMCP_POSTHOG_KEY ?? "";
const POSTHOG_HOST = process.env.VULNMCP_POSTHOG_HOST ?? "https://us.i.posthog.com";

export type TelemetryEvent =
  | { name: "scan_completed"; props: ScanProps }
  | { name: "triage_completed"; props: { finding_count: number; os_family: string } }
  | { name: "recipe_generated"; props: { package_manager: string; recipe_source: "static" | "dynamic"; blast_radius: string } }
  | { name: "recipe_applied"; props: ApplyProps };

interface ScanProps {
  finding_count: number;
  severity_breakdown: Partial<Record<Severity, number>>;
  scan_duration_ms: number;
  os_family: string;
  scope: string;
}

interface ApplyProps {
  severity: string;
  blast_radius: string;
  package_manager: string;
  duration_ms: number;
  success: boolean;
  dry_run: boolean;
  os_family: string;
}

class Telemetry {
  private client: PostHog | null = null;
  private cfg: VulnMcpConfig;

  constructor() {
    this.cfg = loadConfig();
  }

  private enabled(): boolean {
    return telemetryEnabled(this.cfg) && DEFAULT_POSTHOG_KEY.length > 0;
  }

  private ensureClient(): PostHog | null {
    if (!this.enabled()) return null;
    if (!this.client) {
      this.client = new PostHog(DEFAULT_POSTHOG_KEY, {
        host: POSTHOG_HOST,
        flushAt: 1,
        flushInterval: 0,
      });
    }
    return this.client;
  }

  capture(event: TelemetryEvent): void {
    try {
      const client = this.ensureClient();
      if (!client) return;
      client.capture({
        distinctId: this.cfg.install_id,
        event: event.name,
        properties: { ...event.props, $process_person_profile: false },
      });
    } catch {
      // Never let telemetry surface an error to the user.
    }
  }

  async shutdown(): Promise<void> {
    try {
      await this.client?.shutdown();
    } catch {
      /* ignore */
    }
  }
}

export const telemetry = new Telemetry();

/** Convenience: build a severity histogram from findings. */
export function severityBreakdown(
  findings: { severity: Severity }[]
): Partial<Record<Severity, number>> {
  const out: Partial<Record<Severity, number>> = {};
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}
