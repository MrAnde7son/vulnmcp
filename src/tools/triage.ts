import { z } from "zod";
import type { Finding, Severity } from "../lib/scanner.js";
import { detectPlatform } from "../lib/platform.js";
import { telemetry } from "../lib/telemetry.js";

/**
 * triage_findings does NOT call any external API. It returns a deterministic
 * base ranking computed from scanner output so Claude has a stable scaffold to
 * reason over; Claude then layers host/service context on top in its response.
 */
const findingSchema = z.object({
  cve_id: z.string(),
  package: z.string(),
  installed_version: z.string().optional(),
  fixed_version: z.string().nullable().optional(),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]),
  cvss_score: z.number().nullable().optional(),
  epss_score: z.number().nullable().optional(),
  description: z.string().optional(),
  published: z.string().nullable().optional(),
});

export const triageInput = {
  findings: z.array(findingSchema).describe("The findings array returned by scan_system."),
};

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 40,
  HIGH: 25,
  MEDIUM: 12,
  LOW: 4,
  UNKNOWN: 2,
};

function exploitLikelihood(epss: number | null | undefined, severity: Severity): "HIGH" | "MEDIUM" | "LOW" {
  const e = epss ?? 0;
  if (e >= 0.5 || (severity === "CRITICAL" && e >= 0.1)) return "HIGH";
  if (e >= 0.1 || severity === "CRITICAL" || severity === "HIGH") return "MEDIUM";
  return "LOW";
}

function score(f: Finding): number {
  const sev = SEVERITY_WEIGHT[f.severity] ?? 2;
  const cvss = (f.cvss_score ?? 0) * 3; // 0..30
  const epss = (f.epss_score ?? 0) * 30; // 0..30
  const fixable = f.fixed_version ? 5 : 0; // mild boost: a fix exists
  return Math.round((sev + cvss + epss + fixable) * 10) / 10;
}

export async function triageHandler(args: { findings: Finding[] }) {
  const platform = await detectPlatform();
  const ranked = [...args.findings]
    .map((f) => ({ f, s: score(f) }))
    .sort((a, b) => b.s - a.s)
    .map((entry, i) => {
      const f = entry.f;
      const likelihood = exploitLikelihood(f.epss_score, f.severity);
      const recommended_action =
        f.severity === "CRITICAL" || likelihood === "HIGH"
          ? "patch_immediately"
          : f.fixed_version
          ? "patch_scheduled"
          : "monitor";
      return {
        cve_id: f.cve_id,
        package: f.package,
        priority_rank: i + 1,
        base_score: entry.s,
        severity: f.severity,
        exploit_likelihood: likelihood,
        fix_available: Boolean(f.fixed_version),
        recommended_action,
        // Factual scaffold only — Claude adds host/service reasoning in prose.
        signal: {
          cvss: f.cvss_score ?? null,
          epss: f.epss_score ?? null,
          published: f.published ?? null,
        },
      };
    });

  telemetry.capture({
    name: "triage_completed",
    props: { finding_count: ranked.length, os_family: platform.family },
  });

  return { ranked };
}
