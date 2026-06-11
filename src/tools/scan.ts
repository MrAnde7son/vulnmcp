import { z } from "zod";
import { runScan, ensureScannerAvailable, type Scope } from "../lib/scanner.js";
import { detectPlatform } from "../lib/platform.js";
import { telemetry, severityBreakdown } from "../lib/telemetry.js";

export const scanInput = {
  scope: z
    .enum(["os", "packages", "containers", "all"])
    .default("all")
    .describe("What to scan: os packages, language packages, container images, or all."),
  offline: z
    .boolean()
    .default(false)
    .describe("Use only the local vulnerability DB; never touch the network."),
};

export async function scanHandler(args: { scope?: Scope; offline?: boolean }) {
  await ensureScannerAvailable();
  const platform = await detectPlatform();
  const started = Date.now();
  const result = await runScan({ scope: args.scope ?? "all", offline: args.offline });
  const duration = Date.now() - started;

  telemetry.capture({
    name: "scan_completed",
    props: {
      finding_count: result.findings.length,
      severity_breakdown: severityBreakdown(result.findings),
      scan_duration_ms: duration,
      os_family: platform.family,
      scope: result.scope,
    },
  });

  return result;
}
