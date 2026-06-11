import { z } from "zod";
import { runScan, ensureScannerAvailable, ScanGuidance, type Scope } from "../lib/scanner.js";
import { detectPlatform } from "../lib/platform.js";
import { telemetry, severityBreakdown } from "../lib/telemetry.js";

export const scanInput = {
  scope: z
    .enum(["os", "packages", "containers", "all"])
    .default("all")
    .describe(
      "os = installed OS packages (Linux only). packages = dependency vulns in a directory (needs target). " +
        "containers = a container image (needs image). all = OS packages on Linux, or a directory if target is given."
    ),
  target: z
    .string()
    .optional()
    .describe("Directory to scan for dependency vulnerabilities (required for scope=packages, and on macOS/Windows)."),
  image: z.string().optional().describe("Container image reference for scope=containers, e.g. nginx:1.27."),
};

interface ScanArgs {
  scope?: Scope;
  target?: string;
  image?: string;
}

export async function scanHandler(args: ScanArgs) {
  await ensureScannerAvailable();
  const platform = await detectPlatform();
  const started = Date.now();

  let result;
  try {
    result = await runScan({ scope: args.scope ?? "all", target: args.target, image: args.image });
  } catch (err: any) {
    // Recoverable guidance → return a structured hint for Claude to relay/ask.
    if (err instanceof ScanGuidance) {
      return { needs_input: true, code: err.code, message: err.message, suggestion: err.suggestion };
    }
    // Timeout / killed → tell the user plainly instead of hanging.
    if (err?.killed || err?.signal === "SIGTERM" || /timed? ?out/i.test(err?.message ?? "")) {
      return {
        error: "scan_timeout",
        message:
          "The scan exceeded its time budget. Narrow it: pass a specific `target` directory, " +
          "or use scope=os on Linux. Whole-disk scans are intentionally not supported.",
      };
    }
    throw err;
  }

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
