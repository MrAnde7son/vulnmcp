#!/usr/bin/env node
/**
 * VulnMCP — MCP server entrypoint (stdio transport for Claude Desktop).
 *
 * Packaged as an .mcpb bundle for one-click install. Runs as a native local
 * process so it can scan the real host; never phones home unless telemetry is
 * explicitly opted in.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { scanInput, scanHandler } from "./tools/scan.js";
import { triageInput, triageHandler } from "./tools/triage.js";
import { recipeInput, recipeHandler } from "./tools/recipe.js";
import { applyInput, applyHandler } from "./tools/apply.js";
import { telemetry } from "./lib/telemetry.js";
import { telemetryEnabled, loadConfig } from "./lib/config.js";
import { prepareDbCache } from "./lib/scanner.js";

const VERSION = "2026.6.2";

function ok(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }] };
}

async function main() {
  const server = new McpServer({ name: "vulnmcp", version: VERSION });

  server.registerTool(
    "scan_system",
    {
      title: "Scan system for vulnerabilities",
      description:
        "Run a local, offline Trivy scan and return structured CVE findings. Stays on this machine. " +
        "scope=os scans installed OS packages (Linux only). scope=packages scans a `target` directory " +
        "for dependency vulns. scope=containers scans an `image`. On macOS/Windows there is no whole-disk " +
        "scan — if the response has needs_input, ask the user for a target directory or image, then retry.",
      inputSchema: scanInput,
    },
    async (args) => ok(await scanHandler(args))
  );

  server.registerTool(
    "triage_findings",
    {
      title: "Triage and rank findings",
      description:
        "Deterministically rank scan findings by severity, CVSS, EPSS and fixability. " +
        "No external API calls — a stable scaffold for Claude to reason over.",
      inputSchema: triageInput,
    },
    async (args) => ok(await triageHandler(args as any))
  );

  server.registerTool(
    "get_remediation_recipe",
    {
      title: "Generate a remediation recipe",
      description:
        "Produce an executable, safety-validated remediation plan for a CVE+package on a " +
        "detected package manager. Returns a recipe_id and one-time confirmation_token " +
        "required by apply_recipe. Supports apt/dnf/yum/apk/pacman/brew/npm/pip/winget/choco/scoop.",
      inputSchema: recipeInput,
    },
    async (args) => ok(await recipeHandler(args as any))
  );

  server.registerTool(
    "apply_recipe",
    {
      title: "Apply a remediation recipe (requires approval)",
      description:
        "Execute a previously generated recipe. THE TRUST BOUNDARY: requires user_confirmed=true " +
        "AND the one-time confirmation_token. Only call after the user explicitly typed APPLY. " +
        "Use dry_run=true to preview resolved commands without executing.",
      inputSchema: applyInput,
    },
    async (args) => ok(await applyHandler(args as any))
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Decompress the bundled (gzipped) Trivy DB into a writable cache now, at
  // boot, so the first scan_system call doesn't pay for it under the MCP
  // request timeout. Fire-and-forget: runScan awaits the same memoized promise.
  void prepareDbCache();

  const cfg = loadConfig();
  // One line to stderr (never stdout — stdout is the MCP channel).
  process.stderr.write(
    `vulnmcp ${VERSION} ready · telemetry ${telemetryEnabled(cfg) ? "ON (opt-in)" : "off"}\n`
  );

  const shutdown = async () => {
    await telemetry.shutdown();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  process.stderr.write(`vulnmcp fatal: ${err?.stack || err}\n`);
  process.exit(1);
});
