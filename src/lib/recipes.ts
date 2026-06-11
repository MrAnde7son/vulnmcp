/**
 * Remediation recipe model + static template loader + safety validation.
 *
 * A recipe is an ordered list of shell steps with an abstract `elevated` flag.
 * Static templates live in /recipes/<manager>.yaml and use {{placeholders}}.
 * The same schema is used for Claude-generated dynamic recipes so that both go
 * through the identical safety gate before they can ever be applied.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import type { PackageManager } from "./platform.js";

export type BlastRadius = "LOW" | "MEDIUM" | "HIGH";
export type RecipeSource = "static" | "dynamic";

export interface RecipeStep {
  id: number;
  description: string;
  /** Full command string, for display. Argv is derived for execution. */
  command: string;
  /** Requires privilege escalation (sudo on POSIX / admin token on Windows). */
  elevated: boolean;
  safe_to_automate: boolean;
}

export interface Recipe {
  cve_id: string;
  package: string;
  package_manager: PackageManager | string;
  recipe_type: string;
  source: RecipeSource;
  steps: RecipeStep[];
  rollback: { command: string; elevated: boolean } | null;
  reboot_required: boolean;
  service_restart: string[];
  estimated_duration_seconds: number;
  blast_radius: BlastRadius;
}

interface RecipeTemplate {
  recipe_type: string;
  reboot_required?: boolean;
  service_restart?: string[];
  estimated_duration_seconds?: number;
  blast_radius?: BlastRadius;
  steps: Array<{
    description: string;
    command: string;
    elevated?: boolean;
    safe_to_automate?: boolean;
  }>;
  rollback?: { command: string; elevated?: boolean };
}

function recipesRoot(): string {
  // dist/lib/recipes.js -> ../../recipes ; src/lib/recipes.ts -> ../../recipes
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    process.env.VULNMCP_RECIPES_DIR,
    path.join(here, "..", "..", "recipes"),
    path.join(here, "..", "recipes"),
  ].filter(Boolean) as string[];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return candidates[candidates.length - 1];
}

function interpolate(s: string, vars: Record<string, string>): string {
  return s.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, k) => vars[k] ?? "");
}

export interface RecipeVars {
  package: string;
  installed_version: string;
  fixed_version: string;
}

/** Load and fill a static template for a package manager, if one exists. */
export function loadStaticRecipe(
  manager: PackageManager | string,
  cve_id: string,
  vars: RecipeVars
): Recipe | null {
  const file = path.join(recipesRoot(), `${manager}.yaml`);
  if (!fs.existsSync(file)) return null;
  const tpl = YAML.parse(fs.readFileSync(file, "utf8")) as RecipeTemplate;
  const v = { ...vars, cve_id };

  const steps: RecipeStep[] = tpl.steps.map((s, i) => ({
    id: i + 1,
    description: interpolate(s.description, v),
    command: interpolate(s.command, v),
    elevated: s.elevated ?? false,
    safe_to_automate: s.safe_to_automate ?? true,
  }));

  return {
    cve_id,
    package: vars.package,
    package_manager: manager,
    recipe_type: tpl.recipe_type,
    source: "static",
    steps,
    rollback: tpl.rollback
      ? { command: interpolate(tpl.rollback.command, v), elevated: tpl.rollback.elevated ?? true }
      : null,
    reboot_required: tpl.reboot_required ?? false,
    service_restart: tpl.service_restart ?? [],
    estimated_duration_seconds: tpl.estimated_duration_seconds ?? 30,
    blast_radius: tpl.blast_radius ?? "LOW",
  };
}

export function listStaticManagers(): string[] {
  try {
    return fs
      .readdirSync(recipesRoot())
      .filter((f) => f.endsWith(".yaml"))
      .map((f) => f.replace(/\.yaml$/, ""));
  } catch {
    return [];
  }
}

/* ----------------------------- Safety gate ------------------------------- */

export interface SafetyViolation {
  step?: number;
  reason: string;
  command: string;
}

/**
 * Hard scope restrictions from the spec. A recipe that trips ANY of these is
 * rejected before it can be applied — for both static and dynamic recipes.
 */
const FORBIDDEN_PATTERNS: Array<{ re: RegExp; reason: string }> = [
  { re: /\b(curl|wget|iwr|invoke-webrequest)\b/i, reason: "downloads from a URL without a pinned checksum" },
  { re: /\b(iptables|nft|ufw|firewall-cmd|netsh\s+advfirewall|pfctl)\b/i, reason: "modifies firewall/iptables rules" },
  { re: /\b(insmod|rmmod|modprobe)\b/i, reason: "loads or unloads kernel modules" },
  { re: /\brm\s+-rf?\s+\/(?:\s|$)/i, reason: "recursive delete of a root path" },
  { re: /\b(mkfs|dd\s+if=|fdisk|diskpart)\b/i, reason: "destructive disk operation" },
  { re: />\s*\/etc\/(?!apt|yum|dnf)/i, reason: "writes into /etc outside package-manager config" },
  { re: /\b(bash|sh|powershell|pwsh)\s+-c\b/i, reason: "executes an arbitrary nested shell" },
  { re: /\|\s*(bash|sh|powershell|pwsh)\b/i, reason: "pipes content into a shell interpreter" },
  { re: /\b(eval|source)\b/i, reason: "evaluates dynamic shell content" },
];

/** Allowed leading executables. Anything else must be justified by review. */
const ALLOWED_COMMANDS = new Set([
  "apt-get", "apt", "dpkg",
  "dnf", "yum", "rpm",
  "apk",
  "pacman",
  "brew",
  "npm", "pip", "pip3",
  "winget", "choco", "scoop",
  "systemctl", "service",
  "sc", "net",
  "dpkg-query", "rpm",
  "echo", "true",
]);

export function validateRecipeSafety(recipe: Recipe): SafetyViolation[] {
  const violations: SafetyViolation[] = [];
  const allCommands = [
    ...recipe.steps.map((s) => ({ step: s.id, command: s.command })),
    ...(recipe.rollback ? [{ step: undefined, command: recipe.rollback.command }] : []),
  ];

  for (const { step, command } of allCommands) {
    for (const { re, reason } of FORBIDDEN_PATTERNS) {
      if (re.test(command)) violations.push({ step, reason, command });
    }
    const lead = command.trim().split(/\s+/)[0]?.replace(/^sudo$/, "");
    const exe = lead === "sudo" ? command.trim().split(/\s+/)[1] : lead;
    if (exe && !ALLOWED_COMMANDS.has(exe)) {
      violations.push({
        step,
        reason: `command "${exe}" is not in the allow-list of package/service tools`,
        command,
      });
    }
  }
  return violations;
}
