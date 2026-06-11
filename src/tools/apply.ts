import { z } from "zod";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { session } from "../lib/approval.js";
import { appendAudit } from "../lib/audit-log.js";
import {
  detectPlatform,
  isElevated,
  elevatedInvocation,
  type OsFamily,
} from "../lib/platform.js";
import { validateRecipeSafety, type Recipe, type RecipeStep } from "../lib/recipes.js";
import { telemetry } from "../lib/telemetry.js";

const pexecFile = promisify(execFile);

export const applyInput = {
  recipe_id: z.string().describe("recipe_id returned by get_remediation_recipe."),
  confirmation_token: z
    .string()
    .describe("One-time token from get_remediation_recipe. Required — apply is a no-op without it."),
  user_confirmed: z
    .boolean()
    .describe("Must be true. Set only after the user explicitly typed APPLY."),
  dry_run: z.boolean().default(false).describe("Print commands without executing them."),
};

interface ApplyArgs {
  recipe_id: string;
  confirmation_token: string;
  user_confirmed: boolean;
  dry_run?: boolean;
}

/** Minimal, shell-free argv tokenizer (recipes forbid shell metacharacters). */
function tokenize(command: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(command))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

function planStep(step: RecipeStep, family: OsFamily) {
  const argv = tokenize(step.command);
  const [cmd, ...rest] = argv;
  if (step.elevated) {
    const e = elevatedInvocation(family, cmd, rest);
    return { command: e.command, args: e.args, needsPreElevatedProcess: e.needsPreElevatedProcess };
  }
  return { command: cmd, args: rest, needsPreElevatedProcess: false };
}

export async function applyHandler(args: ApplyArgs) {
  const platform = await detectPlatform();

  // 1) Trust boundary: consume the one-time token.
  const consumed = session.consume(args.recipe_id, args.user_confirmed, args.confirmation_token);
  if (!consumed.ok) {
    appendAudit({
      action: "REJECTED",
      cve_id: args.recipe_id,
      package: "-",
      package_manager: "-",
      result: consumed.reason,
    });
    return { status: "failed" as const, error: consumed.reason };
  }
  const recipe: Recipe = consumed.recipe;

  // 2) Re-validate safety at apply time (defense in depth).
  const violations = validateRecipeSafety(recipe);
  if (violations.length > 0) {
    appendAudit({
      action: "REJECTED",
      cve_id: recipe.cve_id,
      package: recipe.package,
      package_manager: String(recipe.package_manager),
      result: "safety_gate_failed_at_apply",
    });
    return { status: "failed" as const, error: "safety gate failed at apply", violations };
  }

  // 3) On Windows, elevated steps require an already-elevated process.
  const needsElevation = recipe.steps.some((s) => s.elevated);
  if (needsElevation && platform.family === "windows" && !(await isElevated("windows"))) {
    const msg =
      "This recipe needs administrator rights. Restart Claude Desktop 'as administrator' " +
      "and retry, or apply the steps manually.";
    appendAudit({
      action: "FAILED",
      cve_id: recipe.cve_id,
      package: recipe.package,
      package_manager: String(recipe.package_manager),
      result: "needs_admin",
    });
    return { status: "failed" as const, error: msg };
  }

  const started = Date.now();
  const steps_executed: Array<{
    id: number;
    command: string;
    status: "ok" | "failed" | "planned";
    stdout?: string;
    stderr?: string;
    exit_code?: number | null;
  }> = [];

  // 4) Dry run: return the resolved plan without executing.
  if (args.dry_run) {
    for (const step of recipe.steps) {
      const plan = planStep(step, platform.family);
      steps_executed.push({
        id: step.id,
        command: [plan.command, ...plan.args].join(" "),
        status: "planned",
      });
    }
    telemetry.capture({
      name: "recipe_applied",
      props: {
        severity: "-",
        blast_radius: recipe.blast_radius,
        package_manager: String(recipe.package_manager),
        duration_ms: Date.now() - started,
        success: true,
        dry_run: true,
        os_family: platform.family,
      },
    });
    appendAudit({
      action: "DRY_RUN",
      cve_id: recipe.cve_id,
      package: recipe.package,
      to_version: recipe.cve_id,
      package_manager: String(recipe.package_manager),
      result: "dry_run",
    });
    return {
      status: "dry_run" as const,
      steps_executed,
      reboot_required: recipe.reboot_required,
      service_restart: recipe.service_restart,
    };
  }

  // 5) Execute steps sequentially; stop on first failure.
  let ok = true;
  let failureStderr = "";
  for (const step of recipe.steps) {
    const plan = planStep(step, platform.family);
    try {
      const { stdout, stderr } = await pexecFile(plan.command, plan.args, {
        timeout: 120_000,
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
      });
      steps_executed.push({
        id: step.id,
        command: [plan.command, ...plan.args].join(" "),
        status: "ok",
        stdout: stdout.slice(0, 8000),
        stderr: stderr.slice(0, 8000),
        exit_code: 0,
      });
    } catch (err: any) {
      ok = false;
      failureStderr = (err?.stderr || err?.message || "").slice(0, 8000);
      steps_executed.push({
        id: step.id,
        command: [plan.command, ...plan.args].join(" "),
        status: "failed",
        stdout: (err?.stdout || "").slice(0, 8000),
        stderr: failureStderr,
        exit_code: typeof err?.code === "number" ? err.code : null,
      });
      break;
    }
  }

  const duration_ms = Date.now() - started;

  appendAudit({
    action: ok ? "APPLIED" : "FAILED",
    cve_id: recipe.cve_id,
    package: recipe.package,
    package_manager: String(recipe.package_manager),
    result: ok ? "success" : "step_failed",
  });

  telemetry.capture({
    name: "recipe_applied",
    props: {
      severity: "-",
      blast_radius: recipe.blast_radius,
      package_manager: String(recipe.package_manager),
      duration_ms,
      success: ok,
      dry_run: false,
      os_family: platform.family,
    },
  });

  return {
    status: ok ? ("success" as const) : ("failed" as const),
    steps_executed,
    duration_ms,
    reboot_required: recipe.reboot_required,
    service_restart: recipe.service_restart,
    rollback: recipe.rollback,
    verified: ok,
    ...(ok ? {} : { error: failureStderr || "a step failed; see steps_executed" }),
  };
}
