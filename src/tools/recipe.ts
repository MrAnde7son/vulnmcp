import { z } from "zod";
import {
  loadStaticRecipe,
  validateRecipeSafety,
  type Recipe,
  type RecipeStep,
  type BlastRadius,
} from "../lib/recipes.js";
import { session } from "../lib/approval.js";
import { detectPlatform, type PackageManager } from "../lib/platform.js";
import { telemetry } from "../lib/telemetry.js";

const stepSchema = z.object({
  description: z.string(),
  command: z.string(),
  elevated: z.boolean().default(false),
  safe_to_automate: z.boolean().default(true),
});

export const recipeInput = {
  cve_id: z.string().describe("The CVE to remediate, e.g. CVE-2024-3094."),
  package: z.string().describe("The affected package name."),
  installed_version: z.string().default("").describe("Currently installed version."),
  fixed_version: z.string().default("").describe("Target fixed version from the scan."),
  package_manager: z
    .enum(["apt", "dnf", "yum", "apk", "pacman", "brew", "npm", "pip", "winget", "choco", "scoop"])
    .describe("Package manager to use. Must be one detected on this host."),
  /**
   * For CVEs with no static template, Claude supplies a dynamic recipe here.
   * It is run through the IDENTICAL safety gate as static recipes before it can
   * ever be registered for apply.
   */
  dynamic_steps: z
    .array(stepSchema)
    .optional()
    .describe("Optional Claude-generated steps when no static recipe exists. Validated server-side."),
  dynamic_rollback: z
    .object({ command: z.string(), elevated: z.boolean().default(true) })
    .optional(),
  reboot_required: z.boolean().optional(),
  service_restart: z.array(z.string()).optional(),
  blast_radius: z.enum(["LOW", "MEDIUM", "HIGH"]).optional(),
};

interface RecipeArgs {
  cve_id: string;
  package: string;
  installed_version?: string;
  fixed_version?: string;
  package_manager: PackageManager;
  dynamic_steps?: Array<z.infer<typeof stepSchema>>;
  dynamic_rollback?: { command: string; elevated?: boolean };
  reboot_required?: boolean;
  service_restart?: string[];
  blast_radius?: BlastRadius;
}

function buildDynamicRecipe(args: RecipeArgs): Recipe {
  const steps: RecipeStep[] = (args.dynamic_steps ?? []).map((s, i) => ({
    id: i + 1,
    description: s.description,
    command: s.command,
    elevated: s.elevated ?? false,
    safe_to_automate: s.safe_to_automate ?? false,
  }));
  return {
    cve_id: args.cve_id,
    package: args.package,
    package_manager: args.package_manager,
    recipe_type: "dynamic",
    source: "dynamic",
    steps,
    rollback: args.dynamic_rollback
      ? { command: args.dynamic_rollback.command, elevated: args.dynamic_rollback.elevated ?? true }
      : null,
    reboot_required: args.reboot_required ?? false,
    service_restart: args.service_restart ?? [],
    estimated_duration_seconds: 60,
    blast_radius: args.blast_radius ?? "MEDIUM",
  };
}

export async function recipeHandler(args: RecipeArgs) {
  const platform = await detectPlatform();

  // The requested manager must actually exist on this host.
  if (!platform.packageManagers.includes(args.package_manager)) {
    return {
      error: `package manager "${args.package_manager}" not detected on this host`,
      detected_managers: platform.packageManagers,
    };
  }

  let recipe =
    loadStaticRecipe(args.package_manager, args.cve_id, {
      package: args.package,
      installed_version: args.installed_version ?? "",
      fixed_version: args.fixed_version ?? "",
    }) ?? null;

  let source: "static" | "dynamic" = "static";
  if (!recipe) {
    if (!args.dynamic_steps?.length) {
      return {
        error: `no static recipe for "${args.package_manager}" and no dynamic_steps supplied`,
        hint: "Provide dynamic_steps (Claude-generated). They will be safety-validated server-side.",
      };
    }
    recipe = buildDynamicRecipe(args);
    source = "dynamic";
  }

  // SAFETY GATE — applies to both static and dynamic recipes.
  const violations = validateRecipeSafety(recipe);
  if (violations.length > 0) {
    return {
      error: "recipe rejected by safety gate",
      violations,
      recipe_preview: recipe,
    };
  }

  // Register in the session store; mint a one-time confirmation token.
  const { recipe_id, confirmation_token } = session.register(recipe);

  telemetry.capture({
    name: "recipe_generated",
    props: {
      package_manager: String(recipe.package_manager),
      recipe_source: source,
      blast_radius: recipe.blast_radius,
    },
  });

  return {
    recipe_id,
    confirmation_token,
    ...recipe,
    // Reminder surfaced to the model so it shows the gate to the user.
    _apply_instructions:
      "Show these steps, the rollback, and any service_restart to the user. " +
      "Ask them to type APPLY or SKIP. Only call apply_recipe with user_confirmed=true " +
      "and this confirmation_token after they type APPLY.",
  };
}
