import { describe, it, expect } from "vitest";
import { session } from "../src/lib/approval.js";
import type { Recipe } from "../src/lib/recipes.js";

const demo: Recipe = {
  cve_id: "CVE-2024-3094",
  package: "xz-utils",
  package_manager: "apt",
  recipe_type: "package_upgrade",
  source: "static",
  steps: [{ id: 1, description: "x", command: "apt-get update", elevated: true, safe_to_automate: true }],
  rollback: null,
  reboot_required: false,
  service_restart: [],
  estimated_duration_seconds: 10,
  blast_radius: "LOW",
};

describe("approval trust boundary", () => {
  it("refuses apply without user_confirmed", () => {
    const { recipe_id, confirmation_token } = session.register(demo);
    const r = session.consume(recipe_id, false, confirmation_token);
    expect(r.ok).toBe(false);
  });

  it("refuses apply with a wrong token", () => {
    const { recipe_id } = session.register(demo);
    const r = session.consume(recipe_id, true, "deadbeef");
    expect(r.ok).toBe(false);
  });

  it("refuses an unknown recipe_id", () => {
    const r = session.consume("rec_does_not_exist", true, "x");
    expect(r.ok).toBe(false);
  });

  it("accepts a valid confirmation exactly once (one-time token)", () => {
    const { recipe_id, confirmation_token } = session.register(demo);
    const first = session.consume(recipe_id, true, confirmation_token);
    expect(first.ok).toBe(true);
    const second = session.consume(recipe_id, true, confirmation_token);
    expect(second.ok).toBe(false); // token already spent
  });
});
