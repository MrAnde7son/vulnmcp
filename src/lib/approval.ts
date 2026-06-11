/**
 * The trust boundary.
 *
 * `get_remediation_recipe` registers a recipe in this in-memory, per-process
 * session store and mints a one-time confirmation token. `apply_recipe` is a
 * no-op unless it presents (a) user_confirmed=true AND (b) a recipe_id that
 * exists in this session with an unconsumed token. The model cannot fabricate
 * an apply for arbitrary commands — it can only apply a recipe this server
 * actually generated and validated in the current session.
 */
import crypto from "node:crypto";
import type { Recipe } from "./recipes.js";

interface SessionRecipe {
  recipe_id: string;
  token: string;
  recipe: Recipe;
  consumed: boolean;
  created_at: number;
}

/** Recipes expire so a stale id can't be applied much later. */
const RECIPE_TTL_MS = 30 * 60 * 1000;

class SessionStore {
  private byId = new Map<string, SessionRecipe>();

  register(recipe: Recipe): { recipe_id: string; confirmation_token: string } {
    const recipe_id = `rec_${crypto.randomBytes(8).toString("hex")}`;
    const token = crypto.randomBytes(16).toString("hex");
    this.byId.set(recipe_id, {
      recipe_id,
      token,
      recipe,
      consumed: false,
      created_at: Date.now(),
    });
    return { recipe_id, confirmation_token: token };
  }

  get(recipe_id: string): SessionRecipe | undefined {
    const entry = this.byId.get(recipe_id);
    if (!entry) return undefined;
    if (Date.now() - entry.created_at > RECIPE_TTL_MS) {
      this.byId.delete(recipe_id);
      return undefined;
    }
    return entry;
  }

  /**
   * Verify and atomically consume the one-time token. Returns the recipe on
   * success, or a structured rejection reason.
   */
  consume(
    recipe_id: string,
    user_confirmed: boolean,
    token?: string
  ): { ok: true; recipe: Recipe } | { ok: false; reason: string } {
    if (!user_confirmed) {
      return { ok: false, reason: "user_confirmed must be true; refusing to apply" };
    }
    const entry = this.get(recipe_id);
    if (!entry) {
      return { ok: false, reason: "unknown or expired recipe_id; regenerate the recipe first" };
    }
    if (entry.consumed) {
      return { ok: false, reason: "this recipe has already been applied (token spent)" };
    }
    if (token && token !== entry.token) {
      return { ok: false, reason: "confirmation token mismatch" };
    }
    entry.consumed = true;
    return { ok: true, recipe: entry.recipe };
  }
}

export const session = new SessionStore();
