import { describe, it, expect } from "vitest";
import { runScan, ScanGuidance } from "../src/lib/scanner.js";

/**
 * These assert the guards that prevent the v1 timeout regression: scans must
 * never fall through to `trivy rootfs /`, and missing inputs must surface as
 * recoverable guidance BEFORE any trivy process is spawned (so no test here
 * needs trivy installed).
 */
describe("scan input guards (no whole-disk scans)", () => {
  it("requires an image for scope=containers", async () => {
    await expect(runScan({ scope: "containers" })).rejects.toMatchObject({
      name: "ScanGuidance",
      code: "needs_image",
    });
  });

  it("requires a target dir for scope=packages", async () => {
    await expect(runScan({ scope: "packages" })).rejects.toMatchObject({
      name: "ScanGuidance",
      code: "needs_target",
    });
  });

  it("rejects a non-existent target path", async () => {
    await expect(
      runScan({ scope: "packages", target: "/definitely/not/a/real/path/xyz" })
    ).rejects.toBeInstanceOf(ScanGuidance);
  });
});
