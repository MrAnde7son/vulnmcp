import { describe, it, expect } from "vitest";
import { triageHandler } from "../src/tools/triage.js";
import type { Finding } from "../src/lib/scanner.js";

const findings: Finding[] = [
  {
    cve_id: "CVE-LOW",
    package: "a",
    installed_version: "1.0",
    fixed_version: "1.1",
    severity: "LOW",
    cvss_score: 3.1,
    epss_score: 0.01,
    description: "",
    published: null,
    pkg_manager: "apt",
  },
  {
    cve_id: "CVE-CRIT",
    package: "xz-utils",
    installed_version: "5.6.0",
    fixed_version: "5.6.1",
    severity: "CRITICAL",
    cvss_score: 10.0,
    epss_score: 0.94,
    description: "",
    published: null,
    pkg_manager: "apt",
  },
];

describe("triage ranking", () => {
  it("ranks the critical/high-EPSS finding first", async () => {
    const { ranked } = await triageHandler({ findings });
    expect(ranked[0].cve_id).toBe("CVE-CRIT");
    expect(ranked[0].priority_rank).toBe(1);
    expect(ranked[0].exploit_likelihood).toBe("HIGH");
    expect(ranked[0].recommended_action).toBe("patch_immediately");
  });

  it("marks fix availability", async () => {
    const { ranked } = await triageHandler({ findings });
    expect(ranked.every((r) => r.fix_available)).toBe(true);
  });
});
