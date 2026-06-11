#!/usr/bin/env node
/**
 * Fetch + checksum-verify the Trivy binary for a target platform and stage it
 * under bin/ for inclusion in the .mcpb bundle.
 *
 * Usage:
 *   node scripts/fetch-trivy.mjs --platform darwin-arm64
 *   node scripts/fetch-trivy.mjs --platform linux-amd64
 *   node scripts/fetch-trivy.mjs --platform windows-amd64
 *
 * SECURITY: every download is verified against a pinned SHA-256 below. Update
 * TRIVY_VERSION and CHECKSUMS together from the official release's
 * `trivy_<ver>_checksums.txt`. A mismatch aborts the build.
 */
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const TRIVY_VERSION = "0.58.1";

// Pinned SHA-256 of each release archive. Fill from the release checksums file:
//   https://github.com/aquasecurity/trivy/releases/download/v<ver>/trivy_<ver>_checksums.txt
// Empty string => "not pinned yet"; the script refuses to proceed without a pin.
const CHECKSUMS = {
  "darwin-arm64": { asset: `trivy_${TRIVY_VERSION}_macOS-ARM64.tar.gz`, sha256: "" },
  "darwin-amd64": { asset: `trivy_${TRIVY_VERSION}_macOS-64bit.tar.gz`, sha256: "" },
  "linux-amd64": { asset: `trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz`, sha256: "" },
  "linux-arm64": { asset: `trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz`, sha256: "" },
  "windows-amd64": { asset: `trivy_${TRIVY_VERSION}_windows-64bit.zip`, sha256: "" },
};

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
}

async function main() {
  const platform = arg("platform");
  if (!platform || !CHECKSUMS[platform]) {
    console.error(`--platform required, one of: ${Object.keys(CHECKSUMS).join(", ")}`);
    process.exit(1);
  }
  const { asset, sha256 } = CHECKSUMS[platform];
  if (!sha256 && !process.env.VULNMCP_ALLOW_UNPINNED) {
    console.error(
      `Refusing: no pinned SHA-256 for ${platform}.\n` +
        `Add it to scripts/fetch-trivy.mjs from the v${TRIVY_VERSION} checksums file, ` +
        `or set VULNMCP_ALLOW_UNPINNED=1 for local dev only.`
    );
    process.exit(2);
  }

  const url = `https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${asset}`;
  const tmpDir = fs.mkdtempSync(path.join(root, ".trivy-dl-"));
  const archive = path.join(tmpDir, asset);

  console.log(`↓ ${url}`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());

  const got = crypto.createHash("sha256").update(buf).digest("hex");
  if (sha256 && got !== sha256) {
    throw new Error(`checksum mismatch for ${asset}\n  expected ${sha256}\n  got      ${got}`);
  }
  if (!sha256) console.warn(`⚠ UNPINNED build — got sha256=${got} (pin this!)`);
  fs.writeFileSync(archive, buf);

  // Extract just the trivy binary into bin/.
  const binDir = path.join(root, "bin");
  fs.mkdirSync(binDir, { recursive: true });
  const isWin = platform.startsWith("windows");
  if (isWin) {
    execFileSync("unzip", ["-o", archive, "trivy.exe", "-d", binDir], { stdio: "inherit" });
  } else {
    execFileSync("tar", ["-xzf", archive, "-C", binDir, "trivy"], { stdio: "inherit" });
    fs.chmodSync(path.join(binDir, "trivy"), 0o755);
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
  console.log(`✓ trivy ${TRIVY_VERSION} staged in bin/ for ${platform}`);
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
