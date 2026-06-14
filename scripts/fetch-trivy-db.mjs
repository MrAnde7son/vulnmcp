#!/usr/bin/env node
/**
 * Pre-download the Trivy vulnerability DB into ./trivy-cache so it can be shipped
 * inside the .mcpb. At runtime the server uses this cache with --skip-db-update,
 * so a scan NEVER downloads anything (the first-run ghcr.io pull is what blew the
 * Claude Desktop tool timeout).
 *
 * The raw BoltDB (db/trivy.db) is now ~1GB, which exceeds the .mcpb loader's
 * 512MB-per-file limit and makes the bundle refuse to install. BoltDB gzips
 * ~15:1, so we ship db/trivy.db.gz (~60MB) instead; the server decompresses it
 * once into a writable cache on startup (see prepareDbCache in lib/scanner.ts).
 *
 * The DB is OS-agnostic, so any runnable trivy works. Resolution order:
 *   --trivy <path>  |  TRIVY_BIN env  |  ./bin/trivy (if it runs)  |  trivy on PATH
 */
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { pipeline } from "node:stream/promises";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const cacheDir = path.join(root, "trivy-cache");

function argVal(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function runs(bin) {
  try {
    execFileSync(bin, ["--version"], { stdio: "ignore", timeout: 8000 });
    return true;
  } catch {
    return false;
  }
}

function resolveTrivy() {
  const candidates = [argVal("trivy"), process.env.TRIVY_BIN, path.join(root, "bin", "trivy"), "trivy"].filter(
    Boolean
  );
  for (const c of candidates) if (runs(c)) return c;
  throw new Error(
    "No runnable trivy found. Pass --trivy <path>, set TRIVY_BIN, or install trivy on PATH.\n" +
      "(./bin/trivy is the TARGET platform's binary and may not run on this host — that's expected in CI.)"
  );
}

const trivy = resolveTrivy();
fs.mkdirSync(cacheDir, { recursive: true });
console.log(`↓ downloading Trivy DB into ${cacheDir} using ${trivy}`);

// `image --download-db-only` fetches just the vuln DB (no Java DB — runtime uses
// --offline-scan, so Java DB isn't needed and would bloat the bundle by ~1GB).
execFileSync(trivy, ["--cache-dir", cacheDir, "image", "--download-db-only"], {
  stdio: "inherit",
  timeout: 5 * 60 * 1000,
});

// Sanity check: the metadata + db blob must exist.
const dbDir = path.join(cacheDir, "db");
const rawDb = path.join(dbDir, "trivy.db");
if (!fs.existsSync(path.join(dbDir, "metadata.json")) || !fs.existsSync(rawDb)) {
  throw new Error(`DB download did not produce ${dbDir}/{metadata.json,trivy.db}`);
}

// Compress the BoltDB and drop the raw file so no single bundle entry exceeds
// the .mcpb 512MB-per-file limit. metadata.json stays as-is (it's tiny).
const gzDb = `${rawDb}.gz`;
console.log(`↻ compressing ${path.basename(rawDb)} → ${path.basename(gzDb)} (bundle 512MB/file limit)`);
await pipeline(fs.createReadStream(rawDb), zlib.createGzip({ level: 6 }), fs.createWriteStream(gzDb));
fs.rmSync(rawDb);

if (!fs.existsSync(gzDb)) {
  throw new Error(`compression did not produce ${gzDb}`);
}
const size = execFileSync("du", ["-sh", cacheDir]).toString().split("\t")[0];
console.log(`✓ Trivy DB staged compressed (${size.trim()})`);
