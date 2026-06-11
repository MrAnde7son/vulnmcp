#!/usr/bin/env node
/**
 * Generate assets/icon.png — a 512x512 "protected shield + check" mark.
 * Pure Node (zlib), 2x supersampled for anti-aliasing. Re-run only to tweak
 * the design; the PNG itself is committed.
 */
import zlib from "node:zlib";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SIZE = 512;
const SS = 2; // supersample factor
const W = SIZE * SS;
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

// --- geometry helpers ---
const lerp = (a, b, t) => a + (b - a) * t;
function qbez(p0, p1, p2, t) {
  const u = 1 - t;
  return [u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0], u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1]];
}
function pointInPoly(x, y, pts) {
  let inside = false;
  for (let i = 0, j = pts.length - 1; i < pts.length; j = i++) {
    const xi = pts[i][0], yi = pts[i][1], xj = pts[j][0], yj = pts[j][1];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
function distToSeg(px, py, a, b) {
  const dx = b[0] - a[0], dy = b[1] - a[1];
  const l2 = dx * dx + dy * dy || 1;
  let t = ((px - a[0]) * dx + (py - a[1]) * dy) / l2;
  t = Math.max(0, Math.min(1, t));
  const cx = a[0] + t * dx, cy = a[1] + t * dy;
  return Math.hypot(px - cx, py - cy);
}

// Shield outline (in 512-space), then scaled by SS.
function shieldPoints() {
  const pts = [[146, 150], [366, 150], [366, 248]];
  for (let i = 1; i <= 24; i++) pts.push(qbez([366, 248], [366, 366], [256, 404], i / 24));
  for (let i = 1; i <= 24; i++) pts.push(qbez([256, 404], [146, 366], [146, 248], i / 24));
  return pts.map(([x, y]) => [x * SS, y * SS]);
}
const SHIELD = shieldPoints();
const CHECK = [[206, 262], [244, 300], [322, 210]].map(([x, y]) => [x * SS, y * SS]);
const CHECK_HW = 15 * SS;

// Rounded-rect background test.
const PAD = 24 * SS, R = 96 * SS;
function inRoundRect(x, y) {
  const lo = PAD, hi = W - PAD;
  if (x < lo || x > hi || y < lo || y > hi) return false;
  const cx = Math.min(Math.max(x, lo + R), hi - R);
  const cy = Math.min(Math.max(y, lo + R), hi - R);
  return Math.hypot(x - cx, y - cy) <= R || (x >= lo + R && x <= hi - R) || (y >= lo + R && y <= hi - R);
}

function colorAt(x, y) {
  // returns [r,g,b,a] 0..255, or null for transparent
  if (!inRoundRect(x, y)) return null;
  const t = y / W;
  // indigo gradient background
  let r = Math.round(lerp(0x6d, 0x4f, t));
  let g = Math.round(lerp(0x5e, 0x46, t));
  let b = Math.round(lerp(0xf6, 0xe5, t));
  if (pointInPoly(x, y, SHIELD)) {
    r = 0xff; g = 0xff; b = 0xff; // white shield
    let best = Infinity;
    best = Math.min(best, distToSeg(x, y, CHECK[0], CHECK[1]));
    best = Math.min(best, distToSeg(x, y, CHECK[1], CHECK[2]));
    if (best <= CHECK_HW) { r = 0x16; g = 0xa3; b = 0x4a; } // green check
  }
  return [r, g, b, 255];
}

// Render with supersampling -> 512x512 RGBA.
const out = Buffer.alloc(SIZE * SIZE * 4);
for (let y = 0; y < SIZE; y++) {
  for (let x = 0; x < SIZE; x++) {
    let r = 0, g = 0, b = 0, a = 0;
    for (let sy = 0; sy < SS; sy++) {
      for (let sx = 0; sx < SS; sx++) {
        const c = colorAt(x * SS + sx + 0.5, y * SS + sy + 0.5);
        if (c) { r += c[0]; g += c[1]; b += c[2]; a += c[3]; }
      }
    }
    const n = SS * SS, i = (y * SIZE + x) * 4;
    out[i] = Math.round(r / n);
    out[i + 1] = Math.round(g / n);
    out[i + 2] = Math.round(b / n);
    out[i + 3] = Math.round(a / n);
  }
}

// --- minimal PNG encoder ---
function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}
function chunk(type, data) {
  const t = Buffer.from(type, "ascii");
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(Buffer.concat([t, data])));
  return Buffer.concat([len, t, data, crc]);
}
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0); ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8; ihdr[9] = 6; // 8-bit, RGBA
const raw = Buffer.alloc(SIZE * (SIZE * 4 + 1));
for (let y = 0; y < SIZE; y++) {
  raw[y * (SIZE * 4 + 1)] = 0; // filter: none
  out.copy(raw, y * (SIZE * 4 + 1) + 1, y * SIZE * 4, (y + 1) * SIZE * 4);
}
const png = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  chunk("IHDR", ihdr),
  chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
  chunk("IEND", Buffer.alloc(0)),
]);
fs.mkdirSync(path.join(root, "assets"), { recursive: true });
fs.writeFileSync(path.join(root, "assets", "icon.png"), png);
console.log(`✓ wrote assets/icon.png (${png.length} bytes)`);
