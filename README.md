# VulnMCP

**On-machine vulnerability detection and approval-gated remediation for Claude Desktop.**
macOS · Linux · Windows.

VulnMCP is a local [MCP](https://modelcontextprotocol.io) server, packaged as a
one-click Claude Desktop **plugin** (`.mcpb`). It scans your host with
[Trivy](https://trivy.dev), ranks what it finds, and walks you through fixing it
— showing the exact commands, the rollback, and the blast radius, and never
changing anything until you explicitly type **APPLY**.

- **Local.** No cloud, no background agent, no vendor account.
- **Honest.** The model never invents CVE data — it only reasons over scanner output.
- **Safe by construction.** A server-enforced one-time approval token gates every change.
- **Cross-platform.** apt · dnf · yum · apk · pacman · brew · npm · pip · winget · choco · scoop.

---

## Why it's a plugin, not a "skill"

A scanner has to see your *real* installed packages. Claude Desktop **Agent
Skills** run in an isolated sandbox and can't touch the host, so a skill would
scan an empty container. The only mechanism with real host access is a **local
MCP server** — and the one-click way to ship one to Claude Desktop is the
`.mcpb` bundle (formerly `.dxt`). That's exactly what VulnMCP is: an MCP server,
packaged as a plugin you install by double-clicking.

---

## Install

### Plugin (recommended)

1. Download `vulnmcp.mcpb` from the [latest release](https://github.com/MrAnde7son/vulnmcp/releases).
2. Double-click it. Claude Desktop installs it — no JSON editing.
3. (Optional) toggle **Share anonymous usage stats** in the plugin's settings.

Trivy is bundled in the `.mcpb` (pinned + checksum-verified per platform), so
there's nothing else to install.

### From source (dev)

```bash
git clone https://github.com/MrAnde7son/vulnmcp && cd vulnmcp
npm install && npm run build
# Requires trivy on PATH, or set VULNMCP_TRIVY_PATH.
```

Then point Claude Desktop's `claude_desktop_config.json` at it:

```json
{
  "mcpServers": {
    "vulnmcp": {
      "command": "node",
      "args": ["/absolute/path/to/vulnmcp/dist/index.js"],
      "env": {}
    }
  }
}
```

---

## Tools

| Tool | What it does |
|---|---|
| `scan_system` | Runs Trivy locally; returns structured CVE findings. Scope: `os \| packages \| containers \| all`. |
| `triage_findings` | Deterministically ranks findings by severity / CVSS / EPSS / fixability. No API calls. |
| `get_remediation_recipe` | Produces a safety-validated, executable plan + a one-time approval token. |
| `apply_recipe` | Executes a recipe — **only** with `user_confirmed=true` and the token. The trust boundary. |

### Example

```
You:    Scan my system for vulnerabilities.
Claude: [scan_system] Found 4 — CRITICAL CVE-2024-3094 (xz-utils 5.6.0), …
You:    Fix the critical one.
Claude: [get_remediation_recipe]
        STEP 1  apt-get update                                    [sudo]
        STEP 2  apt-get install --only-upgrade xz-utils=5.6.1-1    [sudo]
        STEP 3  dpkg-query -W -f='${Version}' xz-utils
        ROLLBACK: apt-get install xz-utils=5.6.0-1
        Service restart: ssh · Reboot: no · Blast radius: LOW
        Type APPLY to proceed or SKIP.
You:    APPLY
Claude: [apply_recipe user_confirmed=true] ✓ xz-utils is now 5.6.1. Logged.
```

---

## Trust model

1. **Approval gate.** `apply_recipe` is a no-op without `user_confirmed=true`
   **and** a one-time `confirmation_token` minted by `get_remediation_recipe`
   in the same session. The model cannot fabricate an apply for arbitrary
   commands — only re-run a recipe this server generated and validated.
2. **Safety gate.** Every recipe (static *and* Claude-generated) is rejected if
   it downloads-and-pipes-to-shell, touches firewall/iptables, loads kernel
   modules, does destructive disk/`rm -rf /` ops, or uses a command outside the
   package/service allow-list. Validated at generation **and** at apply.
3. **Elevation model.** POSIX prefixes `sudo`; Windows requires an already-admin
   process and refuses cleanly otherwise (no half-applied recipes).
4. **Audit log.** Every apply/reject is appended to `~/.vulnmcp/audit.log`
   (+ `audit.jsonl`). Local only — never transmitted.

---

## Telemetry (opt-in)

**Off by default.** Nothing is sent until you turn it on in the plugin settings,
run `vulnmcp telemetry on`, or set `VULNMCP_TELEMETRY=1`.

| Sent (anonymous, aggregate) | Never sent |
|---|---|
| event counts, severity histograms, durations, OS family, package manager, blast radius | CVE ids, package names, hostnames, file paths, IPs, command output |

`distinct_id` is a random install id (`~/.vulnmcp/config.json`), never anything
host-identifying. Backend: PostHog. Check or change state any time:

```bash
vulnmcp telemetry status
vulnmcp telemetry off
```

---

## Build the plugin

```bash
npm run fetch:trivy -- --platform darwin-arm64   # stage the pinned binary
npm run bundle                                    # -> vulnmcp.mcpb
```

Pin each platform's Trivy SHA-256 in `scripts/fetch-trivy.mjs` before release.

---

## Development

```bash
npm run dev         # run the server from TS (tsx)
npm test            # vitest — safety gate, approval token, triage
npm run typecheck
```

## Roadmap

| Phase | Scope |
|---|---|
| v1 | OS + language packages, all major managers, macOS/Linux/Windows, static + dynamic recipes |
| v2 | Container image scanning, config hardening (CIS), compensating controls |
| v3 | Fleet mode — feeds into [Hakuna](https://github.com/hakuna) enterprise |

## License

[Apache-2.0](./LICENSE) © Hakuna.
