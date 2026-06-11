#!/usr/bin/env node
/**
 * `vulnmcp telemetry [on|off|status]` — the opt-in control surface.
 *
 * Telemetry is OFF until a user explicitly turns it on here (or via
 * VULNMCP_TELEMETRY=1). This CLI exists so consent is a deliberate action.
 */
import { loadConfig, setTelemetry, telemetryEnabled, configPath } from "./lib/config.js";

function printStatus() {
  const cfg = loadConfig();
  const on = telemetryEnabled(cfg);
  const envForced = process.env.VULNMCP_TELEMETRY != null;
  console.log(`telemetry: ${on ? "ON" : "off"}${envForced ? " (forced via VULNMCP_TELEMETRY)" : ""}`);
  console.log(`install_id: ${cfg.install_id}`);
  console.log(`config: ${configPath()}`);
  if (on) {
    console.log(
      "\nWhat is sent (anonymous, aggregate only):\n" +
        "  • scan/triage/apply event counts, severities, durations, os family, package manager\n" +
        "What is NEVER sent:\n" +
        "  • CVE ids, package names, hostnames, file paths, IPs, command output"
    );
  }
}

function main() {
  const [, , sub, action] = process.argv;
  if (sub !== "telemetry") {
    console.log("usage: vulnmcp telemetry [on|off|status]");
    process.exit(sub ? 1 : 0);
  }
  switch (action) {
    case "on":
    case "enable":
      setTelemetry(true);
      console.log("Telemetry ENABLED. Thank you — this is anonymous and aggregate only.");
      printStatus();
      break;
    case "off":
    case "disable":
      setTelemetry(false);
      console.log("Telemetry DISABLED. Nothing will be sent.");
      break;
    case "status":
    case undefined:
      printStatus();
      break;
    default:
      console.log("usage: vulnmcp telemetry [on|off|status]");
      process.exit(1);
  }
}

main();
