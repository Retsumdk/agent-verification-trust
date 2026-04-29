#!/usr/bin/env bun
/**
 * Agent Verification Trust - CLI Tools
 */

import { existsSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";

export interface CLIConfig {
  storePath: string;
  verbose: boolean;
  format: "json" | "text";
}

const DEFAULT_CONFIG: CLIConfig = {
  storePath: join(process.cwd(), ".agent-verification"),
  verbose: false,
  format: "json",
};

export function loadConfig(configPath?: string): CLIConfig {
  if (configPath && existsSync(configPath)) {
    try {
      const data = JSON.parse(readFileSync(configPath, "utf-8"));
      return { ...DEFAULT_CONFIG, ...data };
    } catch {
      // Use defaults
    }
  }
  return { ...DEFAULT_CONFIG };
}

export function saveConfig(config: CLIConfig, configPath: string): void {
  writeFileSync(configPath, JSON.stringify(config, null, 2));
}

export function formatOutput(data: any, format: "json" | "text"): string {
  if (format === "json") {
    return JSON.stringify(data, null, 2);
  }

  // Text format
  if (typeof data === "object" && data !== null) {
    const lines: string[] = [];
    for (const [key, value] of Object.entries(data)) {
      if (Array.isArray(value)) {
        lines.push(`${key}: [${value.join(", ")}]`);
      } else if (typeof value === "object") {
        lines.push(`${key}:`);
        for (const [k, v] of Object.entries(value as Record<string, any>)) {
          lines.push(`  ${k}: ${v}`);
        }
      } else {
        lines.push(`${key}: ${value}`);
      }
    }
    return lines.join("\n");
  }

  return String(data);
}

export function validateAgentId(agentId: string): boolean {
  // Agent ID should be alphanumeric with optional hyphens/underscores
  const validPattern = /^[a-zA-Z0-9_-]{1,64}$/;
  return validPattern.test(agentId);
}

export function validatePublicKey(key: string): boolean {
  // Public key should be hex-encoded, 64 characters minimum
  const hexPattern = /^[a-fA-F0-9]{64,}$/;
  return hexPattern.test(key);
}

export function timestampNow(): string {
  return new Date().toISOString();
}

export function parseSnapshotFile(path: string): any {
  if (!existsSync(path)) {
    throw new Error(`Snapshot file not found: ${path}`);
  }
  try {
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    throw new Error(`Invalid JSON in snapshot file: ${path}`);
  }
}