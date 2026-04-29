#!/usr/bin/env bun
/**
 * Agent Verification Trust - Behavioral Snapshot Generator
 * 
 * Collects and generates behavioral snapshots for agent attestation
 */

import { createHash, randomBytes } from "crypto";

interface ToolMetric {
  toolName: string;
  invocationCount: number;
  avgDuration: number;
  errorCount: number;
  lastUsed: string;
}

interface MemoryAccessMetric {
  readCount: number;
  writeCount: number;
  avgLatency: number;
  workingSetSize: number;
}

interface ReasoningMetric {
  depth: number;
  branchingFactor: number;
  backtrackCount: number;
  selfCorrectionCount: number;
}

interface BehavioralSnapshot {
  toolUsagePatterns: Record<string, number>;
  responseLatency: { p50: number; p95: number; p99: number };
  errorRate: number;
  successRate: number;
  memoryAccessFrequency: number;
  reasoningDepth: number;
  selfCorrectionRate: number;
  trustScore: number;
  timestamp: string;
  sessionId: string;
  agentId: string;
}

class SnapshotGenerator {
  private toolMetrics: Map<string, ToolMetric> = new Map();
  private memoryMetrics: MemoryAccessMetric = {
    readCount: 0,
    writeCount: 0,
    avgLatency: 0,
    workingSetSize: 0,
  };
  private reasoningMetrics: ReasoningMetric = {
    depth: 0,
    branchingFactor: 0,
    backtrackCount: 0,
    selfCorrectionCount: 0,
  };
  private latencySamples: number[] = [];
  private errorCount = 0;
  private successCount = 0;
  private sessionStart: number;

  constructor(private agentId: string, private sessionId?: string) {
    this.sessionId = sessionId || randomBytes(8).toString("hex");
    this.sessionStart = Date.now();
  }

  recordToolInvocation(toolName: string, duration: number, success: boolean): void {
    const existing = this.toolMetrics.get(toolName) || {
      toolName,
      invocationCount: 0,
      avgDuration: 0,
      errorCount: 0,
      lastUsed: "",
    };

    const newCount = existing.invocationCount + 1;
    const newAvgDuration = (existing.avgDuration * existing.invocationCount + duration) / newCount;

    this.toolMetrics.set(toolName, {
      toolName,
      invocationCount: newCount,
      avgDuration: newAvgDuration,
      errorCount: existing.errorCount + (success ? 0 : 1),
      lastUsed: new Date().toISOString(),
    });

    this.recordResponseLatency(duration);
    this.recordOutcome(success);
  }

  recordResponseLatency(latencyMs: number): void {
    this.latencySamples.push(latencyMs);
    // Keep last 1000 samples
    if (this.latencySamples.length > 1000) {
      this.latencySamples.shift();
    }
  }

  recordOutcome(success: boolean): void {
    if (success) {
      this.successCount++;
    } else {
      this.errorCount++;
    }
  }

  recordMemoryAccess(type: "read" | "write", latencyMs: number): void {
    if (type === "read") {
      this.memoryMetrics.readCount++;
    } else {
      this.memoryMetrics.writeCount++;
    }

    const totalOps = this.memoryMetrics.readCount + this.memoryMetrics.writeCount;
    this.memoryMetrics.avgLatency = 
      (this.memoryMetrics.avgLatency * (totalOps - 1) + latencyMs) / totalOps;
  }

  recordReasoningEvent(depth: number, branchingFactor: number): void {
    this.reasoningMetrics.depth = Math.max(this.reasoningMetrics.depth, depth);
    this.reasoningMetrics.branchingFactor = Math.max(
      this.reasoningMetrics.branchingFactor,
      branchingFactor
    );
  }

  recordSelfCorrection(): void {
    this.reasoningMetrics.selfCorrectionCount++;
  }

  recordBacktrack(): void {
    this.reasoningMetrics.backtrackCount++;
  }

  private calculatePercentile(sorted: number[], p: number): number {
    const idx = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[Math.max(0, idx)] || 0;
  }

  generateSnapshot(): BehavioralSnapshot {
    // Calculate tool usage patterns
    const toolUsagePatterns: Record<string, number> = {};
    for (const [name, metric] of this.toolMetrics) {
      toolUsagePatterns[name] = metric.invocationCount;
    }

    // Calculate latency percentiles
    const sorted = [...this.latencySamples].sort((a, b) => a - b);
    const latency: { p50: number; p95: number; p99: number } = {
      p50: this.calculatePercentile(sorted, 50),
      p95: this.calculatePercentile(sorted, 95),
      p99: this.calculatePercentile(sorted, 99),
    };

    // Calculate error and success rates
    const totalOutcomes = this.errorCount + this.successCount;
    const errorRate = totalOutcomes > 0 ? this.errorCount / totalOutcomes : 0;
    const successRate = totalOutcomes > 0 ? this.successCount / totalOutcomes : 0;

    // Calculate memory access frequency
    const sessionDurationMs = Date.now() - this.sessionStart;
    const sessionDurationSec = sessionDurationMs / 1000;
    const memoryAccessFrequency = sessionDurationSec > 0 
      ? (this.memoryMetrics.readCount + this.memoryMetrics.writeCount) / sessionDurationSec 
      : 0;

    // Calculate self-correction rate
    const selfCorrectionRate = totalOutcomes > 0 
      ? this.reasoningMetrics.selfCorrectionCount / totalOutcomes 
      : 0;

    // Calculate trust score (heuristic based on multiple factors)
    const trustScore = this.calculateTrustScore(
      successRate,
      errorRate,
      this.reasoningMetrics.selfCorrectionCount,
      toolUsagePatterns
    );

    return {
      toolUsagePatterns,
      responseLatency: latency,
      errorRate,
      successRate,
      memoryAccessFrequency,
      reasoningDepth: this.reasoningMetrics.depth,
      selfCorrectionRate,
      trustScore,
      timestamp: new Date().toISOString(),
      sessionId: this.sessionId!,
      agentId: this.agentId,
    };
  }

  private calculateTrustScore(
    successRate: number,
    errorRate: number,
    selfCorrectionCount: number,
    toolPatterns: Record<string, number>
  ): number {
    // Base score from success rate
    let score = successRate * 0.5;

    // Penalty for high error rate
    score -= Math.min(errorRate * 0.3, 0.3);

    // Bonus for self-corrections (shows metacognition)
    const selfCorrectionBonus = Math.min(selfCorrectionCount * 0.02, 0.15);
    score += selfCorrectionBonus;

    // Slight bonus for tool diversity
    const toolDiversity = Object.keys(toolPatterns).length;
    score += Math.min(toolDiversity * 0.01, 0.1);

    // Slight penalty for over-reliance on single tool
    const maxToolUsage = Math.max(...Object.values(toolPatterns), 0);
    if (maxToolUsage > 50 && Object.keys(toolPatterns).length === 1) {
      score -= 0.1;
    }

    return Math.max(0, Math.min(score, 1));
  }

  getMetrics(): {
    toolMetrics: ToolMetric[];
    memoryMetrics: MemoryAccessMetric;
    reasoningMetrics: ReasoningMetric;
    latencyStats: { p50: number; p95: number; p99: number };
    errorCount: number;
    successCount: number;
  } {
    const sorted = [...this.latencySamples].sort((a, b) => a - b);
    return {
      toolMetrics: Array.from(this.toolMetrics.values()),
      memoryMetrics: { ...this.memoryMetrics },
      reasoningMetrics: { ...this.reasoningMetrics },
      latencyStats: {
        p50: this.calculatePercentile(sorted, 50),
        p95: this.calculatePercentile(sorted, 95),
        p99: this.calculatePercentile(sorted, 99),
      },
      errorCount: this.errorCount,
      successCount: this.successCount,
    };
  }

  getSessionId(): string {
    return this.sessionId!;
  }
}

// Factory function
function createSnapshotGenerator(agentId: string, sessionId?: string): SnapshotGenerator {
  return new SnapshotGenerator(agentId, sessionId);
}

export { SnapshotGenerator, createSnapshotGenerator };
export type { BehavioralSnapshot, ToolMetric, MemoryAccessMetric, ReasoningMetric };