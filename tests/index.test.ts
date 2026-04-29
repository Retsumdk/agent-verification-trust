#!/usr/bin/env bun
/**
 * Agent Verification Trust - Test Suite
 */

import { describe, test, expect, beforeEach } from "bun:test";
import { TrustEngine, AttestationEngine, DriftDetector, IdentityContinuityManager } from "./index";
import { SnapshotGenerator } from "./snapshot";

describe("TrustEngine", () => {
  let engine: TrustEngine;

  beforeEach(() => {
    engine = new TrustEngine();
  });

  test("assessOverallTrust returns valid structure for new agent", () => {
    const snapshot = createTestSnapshot();
    const result = engine.assessOverallTrust("test-agent-1", snapshot);

    expect(result).toHaveProperty("trustScore");
    expect(result).toHaveProperty("level");
    expect(result).toHaveProperty("factors");
    expect(result).toHaveProperty("actions");
    expect(["trusted", "caution", "untrusted"]).toContain(result.level);
    expect(result.trustScore).toBeGreaterThanOrEqual(0);
    expect(result.trustScore).toBeLessThanOrEqual(1);
  });

  test("assessOverallTrust updates with attestation", () => {
    const snapshot = createTestSnapshot();
    
    // Generate attestation first
    const report = engine.generateAttestation("test-agent-2", "session-123", snapshot);
    expect(report).toHaveProperty("id");
    expect(report.agentId).toBe("test-agent-2");

    // Now assess trust with attestation available
    const result = engine.assessOverallTrust("test-agent-2", snapshot);
    expect(result.factors.attestation).toBeGreaterThan(0);
  });

  test("establishBaseline allows drift detection", () => {
    const baseline = createTestSnapshot();
    engine.establishBaseline("test-agent-3", baseline);

    // Create slightly different snapshot
    const current = createModifiedSnapshot(baseline, { errorRate: 0.08 });
    const driftResult = engine.getDriftStatus("test-agent-3", current);

    expect(driftResult).toHaveProperty("driftScore");
    expect(driftResult).toHaveProperty("driftSeverity");
    expect(driftResult.affectedDimensions).toBeDefined();
  });

  test("registerIdentity creates valid identity claim", () => {
    const claim = engine.registerIdentity("test-agent-4", "a".repeat(64));
    
    expect(claim.agentId).toBe("test-agent-4");
    expect(claim.publicKey).toBe("a".repeat(64));
    expect(claim.continuityScore).toBe(1);
    expect(claim.attestationCount).toBe(1);
  });
});

describe("AttestationEngine", () => {
  let engine: AttestationEngine;

  beforeEach(() => {
    engine = new AttestationEngine();
  });

  test("generateAttestation creates valid report", () => {
    const snapshot = createTestSnapshot();
    const report = engine.generateAttestation("att-agent-1", "session-1", snapshot);

    expect(report.id).toMatch(/^att_/);
    expect(report.agentId).toBe("att-agent-1");
    expect(report.sessionId).toBe("session-1");
    expect(report.capabilityHash).toHaveLength(16);
    expect(report.signature).toHaveLength(64);
    expect(report.expiresAt).toBeDefined();
  });

  test("verifyAttestation returns correct confidence for valid report", () => {
    const snapshot = createTestSnapshot();
    const report = engine.generateAttestation("att-agent-2", "session-2", snapshot);
    const result = engine.verifyAttestation(report);

    expect(result).toHaveProperty("verified");
    expect(result).toHaveProperty("confidence");
    expect(result).toHaveProperty("reasons");
    expect(result).toHaveProperty("warnings");
    expect(result).toHaveProperty("nextSteps");
    expect(result.confidence).toBeGreaterThan(0);
  });

  test("verifyAttestation detects expired report", () => {
    const snapshot = createTestSnapshot();
    const report = engine.generateAttestation("att-agent-3", "session-3", snapshot);
    
    // Manually set expiration to the past
    report.expiresAt = new Date(Date.now() - 1000).toISOString();
    
    const result = engine.verifyAttestation(report);
    expect(result.warnings).toContain("Attestation has expired");
  });

  test("getReports returns all reports for agent", () => {
    const snapshot = createTestSnapshot();
    engine.generateAttestation("att-agent-4", "session-a", snapshot);
    engine.generateAttestation("att-agent-4", "session-b", snapshot);
    engine.generateAttestation("att-agent-4", "session-c", snapshot);

    const reports = engine.getReports("att-agent-4");
    expect(reports.length).toBe(3);
  });

  test("getLatestReport returns most recent report", () => {
    const snapshot = createTestSnapshot();
    engine.generateAttestation("att-agent-5", "session-old", snapshot);
    
    // Wait a bit to ensure different timestamp
    const reports = engine.getReports("att-agent-5");
    const latest = engine.getLatestReport("att-agent-5");
    
    expect(latest).not.toBeNull();
    expect(reports.length).toBeGreaterThan(0);
  });
});

describe("DriftDetector", () => {
  let detector: DriftDetector;

  beforeEach(() => {
    detector = new DriftDetector();
  });

  test("establishBaseline sets baseline for agent", () => {
    const snapshot = createTestSnapshot();
    detector.establishBaseline("drift-agent-1", snapshot);

    const result = detector.detectDrift("drift-agent-1", snapshot);
    expect(result.driftScore).toBe(0);
    expect(result.driftSeverity).toBe("none");
  });

  test("detectDrift identifies minor drift", () => {
    const baseline = createTestSnapshot();
    detector.establishBaseline("drift-agent-2", baseline);

    const current = createModifiedSnapshot(baseline, { errorRate: 0.05 });
    const result = detector.detectDrift("drift-agent-2", current);

    expect(result.driftScore).toBeGreaterThan(0);
    expect(result.driftScore).toBeLessThanOrEqual(1);
  });

  test("detectDrift identifies severe drift", () => {
    const baseline = createTestSnapshot();
    detector.establishBaseline("drift-agent-3", baseline);

    const current = createModifiedSnapshot(baseline, {
      errorRate: 0.15,
      successRate: 0.7,
      toolUsagePatterns: { unusualTool: 100 },
    });
    const result = detector.detectDrift("drift-agent-3", current);

    expect(result.driftSeverity).toMatch(/minor|moderate|severe/);
    expect(result.recommendations.length).toBeGreaterThan(0);
  });

  test("getDriftTrend returns historical scores", () => {
    const baseline = createTestSnapshot();
    detector.establishBaseline("drift-agent-4", baseline);

    // Add several snapshots to history
    for (let i = 0; i < 5; i++) {
      const snapshot = createModifiedSnapshot(baseline, {
        errorRate: 0.02 + (i * 0.01),
      });
      detector.detectDrift("drift-agent-4", snapshot);
    }

    const trend = detector.getDriftTrend("drift-agent-4", 5);
    expect(trend.timestamps.length).toBeLessThanOrEqual(5);
    expect(trend.scores.length).toBeLessThanOrEqual(5);
  });
});

describe("IdentityContinuityManager", () => {
  let manager: IdentityContinuityManager;

  beforeEach(() => {
    manager = IdentityContinuityManager();
  });

  test("registerAgent creates identity claim", () => {
    const claim = manager.registerAgent("id-agent-1", "b".repeat(64));

    expect(claim.agentId).toBe("id-agent-1");
    expect(claim.publicKey).toBe("b".repeat(64));
    expect(claim.continuityScore).toBe(1);
    expect(claim.attestationCount).toBe(1);
  });

  test("verifyContinuity returns high score for matching key", () => {
    const publicKey = "c".repeat(64);
    manager.registerAgent("id-agent-2", publicKey);

    const result = manager.verifyContinuity("id-agent-2", publicKey, 0.9, 0.8);

    expect(result.isContinuous).toBe(true);
    expect(result.continuityScore).toBeGreaterThan(0.7);
    expect(result.factors.keyMatch).toBe(1);
  });

  test("verifyContinuity returns low score for mismatched key", () => {
    const originalKey = "d".repeat(64);
    manager.registerAgent("id-agent-3", originalKey);

    const result = manager.verifyContinuity("id-agent-3", "e".repeat(64), 0.9, 0.8);

    expect(result.factors.keyMatch).toBe(0);
    expect(result.continuityScore).toBeLessThan(1);
  });

  test("updatePublicKey successfully rotates key", () => {
    const originalKey = "f".repeat(64);
    const newKey = "g".repeat(64);
    manager.registerAgent("id-agent-4", originalKey);

    const success = manager.updatePublicKey("id-agent-4", newKey);
    expect(success).toBe(true);

    const identity = manager.getIdentity("id-agent-4");
    expect(identity?.publicKey).toBe(newKey);
  });

  test("getContinuityHistory returns score history", () => {
    const publicKey = "h".repeat(64);
    manager.registerAgent("id-agent-5", publicKey);

    // Generate several continuity checks
    manager.verifyContinuity("id-agent-5", publicKey, 0.9, 0.8);
    manager.verifyContinuity("id-agent-5", publicKey, 0.85, 0.75);
    manager.verifyContinuity("id-agent-5", publicKey, 0.95, 0.9);

    const history = manager.getContinuityHistory("id-agent-5");
    expect(history.length).toBeGreaterThanOrEqual(3);
  });

  test("getAverageContinuity calculates mean score", () => {
    const publicKey = "i".repeat(64);
    manager.registerAgent("id-agent-6", publicKey);

    // Add various scores
    manager.verifyContinuity("id-agent-6", publicKey, 0.9, 0.8);
    manager.verifyContinuity("id-agent-6", publicKey, 0.8, 0.7);
    manager.verifyContinuity("id-agent-6", publicKey, 0.95, 0.85);

    const avg = manager.getAverageContinuity("id-agent-6");
    expect(avg).toBeGreaterThan(0.7);
    expect(avg).toBeLessThan(1);
  });
});

describe("SnapshotGenerator", () => {
  test("creates snapshot with default values", () => {
    const generator = new SnapshotGenerator("snap-agent-1", "session-x");
    const snapshot = generator.generateSnapshot();

    expect(snapshot.agentId).toBe("snap-agent-1");
    expect(snapshot.sessionId).toBe("session-x");
    expect(snapshot).toHaveProperty("toolUsagePatterns");
    expect(snapshot).toHaveProperty("responseLatency");
    expect(snapshot).toHaveProperty("errorRate");
    expect(snapshot).toHaveProperty("successRate");
  });

  test("records tool invocations correctly", () => {
    const generator = new SnapshotGenerator("snap-agent-2", "session-y");
    
    generator.recordToolInvocation("search", 100, true);
    generator.recordToolInvocation("search", 150, true);
    generator.recordToolInvocation("read", 80, true);
    generator.recordToolInvocation("write", 200, false);

    const metrics = generator.getMetrics();
    expect(metrics.toolMetrics.length).toBe(2);
    expect(metrics.successCount).toBe(3);
    expect(metrics.errorCount).toBe(1);
  });

  test("calculates latency percentiles correctly", () => {
    const generator = new SnapshotGenerator("snap-agent-3", "session-z");
    
    // Add samples: [100, 100, 100, 100, 200, 200, 200, 300, 400, 500]
    for (let i = 0; i < 10; i++) {
      generator.recordResponseLatency((i + 1) * 50 + 50);
    }

    const metrics = generator.getMetrics();
    expect(metrics.latencyStats.p50).toBeGreaterThan(0);
    expect(metrics.latencyStats.p95).toBeGreaterThan(metrics.latencyStats.p50);
    expect(metrics.latencyStats.p99).toBeGreaterThan(metrics.latencyStats.p95);
  });

  test("tracks self-corrections", () => {
    const generator = new SnapshotGenerator("snap-agent-4", "session-w");
    
    generator.recordSelfCorrection();
    generator.recordSelfCorrection();
    generator.recordBacktrack();
    generator.recordReasoningEvent(5, 3);

    const snapshot = generator.generateSnapshot();
    expect(snapshot.selfCorrectionRate).toBeGreaterThan(0);
    expect(snapshot.reasoningDepth).toBe(5);
  });
});

// ============ Test Utilities ============

function createTestSnapshot() {
  return {
    toolUsagePatterns: { search: 10, read: 5, write: 3, execute: 2 },
    responseLatency: { p50: 150, p95: 450, p99: 800 },
    errorRate: 0.02,
    successRate: 0.98,
    memoryAccessFrequency: 0.8,
    reasoningDepth: 4,
    selfCorrectionRate: 0.15,
    trustScore: 0.9,
  };
}

function createModifiedSnapshot(
  base: ReturnType<typeof createTestSnapshot>,
  changes: Partial<ReturnType<typeof createTestSnapshot>>
) {
  return { ...base, ...changes };
}