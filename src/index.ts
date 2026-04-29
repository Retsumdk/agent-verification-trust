#!/usr/bin/env bun
/**
 * Agent Verification & Trust System
 * 
 * Provides cryptographic attestation, behavioral drift detection,
 * and cross-session identity verification for autonomous AI agents.
 * 
 * Built by Retsumdk
 */

import { createHash, randomBytes, timingSafeEqual } from "crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";

// ============ Types ============

interface AttestationReport {
  id: string;
  agentId: string;
  timestamp: string;
  sessionId: string;
  behavioralSnapshot: BehavioralSnapshot;
  capabilityHash: string;
  signature: string;
  expiresAt: string;
}

interface BehavioralSnapshot {
  toolUsagePatterns: Record<string, number>;
  responseLatency: LatencyStats;
  errorRate: number;
  successRate: number;
  memoryAccessFrequency: number;
  reasoningDepth: number;
  selfCorrectionRate: number;
  trustScore: number;
}

interface LatencyStats {
  p50: number;
  p95: number;
  p99: number;
}

interface DriftResult {
  agentId: string;
  baselineHash: string;
  currentHash: string;
  driftScore: number;
  driftSeverity: "none" | "minor" | "moderate" | "severe";
  affectedDimensions: string[];
  recommendations: string[];
  timestamp: string;
}

interface IdentityClaim {
  agentId: string;
  establishedAt: string;
  publicKey: string;
  attestationCount: number;
  lastVerified: string;
  continuityScore: number;
}

interface VerificationResult {
  verified: boolean;
  confidence: number;
  reasons: string[];
  warnings: string[];
  nextSteps: string[];
}

// ============ Attestation Engine ============

class AttestationEngine {
  private storePath: string;
  private reports: Map<string, AttestationReport> = new Map();

  constructor(storePath?: string) {
    this.storePath = storePath || join(process.cwd(), ".agent-attestation");
    this.ensureStore();
    this.loadExisting();
  }

  private ensureStore(): void {
    if (!existsSync(this.storePath)) {
      mkdirSync(this.storePath, { recursive: true });
    }
  }

  private loadExisting(): void {
    const indexPath = join(this.storePath, "index.json");
    if (existsSync(indexPath)) {
      try {
        const data = JSON.parse(readFileSync(indexPath, "utf-8"));
        for (const [id, report] of Object.entries(data)) {
          this.reports.set(id, report as AttestationReport);
        }
      } catch (e) {
        console.warn("Failed to load existing attestation store:", e);
      }
    }
  }

  private persist(): void {
    const indexPath = join(this.storePath, "index.json");
    const data = Object.fromEntries(this.reports);
    writeFileSync(indexPath, JSON.stringify(data, null, 2));
  }

  generateAttestation(
    agentId: string,
    sessionId: string,
    behavioralSnapshot: BehavioralSnapshot,
    privateKey?: string
  ): AttestationReport {
    const capabilityHash = this.computeCapabilityHash(behavioralSnapshot);
    const payload = `${agentId}:${sessionId}:${capabilityHash}:${Date.now()}`;
    const signature = this.sign(payload, privateKey);

    const report: AttestationReport = {
      id: this.generateId(),
      agentId,
      timestamp: new Date().toISOString(),
      sessionId,
      behavioralSnapshot,
      capabilityHash,
      signature,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24h
    };

    this.reports.set(report.id, report);
    this.persist();

    return report;
  }

  verifyAttestation(report: AttestationReport, publicKey?: string): VerificationResult {
    const result: VerificationResult = {
      verified: false,
      confidence: 0,
      reasons: [],
      warnings: [],
      nextSteps: [],
    };

    // Check expiration
    const expiresAt = new Date(report.expiresAt);
    if (expiresAt < new Date()) {
      result.warnings.push("Attestation has expired");
      result.confidence -= 20;
    } else {
      result.reasons.push("Attestation within valid period");
      result.confidence += 30;
    }

    // Verify signature
    const payload = `${report.agentId}:${report.sessionId}:${report.capabilityHash}:${new Date(report.timestamp).getTime()}`;
    const isValid = this.verifySignature(payload, report.signature, publicKey);
    if (isValid) {
      result.reasons.push("Cryptographic signature verified");
      result.confidence += 40;
    } else {
      result.warnings.push("Signature verification failed");
      result.confidence -= 30;
    }

    // Check behavioral consistency
    const currentHash = this.computeCapabilityHash(report.behavioralSnapshot);
    if (currentHash === report.capabilityHash) {
      result.reasons.push("Behavioral snapshot matches capability hash");
      result.confidence += 20;
    } else {
      result.warnings.push("Behavioral snapshot has diverged from attestation");
      result.confidence -= 20;
    }

    // Verify timestamp is reasonable
    const age = Date.now() - new Date(report.timestamp).getTime();
    if (age < 3600000) {
      result.reasons.push("Attestation is recent (< 1 hour)");
      result.confidence += 10;
    }

    result.verified = result.confidence >= 50;
    
    if (result.verified) {
      result.nextSteps.push("Agent is trusted for current session");
    } else {
      result.nextSteps.push("Request fresh attestation before proceeding");
      result.nextSteps.push("Compare against historical behavior patterns");
    }

    return result;
  }

  private computeCapabilityHash(snapshot: BehavioralSnapshot): string {
    const data = JSON.stringify(snapshot);
    return createHash("sha256").update(data).digest("hex").substring(0, 16);
  }

  private sign(payload: string, privateKey?: string): string {
    const key = privateKey || this.getOrCreateKey();
    return createHash("sha256").update(payload + key).digest("hex");
  }

  private verifySignature(payload: string, signature: string, publicKey?: string): boolean {
    const expected = this.sign(payload, publicKey);
    return timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  }

  private getOrCreateKey(): string {
    const keyPath = join(this.storePath, ".key");
    if (existsSync(keyPath)) {
      return readFileSync(keyPath, "utf-8");
    }
    const key = randomBytes(32).toString("hex");
    writeFileSync(keyPath, key);
    return key;
  }

  private generateId(): string {
    return `att_${randomBytes(16).toString("hex")}`;
  }

  getReports(agentId?: string): AttestationReport[] {
    const reports = Array.from(this.reports.values());
    if (agentId) {
      return reports.filter(r => r.agentId === agentId);
    }
    return reports;
  }

  getLatestReport(agentId: string): AttestationReport | null {
    const reports = this.getReports(agentId).sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
    return reports[0] || null;
  }
}

// ============ Drift Detector ============

class DriftDetector {
  private baselines: Map<string, BehavioralSnapshot> = new Map();
  private history: Map<string, BehavioralSnapshot[]> = new Map();
  private storePath: string;

  constructor(storePath?: string) {
    this.storePath = storePath || join(process.cwd(), ".agent-drift");
    this.ensureStore();
    this.loadBaselines();
  }

  private ensureStore(): void {
    if (!existsSync(this.storePath)) {
      mkdirSync(this.storePath, { recursive: true });
    }
  }

  private loadBaselines(): void {
    const baselinePath = join(this.storePath, "baselines.json");
    if (existsSync(baselinePath)) {
      try {
        const data = JSON.parse(readFileSync(baselinePath, "utf-8"));
        for (const [agentId, snapshot] of Object.entries(data)) {
          this.baselines.set(agentId, snapshot as BehavioralSnapshot);
        }
      } catch (e) {
        console.warn("Failed to load drift baselines:", e);
      }
    }

    const historyPath = join(this.storePath, "history.json");
    if (existsSync(historyPath)) {
      try {
        const data = JSON.parse(readFileSync(historyPath, "utf-8"));
        for (const [agentId, snapshots] of Object.entries(data)) {
          this.history.set(agentId, snapshots as BehavioralSnapshot[]);
        }
      } catch (e) {
        console.warn("Failed to load drift history:", e);
      }
    }
  }

  private persistBaselines(): void {
    const baselinePath = join(this.storePath, "baselines.json");
    const data = Object.fromEntries(this.baselines);
    writeFileSync(baselinePath, JSON.stringify(data, null, 2));
  }

  private persistHistory(): void {
    const historyPath = join(this.storePath, "history.json");
    const data = Object.fromEntries(this.history);
    writeFileSync(historyPath, JSON.stringify(data, null, 2));
  }

  establishBaseline(agentId: string, snapshot: BehavioralSnapshot): void {
    this.baselines.set(agentId, snapshot);
    const history = this.history.get(agentId) || [];
    history.push(snapshot);
    // Keep last 100 snapshots
    if (history.length > 100) {
      history.shift();
    }
    this.history.set(agentId, history);
    this.persistBaselines();
    this.persistHistory();
  }

  detectDrift(agentId: string, currentSnapshot: BehavioralSnapshot): DriftResult {
    const baseline = this.baselines.get(agentId);
    
    // If no baseline, establish one and report no drift
    if (!baseline) {
      this.establishBaseline(agentId, currentSnapshot);
      return {
        agentId,
        baselineHash: "none",
        currentHash: this.hashSnapshot(currentSnapshot),
        driftScore: 0,
        driftSeverity: "none",
        affectedDimensions: [],
        recommendations: ["Baseline established from first observation"],
        timestamp: new Date().toISOString(),
      };
    }

    // Record current snapshot in history
    const history = this.history.get(agentId) || [];
    history.push(currentSnapshot);
    if (history.length > 100) history.shift();
    this.history.set(agentId, history);
    this.persistHistory();

    const baselineHash = this.hashSnapshot(baseline);
    const currentHash = this.hashSnapshot(currentSnapshot);

    // Calculate drift across dimensions
    const dimensionDrifts = this.calculateDimensionDrifts(baseline, currentSnapshot);
    const affectedDimensions = Object.entries(dimensionDrifts)
      .filter(([_, drift]) => drift > 0.2)
      .map(([dim, _]) => dim);

    // Overall drift score (0-1)
    const driftScore = this.calculateOverallDriftScore(dimensionDrifts);
    
    // Determine severity
    let driftSeverity: DriftResult["driftSeverity"] = "none";
    if (driftScore > 0.6) driftSeverity = "severe";
    else if (driftScore > 0.4) driftSeverity = "moderate";
    else if (driftScore > 0.2) driftSeverity = "minor";

    // Generate recommendations
    const recommendations = this.generateDriftRecommendations(driftSeverity, dimensionDrifts);

    return {
      agentId,
      baselineHash,
      currentHash,
      driftScore,
      driftSeverity,
      affectedDimensions,
      recommendations,
      timestamp: new Date().toISOString(),
    };
  }

  private hashSnapshot(snapshot: BehavioralSnapshot): string {
    return createHash("sha256").update(JSON.stringify(snapshot)).digest("hex").substring(0, 16);
  }

  private calculateDimensionDrifts(baseline: BehavioralSnapshot, current: BehavioralSnapshot): Record<string, number> {
    const drifts: Record<string, number> = {};

    // Tool usage pattern drift
    const baselineTools = Object.values(baseline.toolUsagePatterns).reduce((a, b) => a + b, 0) || 1;
    const currentTools = Object.values(current.toolUsagePatterns).reduce((a, b) => a + b, 0) || 1;
    drifts.toolUsageMagnitude = Math.abs(currentTools - baselineTools) / baselineTools;

    // Tool diversity drift
    const baselineDiversity = Object.keys(baseline.toolUsagePatterns).length || 1;
    const currentDiversity = Object.keys(current.toolUsagePatterns).length || 1;
    drifts.toolDiversity = Math.abs(currentDiversity - baselineDiversity) / baselineDiversity;

    // Error rate drift
    drifts.errorRate = Math.abs(current.errorRate - baseline.errorRate);

    // Success rate drift
    drifts.successRate = Math.abs(current.successRate - baseline.successRate);

    // Response latency drift (p95)
    drifts.latencyP95 = Math.abs(current.responseLatency.p95 - baseline.responseLatency.p95) / 
      (baseline.responseLatency.p95 || 1);

    // Self-correction rate drift
    drifts.selfCorrectionRate = Math.abs(current.selfCorrectionRate - baseline.selfCorrectionRate);

    // Memory access drift
    drifts.memoryAccessFrequency = Math.abs(current.memoryAccessFrequency - baseline.memoryAccessFrequency) / 
      (baseline.memoryAccessFrequency || 1);

    return drifts;
  }

  private calculateOverallDriftScore(dimensionDrifts: Record<string, number>): number {
    const weights: Record<string, number> = {
      toolUsageMagnitude: 0.15,
      toolDiversity: 0.20,
      errorRate: 0.25,
      successRate: 0.15,
      latencyP95: 0.10,
      selfCorrectionRate: 0.10,
      memoryAccessFrequency: 0.05,
    };

    let weightedSum = 0;
    let totalWeight = 0;

    for (const [dim, drift] of Object.entries(dimensionDrifts)) {
      const weight = weights[dim] || 0.1;
      weightedSum += Math.min(drift, 1) * weight;
      totalWeight += weight;
    }

    return Math.min(weightedSum / totalWeight, 1);
  }

  private generateDriftRecommendations(
    severity: DriftResult["driftSeverity"],
    dimensionDrifts: Record<string, number>
  ): string[] {
    const recommendations: string[] = [];

    switch (severity) {
      case "severe":
        recommendations.push("Immediate review recommended - significant behavioral deviation detected");
        recommendations.push("Consider temporarily restricting agent autonomy");
        recommendations.push("Request human-in-the-loop verification");
        break;
      case "moderate":
        recommendations.push("Schedule closer monitoring over next 24 hours");
        recommendations.push("Compare recent decisions against established patterns");
        recommendations.push("Consider requesting fresh attestation");
        break;
      case "minor":
        recommendations.push("Continue normal monitoring");
        recommendations.push("Track drift trend over next few sessions");
        break;
      default:
        recommendations.push("No action required");
    }

    // Dimension-specific recommendations
    if (dimensionDrifts.errorRate > 0.3) {
      recommendations.push("Investigate error rate increase - possible environment or capability issue");
    }
    if (dimensionDrifts.toolDiversity > 0.4) {
      recommendations.push("Tool usage pattern has changed significantly - verify intentionality");
    }
    if (dimensionDrifts.selfCorrectionRate > 0.3) {
      recommendations.push("Self-correction behavior has shifted - may indicate learning or instability");
    }

    return recommendations;
  }

  getDriftTrend(agentId: string, windowSize: number = 10): { timestamps: string[]; scores: number[] } {
    const history = this.history.get(agentId) || [];
    const baseline = this.baselines.get(agentId);
    
    if (!baseline || history.length === 0) {
      return { timestamps: [], scores: [] };
    }

    const recent = history.slice(-windowSize);
    const timestamps: string[] = [];
    const scores: number[] = [];

    for (const snapshot of recent) {
      const result = this.detectDrift(agentId, snapshot);
      timestamps.push(result.timestamp);
      scores.push(result.driftScore);
    }

    return { timestamps, scores };
  }
}

// ============ Identity Continuity Manager ============

class IdentityContinuityManager {
  private identities: Map<string, IdentityClaim> = new Map();
  private storePath: string;
  private continuityScores: Map<string, number[]> = new Map();

  constructor(storePath?: string) {
    this.storePath = storePath || join(process.cwd(), ".agent-identity");
    this.ensureStore();
    this.loadIdentities();
  }

  private ensureStore(): void {
    if (!existsSync(this.storePath)) {
      mkdirSync(this.storePath, { recursive: true });
    }
  }

  private loadIdentities(): void {
    const identityPath = join(this.storePath, "identities.json");
    if (existsSync(identityPath)) {
      try {
        const data = JSON.parse(readFileSync(identityPath, "utf-8"));
        for (const [agentId, claim] of Object.entries(data)) {
          this.identities.set(agentId, claim as IdentityClaim);
        }
      } catch (e) {
        console.warn("Failed to load identities:", e);
      }
    }

    const scoresPath = join(this.storePath, "continuity-scores.json");
    if (existsSync(scoresPath)) {
      try {
        const data = JSON.parse(readFileSync(scoresPath, "utf-8"));
        for (const [agentId, scores] of Object.entries(data)) {
          this.continuityScores.set(agentId, scores as number[]);
        }
      } catch (e) {
        console.warn("Failed to load continuity scores:", e);
      }
    }
  }

  private persistIdentities(): void {
    const identityPath = join(this.storePath, "identities.json");
    const data = Object.fromEntries(this.identities);
    writeFileSync(identityPath, JSON.stringify(data, null, 2));
  }

  private persistScores(): void {
    const scoresPath = join(this.storePath, "continuity-scores.json");
    const data = Object.fromEntries(this.continuityScores);
    writeFileSync(scoresPath, JSON.stringify(data, null, 2));
  }

  registerAgent(agentId: string, publicKey: string): IdentityClaim {
    const claim: IdentityClaim = {
      agentId,
      establishedAt: new Date().toISOString(),
      publicKey,
      attestationCount: 1,
      lastVerified: new Date().toISOString(),
      continuityScore: 1.0,
    };

    this.identities.set(agentId, claim);
    this.continuityScores.set(agentId, [1.0]);
    this.persistIdentities();
    this.persistScores();

    return claim;
  }

  verifyContinuity(
    agentId: string,
    currentPublicKey: string,
    behavioralConsistency: number,
    attestationFreshness: number
  ): { isContinuous: boolean; continuityScore: number; factors: Record<string, number> } {
    const identity = this.identities.get(agentId);
    
    if (!identity) {
      return {
        isContinuous: false,
        continuityScore: 0,
        factors: { reason: "Agent not registered" },
      };
    }

    // Calculate factors
    const keyMatch = currentPublicKey === identity.publicKey ? 1 : 0;
    const consistencyFactor = Math.max(0, Math.min(1, behavioralConsistency));
    const freshnessFactor = Math.max(0, Math.min(1, attestationFreshness));

    // Key change penalty (if key changed, need more attestation)
    const keyFactor = keyMatch === 1 ? 1 : 0.5;

    // Calculate overall continuity score
    const continuityScore = (
      consistencyFactor * 0.4 +
      freshnessFactor * 0.3 +
      keyFactor * 0.3
    );

    // Update continuity history
    const scores = this.continuityScores.get(agentId) || [];
    scores.push(continuityScore);
    if (scores.length > 100) scores.shift();
    this.continuityScores.set(agentId, scores);
    this.persistScores();

    // Update identity
    identity.lastVerified = new Date().toISOString();
    identity.continuityScore = continuityScore;
    this.persistIdentities();

    const isContinuous = continuityScore >= 0.7;

    return {
      isContinuous,
      continuityScore,
      factors: {
        keyMatch,
        behavioralConsistency: consistencyFactor,
        attestationFreshness: freshnessFactor,
        overall: continuityScore,
      },
    };
  }

  getIdentity(agentId: string): IdentityClaim | null {
    return this.identities.get(agentId) || null;
  }

  updatePublicKey(agentId: string, newPublicKey: string): boolean {
    const identity = this.identities.get(agentId);
    if (!identity) return false;

    identity.publicKey = newPublicKey;
    identity.lastVerified = new Date().toISOString();
    this.persistIdentities();
    return true;
  }

  getContinuityHistory(agentId: string): number[] {
    return this.continuityScores.get(agentId) || [];
  }

  getAverageContinuity(agentId: string): number {
    const scores = this.getContinuityHistory(agentId);
    if (scores.length === 0) return 0;
    return scores.reduce((a, b) => a + b, 0) / scores.length;
  }
}

// ============ Trust Engine ============

class TrustEngine {
  private attestation: AttestationEngine;
  private drift: DriftDetector;
  private identity: IdentityContinuityManager;

  constructor() {
    this.attestation = new AttestationEngine();
    this.drift = new DriftDetector();
    this.identity = new IdentityContinuityManager();
  }

  assessOverallTrust(agentId: string, currentSnapshot: BehavioralSnapshot): {
    trustScore: number;
    level: "trusted" | "caution" | "untrusted";
    factors: Record<string, number>;
    actions: string[];
  } {
    // Get latest attestation
    const latestAttestation = this.attestation.getLatestReport(agentId);
    
    // Get drift status
    const driftResult = this.drift.detectDrift(agentId, currentSnapshot);
    
    // Get identity status
    const identity = this.identity.getIdentity(agentId);
    const continuityHistory = this.identity.getContinuityHistory(agentId);
    const avgContinuity = this.identity.getAverageContinuity(agentId);

    // Calculate attestation factor (0-1)
    let attestationFactor = 0;
    if (latestAttestation) {
      const verification = this.attestation.verifyAttestation(latestAttestation);
      attestationFactor = verification.confidence / 100;
    }

    // Calculate drift factor (inverse of drift score, so high drift = low factor)
    const driftFactor = 1 - driftResult.driftScore;

    // Calculate identity factor
    const identityFactor = avgContinuity;

    // Overall trust score (weighted average)
    const trustScore = (
      attestationFactor * 0.35 +
      driftFactor * 0.35 +
      identityFactor * 0.30
    );

    // Determine trust level
    let level: "trusted" | "caution" | "untrusted";
    if (trustScore >= 0.75) level = "trusted";
    else if (trustScore >= 0.4) level = "caution";
    else level = "untrusted";

    // Generate recommended actions
    const actions: string[] = [];
    if (level === "untrusted") {
      actions.push("Block autonomous actions until verification complete");
      actions.push("Request fresh attestation");
      actions.push("Require human approval for high-stakes operations");
    } else if (level === "caution") {
      actions.push("Enable enhanced logging");
      actions.push("Monitor for continued drift");
      actions.push("Verify with attestation if available");
    } else {
      actions.push("Allow normal autonomous operation");
      actions.push("Continue periodic verification");
    }

    return {
      trustScore,
      level,
      factors: {
        attestation: attestationFactor,
        drift: driftFactor,
        identity: identityFactor,
        overall: trustScore,
      },
      actions,
    };
  }

  // Delegate to sub-engines
  generateAttestation(agentId: string, sessionId: string, snapshot: BehavioralSnapshot): AttestationReport {
    return this.attestation.generateAttestation(agentId, sessionId, snapshot);
  }

  getDriftStatus(agentId: string, currentSnapshot: BehavioralSnapshot): DriftResult {
    return this.drift.detectDrift(agentId, currentSnapshot);
  }

  establishBaseline(agentId: string, snapshot: BehavioralSnapshot): void {
    this.drift.establishBaseline(agentId, snapshot);
  }

  registerIdentity(agentId: string, publicKey: string): IdentityClaim {
    return this.identity.registerAgent(agentId, publicKey);
  }

  verifyIdentityContinuity(agentId: string, publicKey: string, behavioralConsistency: number, attestationFreshness: number) {
    return this.identity.verifyContinuity(agentId, publicKey, behavioralConsistency, attestationFreshness);
  }
}

// ============ CLI Interface ============

import { Command } from "commander";

const trustEngine = new TrustEngine();

const program = new Command();

program
  .name("agent-verification-trust")
  .description("Agent verification and trust system with attestation, drift detection, and cross-session identity verification")
  .version("1.0.0");

// Attestation commands
program
  .command("attest <agentId>")
  .description("Generate attestation report for an agent")
  .option("-s, --session <id>", "Session ID", () => randomBytes(8).toString("hex"))
  .option("-o, --output <path>", "Output file path")
  .action(async (agentId, options) => {
    const snapshot: BehavioralSnapshot = {
      toolUsagePatterns: { search: 10, read: 5, write: 3, execute: 2 },
      responseLatency: { p50: 150, p95: 450, p99: 800 },
      errorRate: 0.02,
      successRate: 0.98,
      memoryAccessFrequency: 0.8,
      reasoningDepth: 4,
      selfCorrectionRate: 0.15,
      trustScore: 0.9,
    };

    const report = trustEngine.generateAttestation(agentId, options.session, snapshot);
    
    if (options.output) {
      writeFileSync(options.output, JSON.stringify(report, null, 2));
      console.log(`Attestation saved to ${options.output}`);
    } else {
      console.log(JSON.stringify(report, null, 2));
    }
  });

// Verify attestation
program
  .command("verify <reportFile>")
  .description("Verify an attestation report")
  .action(async (reportFile) => {
    const report: AttestationReport = JSON.parse(readFileSync(reportFile, "utf-8"));
    const result = trustEngine.attestation.verifyAttestation(report);
    console.log(JSON.stringify(result, null, 2));
  });

// Drift detection commands
program
  .command("drift <agentId>")
  .description("Detect behavioral drift for an agent")
  .option("-s, --snapshot <path>", "Snapshot file path")
  .action(async (agentId, options) => {
    const snapshot: BehavioralSnapshot = options.snapshot
      ? JSON.parse(readFileSync(options.snapshot, "utf-8"))
      : {
          toolUsagePatterns: { search: 12, read: 6, write: 4, execute: 1 },
          responseLatency: { p50: 180, p95: 520, p99: 950 },
          errorRate: 0.04,
          successRate: 0.94,
          memoryAccessFrequency: 0.7,
          reasoningDepth: 3,
          selfCorrectionRate: 0.22,
          trustScore: 0.85,
        };

    const result = trustEngine.getDriftStatus(agentId, snapshot);
    console.log(JSON.stringify(result, null, 2));
  });

// Baseline commands
program
  .command("baseline <agentId>")
  .description("Establish behavioral baseline for an agent")
  .option("-s, --snapshot <path>", "Snapshot file path")
  .action(async (agentId, options) => {
    const snapshot: BehavioralSnapshot = options.snapshot
      ? JSON.parse(readFileSync(options.snapshot, "utf-8"))
      : {
          toolUsagePatterns: { search: 10, read: 5, write: 3, execute: 2 },
          responseLatency: { p50: 150, p95: 450, p99: 800 },
          errorRate: 0.02,
          successRate: 0.98,
          memoryAccessFrequency: 0.8,
          reasoningDepth: 4,
          selfCorrectionRate: 0.15,
          trustScore: 0.9,
        };

    trustEngine.establishBaseline(agentId, snapshot);
    console.log(`Baseline established for agent ${agentId}`);
  });

// Identity commands
program
  .command("register <agentId>")
  .description("Register a new agent identity")
  .option("-k, --key <publicKey>", "Public key for the agent", () => randomBytes(32).toString("hex"))
  .action(async (agentId, options) => {
    const claim = trustEngine.registerIdentity(agentId, options.key);
    console.log(JSON.stringify(claim, null, 2));
  });

// Trust assessment
program
  .command("trust <agentId>")
  .description("Assess overall trust score for an agent")
  .option("-s, --snapshot <path>", "Current snapshot file path")
  .action(async (agentId, options) => {
    const snapshot: BehavioralSnapshot = options.snapshot
      ? JSON.parse(readFileSync(options.snapshot, "utf-8"))
      : {
          toolUsagePatterns: { search: 10, read: 5, write: 3, execute: 2 },
          responseLatency: { p50: 150, p95: 450, p99: 800 },
          errorRate: 0.02,
          successRate: 0.98,
          memoryAccessFrequency: 0.8,
          reasoningDepth: 4,
          selfCorrectionRate: 0.15,
          trustScore: 0.9,
        };

    const result = trustEngine.assessOverallTrust(agentId, snapshot);
    console.log(JSON.stringify(result, null, 2));
  });

program.parse(process.argv);

export { AttestationEngine, DriftDetector, IdentityContinuityManager, TrustEngine };
export type { AttestationReport, BehavioralSnapshot, DriftResult, IdentityClaim, VerificationResult };