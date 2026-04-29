# Agent Verification & Trust System

A comprehensive system for verifying AI agent identity, detecting behavioral drift, and establishing cryptographic trust across sessions. Built for autonomous AI agents that need verifiable credentials and continuous identity verification.

## Features

- **Cryptographic Attestation** - Generate signed attestation reports proving agent behavioral state at any point in time
- **Behavioral Drift Detection** - Detect when agent behavior deviates from established baseline patterns
- **Cross-Session Identity Continuity** - Verify that an agent maintaining identity across sessions and key rotations
- **Trust Scoring Engine** - Calculate overall trust scores combining attestation, drift, and identity factors
- **Snapshot Generation** - Collect and generate behavioral snapshots for verification

## Installation

```bash
git clone https://github.com/Retsumdk/agent-verification-trust.git
cd agent-verification-trust
bun install
```

## Usage

### CLI Commands

#### Generate Attestation
```bash
bun run src/index.ts attest <agentId> --session <sessionId> --output report.json
```

#### Verify Attestation
```bash
bun run src/index.ts verify report.json
```

#### Detect Drift
```bash
bun run src/index.ts drift <agentId> --snapshot snapshot.json
```

#### Establish Baseline
```bash
bun run src/index.ts baseline <agentId> --snapshot snapshot.json
```

#### Register Agent Identity
```bash
bun run src/index.ts register <agentId> --key <publicKeyHex>
```

#### Assess Trust Score
```bash
bun run src/index.ts trust <agentId> --snapshot snapshot.json
```

### Programmatic Usage

```typescript
import { TrustEngine } from "./src/index";
import type { BehavioralSnapshot } from "./src/snapshot";

const engine = new TrustEngine();

// Create behavioral snapshot
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

// Generate attestation
const report = engine.generateAttestation("agent-1", "session-123", snapshot);

// Establish baseline for drift detection
engine.establishBaseline("agent-1", snapshot);

// Assess trust
const result = engine.assessOverallTrust("agent-1", snapshot);
console.log(`Trust level: ${result.level} (score: ${result.trustScore})`);
```

## Architecture

### Core Components

1. **AttestationEngine** - Generates and verifies cryptographic attestation reports
2. **DriftDetector** - Establishes baselines and detects behavioral drift over time
3. **IdentityContinuityManager** - Manages agent identity across sessions with key rotation support
4. **TrustEngine** - Combines all components into unified trust assessment

### Data Model

#### BehavioralSnapshot
```typescript
interface BehavioralSnapshot {
  toolUsagePatterns: Record<string, number>;  // Tool name -> invocation count
  responseLatency: { p50: number; p95: number; p99: number };
  errorRate: number;           // 0-1
  successRate: number;          // 0-1
  memoryAccessFrequency: number; // Operations per second
  reasoningDepth: number;      // Max reasoning depth observed
  selfCorrectionRate: number;  // Self-corrections per operation
  trustScore: number;           // Internal trust estimate
}
```

#### AttestationReport
```typescript
interface AttestationReport {
  id: string;
  agentId: string;
  timestamp: string;
  sessionId: string;
  behavioralSnapshot: BehavioralSnapshot;
  capabilityHash: string;      // SHA256 of snapshot (first 16 chars)
  signature: string;            // Cryptographic signature
  expiresAt: string;           // 24 hour validity
}
```

#### DriftResult
```typescript
interface DriftResult {
  agentId: string;
  baselineHash: string;
  currentHash: string;
  driftScore: number;          // 0-1
  driftSeverity: "none" | "minor" | "moderate" | "severe";
  affectedDimensions: string[];
  recommendations: string[];
  timestamp: string;
}
```

## Trust Score Calculation

The trust score combines three weighted factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| Attestation | 35% | Confidence from valid attestation reports |
| Drift | 35% | Inverse of behavioral drift score |
| Identity | 30% | Historical continuity score |

**Trust Levels:**
- `trusted` (≥0.75): Normal autonomous operation allowed
- `caution` (0.40-0.74): Enhanced monitoring recommended
- `untrusted` (<0.40): Human approval required for high-stakes operations

## Drift Detection Dimensions

The system tracks drift across multiple dimensions:

- **toolUsageMagnitude** - Total tool usage count deviation
- **toolDiversity** - Number of different tools used
- **errorRate** - Error frequency changes
- **successRate** - Success rate changes
- **latencyP95** - Response time at 95th percentile
- **selfCorrectionRate** - Self-correction behavior changes
- **memoryAccessFrequency** - Memory operation rate changes

## Configuration

Data is stored in `.agent-*` directories in the working directory:
- `.agent-attestation/` - Attestation reports and index
- `.agent-drift/` - Baselines and drift history
- `.agent-identity/` - Identity claims and continuity scores

## Running Tests

```bash
bun test
```

## License

MIT License