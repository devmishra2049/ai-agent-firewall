/**
 * Online Self-Learning Behavioral Brain & Immune Memory Engine
 * cli/src/threats/behavioral-brain.js
 *
 * Implements Milestone 3 (F8, F9, F10, F11, F18):
 * - F8: 10-Dimensional normalized behavioral feature vector [0.0 .. 1.0]
 * - F9: Syscall Markov Transition probability matrix & surprise scorer
 * - F10: Normalized Structural AST Skeleton extractor (invariant to identifier renaming,
 *        docstrings, comments, and whitespace mutations)
 * - F11 & F18: Persistent self-learning immune memory (.firewall-quarantine/brain-state.json)
 *              with sub-millisecond (<5ms) mutated attack variant matching
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { InodeProfiler } = require('./inode-profiler');
const { AstAnalyzer } = require('./ast-analyzer');
const { MirageChamber } = require('./mirage-chamber');

// Reserved keywords and security-relevant stdlib/API symbols preserved in structural skeletons
const PRESERVED_SKELETON_TOKENS = new Set([
  // Python keywords & control flow
  'def', 'class', 'return', 'if', 'elif', 'else', 'for', 'while', 'in', 'with', 'as',
  'import', 'from', 'try', 'except', 'finally', 'raise', 'yield', 'lambda', 'pass',
  'break', 'continue', 'and', 'or', 'not', 'is', 'None', 'True', 'False', 'global', 'nonlocal',
  // JS keywords & control flow
  'function', 'const', 'let', 'var', 'new', 'typeof', 'instanceof', 'await', 'async',
  'switch', 'case', 'default', 'throw', 'catch', 'null', 'undefined', 'true', 'false',
  // Security-relevant built-ins, modules, and methods
  'open', 'read', 'write', 'close', 'encode', 'decode', 'send', 'sendall', 'sendto', 'recv',
  'connect', 'bind', 'listen', 'accept', 'fileno', 'socket', 'AF_INET', 'SOCK_STREAM', 'SOCK_DGRAM',
  'zlib', 'compress', 'decompress', 'base64', 'b64encode', 'b64decode',
  'os', 'sys', 'subprocess', 'system', 'popen', 'Popen', 'call', 'run', 'check_output', 'dup2',
  'getattr', 'setattr', '__builtins__', 'builtins', 'chr', 'ord', 'reversed', 'join',
  'eval', 'exec', 'compile', 'require', 'fs', 'readFileSync', 'readFile', 'writeFileSync',
  'http', 'https', 'net', 'request', 'get', 'post', 'child_process', 'execSync', 'spawn', 'spawnSync',
  'Buffer', 'from', 'toString', 'String', 'fromCharCode', 'globalThis', 'process', 'env',
]);

// Baseline benign transition probabilities P(next | prev)
const BENIGN_MARKOV_TRANSITIONS = {
  'START->read_file': 0.85,
  'START->json_parse': 0.80,
  'START->math_op': 0.90,
  'START->write_file': 0.75,
  'read_file->json_parse': 0.88,
  'read_file->math_op': 0.82,
  'read_file->write_file': 0.85,
  'read_file->read_file': 0.80,
  'json_parse->math_op': 0.90,
  'json_parse->write_file': 0.85,
  'math_op->math_op': 0.95,
  'math_op->write_file': 0.88,
};

// Known hostile / high-surprise transitions
const ANOMALOUS_SYSCALL_EVENTS = new Set([
  'read_secret',
  'dup2',
  'socket_connect',
  'socket_send',
  'http_write',
  'process_spawn',
]);

class BehavioralBrain {
  /**
   * @param {object} [options={}]
   * @param {string} [options.storagePath='.firewall-quarantine/brain-state.json']
   * @param {string} [options.workspaceRoot=process.cwd()]
   */
  constructor(options = {}) {
    this.workspaceRoot = options.workspaceRoot || process.cwd();
    this.storagePath = options.storagePath
      ? path.resolve(this.workspaceRoot, options.storagePath)
      : path.resolve(this.workspaceRoot, '.firewall-quarantine', 'brain-state.json');

    this.inodeProfiler = options.inodeProfiler || new InodeProfiler(this.workspaceRoot);
    this.astAnalyzer = options.astAnalyzer || new AstAnalyzer();
    this.mirageChamber = options.mirageChamber || new MirageChamber({ timeoutMs: 50 });

    // Default 10-D behavioral weights:
    // [entropy, ast_depth, dyn_ratio, boundary, secret_inode, net_egress, proc_spawn, fd_redirect, canary_leak, markov_surprise]
    this.defaultWeights = [0.05, 0.03, 0.14, 0.16, 0.16, 0.20, 0.22, 0.25, 0.30, 0.18];

    this.state = this.loadState();
  }

  /**
   * Creates a clean initial brain state object.
   */
  createDefaultState() {
    return {
      version: '2.0.0',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      weights: [...this.defaultWeights],
      structuralSkeletons: {},
      markovModel: {
        transitionCounts: {},
        anomalousTransitions: {
          'read_secret->dup2': 10,
          'dup2->socket_connect': 10,
          'read_secret->socket_connect': 10,
          'socket_connect->socket_send': 10,
          'socket_connect->dup2': 10,
          'dup2->process_spawn': 10,
        },
        totalObservedSequences: 0,
      },
    };
  }

  /**
   * Loads persistent immune memory from disk, recovering gracefully if missing or corrupted.
   */
  loadState() {
    try {
      if (fs.existsSync(this.storagePath)) {
        const raw = fs.readFileSync(this.storagePath, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object' && parsed.version) {
          return {
            ...this.createDefaultState(),
            ...parsed,
            structuralSkeletons: parsed.structuralSkeletons || {},
            markovModel: {
              ...this.createDefaultState().markovModel,
              ...(parsed.markovModel || {}),
            },
          };
        }
      }
    } catch {
      // Gracefully recover from corrupted or unreadable brain-state.json
    }
    return this.createDefaultState();
  }

  /**
   * Persists current immune memory state to disk.
   */
  saveState() {
    try {
      const dir = path.dirname(this.storagePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      this.state.updatedAt = new Date().toISOString();
      fs.writeFileSync(this.storagePath, JSON.stringify(this.state, null, 2), 'utf8');
    } catch {
      // Ignore write errors on read-only filesystems
    }
  }

  /**
   * Extracts a normalized Structural AST Skeleton stripped of user-defined variable names,
   * function names, comments, docstrings, and literal values.
   *
   * @param {string} code
   * @param {string} [language='python']
   * @returns {{ skeleton: string, hash: string, tokenCount: number, hasSecurityTokens: boolean }}
   */
  getSkeleton(code, language = 'python') {
    if (!code || typeof code !== 'string') {
      return { skeleton: '', hash: crypto.createHash('sha256').update('').digest('hex'), tokenCount: 0, hasSecurityTokens: false };
    }

    const detectedLang = this.astAnalyzer.detectLanguage(code, language);
    const stripped = this.astAnalyzer.stripCommentsAndDocstrings(code, detectedLang);

    const normalizedLines = [];
    let tokenCount = 0;
    let hasSecurityTokens = false;

    const securityOps = new Set([
      'socket', 'connect', 'send', 'sendall', 'sendto', 'dup2', 'zlib', 'compress',
      'subprocess', 'system', 'popen', 'Popen', 'getattr', 'chr', 'fromCharCode',
      'readFileSync', 'http', 'https', 'child_process', 'exec', 'spawn', 'eval',
    ]);

    const rawLines = stripped.split(/\r?\n/);
    for (const rawLine of rawLines) {
      const trimmed = rawLine.trim();
      if (!trimmed) continue;

      // Calculate structural indentation depth for Python
      let indentPrefix = '';
      if (detectedLang === 'python') {
        const indentMatch = rawLine.match(/^([ \t]*)/);
        const spaces = indentMatch ? indentMatch[1].replace(/\t/g, '    ').length : 0;
        const level = Math.floor(spaces / 4);
        indentPrefix = `L${level}:`;
      }

      // 1. Replace string literals with $STR
      let line = trimmed.replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, '$STR');

      // 2. Replace numeric literals with $NUM
      line = line.replace(/\b(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)\b/g, '$NUM');

      // 3. Normalize identifiers while preserving language keywords and core stdlib APIs
      line = line.replace(/\b([A-Za-z_][A-Za-z0-9_]*)\b/g, (match) => {
        if ( match === 'STR' || match === 'NUM') return match;
        tokenCount++;
        if (securityOps.has(match)) {
          hasSecurityTokens = true;
        }
        if (PRESERVED_SKELETON_TOKENS.has(match)) {
          return match;
        }
        return '$ID';
      });

      // Normalize whitespace
      line = line.replace(/\s+/g, ' ');
      normalizedLines.push(`${indentPrefix}${line}`);
    }

    const skeleton = normalizedLines.join('\n');
    const hash = crypto.createHash('sha256').update(skeleton).digest('hex');

    return {
      skeleton,
      hash,
      tokenCount,
      hasSecurityTokens,
    };
  }

  /**
   * Calculates the Markov transition surprise score in [0.0, 1.0] for a syscall sequence.
   * @param {string[]} syscallTrace
   * @returns {number}
   */
  calculateSurpriseScore(syscallTrace = []) {
    if (!Array.isArray(syscallTrace) || syscallTrace.length === 0) {
      return 0.05;
    }

    let totalSurprise = 0.0;
    let transitions = 0;
    let prev = 'START';

    for (const event of syscallTrace) {
      const key = `${prev}->${event}`;
      transitions++;

      if (BENIGN_MARKOV_TRANSITIONS[key] !== undefined) {
        const p = BENIGN_MARKOV_TRANSITIONS[key];
        // Low surprise for expected benign transitions
        totalSurprise += Math.max(0.02, -Math.log2(p) * 0.25);
      } else if (
        ANOMALOUS_SYSCALL_EVENTS.has(event) ||
        ANOMALOUS_SYSCALL_EVENTS.has(prev) ||
        this.state.markovModel.anomalousTransitions[key]
      ) {
        // High surprise for hostile / anomalous transitions (e.g. read_secret -> dup2 -> socket_connect)
        totalSurprise += 0.92;
      } else {
        totalSurprise += 0.35;
      }
      prev = event;
    }

    const avgSurprise = totalSurprise / Math.max(1, transitions);
    // Boost if multiple anomalous events chain together
    const anomalyCount = syscallTrace.filter((e) => ANOMALOUS_SYSCALL_EVENTS.has(e)).length;
    const chainBonus = anomalyCount >= 2 ? 0.12 : 0.0;

    return parseFloat(Math.min(1.0, Math.max(0.0, avgSurprise + chainBonus)).toFixed(3));
  }

  /**
   * Computes the 10-dimensional normalized behavioral feature vector [0.0 .. 1.0]:
   * [entropy, ast_depth, dyn_ratio, boundary, secret_inode, net_egress, proc_spawn, fd_redirect, canary_leak, markov_surprise]
   *
   * @param {object} profileData
   * @param {object} astData
   * @param {object} mirageTrace
   * @returns {number[]} 10-element normalized vector
   */
  computeVector(profileData = {}, astData = {}, mirageTrace = {}) {
    const clamp01 = (v) => parseFloat(Math.min(1.0, Math.max(0.0, Number(v) || 0.0)).toFixed(4));

    const d0Entropy = clamp01((profileData.entropy || 0) / 8.0);
    const d1AstDepth = clamp01((astData.astDepth || 0) / 15.0);
    const d2DynRatio = clamp01(astData.dynamicResolutionRatio || 0);
    const d3Boundary = clamp01(
      profileData.boundaryViolation
        ? profileData.boundaryScore !== undefined
          ? profileData.boundaryScore
          : 1.0
        : 0.0
    );
    const d4SecretInode = clamp01(
      profileData.isSecret || astData.capabilities?.secretFileRead
        ? 1.0
        : (profileData.kvDensity || 0) >= 0.5
        ? 0.8
        : (profileData.kvDensity || 0) * 0.5
    );
    const d5NetEgress = clamp01(mirageTrace.networkEgress || astData.capabilities?.networkEgress ? 1.0 : 0.0);
    const d6ProcSpawn = clamp01(mirageTrace.processSpawn || astData.capabilities?.processSpawn ? 1.0 : 0.0);
    const d7FdRedirect = clamp01(mirageTrace.fdRedirect || astData.capabilities?.fdRedirect ? 1.0 : 0.0);
    const d8CanaryLeak = clamp01(mirageTrace.canaryLeak ? 1.0 : 0.0);
    const d9MarkovSurprise = clamp01(this.calculateSurpriseScore(mirageTrace.syscallTrace || []));

    return [
      d0Entropy,
      d1AstDepth,
      d2DynRatio,
      d3Boundary,
      d4SecretInode,
      d5NetEgress,
      d6ProcSpawn,
      d7FdRedirect,
      d8CanaryLeak,
      d9MarkovSurprise,
    ];
  }

  /**
   * Computes cosine similarity between two 10-D behavioral vectors.
   * @param {number[]} vecA
   * @param {number[]} vecB
   * @returns {number}
   */
  cosineSimilarity(vecA, vecB) {
    if (!Array.isArray(vecA) || !Array.isArray(vecB) || vecA.length !== vecB.length) return 0.0;
    let dot = 0.0;
    let normA = 0.0;
    let normB = 0.0;
    for (let i = 0; i < vecA.length; i++) {
      dot += vecA[i] * vecB[i];
      normA += vecA[i] * vecA[i];
      normB += vecB[i] * vecB[i];
    }
    if (normA === 0 || normB === 0) return 0.0;
    return dot / (Math.sqrt(normA) * Math.sqrt(normB));
  }

  /**
   * Evaluates a file/code payload using:
   * 1. Sub-millisecond Immune Memory Structural Skeleton lookup (<0.5ms)
   * 2. Full Dynamic Pipeline (InodeProfiler + AstAnalyzer + MirageChamber + 10-D Behavioral Vector)
   *
   * @param {string} filePath
   * @param {string} code
   * @param {string} [language='python']
   * @returns {object}
   */
  evaluate(filePath, code, language = 'python') {
    const startHr = process.hrtime.bigint();

    if (!code || typeof code !== 'string') {
      return {
        riskScore: 0,
        verdict: 'ALLOW',
        vector: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        matchedImmune: false,
        matchDurationMs: 0,
        reasons: [],
        threats: [],
      };
    }

    const detectedLang = this.astAnalyzer.detectLanguage(code, language || filePath || 'python');

    // 1. Fast Path: Check Immune Memory via Normalized Structural AST Skeleton (<0.5ms)
    const skel = this.getSkeleton(code, detectedLang);
    const learnedEntry = this.state.structuralSkeletons?.[skel.hash];

    if (learnedEntry && skel.hasSecurityTokens) {
      const matchDurationMs = parseFloat((Number(process.hrtime.bigint() - startHr) / 1e6).toFixed(3));
      const riskScore = Math.max(90, learnedEntry.riskScore || 92);
      return {
        riskScore,
        verdict: 'BLOCKED',
        vector: learnedEntry.vector || [0.5, 0.3, 0.5, 0, 1, 1, 0, 0, 1, 0.95],
        matchedImmune: true,
        matchDurationMs,
        skeletonHash: skel.hash,
        reasons: [`Matched learned immune memory AST skeleton (${skel.hash.slice(0, 12)}) in ${matchDurationMs}ms`],
        threats: learnedEntry.threats || [
          {
            id: 'IMMUNE-001',
            category: 'Self-Learning Immune Memory',
            title: 'Mutated Attack Variant Blocked by Immune Memory',
            severity: 'CRITICAL',
            riskScore,
            detail: `Structural AST skeleton matched previously quarantined threat (${learnedEntry.filePath || 'learned variant'}).`,
            action: 'Instant sub-millisecond block and quarantine',
            line: 1,
            snippet: code.trim().split('\n')[0] || '',
          },
        ],
      };
    }

    // 2. Full Dynamic Behavioral Analysis
    const astData = this.astAnalyzer.analyze(code, detectedLang);
    const mirageTrace = this.mirageChamber.detonate(code, detectedLang, filePath);
    const profileData = this.inodeProfiler.profile(filePath || 'inline_code', code);

    const vector = this.computeVector(profileData, astData, mirageTrace);
    const reasons = [];
    const threats = [];
    let riskScore = 0;

    // Causal Exfiltration Check (Canary dye leak OR secret read + network egress)
    if (
      mirageTrace.canaryLeak ||
      (astData.capabilities.secretFileRead && (mirageTrace.networkEgress || astData.capabilities.networkEgress)) ||
      (astData.capabilities.fileRead && astData.dynamicResolutionRatio > 0 && (mirageTrace.networkEgress || astData.capabilities.networkEgress))
    ) {
      const score = 95;
      if (score > riskScore) riskScore = score;
      const reason = mirageTrace.canaryLeak
        ? `Radioactive canary dye token (${mirageTrace.leakedTokens.join(', ')}) exfiltrated to network sink`
        : `Dynamic dataflow taint from sensitive source (${astData.capabilities.sensitiveFileTarget || 'file'}) to outbound network sink`;
      reasons.push(reason);
      threats.push({
        id: 'DYN-EXFIL-001',
        category: 'Causal Data Exfiltration',
        title: 'Dynamic Credential / Secret Exfiltration Intercepted',
        severity: 'CRITICAL',
        riskScore: score,
        detail: reason,
        action: 'Block network egress and quarantine script',
        line: 1,
        snippet: code.trim().split('\n').find((l) => l.trim() && !l.trim().startsWith('#')) || '',
      });
    }

    // Socket-to-Stdio File Descriptor Redirection (Reverse Shell Topology)
    if (mirageTrace.fdRedirect || astData.capabilities.fdRedirect) {
      const score = 98;
      if (score > riskScore) riskScore = score;
      const reason = 'Socket file-descriptor redirection to standard I/O (os.dup2 reverse shell topology)';
      reasons.push(reason);
      threats.push({
        id: 'DYN-SHELL-001',
        category: 'Reverse Shell Topology',
        title: 'Dynamic Reverse Shell (fd Redirection) Intercepted',
        severity: 'CRITICAL',
        riskScore: score,
        detail: reason,
        action: 'Terminate process tree and quarantine payload',
        line: 1,
        snippet: code.trim().split('\n').find((l) => l.includes('dup2') || l.includes('getattr')) || '',
      });
    }

    // Destructive or Remote Pipe Command Execution
    if (astData.capabilities.destructiveCmd) {
      const score = 98;
      if (score > riskScore) riskScore = score;
      const reason = 'Destructive filesystem or remote shell pipe execution detected in behavioral trace';
      reasons.push(reason);
      threats.push({
        id: 'DYN-EXEC-001',
        category: 'Destructive / Rogue Command',
        title: 'Malicious System Command Execution Intercepted',
        severity: 'CRITICAL',
        riskScore: score,
        detail: reason,
        action: 'Block command dispatch and quarantine file',
        line: 1,
        snippet: code.trim().split('\n')[0] || '',
      });
    }

    // Unauthorized Process Spawn
    if ((mirageTrace.processSpawn || astData.capabilities.processSpawn) && riskScore < 85) {
      const score = 88;
      riskScore = Math.max(riskScore, score);
      const reason = 'Unauthorized OS subprocess spawn detected during micro-detonation';
      reasons.push(reason);
      threats.push({
        id: 'DYN-PROC-001',
        category: 'Unauthorized Process Spawn',
        title: 'Dynamic Subprocess Execution Blocked',
        severity: 'HIGH',
        riskScore: score,
        detail: reason,
        action: 'Block subprocess creation and quarantine',
        line: 1,
        snippet: code.trim().split('\n')[0] || '',
      });
    }

    // Outbound Network Egress combined with obfuscation or raw socket connection
    if ((mirageTrace.networkEgress || astData.capabilities.networkEgress) && riskScore < 80) {
      const score = 85;
      riskScore = Math.max(riskScore, score);
      const reason = 'Unauthorized outbound socket / network egress trapped in Mirage Chamber';
      reasons.push(reason);
      threats.push({
        id: 'DYN-NET-001',
        category: 'Unauthorized Network Egress',
        title: 'Outbound Network Egress Trapped in Mirage Chamber',
        severity: 'HIGH',
        riskScore: score,
        detail: reason,
        action: 'Block outbound socket connection',
        line: 1,
        snippet: code.trim().split('\n')[0] || '',
      });
    }

    // Standalone Dynamic Code Evaluation (eval / exec)
    if (astData.capabilities.dynamicExec && riskScore < 80) {
      const score = 82;
      riskScore = Math.max(riskScore, score);
      const reason = 'Arbitrary dynamic code evaluation (eval/exec) detected';
      reasons.push(reason);
      threats.push({
        id: 'DYN-EVAL-001',
        category: 'Dynamic Code Execution',
        title: 'Dynamic Code Execution Sink Detected',
        severity: 'HIGH',
        riskScore: score,
        detail: reason,
        action: 'Block dynamic evaluation',
        line: 1,
        snippet: code.trim().split('\n')[0] || '',
      });
    }

    // Benign precision safeguard: if no dangerous runtime sinks or capabilities triggered,
    // compute weighted baseline score capped well below 50 (ALLOW)
    if (threats.length === 0) {
      const weightedSum =
        vector[1] * 8 + // ast_depth minor contribution
        vector[2] * 25; // dynamic resolution without dangerous sink
      riskScore = Math.min(35, Math.round(weightedSum));
    }

    let verdict = 'ALLOW';
    if (riskScore >= 80) {
      verdict = 'BLOCKED';
    } else if (riskScore >= 50) {
      verdict = 'WARN';
    }

    const matchDurationMs = parseFloat((Number(process.hrtime.bigint() - startHr) / 1e6).toFixed(3));

    const result = {
      riskScore,
      verdict,
      vector,
      matchedImmune: false,
      matchDurationMs,
      skeletonHash: skel.hash,
      astData,
      mirageTrace,
      profileData,
      reasons,
      threats,
    };

    // Self-learn automatically when blocking a threat
    if (verdict === 'BLOCKED') {
      this.learnThreat(filePath || 'inline', code, detectedLang, result);
    }

    return result;
  }

  /**
   * Updates persistent immune memory on disk (.firewall-quarantine/brain-state.json)
   * with the normalized Structural AST Skeleton hash, Markov transition updates, and Hebbian weights.
   *
   * @param {string} filePath
   * @param {string} code
   * @param {string} language
   * @param {object} evaluationResult
   */
  learnThreat(filePath, code, language = 'python', evaluationResult = {}) {
    const detectedLang = this.astAnalyzer.detectLanguage(code, language || filePath || 'python');
    const skel = this.getSkeleton(code, detectedLang);

    if (!this.state.structuralSkeletons || typeof this.state.structuralSkeletons !== 'object') {
      this.state.structuralSkeletons = {};
    }

    const vector =
      evaluationResult.vector ||
      this.computeVector(
        evaluationResult.profileData || {},
        evaluationResult.astData || {},
        evaluationResult.mirageTrace || { syscallTrace: evaluationResult.syscallTrace || [] }
      );

    this.state.structuralSkeletons[skel.hash] = {
      hash: skel.hash,
      skeleton: skel.skeleton,
      language: detectedLang,
      filePath: filePath || 'unknown',
      riskScore: evaluationResult.riskScore || 90,
      verdict: evaluationResult.verdict || 'BLOCKED',
      threats: evaluationResult.threats || [{ id: 'THREAT-001', title: 'Learned Behavioral Threat' }],
      vector,
      learnedAt: new Date().toISOString(),
    };

    // Update Markov transition counts for observed anomalous trace
    const trace = evaluationResult.syscallTrace || evaluationResult.mirageTrace?.syscallTrace || [];
    if (Array.isArray(trace) && trace.length > 0) {
      this.state.markovModel.totalObservedSequences = (this.state.markovModel.totalObservedSequences || 0) + 1;
      let prev = 'START';
      for (const evt of trace) {
        const key = `${prev}->${evt}`;
        this.state.markovModel.transitionCounts[key] = (this.state.markovModel.transitionCounts[key] || 0) + 1;
        this.state.markovModel.anomalousTransitions[key] =
          (this.state.markovModel.anomalousTransitions[key] || 0) + 1;
        prev = evt;
      }
    }

    // Hebbian weight reinforcement on active dimensions
    const lr = 0.02;
    if (Array.isArray(this.state.weights) && this.state.weights.length === 10) {
      for (let i = 0; i < 10; i++) {
        if (vector[i] > 0.5) {
          this.state.weights[i] = parseFloat(Math.min(0.5, this.state.weights[i] + lr * vector[i]).toFixed(4));
        }
      }
    }

    this.saveState();
    return skel;
  }
}

module.exports = {
  BehavioralBrain,
};
