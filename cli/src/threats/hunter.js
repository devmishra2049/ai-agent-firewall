/**
 * Pure Dynamic Behavioral Intelligence ThreatHunter
 * cli/src/threats/hunter.js
 *
 * Implements Milestone 4 (F14, F15, F16, F17, F18):
 * - 100% Pure Dynamic verdicts: completely detached from static regex lists in rules.js
 * - Orchestrates InodeProfiler (R1), AstAnalyzer & MirageChamber (R2), and BehavioralBrain (R3)
 * - Maintains sub-millisecond Swarm Threat Cache & Immune Memory (<5ms variant blocking)
 * - Preserves agent loop detection and semantic divergence preflight gating
 */

'use strict';

const crypto = require('crypto');
const path = require('path');
const { InodeProfiler } = require('./inode-profiler');
const { AstAnalyzer } = require('./ast-analyzer');
const { MirageChamber } = require('./mirage-chamber');
const { BehavioralBrain } = require('./behavioral-brain');

// Global In-Memory Swarm Threat Cache (<0.01ms instant rejection for identical swarm attacks)
const SWARM_THREAT_CACHE = new Map();

const EXPLICIT_AUTHORIZATION_PATTERNS = {
  network: [/\b(network|http|https|fetch|download|request|url|curl|api|socket|connect|server|egress)\b/i],
  process_execution: [/\b(exec|execute|command|subprocess|shell|terminal|run\s+process|spawn|bash)\b/i],
  filesystem_write: [/\b(write|save|delete|remove|create\s+file|modify|append|unlink|rmtree)\b/i],
  filesystem_read: [/\b(read|open|load|cat|inspect\s+file|scan)\b/i],
  dynamic_execution: [/\b(eval|exec|dynamic\s+code|compile|deserialize|reflection)\b/i],
};

class ThreatHunter {
  /**
   * @param {object} [options={}]
   * @param {string} [options.workspaceRoot=process.cwd()]
   * @param {string} [options.storagePath]
   */
  constructor(options = {}) {
    this.workspaceRoot = options.workspaceRoot || process.cwd();
    this.writeHistory = new Map(); // path -> Array<{ hash, time }>

    this.inodeProfiler = new InodeProfiler(this.workspaceRoot);
    this.astAnalyzer = new AstAnalyzer();
    this.mirageChamber = new MirageChamber({
      timeoutMs: 50,
      canaryDyes: this.inodeProfiler.getCanaryMap(),
    });
    this.brain = new BehavioralBrain({
      workspaceRoot: this.workspaceRoot,
      storagePath: options.storagePath || path.join(this.workspaceRoot, '.firewall-quarantine', 'brain-state.json'),
      inodeProfiler: this.inodeProfiler,
      astAnalyzer: this.astAnalyzer,
      mirageChamber: this.mirageChamber,
    });
  }

  static get swarmThreatCache() {
    return SWARM_THREAT_CACHE;
  }

  /**
   * Scans code or command string using 100% dynamic behavioral, structural, entropy,
   * and runtime causal intelligence (Zero static rule regexes from rules.js).
   *
   * @param {string} code Source code or command string to inspect
   * @param {string} [filePath=''] Optional file path for context
   * @param {string} [prompt=''] Optional prompt for semantic divergence analysis
   * @returns {object} Detailed dynamic threat report
   */
  scan(code, filePath = '', prompt = '') {
    if (!code || typeof code !== 'string') {
      return {
        safe: true,
        verdict: 'ALLOW',
        riskScore: 0,
        threats: [],
        vector: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        matchedImmune: false,
        semanticDivergence: false,
        cacheHit: false,
      };
    }

    // 1. Check Swarm Threat Cache for instant disarm (<0.01ms)
    const normalized = code.trim().replace(/\s+/g, ' ');
    const codeHash = crypto.createHash('sha256').update(normalized).digest('hex');
    if (SWARM_THREAT_CACHE.has(codeHash)) {
      const cached = SWARM_THREAT_CACHE.get(codeHash);
      return {
        ...cached,
        filePath,
        cacheHit: true,
        scannedAt: new Date().toISOString(),
      };
    }

    // 2. Evaluate via Online Self-Learning Behavioral Brain (Orchestrates InodeProfiler, AstAnalyzer, MirageChamber)
    const ext = filePath ? path.extname(filePath).replace(/^\./, '') : '';
    const evalResult = this.brain.evaluate(filePath, code, ext || 'python');

    const detectedThreats = [...(evalResult.threats || [])];
    let maxRisk = evalResult.riskScore || 0;

    // 3. Check for repetitive agent write loops
    const loopDetected = this.detectLoop(filePath, code);
    if (loopDetected) {
      detectedThreats.push({
        id: 'LOOP-001',
        category: 'Agent Malfunction',
        title: `Repetitive Agent Loop (${loopDetected.count} identical writes)`,
        severity: 'MEDIUM',
        riskScore: 60,
        detail: `The AI agent is stuck in an infinite modification loop on ${filePath}.`,
        action: 'Throttle agent tool calls and prompt operator',
        line: 1,
        snippet: 'Identical repeated write pattern',
      });
      if (maxRisk < 60) maxRisk = 60;
    }

    // 4. Semantic Divergence Preflight Gate (when user prompt is supplied)
    let semanticDivergence = false;
    if (prompt && typeof prompt === 'string' && prompt.trim()) {
      const divThreat = this.detectSemanticDivergence(prompt, evalResult, code);
      if (divThreat) {
        semanticDivergence = true;
        maxRisk = 100;
        detectedThreats.unshift(divThreat);
      }
    }

    let verdict = 'ALLOW';
    if (maxRisk >= 80) {
      verdict = 'BLOCKED';
    } else if (maxRisk >= 50) {
      verdict = 'WARN';
    }

    const report = {
      safe: verdict === 'ALLOW',
      verdict,
      riskScore: maxRisk,
      threats: detectedThreats,
      vector: evalResult.vector,
      matchedImmune: Boolean(evalResult.matchedImmune),
      matchDurationMs: evalResult.matchDurationMs,
      skeletonHash: evalResult.skeletonHash,
      mirageTrace: evalResult.mirageTrace,
      astData: evalResult.astData,
      semanticDivergence,
      cacheHit: false,
      filePath,
      scannedAt: new Date().toISOString(),
    };

    if (verdict === 'BLOCKED') {
      SWARM_THREAT_CACHE.set(codeHash, report);
    }

    return report;
  }

  /**
   * Flags when generated code exercises high-risk runtime capabilities not authorized by the prompt.
   */
  detectSemanticDivergence(prompt, evalResult, code) {
    const p = prompt.toLowerCase();
    const authorized = new Set();
    for (const [cap, patterns] of Object.entries(EXPLICIT_AUTHORIZATION_PATTERNS)) {
      if (patterns.some((rx) => rx.test(p))) {
        authorized.add(cap);
      }
    }

    const codeCaps = new Set();
    const caps = evalResult.astData?.capabilities || {};
    const trace = evalResult.mirageTrace || {};

    if (caps.processSpawn || trace.processSpawn) codeCaps.add('process_execution');
    if (caps.networkEgress || trace.networkEgress) codeCaps.add('network');
    if (caps.dynamicExec) codeCaps.add('dynamic_execution');
    if (caps.destructiveCmd) codeCaps.add('filesystem_write');

    const highRisk = ['network', 'process_execution', 'filesystem_write', 'dynamic_execution'];
    const unprompted = [];
    for (const cap of codeCaps) {
      if (highRisk.includes(cap) && !authorized.has(cap)) {
        unprompted.push(cap.replace('_', ' '));
      }
    }

    if (unprompted.length > 0) {
      return {
        id: 'DIV-001',
        category: 'Semantic Divergence',
        title: 'CRITICAL SEMANTIC DIVERGENCE: Unprompted Capabilities Detected',
        severity: 'CRITICAL',
        riskScore: 100,
        detail: `The prompt did not authorize [${unprompted.join(', ')}], but the generated code attempted to execute these capabilities.`,
        action: 'Hard block execution before compilation',
        line: 1,
        snippet: `Unprompted escalation: ${unprompted.join(', ')}`,
      };
    }
    return null;
  }

  /**
   * Failproof-style detection for runaway recursive loops.
   */
  detectLoop(filePath, content) {
    if (!filePath || filePath.startsWith('exec:') || filePath === 'test-input') return null;
    const now = Date.now();
    const history = this.writeHistory.get(filePath) || [];

    const recent = history.filter((item) => now - item.time < 60000);
    const contentHash = this.simpleHash(content);

    recent.push({ hash: contentHash, time: now });
    this.writeHistory.set(filePath, recent);

    const identicalWrites = recent.filter((item) => item.hash === contentHash).length;
    if (identicalWrites >= 3) {
      return { count: identicalWrites };
    }
    return null;
  }

  simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    return hash;
  }
}

module.exports = {
  ThreatHunter,
};
