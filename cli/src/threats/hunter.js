const crypto = require('crypto');
const { RULES } = require('./rules');

// Global In-Memory Swarm Threat Cache (<0.01ms instant rejection for swarm attacks)
const SWARM_THREAT_CACHE = new Map();

const EXPLICIT_AUTHORIZATION_PATTERNS = {
  network: [/\b(network|http|https|fetch|download|request|url|curl|api|socket|connect|server|egress)\b/i],
  process_execution: [/\b(exec|execute|command|subprocess|shell|terminal|run\s+process|spawn|bash)\b/i],
  filesystem_write: [/\b(write|save|delete|remove|create\s+file|modify|append|unlink|rmtree)\b/i],
  filesystem_read: [/\b(read|open|load|cat|inspect\s+file|scan)\b/i],
  dynamic_execution: [/\b(eval|exec|dynamic\s+code|compile|deserialize|reflection)\b/i],
};

class ThreatHunter {
  constructor() {
    this.writeHistory = new Map(); // path -> Array<{ hash, time, content }>
  }

  static get swarmThreatCache() {
    return SWARM_THREAT_CACHE;
  }

  /**
   * Scan code content against all firewall threat rules and semantic divergence gate.
   * @param {string} code Source code string to inspect
   * @param {string} filePath Optional file path for context
   * @param {string} prompt Optional prompt for semantic divergence analysis
   * @returns {object} Detailed threat report
   */
  scan(code, filePath = '', prompt = '') {
    if (!code || typeof code !== 'string') {
      return { safe: true, verdict: 'ALLOW', riskScore: 0, threats: [], semanticDivergence: false, cacheHit: false };
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

    const lines = code.split('\n');
    const detectedThreats = [];
    let maxRisk = 0;

    for (const rule of RULES) {
      for (const pattern of rule.patterns) {
        if (pattern.test(code)) {
          let matchedLine = 1;
          let matchedSnippet = '';

          for (let i = 0; i < lines.length; i++) {
            if (pattern.test(lines[i])) {
              matchedLine = i + 1;
              matchedSnippet = lines[i].trim();
              break;
            }
          }

          if (!matchedSnippet) {
            const match = code.match(pattern);
            matchedSnippet = match ? match[0].slice(0, 100) : lines[0] || '';
          }

          detectedThreats.push({
            id: rule.id,
            category: rule.category,
            title: rule.title,
            severity: rule.severity,
            riskScore: rule.riskScore,
            detail: rule.detail,
            action: rule.action,
            line: matchedLine,
            snippet: matchedSnippet,
          });

          if (rule.riskScore > maxRisk) {
            maxRisk = rule.riskScore;
          }
          break;
        }
      }
    }

    // Check for repetitive loops (agent spinning wheels)
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

    // 2. Semantic Divergence Preflight Check
    let semanticDivergence = false;
    if (prompt && typeof prompt === 'string' && prompt.trim()) {
      const divThreat = this.detectSemanticDivergence(prompt, detectedThreats, code);
      if (divThreat) {
        semanticDivergence = true;
        maxRisk = 100;
        detectedThreats.unshift(divThreat); // Place divergence at top priority
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
      semanticDivergence,
      cacheHit: false,
      filePath,
      scannedAt: new Date().toISOString(),
    };

    // Cache malicious payload signatures to disarm coordinated swarms
    if (verdict === 'BLOCKED') {
      SWARM_THREAT_CACHE.set(codeHash, report);
    }

    return report;
  }

  /**
   * Flags when generated code attempts high-risk operations not requested by the user prompt.
   */
  detectSemanticDivergence(prompt, detectedThreats, code) {
    const p = prompt.toLowerCase();
    const authorized = new Set();
    for (const [cap, patterns] of Object.entries(EXPLICIT_AUTHORIZATION_PATTERNS)) {
      if (patterns.some((rx) => rx.test(p))) {
        authorized.add(cap);
      }
    }

    const codeCaps = new Set();
    for (const t of detectedThreats) {
      if (['RCE-001', 'RCE-002', 'PROC-001'].includes(t.id)) codeCaps.add('process_execution');
      if (['EXFIL-001', 'NET-001'].includes(t.id)) codeCaps.add('network');
      if (['CRED-001'].includes(t.id)) codeCaps.add('filesystem_read');
      if (['DEST-001', 'DEST-002'].includes(t.id)) codeCaps.add('filesystem_write');
      if (['EVAL-001', 'PY-SINK-001', 'PY-BRIDGE-001'].includes(t.id)) codeCaps.add('dynamic_execution');
    }

    if (/\b(socket|urllib|requests|http|fetch|axios)\b/i.test(code)) codeCaps.add('network');
    if (/\b(subprocess|os\.system|child_process|std::process)\b/i.test(code)) codeCaps.add('process_execution');

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
    if (!filePath) return null;
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
