/**
 * Real-Time Workspace Watcher & Agent Code Inspector
 */

const fs = require('fs');
const path = require('path');
const { ThreatHunter } = require('../threats/hunter');
const { logEvent, threatCard, summaryBox, statusLine, c } = require('../ui/terminal');

const os = require('os');

class WorkspaceInspector {
  constructor(options = {}) {
    this.cwd = options.cwd || process.cwd();
    this.config = options.config || {};
    this.hunter = new ThreatHunter({ workspaceRoot: this.cwd });
    this.stats = {
      filesInspected: 0,
      allowed: 0,
      threatsBlocked: 0,
      loopsCaught: 0,
    };
    this.watcher = null;
    this.isWatching = false;
  }

  isIgnored(filePath) {
    const rel = path.relative(this.cwd, filePath);
    
    // 1. Ignore system and internal firewall codebase directories
    const ignoredDirs = [
      'node_modules', '.git', 'target', 'dist', 'build', '.venv', 'venv', '__pycache__',
      '.firewall-quarantine', 'Library', 'System', '.Trash', '.gemini', '.cache',
      'Applications', 'Movies', 'Music', 'Pictures', '.npm', '.yarn', '.cargo',
      '.rustup', '.local', '.vscode', '.idea', '.cursor', '.DS_Store', 'Containers',
      'cli', 'backend', 'frontend', 'sandbox', 'sandbox-host', 'sandbox-guest',
      'corsair-bridge', 'scripts'
    ];
    
    const parts = rel.split(path.sep);
    if (parts.some((part) => ignoredDirs.includes(part))) {
      return true;
    }

    // 2. Only inspect code, scripts, configs, and env files
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath).toLowerCase();

    // Sensitive dotfiles and infrastructure files
    if (basename.startsWith('.env') || basename === 'dockerfile' || basename.startsWith('dockerfile.')) {
      return false;
    }

    // Explicitly ignore databases, plists, logs, binaries, media
    const noiseExtensions = new Set([
      '.plist', '.db', '.db-shm', '.db-wal', '.sqlite', '.sqlite3',
      '.log', '.lock', '.sock', '.png', '.jpg', '.jpeg', '.gif',
      '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot',
      '.mp4', '.mov', '.zip', '.tar', '.gz', '.dmg', '.pkg',
      '.pyc', '.class', '.o', '.so', '.dylib', '.dll', '.exe',
    ]);
    if (noiseExtensions.has(ext)) {
      return true;
    }

    // Allowable code & configuration extensions
    const codeExtensions = new Set([
      '.js', '.mjs', '.cjs', '.jsx',
      '.ts', '.tsx',
      '.py', '.pyw',
      '.sh', '.bash', '.zsh',
      '.rs', '.go', '.rb', '.php',
      '.c', '.cpp', '.cc', '.h', '.hpp',
      '.java', '.kt', '.scala', '.cs',
      '.sql', '.lua', '.pl',
      '.json', '.yaml', '.yml', '.toml',
      '.xml', '.html', '.htm',
    ]);

    // If it has an extension not in our code list, skip it
    if (ext && !codeExtensions.has(ext)) {
      return true;
    }

    return false;
  }

  async inspectFile(fullPath, action = 'write') {
    if (this.isIgnored(fullPath)) return;
    if (!fs.existsSync(fullPath)) return;

    let stat;
    try {
      stat = fs.statSync(fullPath);
      if (stat.isDirectory()) return;
      if (stat.size > 2 * 1024 * 1024) return; // Skip files > 2MB
    } catch {
      return;
    }

    let content;
    try {
      content = fs.readFileSync(fullPath, 'utf8');
    } catch {
      return;
    }

    // Skip files that have already been replaced by the firewall quarantine stub
    if (content.includes('[AI AGENT FIREWALL] - FILE QUARANTINED')) {
      return;
    }

    const relPath = path.relative(this.cwd, fullPath);
    this.stats.filesInspected++;

    const result = this.hunter.scan(content, relPath);

    if (result.verdict === 'ALLOW') {
      this.stats.allowed++;
      logEvent('ALLOW', `agent wrote ${c.bold}${relPath}${c.reset}`, `Risk Score: ${result.riskScore}/100 • Clean`);
    } else if (result.verdict === 'WARN') {
      this.stats.allowed++;
      const threat = result.threats[0] || {};
      logEvent('WARNING', `agent wrote ${c.bold}${relPath}${c.reset}`, `Risk Score: ${result.riskScore}/100 • ${threat.title || 'Review recommended'}`);
    } else {
      // BLOCKED!
      this.stats.threatsBlocked++;
      const topThreat = result.threats[0] || {
        title: 'Malicious Operation Detected',
        severity: 'CRITICAL',
        category: 'Policy Violation',
        detail: 'Risk score exceeded firewall threshold.',
      };

      // Ring terminal alert bell
      process.stdout.write('\x07');

      if (topThreat.id === 'LOOP-001') {
        this.stats.loopsCaught++;
        logEvent('LOOP', `Agent loop detected on ${relPath}`, topThreat.detail);
      } else {
        threatCard(topThreat, relPath, topThreat.snippet, topThreat.line);
      }

      // Quarantine if configured
      if (this.config.quarantineBlocked !== false) {
        this.quarantine(fullPath, relPath, topThreat);
      }
    }
  }

  quarantine(fullPath, relPath, threat) {
    try {
      const qDir = path.join(this.cwd, this.config.quarantineDir || '.firewall-quarantine');
      if (!fs.existsSync(qDir)) {
        fs.mkdirSync(qDir, { recursive: true });
      }

      const timestamp = Date.now();
      const backupName = `${path.basename(relPath)}.${timestamp}.quarantine`;
      const qPath = path.join(qDir, backupName);

      // Copy malicious file to quarantine vault
      fs.copyFileSync(fullPath, qPath);

      // Neutralize original file with language-aware security placeholder
      const ext = path.extname(relPath).toLowerCase();
      let warningText = '';

      if (ext === '.py') {
        warningText = `"""
[AI AGENT FIREWALL] - FILE QUARANTINED
------------------------------------------------------------------
Threat Detected: ${threat.title} (${threat.severity})
Rule ID:         ${threat.id}
Time:            ${new Date().toISOString()}

The agent-generated code was intercepted and neutralized to protect
your host system. Original copy preserved in ${this.config.quarantineDir || '.firewall-quarantine'}/
"""
import sys
sys.exit("[AI AGENT FIREWALL] Execution aborted: This file contains quarantined malicious code.")
`;
      } else if (['.sh', '.bash', '.zsh'].includes(ext)) {
        warningText = `#!/usr/bin/env bash
# [AI AGENT FIREWALL] - FILE QUARANTINED
# ------------------------------------------------------------------
# Threat Detected: ${threat.title} (${threat.severity})
# Rule ID:         ${threat.id}
# Time:            ${new Date().toISOString()}
#
# Original copy preserved in ${this.config.quarantineDir || '.firewall-quarantine'}/
echo "[AI AGENT FIREWALL] Execution aborted: This file contains quarantined malicious code."
exit 1
`;
      } else {
        warningText = `/*
 * [AI AGENT FIREWALL] - FILE QUARANTINED
 * ------------------------------------------------------------------
 * Threat Detected: ${threat.title} (${threat.severity})
 * Rule ID:         ${threat.id}
 * Time:            ${new Date().toISOString()}
 * 
 * The agent-generated code was intercepted and neutralized to protect
 * your host system. Original copy preserved in ${this.config.quarantineDir || '.firewall-quarantine'}/
 */
throw new Error("[AI AGENT FIREWALL] Execution aborted: This file contains quarantined malicious code.");
`;
      }

      fs.writeFileSync(fullPath, warningText, 'utf8');
      logEvent('QUARANTINE', `Neutralized malicious write to ${relPath}`, `Safely isolated to ${this.config.quarantineDir || '.firewall-quarantine'}/${backupName}`);
    } catch (err) {
      console.error(`[firewall] Quarantine failed:`, err.message);
    }
  }

  start(options = {}) {
    const embedded = options.embedded === true;
    statusLine('WATCH', this.cwd, this.config.mode === 'observe' ? 'OBSERVE ONLY' : 'ZERO-TRUST ENFORCING');
    this.isWatching = true;

    if (path.resolve(this.cwd) === os.homedir()) {
      console.log(`  ${c.yellow}⚠️  Notice: Watching root home directory (~). System files excluded.${c.reset}`);
      console.log(`  ${c.dim}Tip: Run inside your specific project folder (e.g. cd ~/ai-agent-firewall) for targeted monitoring.${c.reset}\n`);
    }

    // Try using chokidar if available, else native fs.watch
    let chokidar;
    try {
      chokidar = require('chokidar');
    } catch {
      chokidar = null;
    }

    if (chokidar) {
      this.watcher = chokidar.watch(this.cwd, {
        ignored: this.config.ignoredPaths || [/(^|[\/\\])\../, 'node_modules', 'target', 'dist'],
        persistent: true,
        ignoreInitial: true,
        awaitWriteFinish: {
          stabilityThreshold: 100,
          pollInterval: 50,
        },
      });

      this.watcher.on('add', (filePath) => this.inspectFile(filePath, 'create'));
      this.watcher.on('change', (filePath) => this.inspectFile(filePath, 'modify'));
    } else {
      // Native recursive fs.watch fallback
      const debounceMap = new Map();
      this.watcher = fs.watch(this.cwd, { recursive: true }, (eventType, filename) => {
        if (!filename) return;
        const fullPath = path.join(this.cwd, filename);
        if (debounceMap.has(fullPath)) {
          clearTimeout(debounceMap.get(fullPath));
        }
        const timer = setTimeout(() => {
          debounceMap.delete(fullPath);
          this.inspectFile(fullPath, eventType);
        }, 120);
        debounceMap.set(fullPath, timer);
      });
    }

    if (!embedded) {
      process.on('SIGINT', () => {
        this.stop();
        process.exit(0);
      });
    }
  }

  stop() {
    if (!this.isWatching) return;
    if (this.watcher) {
      if (typeof this.watcher.close === 'function') {
        this.watcher.close();
      }
    }
    this.isWatching = false;
    summaryBox(this.stats);
  }
}

module.exports = {
  WorkspaceInspector,
};
