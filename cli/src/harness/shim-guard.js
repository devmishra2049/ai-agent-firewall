#!/usr/bin/env node
/**
 * Synchronous Subprocess & Tool-Call Interceptor Shim
 * Intercepts inline commands (-c) and workspace script executions before the OS runs them,
 * eliminating race conditions between agent file creation and execution.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const { ThreatHunter } = require('../threats/hunter');
const { threatCard, logEvent, c } = require('../ui/terminal');
const { loadConfig } = require('../config/policy');

function findRealBinary(binName, shimDir) {
  const pathEnv = process.env.PATH || '';
  const dirs = pathEnv.split(path.delimiter).filter((d) => path.resolve(d) !== path.resolve(shimDir));
  for (const dir of dirs) {
    const candidate = path.join(dir, binName);
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch {
      // ignore
    }
  }
  return null;
}

function isInternalAgentBinary(argPath) {
  if (!argPath) return false;
  const resolved = path.resolve(argPath);
  const internalPatterns = [
    '.hermes',
    '.local/bin',
    '.local/pipx',
    '/opt/homebrew',
    '/usr/local',
    '/Library/Frameworks',
    'node_modules',
    'cli/bin/agent-firewall.js',
    'agent.py',
    'simulate_swarm.py',
    'test_dual_sandbox.py',
  ];
  return internalPatterns.some((pat) => resolved.includes(pat));
}

function quarantineFileSync(fullPath, cwd, config, threat) {
  try {
    const relPath = path.relative(cwd, fullPath);
    const qDir = path.join(cwd, config.quarantineDir || '.firewall-quarantine');
    if (!fs.existsSync(qDir)) {
      fs.mkdirSync(qDir, { recursive: true });
    }
    const timestamp = Date.now();
    const backupName = `${path.basename(relPath)}.${timestamp}.quarantine`;
    const qPath = path.join(qDir, backupName);
    fs.copyFileSync(fullPath, qPath);

    const ext = path.extname(relPath).toLowerCase();
    let stub = `"""\n[AI AGENT FIREWALL] - FILE QUARANTINED\nThreat: ${threat.title} (${threat.id})\n"""\nimport sys\nsys.exit("[AI AGENT FIREWALL] Execution aborted: Quarantined malicious file.")\n`;
    if (['.sh', '.bash', '.zsh'].includes(ext)) {
      stub = `#!/usr/bin/env bash\n# [AI AGENT FIREWALL] - FILE QUARANTINED\necho "[AI AGENT FIREWALL] Execution aborted: Quarantined malicious file."\nexit 1\n`;
    } else if (['.js', '.ts', '.mjs', '.cjs'].includes(ext)) {
      stub = `// [AI AGENT FIREWALL] - FILE QUARANTINED\nthrow new Error("[AI AGENT FIREWALL] Execution aborted: Quarantined malicious file.");\n`;
    }
    fs.writeFileSync(fullPath, stub, 'utf8');
    logEvent('QUARANTINE', `Neutralized malicious script ${relPath} pre-execution`, `Isolated to ${config.quarantineDir || '.firewall-quarantine'}/${backupName}`);
  } catch {
    // ignore quarantine errors
  }
}

function runShim() {
  const binName = process.env.FIREWALL_SHIM_BIN;
  const shimDir = process.env.FIREWALL_SHIM_DIR;
  const cwd = process.env.FIREWALL_WORKSPACE || process.cwd();
  const args = process.argv.slice(2);

  if (!binName || !shimDir) {
    process.exit(1);
  }

  const realBin = findRealBinary(binName, shimDir);
  if (!realBin) {
    console.error(`[AI Agent Firewall] Binary not found in PATH: ${binName}`);
    process.exit(127);
  }

  const hunter = new ThreatHunter();
  const config = loadConfig(cwd);

  // 1. Inspect command-line arguments (e.g. bash -c "...", python3 -c "...", rm -rf, curl, etc.)
  const fullCmdString = `${binName} ${args.join(' ')}`;

  // Check if this is an internal agent process launch
  const firstFileArg = args.find((a) => !a.startsWith('-'));
  if (!isInternalAgentBinary(firstFileArg)) {
    const cmdResult = hunter.scan(fullCmdString, `exec:${binName}`);
    if (cmdResult.verdict === 'BLOCKED') {
      const top = cmdResult.threats[0] || {
        id: 'EXEC-001',
        title: 'Unauthorized Malicious Command Execution',
        severity: 'CRITICAL',
        category: 'Rogue Command Interception',
        detail: 'Agent attempted to execute a blocked command or shell payload.',
        riskScore: cmdResult.riskScore || 100,
      };
      process.stderr.write('\x07');
      threatCard(top, `terminal:${binName}`, fullCmdString, 1);
      console.error(`  ${c.brightRed}${c.bold}🛑 [AI AGENT FIREWALL] Rogue command execution blocked before kernel dispatch.${c.reset}\n`);
      process.exit(1);
    }

    // 2. If executing a script file (e.g. python3 network_test.py, bash exploit.sh, node payload.js),
    // synchronously inspect the script file BEFORE allowing the interpreter to load it!
    if (firstFileArg) {
      const candidatePath = path.resolve(process.cwd(), firstFileArg);
      if (fs.existsSync(candidatePath) && fs.statSync(candidatePath).isFile()) {
        try {
          const content = fs.readFileSync(candidatePath, 'utf8');
          if (!content.includes('[AI AGENT FIREWALL] - FILE QUARANTINED')) {
            const fileResult = hunter.scan(content, path.relative(cwd, candidatePath));
            if (fileResult.verdict === 'BLOCKED') {
              const top = fileResult.threats[0];
              process.stderr.write('\x07');
              threatCard(top, path.relative(cwd, candidatePath), top.snippet, top.line);
              if (config.quarantineBlocked !== false) {
                quarantineFileSync(candidatePath, cwd, config, top);
              }
              console.error(`  ${c.brightRed}${c.bold}🛑 [AI AGENT FIREWALL] Blocked execution of malicious script: ${firstFileArg}${c.reset}\n`);
              process.exit(1);
            }
          }
        } catch {
          // ignore read error
        }
      }
    }
  }

  // 3. Safe to execute real binary
  const res = spawnSync(realBin, args, {
    stdio: 'inherit',
    env: process.env,
  });

  if (res.error) {
    process.exit(1);
  }
  process.exit(res.status ?? 0);
}

function setupShims(workspaceDir) {
  let shimDir = path.join(workspaceDir, '.firewall-quarantine', '.shims');
  try {
    if (!fs.existsSync(shimDir)) {
      fs.mkdirSync(shimDir, { recursive: true });
    }
  } catch {
    shimDir = path.join(os.tmpdir(), 'ai-agent-firewall-shims');
    if (!fs.existsSync(shimDir)) {
      fs.mkdirSync(shimDir, { recursive: true });
    }
  }

  const guardScript = path.resolve(__dirname, 'shim-guard.js');
  const interceptedBins = ['python3', 'python', 'bash', 'sh', 'curl', 'wget', 'nc', 'ncat', 'socat', 'rm'];

  for (const bin of interceptedBins) {
    const shimPath = path.join(shimDir, bin);
    const script = `#!/bin/sh
export FIREWALL_SHIM_BIN="${bin}"
export FIREWALL_SHIM_DIR="${shimDir}"
export FIREWALL_WORKSPACE="${workspaceDir}"
exec "${process.execPath}" "${guardScript}" "$@"
`;
    fs.writeFileSync(shimPath, script, { mode: 0o755 });
  }

  return shimDir;
}

if (require.main === module) {
  runShim();
}

module.exports = {
  setupShims,
};
