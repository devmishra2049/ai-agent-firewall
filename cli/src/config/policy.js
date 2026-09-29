/**
 * Policy & Configuration Manager for AI Agent Firewall
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_CONFIG = {
  version: '1.0.0',
  mode: 'enforce', // 'enforce' (block) or 'observe' (log-only)
  blockOnRiskScore: 80,
  quarantineBlocked: true,
  quarantineDir: '.firewall-quarantine',
  soundAlerts: false,
  ignoredPaths: [
    'node_modules/**',
    '.git/**',
    'target/**',
    'dist/**',
    'build/**',
    '.venv/**',
    '__pycache__/**',
    '.firewall-quarantine/**',
  ],
  protectedPaths: [
    '.env',
    '.env.*',
    '**/.ssh/**',
    '**/id_rsa*',
    'package.json',
    'Cargo.toml',
  ],
  cloudSync: {
    enabled: false,
    backendUrl: 'https://ai-agent-firewall.onrender.com',
  },
  customAgents: [],
};

function loadConfig(cwd = process.cwd()) {
  const configPath = path.join(cwd, '.firewallrc.json');
  if (fs.existsSync(configPath)) {
    try {
      const userConfig = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      return { ...DEFAULT_CONFIG, ...userConfig };
    } catch (err) {
      console.warn(`[firewall] Warning: Could not parse .firewallrc.json, using defaults.`);
    }
  }
  return DEFAULT_CONFIG;
}

function saveCustomAgent(agentObj, cwd = process.cwd()) {
  const configPath = path.join(cwd, '.firewallrc.json');
  const current = loadConfig(cwd);
  const customAgents = Array.isArray(current.customAgents) ? [...current.customAgents] : [];
  customAgents.push(agentObj);
  const updated = { ...current, customAgents };
  try {
    fs.writeFileSync(configPath, JSON.stringify(updated, null, 2), 'utf8');
  } catch {
    // Ignore write errors in read-only dirs
  }
  return updated;
}

function initConfigFile(cwd = process.cwd()) {
  const targetPath = path.join(cwd, '.firewallrc.json');
  if (fs.existsSync(targetPath)) {
    return { created: false, path: targetPath, message: 'Configuration file already exists.' };
  }

  fs.writeFileSync(targetPath, JSON.stringify(DEFAULT_CONFIG, null, 2), 'utf8');
  return { created: true, path: targetPath, message: 'Created default .firewallrc.json policy config.' };
}

module.exports = {
  DEFAULT_CONFIG,
  loadConfig,
  saveCustomAgent,
  initConfigFile,
};
