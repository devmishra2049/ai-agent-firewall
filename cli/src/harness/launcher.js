/**
 * Unified 1-Terminal Interactive Firewall & Coding Agent Launcher
 * Starts the real-time Threat Hunter watcher first, then lets the user pick
 * any famous coding agent (or [+] add a custom agent) to run inside the firewall
 * within the exact same terminal.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const readline = require('readline');
const { spawn, spawnSync } = require('child_process');
const { WorkspaceInspector } = require('../watcher/inspector');
const { ThreatHunter } = require('../threats/hunter');
const { setupShims } = require('./shim-guard');
const { saveCustomAgent, loadConfig } = require('../config/policy');
const { banner, badge, threatCard, logEvent, c } = require('../ui/terminal');

/**
 * Resolve binary path across PATH and common macOS/Linux user directories
 */
function findBinary(binName) {
  if (!binName) return null;
  if (binName === 'builtin-agent') {
    const agentPy = path.resolve(__dirname, '../../../agent.py');
    return fs.existsSync(agentPy) ? agentPy : null;
  }

  const home = os.homedir();
  const extraDirs = [
    path.join(home, '.local', 'bin'),
    path.join(home, '.hermes', 'hermes-agent', 'venv', 'bin'),
    '/opt/homebrew/bin',
    '/usr/local/bin',
    '/usr/bin',
    '/bin',
  ];
  const pathDirs = (process.env.PATH || '').split(path.delimiter);
  const allDirs = [...new Set([...extraDirs, ...pathDirs])];

  for (const dir of allDirs) {
    if (!dir) continue;
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

/**
 * Load GROQ_API_KEY from backend/.env if present so child agents get it automatically
 */
function loadWorkspaceEnvVars(cwd) {
  const extraEnv = {};
  const candidates = [
    path.join(cwd, 'backend', '.env'),
    path.join(cwd, '.env'),
    path.resolve(__dirname, '../../../backend/.env'),
  ];

  for (const envFile of candidates) {
    if (fs.existsSync(envFile)) {
      try {
        const lines = fs.readFileSync(envFile, 'utf8').split('\n');
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#') || !trimmed.includes('=')) continue;
          const [k, ...rest] = trimmed.split('=');
          const key = k.trim();
          const val = rest.join('=').trim().replace(/^['"]|['"]$/g, '');
          if (key === 'GROQ_API_KEY' && val) {
            extraEnv.GROQ_API_KEY = val;
          }
          if (key === 'OPENAI_MODEL' && val && !val.includes(':free')) {
            extraEnv.OPENAI_MODEL = val;
          }
        }
      } catch {
        // ignore
      }
    }
  }
  if (!extraEnv.OPENAI_MODEL) {
    extraEnv.OPENAI_MODEL = 'openai/gpt-oss-120b';
  }
  return extraEnv;
}

/**
 * Create a clean, high-speed Hermes profile inside .firewall-quarantine/profiles/firewall-fast
 * so Hermes uses Groq LPU (<1s latency) and avoids any corrupted ~/.hermes/state.db warning.
 */
function ensureFastHermesProfile(cwd, groqKey, groqModel = 'openai/gpt-oss-120b') {
  let profileDir = path.join(cwd, '.firewall-quarantine', 'profiles', 'firewall-fast');
  try {
    fs.mkdirSync(profileDir, { recursive: true });
  } catch {
    profileDir = path.join(os.tmpdir(), 'ai-agent-firewall-shims', 'profiles', 'firewall-fast');
    fs.mkdirSync(profileDir, { recursive: true });
  }

  const modelBlock = groqKey
    ? `model:
  default: ${groqModel}
  provider: custom:groq
  base_url: https://api.groq.com/openai/v1
  api_key: "${groqKey}"
providers:
  groq:
    name: Groq LPU
    base_url: https://api.groq.com/openai/v1
    api_key: "${groqKey}"
    key_env: GROQ_API_KEY
    default_model: ${groqModel}`
    : `model:\n  default: stepfun/step-3.7-flash:free\n  provider: nous\n  base_url: https://inference-api.nousresearch.com/v1`;

  const configYaml = `${modelBlock}
agent:
  max_turns: 50
  verbose: false
  reasoning_effort: low
terminal:
  backend: local
  cwd: .
  timeout: 60
memory:
  memory_enabled: false
  user_profile_enabled: false
onboarding:
  seen:
    tool_progress_prompt: true
    busy_input_prompt: true
    profile_build_offered: true
`;

  try {
    fs.writeFileSync(path.join(profileDir, 'config.yaml'), configYaml, 'utf8');
    if (groqKey) {
      fs.writeFileSync(
        path.join(profileDir, '.env'),
        `GROQ_API_KEY=${groqKey}\nOPENAI_API_KEY=${groqKey}\nOPENAI_MODEL=${groqModel}\n`,
        'utf8'
      );
    }
  } catch {
    // ignore
  }

  return profileDir;
}

/**
 * Famous Coding Agents Catalog
 */
function getAgentCatalog(cwd, config) {
  const agentPyPath = path.resolve(__dirname, '../../../agent.py');
  const hasAgentPy = fs.existsSync(agentPyPath);
  const hermesBin = findBinary('hermes') || 'hermes';
  const extraEnv = loadWorkspaceEnvVars(cwd);
  const groqKey = extraEnv.GROQ_API_KEY || process.env.GROQ_API_KEY || '';
  const groqModel = extraEnv.OPENAI_MODEL || 'openai/gpt-oss-120b';
  const hermesCmd = groqKey
    ? `${hermesBin} --provider custom:groq -m ${groqModel} --yolo --ignore-rules --toolsets file,terminal`
    : `${hermesBin} --yolo --ignore-rules --toolsets file,terminal`;

  const aiderBin = findBinary('aider') || 'aider';
  const builtinCatalog = [
    {
      key: '1',
      name: 'Hermes Agent (Fast Coding Mode • Groq LPU)',
      desc: 'Nous Research CLI powered by Groq LPU (<1s turns, 6 core tools, 0 skill bloat)',
      bin: 'hermes',
      cmd: hermesCmd,
      installCmd: null,
    },
    {
      key: '2',
      name: 'Fast Autonomous Agent (Built-in Red-Team & Groq CLI)',
      desc: 'Sub-second interactive coding & security test agent (agent.py)',
      bin: hasAgentPy ? 'python3' : 'builtin-agent',
      cmd: `python3 "${agentPyPath}"`,
      installCmd: null,
    },
    {
      key: '3',
      name: 'Claude Code CLI',
      desc: 'Anthropic official terminal coding agent (claude)',
      bin: 'claude',
      cmd: 'claude',
      installCmd: 'npm install -g @anthropic-ai/claude-code',
    },
    {
      key: '4',
      name: 'Aider AI Pair Programmer (Groq LPU • Fast)',
      desc: 'Famous open-source terminal coding agent powered by Groq (openai/gpt-oss-120b)',
      bin: 'aider',
      cmd: `${aiderBin} --model groq/${groqModel} --map-tokens 0 --no-git --no-auto-commits --yes-always --no-show-model-warnings --no-analytics`,
      installCmd: 'python3 -m pip install -U aider-install && aider-install',
    },
    {
      key: '5',
      name: 'OpenAI Codex CLI',
      desc: 'OpenAI lightweight terminal coding agent (codex)',
      bin: 'codex',
      cmd: 'codex',
      installCmd: 'npm install -g @openai/codex',
    },
    {
      key: '6',
      name: 'Google Gemini CLI',
      desc: 'Google Gemini terminal coding agent (gemini)',
      bin: 'gemini',
      cmd: 'gemini',
      installCmd: 'npm install -g @google/gemini-cli',
    },
    {
      key: '7',
      name: 'Cursor Agent CLI',
      desc: 'Cursor terminal agent harness (cursor)',
      bin: 'cursor',
      cmd: 'cursor',
      installCmd: null,
    },
    {
      key: '8',
      name: 'Block Goose Developer Agent',
      desc: 'Open-source autonomous developer agent (goose)',
      bin: 'goose',
      cmd: 'goose session',
      installCmd: 'brew install block-goose-cli',
    },
    {
      key: '9',
      name: 'Ollama Local Coding Agent',
      desc: '100% offline Apple Silicon coding model (qwen2.5-coder:7b)',
      bin: 'ollama',
      cmd: 'ollama run qwen2.5-coder:7b',
      installCmd: 'brew install ollama',
    },
  ];

  // Append user's saved custom agents from .firewallrc.json
  const customList = Array.isArray(config.customAgents) ? config.customAgents : [];
  customList.forEach((custom, idx) => {
    const firstWord = (custom.cmd || '').trim().split(/\s+/)[0];
    builtinCatalog.push({
      key: String(10 + idx),
      name: `${custom.name} (Custom)`,
      desc: `Command: ${custom.cmd}`,
      bin: firstWord,
      cmd: custom.cmd,
      installCmd: null,
      isCustom: true,
    });
  });

  return builtinCatalog.map((item) => ({
    ...item,
    installed: Boolean(findBinary(item.bin)),
  }));
}

function printAgentMenu(catalog) {
  console.log(`  ${c.cyan}┌──────────────────────────────────────────────────────────────────────────────┐${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}  🛡️  ${c.bold}${c.brightWhite}SELECT A CODING AGENT TO RUN INSIDE THE FIREWALL (1-TERMINAL MODE)${c.reset}     ${c.cyan}│${c.reset}`);
  console.log(`  ${c.cyan}├──────────────────────────────────────────────────────────────────────────────┤${c.reset}`);

  for (const item of catalog) {
    const keyBadge = `${c.bold}${c.cyan}[${item.key}]${c.reset}`;
    const statusBadge = item.installed
      ? `${c.green}${c.bold}● READY${c.reset}`
      : `${c.gray}○ INSTALL${c.reset}`;
    const nameStr = item.installed
      ? `${c.bold}${c.brightWhite}${item.name}${c.reset}`
      : `${c.white}${item.name}${c.reset}`;

    console.log(`  ${c.cyan}│${c.reset}  ${keyBadge} ${nameStr}  ${statusBadge}`);
    console.log(`  ${c.cyan}│${c.reset}      ${c.dim}${item.desc}${c.reset}`);
  }

  console.log(`  ${c.cyan}├──────────────────────────────────────────────────────────────────────────────┤${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}  ${c.bold}${c.brightGreen}[+]${c.reset} ➕ ${c.bold}${c.brightGreen}Add & Launch Custom Coding Agent...${c.reset}                                  ${c.cyan}│${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}  ${c.bold}${c.yellow}[0]${c.reset} 👁️  ${c.bold}${c.yellow}Watcher-Only Mode${c.reset} ${c.dim}(Stay in passive filesystem monitoring)${c.reset}           ${c.cyan}│${c.reset}`);
  console.log(`  ${c.cyan}│${c.reset}  ${c.bold}${c.red}[q]${c.reset} ✖  ${c.dim}Stop Firewall & Exit${c.reset}                                                ${c.cyan}│${c.reset}`);
  console.log(`  ${c.cyan}└──────────────────────────────────────────────────────────────────────────────┘${c.reset}`);
}

function askQuestion(rl, query) {
  return new Promise((resolve) => {
    rl.question(query, (ans) => resolve(ans.trim()));
  });
}

/**
 * Spawn the chosen agent inside the active firewall watcher & subprocess shim perimeter
 */
function spawnAgentInFirewall(agentItem, inspector, targetDir, config, onAgentExit) {
  const hunter = new ThreatHunter();

  // 1. Preflight check on the launch command itself
  const cmdCheck = hunter.scan(agentItem.cmd, 'agent-launch');
  if (cmdCheck.verdict === 'BLOCKED') {
    if (inspector && inspector.stats) {
      inspector.stats.threatsBlocked++;
    }
    const threat = cmdCheck.threats[0] || {};
    threatCard(threat, 'terminal:launch', agentItem.cmd, 1);
    console.error(`  ${c.brightRed}${c.bold}Launch Blocked by AI Agent Firewall.${c.reset}\n`);
    if (onAgentExit) onAgentExit(1);
    return;
  }

  // 2. Setup synchronous subprocess & script shims in PATH
  const shimDir = setupShims(targetDir);
  const extraEnv = loadWorkspaceEnvVars(targetDir);
  const groqKey = extraEnv.GROQ_API_KEY || process.env.GROQ_API_KEY || '';
  const groqModel = extraEnv.OPENAI_MODEL || 'openai/gpt-oss-120b';
  if (agentItem.bin === 'hermes' || agentItem.cmd.includes('hermes')) {
    extraEnv.HERMES_HOME = ensureFastHermesProfile(targetDir, groqKey, groqModel);
  }
  const homeBin = path.join(os.homedir(), '.local', 'bin');
  const currentPath = process.env.PATH || '';
  const sandboxedPath = [shimDir, homeBin, '/opt/homebrew/bin', currentPath].join(path.delimiter);

  console.log(`\n  ${c.green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c.reset}`);
  console.log(`  ${badge('FIREWALL PERIMETER ACTIVE', 'green')} Launching ${c.bold}${c.brightWhite}${agentItem.name}${c.reset}`);
  console.log(`  ${c.gray}• Command:${c.reset}            ${c.cyan}$ ${agentItem.cmd}${c.reset}`);
  console.log(`  ${c.gray}• File AST Watcher:${c.reset}   ${c.green}ARMED (Auto-Quarantine to .firewall-quarantine/)${c.reset}`);
  console.log(`  ${c.gray}• Command Shim Guard:${c.reset} ${c.green}ARMED (Intercepting rogue bash/python/curl/rm calls)${c.reset}`);
  console.log(`  ${c.green}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c.reset}\n`);

  // Smart fallback: if command starts with 'python ', use 'python3 ' if 'python' isn't on system
  let execCmd = agentItem.cmd;
  if (/^python(\s|$)/.test(execCmd) && !findBinary('python')) {
    execCmd = execCmd.replace(/^python(\s|$)/, 'python3$1');
  }

  const child = spawn(execCmd, {
    cwd: targetDir,
    shell: true,
    stdio: 'inherit',
    env: {
      ...process.env,
      ...extraEnv,
      PATH: sandboxedPath,
      AI_AGENT_FIREWALL: '1',
      FIREWALL_MODE: config.mode || 'enforce',
      FIREWALL_WORKSPACE: targetDir,
    },
  });

  // Ignore SIGINT in parent while child agent is running so Ctrl+C goes to the child agent
  const sigintHandler = () => {
    // Child receives SIGINT directly from terminal process group
  };
  process.on('SIGINT', sigintHandler);

  child.on('error', (err) => {
    process.removeListener('SIGINT', sigintHandler);
    console.error(`\n  ${c.red}Failed to start agent:${c.reset} ${err.message}`);
    if (onAgentExit) onAgentExit(1);
  });

  child.on('close', (code) => {
    process.removeListener('SIGINT', sigintHandler);
    console.log(`\n  ${c.cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c.reset}`);
    console.log(`  ${badge('AGENT EXITED', 'cyan')} ${c.bold}${agentItem.name}${c.reset} finished (exit code ${code ?? 0}).`);
    console.log(`  ${c.cyan}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${c.reset}`);
    if (onAgentExit) onAgentExit(code ?? 0);
  });
}

/**
 * Main Unified 1-Terminal Interactive Session
 */
async function startInteractiveFirewall(targetDir = process.cwd(), initialConfig = {}) {
  banner();

  let config = loadConfig(targetDir);
  config = { ...config, ...initialConfig };

  // 1. Start the real-time Firewall Watcher FIRST in embedded mode
  const inspector = new WorkspaceInspector({
    cwd: targetDir,
    config,
  });
  inspector.start({ embedded: true });

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  async function promptMenuLoop() {
    config = loadConfig(targetDir);
    const catalog = getAgentCatalog(targetDir, config);
    printAgentMenu(catalog);

    const choice = await askQuestion(
      rl,
      `\n  ${c.bold}${c.brightCyan}❯ Which coding agent do you want to run inside the firewall? [1-${catalog.length}, +, 0, q]: ${c.reset}`
    );

    if (!choice || choice.toLowerCase() === 'q' || choice.toLowerCase() === 'exit') {
      rl.close();
      inspector.stop();
      process.exit(0);
    }

    // Option 0: Watcher-only passive mode
    if (choice === '0' || choice.toLowerCase() === 'watch') {
      rl.close();
      console.log(`\n  ${badge('WATCHER-ONLY MODE', 'yellow')} Passively monitoring ${c.bold}${targetDir}${c.reset} for malicious agent writes...`);
      console.log(`  ${c.dim}Press Ctrl+C at any time to view summary and exit.${c.reset}\n`);
      process.on('SIGINT', () => {
        inspector.stop();
        process.exit(0);
      });
      return;
    }

    // Option [+]: Add & Launch any custom coding agent
    if (choice === '+' || choice.toLowerCase() === 'add' || choice.toLowerCase() === 'plus') {
      console.log(`\n  ${badge('ADD CUSTOM AGENT', 'green')} ${c.bold}Configure a custom coding agent to run inside the firewall:${c.reset}`);
      const customName = await askQuestion(rl, `  ${c.cyan}❯ Enter Agent Name (e.g. "Windsurf", "My Custom Bot"): ${c.reset}`);
      const customCmd = await askQuestion(rl, `  ${c.cyan}❯ Enter Launch Command (e.g. "hermes --cli" or "python3 my_agent.py"): ${c.reset}`);

      if (!customCmd) {
        console.log(`  ${c.yellow}⚠️  No command entered. Returning to menu...${c.reset}\n`);
        return promptMenuLoop();
      }

      const nameToSave = customName || customCmd.split(/\s+/)[0];
      const checkHunter = new ThreatHunter();
      const preCheck = checkHunter.scan(customCmd, 'custom-agent-config');
      if (preCheck.verdict !== 'BLOCKED') {
        saveCustomAgent({ name: nameToSave, cmd: customCmd }, targetDir);
        console.log(`  ${c.green}✔ Saved "${nameToSave}" to .firewallrc.json for future sessions!${c.reset}`);
      }

      const customItem = {
        key: '+',
        name: nameToSave,
        desc: `Custom command: ${customCmd}`,
        bin: customCmd.split(/\s+/)[0],
        cmd: customCmd,
        installed: true,
      };

      rl.pause();
      rl.close();
      spawnAgentInFirewall(customItem, inspector, targetDir, config, () => {
        inspector.stop();
        process.exit(0);
      });
      return;
    }

    // Match numbered option from catalog
    const selected = catalog.find((item) => item.key === choice);
    if (!selected) {
      // Also allow typing the command or agent name directly!
      const byName = catalog.find(
        (item) =>
          item.bin.toLowerCase() === choice.toLowerCase() ||
          item.name.toLowerCase().includes(choice.toLowerCase())
      );

      if (!byName) {
        console.log(`  ${c.yellow}⚠️  Invalid selection "${choice}". Please enter a number from 1-${catalog.length}, '+', or '0'.${c.reset}\n`);
        return promptMenuLoop();
      }
      return handleSelectedAgent(byName);
    }

    return handleSelectedAgent(selected);
  }

  async function handleSelectedAgent(selected) {
    if (!selected.installed && selected.installCmd) {
      console.log(`\n  ${c.yellow}⚠️  "${selected.name}" (${selected.bin}) is not installed on your system yet.${c.reset}`);
      console.log(`  ${c.dim}Install command: $ ${selected.installCmd}${c.reset}`);
      const installAns = await askQuestion(
        rl,
        `  ${c.bold}${c.cyan}❯ Would you like to install it automatically right now? [Y/n]: ${c.reset}`
      );

      if (!installAns || installAns.toLowerCase().startsWith('y')) {
        console.log(`\n  ${badge('INSTALLING', 'cyan')} Running: ${c.bold}${selected.installCmd}${c.reset}...\n`);
        const installRes = spawnSync(selected.installCmd, {
          shell: true,
          stdio: 'inherit',
        });
        if (installRes.status !== 0) {
          console.log(`\n  ${c.red}✖ Installation failed. Please pick another agent or install manually.${c.reset}\n`);
          return promptMenuLoop();
        }
        console.log(`\n  ${c.green}✔ Successfully installed ${selected.name}! Launching inside firewall...${c.reset}`);
      } else {
        return promptMenuLoop();
      }
    }

    rl.pause();
    rl.close();
    spawnAgentInFirewall(selected, inspector, targetDir, config, () => {
      inspector.stop();
      process.exit(0);
    });
  }

  await promptMenuLoop();
}

module.exports = {
  startInteractiveFirewall,
  spawnAgentInFirewall,
  getAgentCatalog,
};
