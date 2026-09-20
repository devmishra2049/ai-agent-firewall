/**
 * Terminal UI & High-Tech ANSI Styling for AI Agent Firewall
 */

const ESC = '\x1b[';

const c = {
  reset: `${ESC}0m`,
  bold: `${ESC}1m`,
  dim: `${ESC}2m`,
  italic: `${ESC}3m`,
  underline: `${ESC}4m`,
  
  // Foreground Colors
  black: `${ESC}30m`,
  red: `${ESC}31m`,
  green: `${ESC}32m`,
  yellow: `${ESC}33m`,
  blue: `${ESC}34m`,
  magenta: `${ESC}35m`,
  cyan: `${ESC}36m`,
  white: `${ESC}37m`,
  gray: `${ESC}90m`,
  
  // Bright colors
  brightRed: `${ESC}91m`,
  brightGreen: `${ESC}92m`,
  brightYellow: `${ESC}93m`,
  brightBlue: `${ESC}94m`,
  brightMagenta: `${ESC}95m`,
  brightCyan: `${ESC}96m`,
  brightWhite: `${ESC}97m`,
  
  // Backgrounds
  bgRed: `${ESC}41m`,
  bgGreen: `${ESC}42m`,
  bgYellow: `${ESC}43m`,
  bgBlue: `${ESC}44m`,
  bgMagenta: `${ESC}45m`,
  bgCyan: `${ESC}46m`,
};

function banner() {
  console.log(`
${c.cyan}${c.bold}   █████╗ ██╗   ${c.brightMagenta}███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗     
  ${c.cyan}██╔══██╗██║   ${c.brightMagenta}██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║     
  ${c.cyan}███████║██║   ${c.brightMagenta}█████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║     
  ${c.cyan}██╔══██║██║   ${c.brightMagenta}██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║     
  ${c.cyan}██║  ██║██║   ${c.brightMagenta}██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗
  ${c.reset}
  ${c.bold}  ┌─────────────────────────────────────────────────────────────┐
    │  ${c.brightWhite}$ ${c.green}aaf watch${c.reset}${c.bold}                                            │
    └─────────────────────────────────────────────────────────────┘${c.reset}
  ${c.gray}  ★ star: ${c.dim}github.com/devmishra2049/ai-agent-firewall${c.gray} →${c.reset}

  ${c.cyan}⚡ [PREFLIGHT]${c.reset} ${c.dim}Zero-Trust Sandbox Perimeter Armed${c.reset}
  ${c.magenta}🔒 [SIGNATURES]${c.reset} ${c.dim}39 Real-Time Zero-Latency Threat Rules Loaded${c.reset}
  ${c.green}🛡️  [HARNESSES]${c.reset} ${c.dim}Claude Code • Cursor • Codex • Aider • Copilot${c.reset}
`);
}

function badge(text, color = 'cyan', bg = false) {
  const fgCode = c[color] || c.cyan;
  if (bg) {
    return `${c.bold}${c.white}${c.bgRed} ${text} ${c.reset}`;
  }
  return `${fgCode}${c.bold}[${text}]${c.reset}`;
}

function statusLine(mode, target, policy = 'ZERO-TRUST ENFORCING') {
  console.log(`  ${badge('STATUS', 'green')} ${c.bold}Active${c.reset}  │  ${badge('POLICY', 'magenta')} ${c.bold}${policy}${c.reset}  │  ${badge('TARGET', 'blue')} ${c.dim}${target}${c.reset}`);
  console.log(`  ${c.gray}Watching agent file generation and tool calls... Press Ctrl+C to stop.${c.reset}\n`);
}

function logEvent(type, message, detail = '') {
  const timestamp = new Date().toLocaleTimeString();
  let prefix = '';
  switch (type) {
    case 'ALLOW':
      prefix = `${c.green}${c.bold} ↳ [ALLOW]${c.reset}`;
      break;
    case 'BLOCKED':
      prefix = `${c.brightRed}${c.bold} ↳ [BLOCKED]${c.reset}`;
      break;
    case 'WARNING':
      prefix = `${c.yellow}${c.bold} ↳ [WARNING]${c.reset}`;
      break;
    case 'QUARANTINE':
      prefix = `${c.magenta}${c.bold} ↳ [QUARANTINED]${c.reset}`;
      break;
    case 'LOOP':
      prefix = `${c.brightMagenta}${c.bold} ↳ [LOOP DETECTED]${c.reset}`;
      break;
    case 'DRIFT':
      prefix = `${c.blue}${c.bold} ↳ [DRIFT]${c.reset}`;
      break;
    default:
      prefix = `${c.cyan}${c.bold} ↳ [${type}]${c.reset}`;
  }
  console.log(`${prefix} ${c.white}${message}${c.reset} ${c.gray}(${timestamp})${c.reset}`);
  if (detail) {
    console.log(`     ${c.dim}${detail}${c.reset}`);
  }
}

function threatCard(threat, file, snippet = '', lineNum = null) {
  const border = c.brightRed + '─'.repeat(74) + c.reset;
  const score = threat.riskScore || 100;
  console.log(`\n  ${border}`);
  console.log(`  ${c.bgRed}${c.white}${c.bold} 🚨 MALICIOUS AGENT CODE DETECTED ${c.reset}  ${c.bold}${threat.title}${c.reset} (${c.brightRed}Severity: ${threat.severity}${c.reset})`);
  console.log(`  ${c.gray}Target:${c.reset} ${c.yellow}${file}${lineNum ? `:${lineNum}` : ''}${c.reset}`);
  console.log(`  ${c.gray}Risk Score:${c.reset} ${c.brightRed}${c.bold}${score}/100${c.reset} ${c.dim}(Threshold: ≥80 Blocks & Quarantines)${c.reset}`);
  console.log(`  ${c.gray}Attack Category:${c.reset} ${c.white}${threat.category}${c.reset}`);
  console.log(`  ${c.gray}Rule Triggered:${c.reset} ${c.dim}${threat.detail}${c.reset}`);
  
  if (snippet) {
    console.log(`\n  ${c.gray}Offending Code:${c.reset}`);
    const lines = snippet.trim().split('\n').slice(0, 5);
    lines.forEach((l, idx) => {
      const num = lineNum ? lineNum + idx : idx + 1;
      console.log(`  ${c.red}${String(num).padStart(4, ' ')} │ ${c.brightWhite}${l}${c.reset}`);
    });
  }
  
  console.log(`\n  ${c.green}${c.bold}🛡️  Action Taken:${c.reset} ${c.bold}${threat.action || 'Execution Blocked & Quarantined'}${c.reset}`);
  console.log(`  ${border}\n`);
}

function summaryBox(stats) {
  console.log(`
  ${c.cyan}┌───────────────────────── INSPECTION SUMMARY ─────────────────────────┐${c.reset}
  ${c.cyan}│${c.reset} Total Files Inspected:   ${c.bold}${String(stats.filesInspected).padEnd(46, ' ')}${c.cyan}│${c.reset}
  ${c.cyan}│${c.reset} Safe Agent Operations:   ${c.green}${c.bold}${String(stats.allowed).padEnd(46, ' ')}${c.cyan}│${c.reset}
  ${c.cyan}│${c.reset} Threats Intercepted:     ${stats.threatsBlocked > 0 ? c.brightRed : c.white}${c.bold}${String(stats.threatsBlocked).padEnd(46, ' ')}${c.cyan}│${c.reset}
  ${c.cyan}│${c.reset} Repetitive Loops Caught: ${c.yellow}${c.bold}${String(stats.loopsCaught || 0).padEnd(46, ' ')}${c.cyan}│${c.reset}
  ${c.cyan}│${c.reset} Threat Hunter Posture:   ${c.green}${c.bold}${'100% OPERATIONAL (ZERO-LATENCY)'.padEnd(46, ' ')}${c.cyan}│${c.reset}
  ${c.cyan}└──────────────────────────────────────────────────────────────────────┘${c.reset}
`);
}

module.exports = {
  c,
  banner,
  badge,
  statusLine,
  logEvent,
  threatCard,
  summaryBox,
};
