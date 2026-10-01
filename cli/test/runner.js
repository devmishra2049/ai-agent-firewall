#!/usr/bin/env node
/**
 * AI Agent Firewall Test Runner
 * Built on Node.js native test runner (node:test). Zero external npm dependencies.
 *
 * Usage:
 *   node test/runner.js                  # Run all test tiers
 *   node test/runner.js --tier=1         # Run Tier 1 only (Dynamic Catch)
 *   node test/runner.js --tier=2         # Run Tier 2 only (Benign Precision)
 *   node test/runner.js --tier=3         # Run Tier 3 only (Immune Memory)
 *   node test/runner.js --tier=4         # Run Tier 4 only (Terminal Integration)
 *   node test/runner.js --list           # List available test suites
 */

const path = require('node:path');
const { spawnSync } = require('node:child_process');

const TIERS = [
  {
    id: 1,
    file: 'tier1_pure_dynamic_catch.test.js',
    name: 'Tier 1: Pure Dynamic Zero-Word Catch',
    description: 'Dynamic secret/boundary profiling, AST constant folding, micro-detonation trap, causal canary dye leaks, dynamic reverse shells',
  },
  {
    id: 2,
    file: 'tier2_benign_precision.test.js',
    name: 'Tier 2: Benign Code Precision & Zero False-Positive Benchmark',
    description: 'Fibonacci, sorting algorithms, prime checkers, math expressions, standard workspace file I/O (verdict ALLOW, Risk < 50)',
  },
  {
    id: 3,
    file: 'tier3_immune_memory.test.js',
    name: 'Tier 3: Online Self-Learning Behavioral Brain & Immune Memory',
    description: 'Structural AST skeleton normalization, Markov surprise scoring, .firewall-quarantine/brain-state.json persistence, mutated variant blocking <5ms',
  },
  {
    id: 4,
    file: 'tier4_terminal_integration.test.js',
    name: 'Tier 4: 1-Terminal Integration & Live Quarantine End-to-End',
    description: 'CLI commands (status, test, scan), live WorkspaceInspector file watching, quarantine vault, terminal telemetry formatting',
  },
];

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
};

function printBanner() {
  console.log(`\n${c.cyan}${c.bold}╔═══════════════════════════════════════════════════════════════════╗`);
  console.log(`║           AI AGENT FIREWALL — E2E TEST RUNNER HARNESS             ║`);
  console.log(`║         Pure Dynamic Behavioral & Immune Verification Suite       ║`);
  console.log(`╚═══════════════════════════════════════════════════════════════════╝${c.reset}\n`);
}

function printList() {
  printBanner();
  console.log(`${c.bold}Available Test Tiers:${c.reset}\n`);
  for (const t of TIERS) {
    console.log(`  ${c.magenta}${c.bold}[Tier ${t.id}]${c.reset} ${c.bold}${t.name}${c.reset}`);
    console.log(`    ${c.dim}File:${c.reset} test/${t.file}`);
    console.log(`    ${c.dim}Scope:${c.reset} ${t.description}\n`);
  }
}

function parseArgs() {
  const args = process.argv.slice(2);
  let selectedTiers = [];
  let isList = false;
  let isWatch = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--list' || arg === '-l') {
      isList = true;
    } else if (arg === '--watch' || arg === '-w') {
      isWatch = true;
    } else if (arg.startsWith('--tier=')) {
      const val = parseInt(arg.split('=')[1], 10);
      if (!isNaN(val)) selectedTiers.push(val);
    } else if (arg === '-t' || arg === '--tier') {
      const val = parseInt(args[++i], 10);
      if (!isNaN(val)) selectedTiers.push(val);
    } else if (/^tier[1-4]$/i.test(arg)) {
      selectedTiers.push(parseInt(arg.replace(/tier/i, ''), 10));
    } else if (/^[1-4]$/.test(arg)) {
      selectedTiers.push(parseInt(arg, 10));
    } else if (arg === '--all' || arg === 'all') {
      selectedTiers = [1, 2, 3, 4];
    }
  }

  if (selectedTiers.length === 0) {
    selectedTiers = [1, 2, 3, 4];
  }

  return { selectedTiers: [...new Set(selectedTiers)], isList, isWatch };
}

function run() {
  const { selectedTiers, isList, isWatch } = parseArgs();

  if (isList) {
    printList();
    process.exit(0);
  }

  printBanner();

  const testDir = __dirname;
  const filesToRun = [];

  console.log(`${c.bold}Selected Test Plan:${c.reset}`);
  for (const tierId of selectedTiers) {
    const tier = TIERS.find((t) => t.id === tierId);
    if (tier) {
      console.log(`  • ${c.cyan}${c.bold}Tier ${tier.id}:${c.reset} ${tier.name}`);
      filesToRun.push(path.join(testDir, tier.file));
    }
  }
  console.log();

  if (filesToRun.length === 0) {
    console.error(`${c.red}No valid test tiers selected.${c.reset}`);
    process.exit(1);
  }

  const nodeArgs = ['--test'];
  if (isWatch) {
    nodeArgs.push('--watch');
  }
  nodeArgs.push(...filesToRun);

  const startTime = Date.now();
  const result = spawnSync(process.execPath, nodeArgs, {
    stdio: 'inherit',
    cwd: path.resolve(__dirname, '..'),
    env: { ...process.env, FORCE_COLOR: '1' },
  });

  const durationMs = Date.now() - startTime;
  console.log(`\n${c.dim}───────────────────────────────────────────────────────────────────${c.reset}`);
  console.log(`  ${c.bold}Test Execution Completed in ${(durationMs / 1000).toFixed(2)}s${c.reset}`);

  if (result.status === 0) {
    console.log(`  ${c.green}${c.bold}✔ ALL TEST TIERS PASSED${c.reset}\n`);
  } else {
    console.log(`  ${c.red}${c.bold}✖ TEST SUITE REPORTED FAILURES (Exit code: ${result.status})${c.reset}\n`);
  }

  process.exit(result.status || 0);
}

run();
