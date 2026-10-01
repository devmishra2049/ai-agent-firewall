# AI Agent Firewall — End-to-End Test Infrastructure

## Overview
The AI Agent Firewall test infrastructure is an opaque-box, multi-tier automated test harness designed to rigorously evaluate the **100% Pure Dynamic, Self-Learning Behavioral Intelligence Firewall**. 

### Core Architectural Principles
1. **Zero External NPM Dependencies**: Built entirely upon Node.js native test modules (`node:test`, `node:assert`, `node:child_process`, `node:fs`, `node:path`). Requires zero third-party testing libraries (no Jest, Mocha, or Chai npm packages required).
2. **Pure Dynamic Behavioral Verification**: Specifically validates that 100% of threat verdicts are driven by intrinsic OS properties, Shannon entropy, AST structural dataflow, micro-detonation causal taint tracking, and online immune memory—not static keyword or regex matching.
3. **Zero False-Positive Precision**: Enforces strict mathematical thresholds ensuring that standard coding tasks (Fibonacci, sorting, prime math, matrix calculations, standard workspace file I/O) receive `ALLOW` verdicts with `riskScore < 50` and are never quarantined.
4. **Sub-5ms Mutated Variant Blocking**: Verifies that once an attack structural skeleton is learned into `.firewall-quarantine/brain-state.json`, subsequent mutated variants (with renamed identifiers, rearranged expressions, altered comments) are intercepted in `<5ms`.

---

## The 4-Tier Test Architecture

The test suite is organized into four progressive tiers located in `cli/test/`:

```
cli/test/
├── runner.js                           # Native CLI test harness and tier selector
├── tier1_pure_dynamic_catch.test.js    # Tier 1: Pure Dynamic Zero-Word Threat Catching
├── tier2_benign_precision.test.js      # Tier 2: Benign Code Precision & Zero-False-Positive Benchmark
├── tier3_immune_memory.test.js         # Tier 3: Online Self-Learning Behavioral Brain & Immune Memory
└── tier4_terminal_integration.test.js  # Tier 4: 1-Terminal Integration & Live Quarantine End-to-End
```

### Tier 1: Pure Dynamic Zero-Word Catch (`tier1_pure_dynamic_catch.test.js`)
- **Scope**: Features F1, F2, F3, F4, F5, F6, F7, F14, F16
- **Test Modules**:
  - **Dynamic Inode Profiler (`InodeProfiler`)**: Profiles Shannon entropy ($H \ge 4.2$ token, $H \ge 5.0$ file), key-value density ($\rho_{kv} \ge 0.50$), POSIX mode (`0600`/`0400`), and path boundary traversal outside workspace root with zero hardcoded filenames.
  - **AST Constant Folding & Dataflow Unwrapping (`AstAnalyzer`)**: Unwraps Python `reversed()`, character arithmetic `chr()`, dynamic `getattr()`, and JavaScript `String.fromCharCode()` / bracket access.
  - **Mirage Chamber Micro-Detonation (`MirageChamber`)**: Validates 30–50ms isolated dry-run execution trapping network egress, child process spawning, socket file-descriptor redirection (`dup2`), and radioactive canary dye token leakage from secret inodes to sinks.
  - **Zero-Word Attacks**: Evaluates Python and JS payloads stealing high-entropy secret files and launching dynamic reverse shells without containing strings `".env"`, `".ssh"`, `"eval"`, `"exec"`, or `"dup2"`. Verifies verdict `BLOCKED` with `riskScore >= 80`.
  - **Static Regex Deprecation**: Verifies that benign scripts with substrings like `"eval"` in variable names or comments are not falsely flagged.

### Tier 2: Benign Code Precision Benchmark (`tier2_benign_precision.test.js`)
- **Scope**: Feature F17
- **Test Modules**:
  - **Algorithmic Benchmarks**: Recursive, iterative, and memoized/DP Fibonacci implementations in Python and JS.
  - **Sorting Algorithms**: QuickSort, MergeSort, HeapSort implementations.
  - **Prime Checkers & Math Utilities**: Sieve of Eratosthenes, primality checkers, quadratic solvers, matrix multiplication.
  - **Standard Workspace File I/O**: Python scripts parsing JSON metrics and writing summary files; Node.js CSV parsers.
  - **Zero Quarantine Verification**: Confirms that running `WorkspaceInspector` on benign code never modifies the source code, never injects quarantine stub banners, and leaves quarantine vaults clean.
  - **Verdict Guarantee**: All benign benchmarks must receive `ALLOW` with `riskScore < 50`.

### Tier 3: Online Self-Learning Behavioral Brain & Immune Memory (`tier3_immune_memory.test.js`)
- **Scope**: Features F8, F9, F10, F11, F18
- **Test Modules**:
  - **Normalized Structural AST Skeletons (`BehavioralBrain.getSkeleton`)**: Strips identifiers, variable names, function names, and literals to generate invariant structural skeleton hashes. Identical structures with renamed variables yield identical hashes.
  - **Persistent Immune Memory**: Verifies that calling `learnThreat` persists structural skeleton hashes, Markov transition matrices, and adaptive feature weights into `.firewall-quarantine/brain-state.json`.
  - **10-Dimensional Behavioral Vector**: Validates computation and normalization ($[0.0, 1.0]$) across:
    `[entropy, ast_depth, dyn_ratio, boundary, secret_inode, net_egress, proc_spawn, fd_redirect, canary_leak, markov_surprise]`.
  - **Markov Transition Surprise Scorer**: Evaluates transition probability matrix surprise scores, verifying high surprise ($>0.80$) for anomalous sequences (`secret_read` $\rightarrow$ `dup2` $\rightarrow$ `socket_connect`).
  - **Rapid Mutated Variant Blocking**: Evaluates mutated attack variants against learned immune memory, asserting `matchedImmune === true`, `riskScore >= 80`, and `duration < 5ms`.
  - **Benign Precision Retention**: Verifies that learning 10+ attack skeletons causes 0% false positives on benign code.
  - **Resilience**: Verifies graceful auto-recovery when `brain-state.json` is missing or corrupted.

### Tier 4: 1-Terminal Integration & Live Quarantine End-to-End (`tier4_terminal_integration.test.js`)
- **Scope**: Features F15, F19
- **Test Modules**:
  - **CLI Command Suite**:
    - `agent-firewall --version` / `-v`: returns exit 0, outputs version.
    - `agent-firewall --help` / `-h`: returns exit 0, outputs USAGE guide and command list.
    - `agent-firewall status`: returns exit 0, outputs firewall system status, engine version, enforcement mode.
    - `agent-firewall test "<prompt>" "<code>"`: evaluates benign code (ALLOW) and malicious code (BLOCKED).
    - `agent-firewall scan <path>`: scans directories, exiting 0 on clean folders and 1 on detected threats.
  - **Live Workspace Watching & Quarantine Vault**:
    - Tests `WorkspaceInspector` intercepting malicious file writes.
    - Asserts that original malicious content is securely moved to `.firewall-quarantine/<file>.<timestamp>.quarantine`.
    - Asserts that the active workspace file is replaced with the neutralizing firewall quarantine banner.
  - **Terminal Telemetry & UI Safety**: Validates ANSI escape formatting and rendering safety for threat cards, summary boxes, badges, and status lines.

---

## Feature Inventory Coverage Matrix

| Feature ID | Feature Name | Primary Milestone | Test Tier | Specific Test Function / Suite |
|:-----------|:-------------|:------------------|:----------|:-------------------------------|
| **F1** | Shannon Entropy Profiler | M1 | Tier 1 | `F1: Profiles high-entropy secret tokens (H >= 4.2)` |
| **F2** | Key-Value Density Analyzer | M1 | Tier 1 | `F2: Detects key-value density (rho_kv >= 0.50)` |
| **F3** | OS Metadata & Permission Inspector | M1 | Tier 1 | `F3: Profiles POSIX private permission modes (0600 / 0400)` |
| **F4** | Path Topology & Boundary Profiler | M1 | Tier 1 | `F4: Detects boundary violations for traversals outside workspace root` |
| **F5** | AST Constant Folding & Dataflow Unwrapping | M2 | Tier 1 | `F5: Resolves Python string reversals...`, `F5: Resolves JS String.fromCharCode...` |
| **F6** | Isolated Micro-Detonation Trap (Mirage Chamber) | M2 | Tier 1 | `F6: Intercepts network egress and process spawns in dry-run trap` |
| **F7** | Radioactive Canary Dye Causal Taint Tracking | M2 | Tier 1 | `F7: Radioactive Canary Dye proves causal exfiltration...` |
| **F8** | 10-D Behavioral Feature Vector Engine | M3 | Tier 3 | `F8: Computes normalized 10-dimensional behavioral feature vector` |
| **F9** | Syscall Markov Surprise Scorer | M3 | Tier 3 | `F9: Calculates high Markov transition surprise score (>0.80)...` |
| **F10** | Normalized Structural AST Skeleton Extractor | M3 | Tier 3 | `F10: Normalized Structural AST Skeleton Invariance` |
| **F11** | Persistent Immune Memory & Mutation Matcher | M3 | Tier 3 | `F11: Persistent Immune Memory & Brain State Schema` |
| **F12** | Python In-Process Audit Guard | M4 | Tier 1 & 4 | Micro-detonation and runtime trap execution |
| **F13** | Node.js In-Process Runtime Guard | M4 | Tier 1 & 4 | Preload interception and network egress trapping |
| **F14** | Static Regex Deprecation in ThreatHunter | M4 | Tier 1 | `F14: Static regex rule lists in rules.js are NOT authoritative source` |
| **F15** | 1-Terminal Integration & Telemetry | M4 | Tier 4 | `CLI Command Invocations`, `Terminal Telemetry & UI Safety` |
| **F16** | Pure Dynamic Zero-Word Catch | M5 | Tier 1 | `F16: Blocks zero-word Python exfil...`, `F16: Blocks zero-word JS exfil...` |
| **F17** | Benign Code Precision (Zero False-Positives) | M5 | Tier 2 | All 9 tests in `tier2_benign_precision.test.js` |
| **F18** | Self-Learning Mutated Variant Rapid Blocking | M5 | Tier 3 | `F18: Mutated Variant Rapid Blocking (<5ms)` |
| **F19** | Seamless 1-Terminal Operation | M5 | Tier 4 | Live `WorkspaceInspector` quarantine and CLI execution |

---

## Test Execution Guide

### 1. Run Complete Test Suite
From the `cli/` directory:
```bash
# Using npm script:
npm test

# Using the native test runner harness:
node test/runner.js

# Using Node.js built-in test runner directly:
node --test test/**/*.test.js
```

### 2. Run Individual Tiers
```bash
# Run Tier 1 only (Pure Dynamic Zero-Word Catch)
node test/runner.js --tier=1

# Run Tier 2 only (Benign Code Precision)
node test/runner.js --tier=2

# Run Tier 3 only (Behavioral Brain & Immune Memory)
node test/runner.js --tier=3

# Run Tier 4 only (1-Terminal Integration & Quarantine)
node test/runner.js --tier=4
```

### 3. List Available Suites
```bash
node test/runner.js --list
```

---

## Expected Output Derivation Methodology

For every test case in the suite, expected outputs are derived from explicit mathematical and behavioral specifications:
1. **Shannon Entropy**:
   $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
   Derived mathematically for uniform and high-entropy base64/hex token distributions ($H \ge 4.2$) versus natural English / code keywords ($H \le 3.5$).
2. **Key-Value Density**:
   $$\rho_{kv} = \frac{\text{Key-Value Lines}}{\text{Total Lines}}$$
   Derived for configuration files without hardcoded filename matching ($\rho_{kv} \ge 0.50$).
3. **Causal Canary Dye Leakage**:
   When radioactive canary tokens (e.g. `CANARY_DYE_77aabb99`) injected into secret file descriptors appear in network buffers or subprocess arguments during Mirage micro-detonation, causal exfiltration is proven with zero ambiguity.
4. **Structural AST Skeleton Invariance**:
   AST identifier neutralization replaces all variable names and function identifiers with uniform tokens (`$VAR`, `$FN`), producing identical SHA-256 hashes across mutated attack variants.
5. **Decision Boundaries**:
   - Risk Score $\ge 80 \implies \text{BLOCKED}$ (immediate execution termination and file quarantine).
   - Risk Score $50 - 79 \implies \text{WARN}$.
   - Risk Score $< 50 \implies \text{ALLOW}$ (zero interference, file preserved intact).
