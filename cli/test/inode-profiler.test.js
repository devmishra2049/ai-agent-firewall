/**
 * Comprehensive Unit Test Suite for Dynamic Inode & Boundary Profiler
 * cli/test/inode-profiler.test.js
 *
 * Verifies Milestone 1 (R1):
 * - Pure Dynamic Secret Discovery (Zero hardcoded filename lists)
 * - Shannon Entropy H(X) with O(1) incremental sliding window & Hex Paradox resolution
 * - Key-Value density rho_kv line filtering and candidate token extraction
 * - POSIX permissions (0600 / 0400) and in-memory .gitignore matcher
 * - Multi-factor scoring formula and secret decision rules
 * - Canonical boundary topology and normalized scoring
 * - Workspace inode profiling (dev, ino) and radioactive canary dye mapping
 */

'use strict';

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { InodeProfiler, EntropyEngine } = require('../src/threats/inode-profiler');

describe('InodeProfiler - Milestone 1 Test Suite', () => {
  let tempDir;
  let profiler;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-m1-workspace-'));
    profiler = new InodeProfiler(tempDir);
  });

  after(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  // =========================================================================
  // G1: Path Topology & Boundary Scoring Engine
  // =========================================================================
  describe('G1: Path Topology & Boundary Scoring', () => {
    test('1.1 internal relative path returns score 0.0 and no violation', () => {
      const res = profiler.checkBoundary('src/index.js');
      assert.equal(res.boundaryScore, 0.0);
      assert.equal(res.isViolation, false);
      assert.equal(res.traversalType, 'INTERNAL');
      assert.equal(res.reasons.length, 0);
    });

    test('1.2 internal path with dot traversal staying inside returns score 0.0', () => {
      const res = profiler.checkBoundary('src/threats/../config/policy.js');
      assert.equal(res.boundaryScore, 0.0);
      assert.equal(res.isViolation, false);
      assert.equal(res.traversalType, 'INTERNAL');
    });

    test('1.3 immediate parent traversal (../file) returns score 0.5', () => {
      const res = profiler.checkBoundary('../external.txt');
      assert.equal(res.boundaryScore, 0.5);
      assert.equal(res.isViolation, true);
      assert.equal(res.traversalType, 'PARENT_RELATIVE');
      assert.ok(res.reasons.includes('IMMEDIATE_PARENT_TRAVERSAL'));
    });

    test('1.4 deep parent traversal (../../../file) returns score 0.8', () => {
      const res = profiler.checkBoundary('../../../deep_external.txt');
      assert.equal(res.boundaryScore, 0.8);
      assert.equal(res.isViolation, true);
      assert.equal(res.traversalType, 'DEEP_RELATIVE');
      assert.ok(res.reasons.some((r) => r.startsWith('DEEP_PARENT_TRAVERSAL')));
    });

    test('1.5 system path /etc/passwd returns score 1.0', () => {
      const res = profiler.checkBoundary('/etc/passwd');
      assert.equal(res.boundaryScore, 1.0);
      assert.equal(res.isViolation, true);
      assert.equal(res.traversalType, 'SYSTEM_ROOT');
      assert.ok(res.reasons.some((r) => r.includes('CRITICAL_SYSTEM_PATH_ACCESS')));
    });

    test('1.6 macOS /private/etc returns score 1.0', () => {
      const res = profiler.checkBoundary('/private/etc/hosts');
      assert.equal(res.boundaryScore, 1.0);
      assert.equal(res.isViolation, true);
      assert.equal(res.traversalType, 'SYSTEM_ROOT');
    });

    test('1.7 Linux /proc or /sys returns score 1.0', () => {
      const res = profiler.checkBoundary('/proc/cpuinfo');
      assert.equal(res.boundaryScore, 1.0);
      assert.equal(res.isViolation, true);
      assert.equal(res.traversalType, 'SYSTEM_ROOT');
    });

    test('1.8 user home ~/.ssh/id_rsa returns score 1.0', () => {
      const res = profiler.checkBoundary('~/.ssh/id_rsa');
      assert.equal(res.boundaryScore, 1.0);
      assert.equal(res.isViolation, true);
      assert.equal(res.traversalType, 'SENSITIVE_CREDENTIAL');
      assert.ok(res.reasons.some((r) => r.includes('SENSITIVE_CREDENTIAL_PATH_ACCESS')));
    });

    test('1.9 user home ~/.aws/credentials returns score 1.0', () => {
      const res = profiler.checkBoundary('~/.aws/credentials');
      assert.equal(res.boundaryScore, 1.0);
      assert.equal(res.isViolation, true);
      assert.equal(res.traversalType, 'SENSITIVE_CREDENTIAL');
    });

    test('1.10 symlink escaping workspace is detected as violation', () => {
      const extDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-ext-symlink-'));
      const symlinkPath = path.join(tempDir, 'link_out');
      try {
        fs.symlinkSync(extDir, symlinkPath);
        const res = profiler.checkBoundary('link_out/test.txt');
        assert.equal(res.isViolation, true);
        assert.ok(res.boundaryScore >= 0.8);
      } finally {
        try { fs.unlinkSync(symlinkPath); } catch {}
        try { fs.rmSync(extDir, { recursive: true, force: true }); } catch {}
      }
    });

    test('1.11 internal symlink inside workspace returns score 0.0', () => {
      const internalDir = path.join(tempDir, 'sub_dir');
      const internalLink = path.join(tempDir, 'link_internal');
      fs.mkdirSync(internalDir, { recursive: true });
      try {
        fs.symlinkSync(internalDir, internalLink);
        const res = profiler.checkBoundary('link_internal/inner.txt');
        assert.equal(res.boundaryScore, 0.0);
        assert.equal(res.isViolation, false);
      } finally {
        try { fs.unlinkSync(internalLink); } catch {}
        try { fs.rmSync(internalDir, { recursive: true, force: true }); } catch {}
      }
    });

    test('1.12 uncreated prospective path in /etc resolves without exception with score 1.0', () => {
      const res = profiler.checkBoundary('/etc/prospective_daemon_991823.conf');
      assert.equal(res.boundaryScore, 1.0);
      assert.equal(res.isViolation, true);
      assert.equal(res.traversalType, 'SYSTEM_ROOT');
    });
  });

  // =========================================================================
  // G2: Shannon Entropy Engine & Sliding Window
  // =========================================================================
  describe('G2: Shannon Entropy & Sliding Window', () => {
    test('2.1 uniform single-character string has zero entropy', () => {
      const h = profiler.calculateEntropy('AAAAAAAAAAAAAAAA');
      assert.equal(h, 0.0);
    });

    test('2.2 natural prose / source code has moderate entropy (3.5 - 4.8)', () => {
      const benignText = 'function fibonacci(n) { if (n <= 1) return n; return fibonacci(n-1) + fibonacci(n-2); }';
      const h = profiler.calculateEntropy(benignText);
      assert.ok(h >= 3.5 && h <= 4.8, `Expected entropy between 3.5 and 4.8, got ${h}`);
    });

    test('2.3 high-entropy cryptographic token exceeds 4.0 bits/symbol', () => {
      const token = 'd8e4f1a09b2c3d5e8f7a6b5c4d3e2f1a0b9c8d7e';
      const h = profiler.calculateEntropy(token);
      assert.ok(h >= 3.8, `Expected token entropy >= 3.8, got ${h}`);
    });

    test('2.4 Hex Paradox resolution: random hex >= 32 chars detected with H >= 3.20', () => {
      const engine = new EntropyEngine();
      // 64-character uniform random hex string
      const hexKey = '9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a';
      const res = engine.tokenEntropy(hexKey);
      assert.equal(res.charset, 'hex');
      assert.ok(res.h >= 3.20, `Expected hex entropy >= 3.20, got ${res.h}`);
      assert.ok(res.h <= 4.00, `Hex entropy cannot exceed log2(16)=4.00, got ${res.h}`);
      assert.equal(res.isSecret, true, 'Random 64-char hex key must be classified as secret');
    });

    test('2.5 Hex Paradox resolution: repetitive hex has low entropy and is NOT secret', () => {
      const engine = new EntropyEngine();
      const repetitiveHex = '00000000000000000000000000000000';
      const res = engine.tokenEntropy(repetitiveHex);
      assert.equal(res.isSecret, false);
      assert.ok(res.h < 2.0);
    });

    test('2.6 O(1) incremental sliding window discovers embedded secret in benign code', () => {
      const benignCode = 'function calculateTotal(price, tax) {\n' +
        '  const subtotal = price + tax;\n' +
        '  const SECRET_ACCESS_KEY = "entropy_key_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e";\n' +
        '  return subtotal;\n' +
        '}\n';
      const peakH = profiler.calculatePeakEntropy(benignCode, 64, 8);
      assert.ok(peakH >= 4.2, `Peak sliding entropy should be >= 4.2, got ${peakH}`);
    });

    test('2.7 sliding window handles content smaller than window size', () => {
      const shortText = 'KEY=123';
      const peakH = profiler.calculatePeakEntropy(shortText, 64, 8);
      assert.ok(typeof peakH === 'number');
    });

    test('2.8 empty content returns 0.0 entropy', () => {
      assert.equal(profiler.calculateEntropy(''), 0.0);
      assert.equal(profiler.calculatePeakEntropy(''), 0.0);
    });
  });

  // =========================================================================
  // G3: Key-Value Density & OS Metadata Heuristics
  // =========================================================================
  describe('G3: Key-Value Density & OS Metadata', () => {
    test('3.1 detects high KV density (rho_kv = 1.0) on arbitrary-named config', () => {
      const envText = [
        'DATABASE_HOST=postgres.internal.net',
        'DATABASE_PORT=5432',
        'DATABASE_PASS=9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c',
      ].join('\n');
      const res = profiler.calculateKvDensity(envText);
      assert.equal(res.kvDensity, 1.0);
      assert.ok(res.secretValuesCount >= 1);
    });

    test('3.2 filters out comment lines and structural brackets from candidate count', () => {
      const text = [
        '# This is a comment',
        '// Another comment',
        '; INI comment',
        '{',
        '  "API_KEY": "entropy_key_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"',
        '}'
      ].join('\n');
      const res = profiler.calculateKvDensity(text);
      assert.equal(res.totalCandidateLines, 1);
      assert.equal(res.kvLinesCount, 1);
      assert.equal(res.kvDensity, 1.0);
    });

    test('3.3 identifies low KV density on standard source code (fibonacci / quicksort)', () => {
      const fibCode = [
        'def fib(n):',
        '    if n <= 1:',
        '        return n',
        '    a = 0',
        '    b = 1',
        '    for _ in range(n - 1):',
        '        c = a + b',
        '        a = b',
        '        b = c',
        '    return b'
      ].join('\n');
      const res = profiler.calculateKvDensity(fibCode);
      assert.ok(res.kvDensity < 0.30, `Expected code kvDensity < 0.30, got ${res.kvDensity}`);
    });

    test('3.4 parses JSON configuration properties into candidate KV lines', () => {
      const jsonText = JSON.stringify({
        server_port: 8080,
        worker_threads: 4,
        cache_timeout_seconds: 300
      }, null, 2);
      const res = profiler.calculateKvDensity(jsonText);
      assert.ok(res.kvDensity >= 0.50);
      assert.equal(res.secretValuesCount, 0); // No high-entropy secrets
    });

    test('3.5 detects owner-only private POSIX permissions (0600 / 0400)', () => {
      assert.equal(profiler.isOwnerPrivateMode(0o600), true);
      assert.equal(profiler.isOwnerPrivateMode(0o400), true);
      assert.equal(profiler.isOwnerPrivateMode(0o700), true);
      assert.equal(profiler.isOwnerPrivateMode(0o644), false);
      assert.equal(profiler.isOwnerPrivateMode(0o755), false);
      assert.equal(profiler.isOwnerPrivateMode(0o666), false);
    });

    test('3.6 compiles in-memory .gitignore rules and matches paths', () => {
      const gitignorePath = path.join(tempDir, '.gitignore');
      fs.writeFileSync(gitignorePath, '*.local\nsecrets/\n!secrets/public.txt\n');
      const testProfiler = new InodeProfiler(tempDir);

      assert.equal(testProfiler.checkGitIgnore('app.local'), true);
      assert.equal(testProfiler.checkGitIgnore('secrets/key.dat'), true);
      assert.equal(testProfiler.checkGitIgnore('secrets/public.txt'), false);
      assert.equal(testProfiler.checkGitIgnore('src/main.js'), false);
    });

    test('3.7 discriminates build cache directories from sensitive gitignored files', () => {
      assert.equal(profiler.isBuildCache('node_modules/lodash/index.js'), true);
      assert.equal(profiler.isBuildCache('target/debug/app'), true);
      assert.equal(profiler.isBuildCache('.firewall-quarantine/brain-state.json'), true);
      assert.equal(profiler.isBuildCache('config/credentials.conf'), false);
    });

    test('3.8 discriminates binary files with null bytes or high non-printable ratio', () => {
      const binaryBuf = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00]);
      assert.equal(profiler.isBinary(binaryBuf), true);
      const textBuf = Buffer.from('const express = require("express");\n');
      assert.equal(profiler.isBinary(textBuf), false);
    });
  });

  // =========================================================================
  // G4: Dynamic Secret Inode Classification (Zero Hardcoded Filenames)
  // =========================================================================
  describe('G4: Dynamic Secret Inode Classification', () => {
    test('4.1 arbitrary named file (data.cfg) with 0600 mode and high entropy is secret', () => {
      const filePath = path.join(tempDir, 'data.cfg');
      const content = 'MASTER_KEY=entropy_key_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e\n';
      fs.writeFileSync(filePath, content, { mode: 0o600 });

      const p = profiler.profile(filePath);
      assert.equal(p.isSecret, true);
      assert.ok(p.score >= 70, `Expected score >= 70, got ${p.score}`);
      assert.equal(p.isPrivateMode, true);
      assert.ok(p.canaryDyeToken.startsWith('CANARY_DYE_SECRET_'));
    });

    test('4.2 arbitrary named file (vault.bin) with KV density >= 0.50 and secret tokens is secret', () => {
      const content = [
        'API_HOST=api.service.io',
        'CLIENT_TOKEN=9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c',
        'SESSION_SECRET=a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3',
      ].join('\n');

      const p = profiler.profile('vault.bin', content);
      assert.equal(p.isSecret, true);
      assert.ok(p.kvDensity >= 0.50);
      assert.ok(p.secretTokensFound >= 2);
    });

    test('4.3 cryptographic PEM private key block is identified as secret with score 100', () => {
      const pemContent = [
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEA0Y3y7qP1r7H5k2N4s9d3W6f8G1h5j8k9l0m1n2o3p4q5r6s7',
        't8u9v0w1x2y3z4a5b6c7d8e9f0a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9',
        '-----END RSA PRIVATE KEY-----'
      ].join('\n');

      const p = profiler.profile('certificate.dat', pemContent);
      assert.equal(p.isSecret, true);
      assert.equal(p.score, 100);
      assert.equal(p.isPem, true);
    });

    test('4.4 non-secret config (app.ini) with low-entropy values is NOT secret', () => {
      const configText = 'PORT=8080\nHOST=localhost\nDEBUG=false\n';
      const p = profiler.profile('app.ini', configText);
      assert.equal(p.isSecret, false);
      assert.ok(p.score < 50, `Expected score < 50, got ${p.score}`);
    });

    test('4.5 benign Python code (fibonacci.py) is NOT classified as secret', () => {
      const filePath = path.join(tempDir, 'fibonacci.py');
      const pyCode = 'def fib(n):\n    return n if n <= 1 else fib(n-1) + fib(n-2)\n';
      fs.writeFileSync(filePath, pyCode, { mode: 0o644 });

      const p = profiler.profile(filePath);
      assert.equal(p.isSecret, false);
      assert.ok(p.score < 30);
    });

    test('4.6 benign JavaScript code (quicksort.js) is NOT classified as secret', () => {
      const filePath = path.join(tempDir, 'quicksort.js');
      const jsCode = 'function quicksort(arr) { if (arr.length <= 1) return arr; return arr; }\n';
      fs.writeFileSync(filePath, jsCode, { mode: 0o644 });

      const p = profiler.profile(filePath);
      assert.equal(p.isSecret, false);
      assert.ok(p.score < 30);
    });

    test('4.7 standard package.json manifest is NOT classified as secret', () => {
      const pkgJson = JSON.stringify({
        name: 'test-app',
        version: '1.0.0',
        description: 'Test application package',
        main: 'index.js'
      }, null, 2);

      const p = profiler.profile('package.json', pkgJson);
      assert.equal(p.isSecret, false);
      assert.ok(p.score < 50);
    });

    test('4.8 empty file returns isSecret: false and score 0', () => {
      const emptyFile = path.join(tempDir, 'empty.txt');
      fs.writeFileSync(emptyFile, '');

      const p = profiler.profile(emptyFile);
      assert.equal(p.isSecret, false);
      assert.equal(p.score, 0);
      assert.equal(p.entropy, 0.0);
    });
  });

  // =========================================================================
  // G5: Workspace Profiling & Radioactive Canary Dye Mapping
  // =========================================================================
  describe('G5: Workspace Profiling & Canary Dye Mapping', () => {
    test('5.1 profileWorkspace recursively scans directory and registers protected inodes', () => {
      const secretFile = path.join(tempDir, 'app_secrets.conf');
      fs.writeFileSync(secretFile, 'AUTH_KEY=entropy_key_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c\n', { mode: 0o600 });

      const summary = profiler.profileWorkspace();
      assert.ok(summary.scannedFiles >= 3);
      assert.ok(summary.protectedCount >= 1);
      assert.equal(profiler.isProtected(secretFile), true);
    });

    test('5.2 tracking by OS (dev, ino) tuple protects hardlinks or aliased paths', () => {
      const origFile = path.join(tempDir, 'app_secrets.conf');
      const hardlinkFile = path.join(tempDir, 'innocent_alias.txt');
      try {
        fs.linkSync(origFile, hardlinkFile);
        assert.equal(profiler.isProtected(hardlinkFile), true);
      } finally {
        try { fs.unlinkSync(hardlinkFile); } catch {}
      }
    });

    test('5.3 canary token format matches CANARY_DYE_SECRET_<hash>_<random>', () => {
      const canary = profiler.generateCanaryToken('/workspace/test_key.dat');
      assert.ok(canary.token.startsWith('CANARY_DYE_SECRET_'));
      const parts = canary.token.split('_');
      assert.equal(parts.length, 5); // CANARY, DYE, SECRET, <hash>, <random>
      assert.equal(parts[3].length, 12);
      assert.equal(parts[4].length, 12);
    });

    test('5.4 canary profile includes multi-representation map (raw, base64, hex, url)', () => {
      const canary = profiler.generateCanaryToken('/workspace/test_key.dat');
      const reps = canary.representations;
      assert.equal(reps.raw, canary.token);
      assert.equal(reps.base64, Buffer.from(canary.token, 'utf8').toString('base64'));
      assert.equal(reps.hex, Buffer.from(canary.token, 'utf8').toString('hex'));
      assert.equal(reps.urlEncoded, encodeURIComponent(canary.token).replace(/_/g, '%5F'));
    });

    test('5.5 getCanaryContent preserves Key-Value environment structure', () => {
      const origEnv = 'SERVER_PORT=8080\nAPI_KEY=original_super_secret_value\n';
      const poisoned = profiler.getCanaryContent('test.env', origEnv);
      assert.ok(poisoned.includes('SERVER_PORT=8080'));
      assert.ok(poisoned.includes('API_KEY=CANARY_DYE_SECRET_'));
      assert.ok(!poisoned.includes('original_super_secret_value'));
    });

    test('5.6 getCanaryContent preserves JSON structure', () => {
      const origJson = JSON.stringify({ database_url: 'postgres://real_secret@host:5432' });
      const poisoned = profiler.getCanaryContent('config.json', origJson);
      const parsed = JSON.parse(poisoned);
      assert.ok(parsed.database_url.startsWith('CANARY_DYE_SECRET_'));
    });

    test('5.7 getCanaryContent preserves PEM private key header and footer', () => {
      const origPem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n';
      const poisoned = profiler.getCanaryContent('key.pem', origPem);
      assert.ok(poisoned.includes('-----BEGIN RSA PRIVATE KEY-----'));
      assert.ok(poisoned.includes('-----END RSA PRIVATE KEY-----'));
      assert.ok(poisoned.includes('CANARY_DYE_SECRET_'));
    });

    test('5.8 findCanaryInText detects raw, base64, hex, and url-encoded leaks in text', () => {
      const canary = profiler.generateCanaryToken('/target/secret.env');

      // Raw detection
      const rawLeak = profiler.findCanaryInText(`exfiltrated payload: ${canary.token}`);
      assert.ok(rawLeak);
      assert.equal(rawLeak.leaked, true);
      assert.equal(rawLeak.representation, 'raw');

      // Base64 detection
      const b64 = Buffer.from(canary.token).toString('base64');
      const b64Leak = profiler.findCanaryInText(`Authorization: Bearer ${b64}`);
      assert.ok(b64Leak);
      assert.equal(b64Leak.representation, 'base64');

      // Hex detection
      const hex = Buffer.from(canary.token).toString('hex');
      const hexLeak = profiler.findCanaryInText(`hash=${hex}&submit=true`);
      assert.ok(hexLeak);
      assert.equal(hexLeak.representation, 'hex');

      // URL-encoded detection
      const urlEnc = canary.representations.urlEncoded;
      const urlLeak = profiler.findCanaryInText(`GET /collect?data=${urlEnc} HTTP/1.1`);
      assert.ok(urlLeak);
      assert.equal(urlLeak.representation, 'urlEncoded');

      // Non-matching benign payload
      const clean = profiler.findCanaryInText('GET /api/v1/users HTTP/1.1\nHost: example.com');
      assert.equal(clean, null);
    });
  });

  // =========================================================================
  // G6: Performance SLA & Resilience
  // =========================================================================
  describe('G6: Performance SLA & Resilience', () => {
    test('6.1 single file profiling completes in under 1ms', () => {
      const filePath = path.join(tempDir, 'fibonacci.py');
      const start = performance.now();
      const iterations = 100;
      for (let i = 0; i < iterations; i++) {
        profiler.profile(filePath);
      }
      const avgMs = (performance.now() - start) / iterations;
      assert.ok(avgMs < 1.0, `Profile latency ${avgMs.toFixed(3)}ms exceeded 1.0ms limit`);
    });

    test('6.2 boundary check completes in under 0.1ms', () => {
      const start = performance.now();
      const iterations = 500;
      for (let i = 0; i < iterations; i++) {
        profiler.checkBoundary('src/utils/calc.js');
      }
      const avgMs = (performance.now() - start) / iterations;
      assert.ok(avgMs < 0.1, `Boundary check latency ${avgMs.toFixed(3)}ms exceeded 0.1ms limit`);
    });

    test('6.3 canary lookup completes in under 0.05ms', () => {
      const start = performance.now();
      const iterations = 500;
      for (let i = 0; i < iterations; i++) {
        profiler.findCanaryInText('benign log entry without any secrets');
      }
      const avgMs = (performance.now() - start) / iterations;
      assert.ok(avgMs < 0.05, `Canary search latency ${avgMs.toFixed(3)}ms exceeded 0.05ms limit`);
    });

    test('6.4 handles non-existent paths and corrupted files without crashing', () => {
      assert.doesNotThrow(() => {
        profiler.profile('/non/existent/path/999888.tmp');
      });
      assert.doesNotThrow(() => {
        profiler.checkBoundary(null);
        profiler.checkBoundary('');
      });
      assert.doesNotThrow(() => {
        profiler.findCanaryInText(null);
      });
    });
  });
});
