/**
 * Dynamic Inode & Boundary Profiler
 * cli/src/threats/inode-profiler.js
 *
 * Implements Milestone 1 (R1): Pure Dynamic Secret & Boundary Discovery.
 * ZERO hardcoded filename lists - no matching on ".env", ".ssh", "id_rsa".
 * All secret and boundary determinations are derived dynamically via:
 * 1. Shannon Information Entropy H(X) with O(1) incremental sliding window and Hex Paradox resolution.
 * 2. Key-Value structural density (rho_kv) and candidate line assignment extraction.
 * 3. POSIX permission modes (0600/0400 owner-only private bitmask).
 * 4. In-memory .gitignore rule engine with build-cache discrimination.
 * 5. Multi-factor composite scoring formula and decision rules.
 * 6. Canonical workspace boundary topology and normalized traversal scoring.
 * 7. Inode tracking (dev, ino) and radioactive canary dye taint mapping.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

/**
 * High-Performance Mathematical Shannon Entropy Engine
 * Provides sub-millisecond O(1) sliding window chunk profiling and
 * character set calibrated token profiling.
 */
class EntropyEngine {
  constructor(windowSize = 64) {
    this.W = windowSize;
    this.log2W = Math.log2(this.W);
    this.invW = 1.0 / this.W;

    // Precompute f(c) = c * log2(c) lookup table for c in [0, W]
    this.fTable = new Float64Array(this.W + 1);
    this.fTable[0] = 0.0;
    for (let i = 1; i <= this.W; i++) {
      this.fTable[i] = i * Math.log2(i);
    }
  }

  /**
   * Computes exact Shannon byte entropy of a buffer [0.0 to 8.0 bits/byte].
   * @param {Buffer|Uint8Array|string} input
   * @returns {number}
   */
  byteEntropy(input) {
    if (!input || input.length === 0) return 0.0;
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
    const len = buf.length;
    if (len === 0) return 0.0;

    const freq = new Uint32Array(256);
    for (let i = 0; i < len; i++) {
      freq[buf[i]]++;
    }

    let h = 0.0;
    for (let i = 0; i < 256; i++) {
      const c = freq[i];
      if (c > 0) {
        const p = c / len;
        h -= p * Math.log2(p);
      }
    }
    return h;
  }

  /**
   * Incremental O(1) sliding window entropy calculation across buffer chunks.
   * Eliminates all logarithmic calls during scanning via the precomputed fTable.
   * @param {Buffer|Uint8Array|string} input
   * @param {number} [step=8] Stride between evaluations
   * @returns {{ maxH: number, peakOffset: number, windowsScanned: number }}
   */
  slidingWindowEntropy(input, step = 8) {
    const W = this.W;
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input || '', 'utf8');
    if (!buf || buf.length < W) {
      const h = this.byteEntropy(buf);
      return { maxH: h, peakOffset: 0, windowsScanned: 1 };
    }

    const len = buf.length;
    const freq = new Uint32Array(256);
    let sumF = 0.0;

    // Initialize initial window [0 .. W-1]
    for (let i = 0; i < W; i++) {
      freq[buf[i]]++;
    }
    for (let i = 0; i < 256; i++) {
      if (freq[i] > 0) {
        sumF += this.fTable[freq[i]];
      }
    }

    let maxH = this.log2W - (sumF * this.invW);
    let peakOffset = 0;
    let windowsScanned = 1;

    // Slide window byte-by-byte with O(1) table updates
    for (let i = W; i < len; i++) {
      const outByte = buf[i - W];
      const inByte = buf[i];

      if (outByte !== inByte) {
        const cOut = freq[outByte];
        sumF += this.fTable[cOut - 1] - this.fTable[cOut];
        freq[outByte]--;

        const cIn = freq[inByte];
        sumF += this.fTable[cIn + 1] - this.fTable[cIn];
        freq[inByte]++;
      }

      if ((i - W + 1) % step === 0) {
        windowsScanned++;
        const curH = this.log2W - (sumF * this.invW);
        if (curH > maxH) {
          maxH = curH;
          peakOffset = i - W + 1;
        }
      }
    }

    return { maxH, peakOffset, windowsScanned };
  }

  /**
   * Character-level entropy with charset-aware calibration (Hex Paradox resolution).
   * Hex tokens have max entropy of 4.0; standard Base64 has max entropy 6.0.
   * @param {string} str
   * @returns {{ h: number, charset: string, isSecret: boolean, length: number, token: string }}
   */
  tokenEntropy(str) {
    if (!str || typeof str !== 'string' || str.length === 0) {
      return { h: 0.0, charset: 'empty', isSecret: false, length: 0, token: '' };
    }

    const len = str.length;
    const freq = Object.create(null);
    for (let i = 0; i < len; i++) {
      const ch = str[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }

    let h = 0.0;
    for (const ch in freq) {
      const p = freq[ch] / len;
      h -= p * Math.log2(p);
    }

    // Charset classification (100% mathematical & structural — zero hardcoded vendor prefixes)
    const isHex = /^[0-9a-fA-F]+$/.test(str);
    const hasHexLetters = /[a-fA-F]/.test(str);
    const hasDigits = /[0-9]/.test(str);
    const isPureAlphaIdentifier = /^[A-Za-z_]+$/.test(str);
    const isBase64 = /^[A-Za-z0-9+/=_-]+$/.test(str);

    let charset = 'symbolic';
    let isSecret = false;

    if (isPureAlphaIdentifier && h < 4.45) {
      // Standard camelCase / snake_case source code identifier without digits
      charset = 'identifier';
      isSecret = false;
    } else if (isHex && (len >= 32 || (hasHexLetters && hasDigits))) {
      charset = 'hex';
      // Hex maximum entropy is 4.0. Hex secrets (MD5, SHA-256) have H >= 3.20 (or H >= 2.5 for len >= 12)
      if ((len >= 32 && h >= 3.00) || (len >= 12 && h >= 2.5 && hasHexLetters && hasDigits)) {
        isSecret = true;
      }
    } else if (isBase64) {
      charset = 'base64';
      // Base64 maximum entropy is 6.0. High entropy secrets have H >= 4.20 (or H >= 3.8 for len >= 16 with digits/symbols)
      if ((len >= 20 && h >= 4.20) || (len >= 16 && h >= 3.8 && hasDigits)) {
        isSecret = true;
      }
    } else {
      charset = 'alphanumeric_symbol';
      // Complex symbols / passwords
      if (len >= 16 && h >= 4.20) {
        isSecret = true;
      }
    }

    return {
      h: parseFloat(h.toFixed(3)),
      charset,
      isSecret,
      length: len,
      token: str
    };
  }

  /**
   * Fast O(N) linear candidate token extractor from raw source code or configuration text.
   * Extracts string literals, key-value assignments, and continuous tokens without backtracking.
   * @param {string} text
   * @returns {string[]}
   */
  extractCandidateTokens(text) {
    if (!text || typeof text !== 'string') return [];
    const tokens = new Set();

    // 1. Quoted string literals: "..." or '...' >= 12 characters
    const quoteRegex = /["']([A-Za-z0-9+/=_\-!@#$%^&*~.]{12,})["']/g;
    let match;
    while ((match = quoteRegex.exec(text)) !== null) {
      tokens.add(match[1]);
    }

    // 2. O(N) line-by-line key-value assignment extraction (ReDoS-proof)
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (trimmed.length < 14) continue;
      const eqIdx = trimmed.indexOf('=');
      const colonIdx = trimmed.indexOf(':');
      const splitIdx = eqIdx !== -1 && (colonIdx === -1 || eqIdx < colonIdx) ? eqIdx : colonIdx;
      if (splitIdx > 0) {
        const val = trimmed
          .slice(splitIdx + 1)
          .trim()
          .replace(/^["'`]|["'`]$/g, '');
        const firstValToken = val.split(/\s+/)[0];
        if (firstValToken && firstValToken.length >= 12 && /^[A-Za-z0-9+/=_\-!@#$%^&*~.]+$/.test(firstValToken)) {
          tokens.add(firstValToken);
        }
      }
    }

    // 3. Unquoted continuous Base64 / Hex tokens >= 16 characters
    const bareRegex = /\b([A-Za-z0-9+/=_\-]{16,})\b/g;
    while ((match = bareRegex.exec(text)) !== null) {
      tokens.add(match[1]);
    }

    return Array.from(tokens);
  }

  /**
   * Evaluates comprehensive content entropy profile.
   * @param {Buffer|string} content
   * @returns {object}
   */
  profileContent(content) {
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(content || '', 'utf8');
    const wholeEntropy = this.byteEntropy(buf);
    const sliding = this.slidingWindowEntropy(buf, 8);
    const text = buf.toString('utf8');
    const candidateTokens = this.extractCandidateTokens(text);

    let maxTokenH = 0.0;
    const secretTokens = [];

    for (const t of candidateTokens) {
      const res = this.tokenEntropy(t);
      if (res.h > maxTokenH) maxTokenH = res.h;
      if (res.isSecret) secretTokens.push(res);
    }

    return {
      wholeEntropy: parseFloat(wholeEntropy.toFixed(3)),
      slidingMaxEntropy: parseFloat(sliding.maxH.toFixed(3)),
      peakOffset: sliding.peakOffset,
      maxTokenEntropy: parseFloat(maxTokenH.toFixed(3)),
      candidateTokenCount: candidateTokens.length,
      secretTokenCount: secretTokens.length,
      secretTokens,
      hasHighFileEntropy: wholeEntropy >= 5.0,
      hasHighSlidingEntropy: sliding.maxH >= 5.0,
      hasSecretTokens: secretTokens.length > 0,
      isSecretEntropyMatch: wholeEntropy >= 5.0 || sliding.maxH >= 5.0 || secretTokens.length > 0
    };
  }
}

/**
 * Dynamic Inode & Boundary Profiler
 * Integrates mathematical entropy, key-value line density, POSIX permissions,
 * in-memory gitignore, boundary topology, and radioactive canary dye mapping.
 */
class InodeProfiler {
  /**
   * @param {string} [workspaceRoot=process.cwd()] - Root directory of monitored workspace
   * @param {object} [options={}] - Configuration options and thresholds
   */
  constructor(workspaceRoot = process.cwd(), options = {}) {
    this.workspaceRoot = path.resolve(workspaceRoot);
    try {
      this.canonicalWorkspaceRoot = fs.realpathSync(this.workspaceRoot);
    } catch {
      this.canonicalWorkspaceRoot = this.workspaceRoot;
    }

    this.options = {
      tokenEntropyThreshold: options.tokenEntropyThreshold || 4.2,
      fileEntropyThreshold: options.fileEntropyThreshold || 5.0,
      kvDensityThreshold: options.kvDensityThreshold || 0.50,
      secretScoreThreshold: options.secretScoreThreshold || 70,
      maxFileSize: options.maxFileSize || 1024 * 1024, // 1MB
      ignoredDirs: options.ignoredDirs || [
        '.git', 'node_modules', '.firewall-quarantine', 'dist', 'build',
        'target', '.venv', 'venv', '__pycache__', '.vscode', '.idea'
      ],
      ...options
    };

    this.entropyEngine = new EntropyEngine(64);
    this.sessionSalt = options.sessionSalt || crypto.randomBytes(16).toString('hex');
    this.gitIgnoreRules = this.loadGitIgnoreRules();

    // Canonical path resolution cache for sub-0.01ms boundary performance
    this.realpathCache = new Map();
    this.realpathCache.set(this.canonicalWorkspaceRoot, this.canonicalWorkspaceRoot);
    this.realpathCache.set(this.workspaceRoot, this.canonicalWorkspaceRoot);

    // Inode and canary state
    this.protectedInodes = new Map(); // `${dev}:${ino}` -> CanaryProfile
    this.protectedPaths = new Map();  // canonicalPath -> CanaryProfile
    this.canaryRegistry = new Map();  // token -> CanaryProfile
    this.canaryMap = new Map();       // canonicalPath -> CanaryProfile
  }

  /**
   * Fast in-memory .gitignore parser and compiler (<0.005ms).
   */
  loadGitIgnoreRules() {
    const gitignorePath = path.join(this.canonicalWorkspaceRoot, '.gitignore');
    if (!fs.existsSync(gitignorePath)) return [];

    try {
      const content = fs.readFileSync(gitignorePath, 'utf8');
      const lines = content.split(/\r?\n/);
      const rules = [];

      for (const rawLine of lines) {
        let line = rawLine.trim();
        if (!line || line.startsWith('#')) continue;

        let isNegative = false;
        if (line.startsWith('!')) {
          isNegative = true;
          line = line.slice(1);
        }

        const isDirOnly = line.endsWith('/');
        if (isDirOnly) line = line.slice(0, -1);

        let regexStr = '';
        if (line.startsWith('/')) {
          regexStr = '^' + this.globToRegex(line.slice(1));
        } else if (line.includes('/')) {
          regexStr = '^' + this.globToRegex(line);
        } else {
          regexStr = '(?:^|/)' + this.globToRegex(line);
        }
        regexStr += '(?:/.*)?$';

        rules.push({ regex: new RegExp(regexStr), isNegative, isDirOnly });
      }
      return rules;
    } catch {
      return [];
    }
  }

  /**
   * Converts gitignore glob expression to regex string.
   */
  globToRegex(glob) {
    let s = '';
    for (let i = 0; i < glob.length; i++) {
      const c = glob[i];
      if (c === '*') {
        if (glob[i + 1] === '*') {
          s += '.*';
          i++;
        } else {
          s += '[^/]*';
        }
      } else if (c === '?') {
        s += '[^/]';
      } else if (c === '.' || c === '$' || c === '^' || c === '+' || c === '(' || c === ')' || c === '[' || c === ']') {
        s += '\\' + c;
      } else {
        s += c;
      }
    }
    return s;
  }

  /**
   * Checks if a relative or absolute path matches gitignore rules.
   * @param {string} filePath
   * @returns {boolean}
   */
  checkGitIgnore(filePath) {
    if (!this.gitIgnoreRules || !this.gitIgnoreRules.length) return false;
    const absPath = path.isAbsolute(filePath) ? filePath : path.resolve(this.canonicalWorkspaceRoot, filePath);
    const relPath = path.relative(this.canonicalWorkspaceRoot, absPath).replace(/\\/g, '/');
    const normalized = relPath.replace(/^\/+/, '');

    let ignored = false;
    for (const rule of this.gitIgnoreRules) {
      if (rule.regex.test(normalized)) {
        ignored = !rule.isNegative;
      }
    }
    return ignored;
  }

  /**
   * Determines if path is inside a build cache or dependency directory.
   */
  isBuildCache(relPath) {
    const parts = relPath.split(path.sep);
    const buildDirs = new Set([
      'node_modules', 'target', 'dist', 'build', '.venv', 'venv',
      '__pycache__', '.git', '.cache', '.firewall-quarantine',
      '.cargo', '.rustup', '.npm', '.yarn', 'coverage', '.pytest_cache'
    ]);
    return parts.some((p) => buildDirs.has(p));
  }

  /**
   * Checks if POSIX mode is owner-only private (0600, 0400, 0700).
   * @param {number} mode
   * @returns {boolean}
   */
  isOwnerPrivateMode(mode) {
    if (typeof mode !== 'number') return false;
    if (process.platform === 'win32') return false;
    const permissionBits = mode & 0o777;
    // Group and others have zero permissions (0o077), owner has at least read permission (0o400)
    return (permissionBits & 0o077) === 0 && (permissionBits & 0o400) !== 0;
  }

  /**
   * Fast check for binary files (null bytes or high non-printable byte ratio).
   * @param {Buffer|string} buffer
   * @returns {boolean}
   */
  isBinary(buffer) {
    if (!buffer) return false;
    const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
    const checkLength = Math.min(buf.length, 512);
    if (checkLength === 0) return false;

    let nonPrintable = 0;
    for (let i = 0; i < checkLength; i++) {
      const byte = buf[i];
      if (byte === 0) return true; // Null byte indicates binary
      if (byte < 7 || (byte > 14 && byte < 32)) {
        nonPrintable++;
      }
    }
    return (nonPrintable / checkLength) > 0.15;
  }

  /**
   * Calculates Shannon Entropy of string or buffer: H(X) = -sum(P(x) * log2(P(x)))
   * @param {string|Buffer} data
   * @returns {number} Entropy in bits/byte (0.0 to 8.0)
   */
  calculateEntropy(data) {
    return this.entropyEngine.byteEntropy(data);
  }

  /**
   * Calculates peak sliding-window Shannon entropy over chunks.
   * @param {string|Buffer} data
   * @param {number} [windowSize=64]
   * @param {number} [stepSize=32]
   * @returns {number}
   */
  calculatePeakEntropy(data, windowSize = 64, stepSize = 32) {
    if (!data || data.length === 0) return 0.0;
    const engine = windowSize === this.entropyEngine.W ? this.entropyEngine : new EntropyEngine(windowSize);
    const res = engine.slidingWindowEntropy(data, stepSize);
    return res.maxH;
  }

  /**
   * Analyzes line density of key-value assignments and extracts secret tokens.
   * @param {string} text
   * @returns {{ kvDensity: number, totalCandidateLines: number, kvLinesCount: number, secretValuesCount: number, secretTokens: object[], isPem: boolean }}
   */
  calculateKvDensity(text) {
    if (!text || typeof text !== 'string') {
      return { kvDensity: 0.0, totalCandidateLines: 0, kvLinesCount: 0, secretValuesCount: 0, secretTokens: [], isPem: false };
    }

    const lines = text.split(/\r?\n/);
    const candidateLines = [];

    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trim();
      if (!trimmed) continue;
      // Skip comments
      if (trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith(';')) continue;
      if (trimmed.startsWith('<!--') && trimmed.endsWith('-->')) continue;
      // Skip standalone structural brackets and fences
      if (trimmed === '{' || trimmed === '}' || trimmed === '[' || trimmed === ']' || trimmed === '---' || trimmed === '```') continue;
      candidateLines.push({ text: trimmed, lineNum: i + 1 });
    }

    if (candidateLines.length === 0) {
      return { kvDensity: 0.0, totalCandidateLines: 0, kvLinesCount: 0, secretValuesCount: 0, secretTokens: [], isPem: false };
    }

    const kvRegexes = [
      /^\s*(?:export\s+)?[A-Za-z0-9_.-]{2,}\s*[:=]\s*(?:.+)?$/,
      /^\s*"[^"\\]*(?:\\.[^"\\]*)*"\s*:\s*.+$/,
      /^\s*\[[A-Za-z0-9_.:-]+\]\s*$/,
      /^-----BEGIN\s+[A-Z0-9\s_-]+KEY-----$/,
      /^-----END\s+[A-Z0-9\s_-]+KEY-----$/,
      /^[A-Za-z0-9+/=]{40,}$/
    ];

    let kvCount = 0;
    let isPem = false;
    const secretTokens = [];

    for (const { text: lineText } of candidateLines) {
      if (/^-----BEGIN\s+[A-Z0-9\s_-]+KEY-----/.test(lineText)) {
        isPem = true;
      }

      const isMatch = kvRegexes.some((rx) => rx.test(lineText));
      if (isMatch) {
        kvCount++;

        // Extract value
        let val = '';
        const eqIdx = lineText.indexOf('=');
        const colonIdx = lineText.indexOf(':');
        if (eqIdx !== -1 && (colonIdx === -1 || eqIdx < colonIdx)) {
          val = lineText.slice(eqIdx + 1).trim();
        } else if (colonIdx !== -1) {
          val = lineText.slice(colonIdx + 1).trim();
        } else {
          val = lineText; // e.g. base64 key chunk
        }

        // Clean value of quotes and trailing comments
        val = val.replace(/^["'`]|["'`]$/g, '').replace(/\s*[#;].*$/, '').replace(/\s*\/\/.*$/, '').trim();

        // Tokenize value
        const tokens = val.split(/\s+/);
        for (const t of tokens) {
          if (t.length >= 12) {
            const tokenRes = this.entropyEngine.tokenEntropy(t);
            if (tokenRes.isSecret) {
              secretTokens.push(tokenRes);
            }
          }
        }
      }
    }

    const kvDensity = candidateLines.length > 0 ? (kvCount / candidateLines.length) : 0.0;
    return {
      kvDensity: parseFloat(kvDensity.toFixed(3)),
      totalCandidateLines: candidateLines.length,
      kvLinesCount: kvCount,
      secretValuesCount: secretTokens.length,
      secretTokens,
      isPem
    };
  }

  /**
   * Helper: Resolves canonical path with ancestor fallback for uncreated paths.
   * Utilizes directory realpath cache for sub-0.01ms performance.
   * @param {string} resolvedPath
   * @returns {string}
   */
  resolveCanonicalPath(resolvedPath, depth = 0) {
    if (depth > 8) return resolvedPath;
    if (this.realpathCache.has(resolvedPath)) {
      return this.realpathCache.get(resolvedPath);
    }

    try {
      const real = fs.realpathSync(resolvedPath);
      this.realpathCache.set(resolvedPath, real);
      return real;
    } catch (err) {
      if (err.code === 'ENOENT' || err.code === 'EACCES') {
        // Check if resolvedPath itself is a broken symlink pointing outside the workspace
        try {
          const lstat = fs.lstatSync(resolvedPath);
          if (lstat.isSymbolicLink()) {
            const linkTarget = fs.readlinkSync(resolvedPath);
            const resolvedTarget = path.isAbsolute(linkTarget)
              ? path.normalize(linkTarget)
              : path.resolve(path.dirname(resolvedPath), linkTarget);
            const realTarget = this.resolveCanonicalPath(resolvedTarget, depth + 1);
            this.realpathCache.set(resolvedPath, realTarget);
            return realTarget;
          }
        } catch {}

        let cur = path.dirname(resolvedPath);
        const parts = [path.basename(resolvedPath)];

        while (cur && cur !== path.dirname(cur)) {
          if (this.realpathCache.has(cur)) {
            const result = path.join(this.realpathCache.get(cur), ...parts);
            this.realpathCache.set(resolvedPath, result);
            return result;
          }

          try {
            const realCur = fs.realpathSync(cur);
            this.realpathCache.set(cur, realCur);
            const result = path.join(realCur, ...parts);
            this.realpathCache.set(resolvedPath, result);
            return result;
          } catch {
            parts.unshift(path.basename(cur));
            cur = path.dirname(cur);
          }
        }
      }
      this.realpathCache.set(resolvedPath, resolvedPath);
      return resolvedPath;
    }
  }

  /**
   * Evaluates path topology and returns normalized boundary violation scoring.
   * @param {string} targetPath
   * @returns {object} BoundaryCheckResult
   */
  checkBoundary(targetPath) {
    if (!targetPath || typeof targetPath !== 'string') {
      return {
        targetPath: '',
        resolvedPath: this.canonicalWorkspaceRoot,
        realPath: this.canonicalWorkspaceRoot,
        isViolation: false,
        boundaryScore: 0.0,
        traversalType: 'INTERNAL',
        reasons: []
      };
    }

    let decoded = targetPath;
    if (decoded.includes('%')) {
      try {
        decoded = decodeURIComponent(decoded);
      } catch {}
    }

    // Expand tilde (~) to os.homedir()
    let expanded = decoded;
    if (expanded === '~' || expanded.startsWith('~/') || expanded.startsWith('~\\')) {
      expanded = path.join(os.homedir(), expanded.slice(2));
    } else if (expanded.startsWith('~')) {
      expanded = path.join(path.dirname(os.homedir()), expanded.slice(1));
    }

    const resolvedPath = path.isAbsolute(expanded)
      ? path.normalize(expanded)
      : path.resolve(this.workspaceRoot, expanded);

    const realPath = this.resolveCanonicalPath(resolvedPath);
    const relFromRoot = path.relative(this.canonicalWorkspaceRoot, realPath);
    const isOutside = relFromRoot.startsWith('..') || path.isAbsolute(relFromRoot);

    if (!isOutside) {
      return {
        targetPath,
        resolvedPath,
        realPath,
        isViolation: false,
        boundaryScore: 0.0,
        traversalType: 'INTERNAL',
        reasons: []
      };
    }

    // Outside workspace boundary
    const reasons = [];
    let boundaryScore = 0.5;
    let traversalType = 'PARENT_RELATIVE';

    // 1. Critical OS System Root Topology (top-level non-user system hierarchies)
    const systemDirs = [
      '/etc', '/private/etc', '/proc', '/sys', '/dev',
      '/root', '/private/var/root', '/boot', '/var/run'
    ];
    const isSystemPath = systemDirs.some((dir) =>
      realPath.startsWith(dir) || resolvedPath.startsWith(dir)
    );

    if (isSystemPath) {
      boundaryScore = 1.0;
      traversalType = 'SYSTEM_ROOT';
      reasons.push(`CRITICAL_SYSTEM_PATH_ACCESS: ${realPath}`);
    }

    // 2. Hidden User-Home Credential/Dot-Topology (100% topological — zero hardcoded directory names)
    const home = os.homedir();
    const relHomeReal = path.relative(home, realPath);
    const relHomeLex = path.relative(home, resolvedPath);
    const isUnderHome =
      (!relHomeReal.startsWith('..') && !path.isAbsolute(relHomeReal)) ||
      (!relHomeLex.startsWith('..') && !path.isAbsolute(relHomeLex));
    const firstHomeSeg = (relHomeLex.startsWith('.') ? relHomeLex : relHomeReal).split(path.sep)[0] || '';
    const isCredentialPath = isUnderHome && firstHomeSeg.startsWith('.') && firstHomeSeg.length > 1;

    if (isCredentialPath) {
      boundaryScore = 1.0;
      traversalType = 'SENSITIVE_CREDENTIAL';
      reasons.push(`SENSITIVE_CREDENTIAL_PATH_ACCESS: ${realPath}`);
    }

    // 3. Symlink Escape Detection
    const relLexical = path.relative(this.workspaceRoot, resolvedPath);
    const isSymlinkEscape = !relLexical.startsWith('..') && isOutside;
    if (isSymlinkEscape) {
      if (boundaryScore < 0.8) boundaryScore = 0.8;
      if (traversalType !== 'SYSTEM_ROOT' && traversalType !== 'SENSITIVE_CREDENTIAL') {
        traversalType = 'SYMLINK_ESCAPE';
      }
      reasons.push(`SYMLINK_ESCAPING_WORKSPACE_ROOT: ${resolvedPath} -> ${realPath}`);
    }

    // 4. Relative Depth Traversal
    if (boundaryScore < 0.8) {
      const parentSteps = relFromRoot.split(path.sep).filter((p) => p === '..').length;
      if (parentSteps > 1) {
        boundaryScore = 0.8;
        traversalType = 'DEEP_RELATIVE';
        reasons.push(`DEEP_PARENT_TRAVERSAL: ${parentSteps} steps outside workspace`);
      } else {
        reasons.push('IMMEDIATE_PARENT_TRAVERSAL');
      }
    }

    return {
      targetPath,
      resolvedPath,
      realPath,
      isViolation: true,
      boundaryScore,
      traversalType,
      reasons
    };
  }

  /**
   * Generates a unique radioactive canary dye token.
   * Format: CANARY_DYE_SECRET_<hash>_<random>
   * @param {string} filePath
   * @param {object} [stat=null]
   * @returns {object} CanaryProfile
   */
  generateCanaryToken(filePath, stat = null) {
    const fileHash = crypto
      .createHash('sha256')
      .update(filePath + this.sessionSalt)
      .digest('hex')
      .slice(0, 12);
    const randomEntropy = crypto.randomBytes(6).toString('hex');
    const token = `CANARY_DYE_SECRET_${fileHash}_${randomEntropy}`;

    const inodeKey = stat ? `${stat.dev}:${stat.ino}` : `dev:ino:${fileHash}`;
    const hexLower = Buffer.from(token, 'utf8').toString('hex');

    const representations = {
      raw: token,
      base64: Buffer.from(token, 'utf8').toString('base64'),
      hex: hexLower,
      hexUpper: hexLower.toUpperCase(),
      urlEncoded: encodeURIComponent(token).replace(/_/g, '%5F'),
      urlEncodedLower: encodeURIComponent(token).replace(/_/g, '%5f'),
    };

    const canaryProfile = {
      token,
      inodeKey,
      filePath,
      representations,
      createdAt: Date.now()
    };

    this.canaryRegistry.set(token, canaryProfile);
    return canaryProfile;
  }

  /**
   * Generates synthetic poisoned content containing the canary dye token.
   * Preserves Key-Value, JSON, and PEM syntax while replacing sensitive credential values.
   * @param {string} filePath
   * @param {string|Buffer|null} [originalContent=null]
   * @returns {string}
   */
  getCanaryContent(filePath, originalContent = null) {
    const canary = this.canaryMap.get(filePath) || this.generateCanaryToken(filePath);
    const token = canary.token;

    let contentStr = '';
    if (typeof originalContent === 'string') {
      contentStr = originalContent;
    } else if (Buffer.isBuffer(originalContent)) {
      contentStr = originalContent.toString('utf8');
    } else {
      try {
        contentStr = fs.readFileSync(filePath, 'utf8');
      } catch {
        contentStr = '';
      }
    }

    // 1. PEM Certificate / Private Key
    if (/-----BEGIN\s+[A-Z0-9\s_-]+KEY-----/.test(contentStr)) {
      return `-----BEGIN RSA PRIVATE KEY-----\n${token}\n-----END RSA PRIVATE KEY-----\n`;
    }

    // 2. JSON Format (with recursive nested object poisoning)
    if (contentStr.trim().startsWith('{') && contentStr.trim().endsWith('}')) {
      try {
        const poisonObj = (node) => {
          if (Array.isArray(node)) return node.map(poisonObj);
          if (typeof node === 'object' && node !== null) {
            const out = {};
            for (const [k, v] of Object.entries(node)) {
              out[k] = typeof v === 'object' && v !== null ? poisonObj(v) : token;
            }
            return out;
          }
          return token;
        };
        const obj = JSON.parse(contentStr);
        return JSON.stringify(poisonObj(obj), null, 2);
      } catch {}
    }

    // 3. Key-Value Environment Format
    const lines = contentStr.split('\n');
    const poisonedLines = [];
    let modifiedAny = false;

    for (const line of lines) {
      const kvMatch = line.match(/^([A-Za-z0-9_.-]+)(\s*[:=]\s*)(.*)$/);
      if (kvMatch) {
        const rawVal = kvMatch[3].trim().replace(/^["'`]|["'`]$/g, '');
        // Replace value if it's long enough to be a secret / credential token (>= 12 chars)
        const isCandidateSecret = rawVal.length >= 12;
        if (isCandidateSecret) {
          poisonedLines.push(`${kvMatch[1]}${kvMatch[2]}${token}`);
          modifiedAny = true;
        } else {
          poisonedLines.push(line);
        }
      } else {
        poisonedLines.push(line);
      }
    }

    if (modifiedAny) {
      return poisonedLines.join('\n');
    }

    // 4. Default Fallback
    return `# SYNTHETIC FIREWALL CANARY DECEPTION\nSECRET_KEY=${token}\nAPI_TOKEN=${token}\n`;
  }

  /**
   * Returns canary dye mappings for consumption by the Mirage Chamber.
   * @returns {Map<string, object>}
   */
  getCanaryMap() {
    return this.canaryMap;
  }

  /**
   * Scans text or buffer for presence of any registered canary token across
   * raw, base64, hex (lower/upper), or URL-encoded (upper/lower) representations.
   * @param {string|Buffer} haystack
   * @returns {object|null} Match details or null
   */
  findCanaryInText(haystack) {
    if (!haystack) return null;
    const str = Buffer.isBuffer(haystack) ? haystack.toString('utf8') : String(haystack);

    for (const [token, profile] of this.canaryRegistry.entries()) {
      const reps = profile.representations;
      if (
        str.includes(reps.urlEncoded) ||
        (reps.urlEncodedLower && str.includes(reps.urlEncodedLower))
      ) {
        return { leaked: true, token, representation: 'urlEncoded', filePath: profile.filePath };
      }
      if (str.includes(reps.base64)) {
        return { leaked: true, token, representation: 'base64', filePath: profile.filePath };
      }
      if (
        str.includes(reps.hex) ||
        (reps.hexUpper && str.includes(reps.hexUpper))
      ) {
        return { leaked: true, token, representation: 'hex', filePath: profile.filePath };
      }
      if (str.includes(reps.raw)) {
        return { leaked: true, token, representation: 'raw', filePath: profile.filePath };
      }
    }
    return null;
  }

  /**
   * Checks whether a file path is a protected secret inode.
   * Dynamically profiles unindexed files on demand.
   * @param {string} filePath
   * @returns {boolean}
   */
  isProtected(filePath) {
    const boundary = this.checkBoundary(filePath);
    const realPath = boundary.realPath;

    if (this.protectedPaths.has(realPath)) {
      return true;
    }

    try {
      const stat = fs.statSync(realPath);
      const inodeKey = `${stat.dev}:${stat.ino}`;
      if (this.protectedInodes.has(inodeKey)) {
        return true;
      }
    } catch {
      return false;
    }

    // Dynamic on-demand evaluation for newly created or unindexed files
    const profile = this.profile(filePath);
    return profile.isSecret;
  }

  /**
   * Profiles a file's OS metadata, boundary topology, and content characteristics.
   * @param {string} filePath - Absolute or relative path to inspect
   * @param {string|Buffer|null} [content=null] - Optional pre-loaded content
   * @returns {object} InodeProfile
   */
  profile(filePath, content = null) {
    const boundary = this.checkBoundary(filePath);
    const resolvedPath = boundary.resolvedPath;
    const realPath = boundary.realPath;

    let stat = null;
    let inode = null;
    let dev = null;
    let mode = null;
    let fileSize = 0;
    let isPrivateMode = false;

    try {
      stat = fs.statSync(realPath);
      inode = stat.ino;
      dev = stat.dev;
      mode = stat.mode & 0o777;
      fileSize = stat.size;
      isPrivateMode = this.isOwnerPrivateMode(mode);
    } catch {
      // Non-existent or unreadable file
    }

    const relPath = path.relative(this.canonicalWorkspaceRoot, realPath);
    const isGitIgnored = this.checkGitIgnore(resolvedPath);
    const isSensitiveGitIgnored = isGitIgnored && !this.isBuildCache(relPath);

    // Fast bounds checks
    if (fileSize === 0 && content === null && stat) {
      return {
        path: realPath,
        relativePath: relPath,
        inode,
        dev,
        size: 0,
        isSecret: false,
        score: 0,
        secretScore: 0,
        boundaryViolation: boundary.isViolation,
        boundaryScore: boundary.boundaryScore,
        boundaryReasons: boundary.reasons,
        traversalType: boundary.traversalType,
        entropy: 0.0,
        fileEntropy: 0.0,
        peakEntropy: 0.0,
        maxTokenEntropy: 0.0,
        kvDensity: 0.0,
        isPrivateMode,
        isGitIgnored,
        isSensitiveGitIgnored,
        isBinary: false,
        canaryDyeToken: null,
        canaryProfile: null,
        reasons: ['Empty file']
      };
    }

    // Read file content if not provided
    let rawContent = content;
    if (rawContent === null && stat && stat.isFile() && fileSize <= this.options.maxFileSize) {
      try {
        rawContent = fs.readFileSync(realPath);
      } catch {
        rawContent = null;
      }
    }

    let isBinaryFile = false;
    let fileEntropy = 0.0;
    let peakEntropy = 0.0;
    let maxTokenEntropy = 0.0;
    let kvDensity = 0.0;
    let secretValuesCount = 0;
    let secretTokens = [];
    let hasPemHeader = false;

    if (rawContent !== null && rawContent !== undefined) {
      isBinaryFile = this.isBinary(rawContent);
      if (!isBinaryFile) {
        const textContent = typeof rawContent === 'string' ? rawContent : rawContent.toString('utf8');
        const buf = Buffer.isBuffer(rawContent) ? rawContent : Buffer.from(textContent, 'utf8');

        fileEntropy = this.entropyEngine.byteEntropy(buf);
        const sliding = this.entropyEngine.slidingWindowEntropy(buf, 8);
        peakEntropy = sliding.maxH;

        // Key-Value structural analysis
        const kvResult = this.calculateKvDensity(textContent);
        kvDensity = kvResult.kvDensity;
        secretValuesCount = kvResult.secretValuesCount;
        secretTokens = kvResult.secretTokens;
        hasPemHeader =
          kvResult.isPem ||
          (/(?:^|\r?\n)-----BEGIN\s+[A-Z0-9\s_-]+KEY-----\s*(?:\r?\n)/.test(textContent) &&
            /(?:^|\r?\n)-----END\s+[A-Z0-9\s_-]+KEY-----/.test(textContent));

        // Candidate token entropy analysis
        const candidateTokens = this.entropyEngine.extractCandidateTokens(textContent);
        for (const t of candidateTokens) {
          const res = this.entropyEngine.tokenEntropy(t);
          if (res.h > maxTokenEntropy) maxTokenEntropy = res.h;
          if (res.isSecret && !secretTokens.some((s) => s.token === t)) {
            secretTokens.push(res);
            secretValuesCount++;
          }
        }
      }
    }

    // Multi-factor Scoring Formula: S = min(100, S_kv + S_entropy + S_perms + S_git)
    let secretScore = 0;
    const reasons = [];

    if (!isBinaryFile && rawContent !== null && rawContent !== undefined) {
      if (hasPemHeader) {
        secretScore = 100;
        reasons.push('Cryptographic PEM private key header detected');
      } else {
        let sKv = 0;
        if (kvDensity >= this.options.kvDensityThreshold) {
          sKv = Math.round(30 * kvDensity);
          secretScore += sKv;
          reasons.push(`High Key-Value density (${(kvDensity * 100).toFixed(0)}%)`);
        }

        let sEntropy = 0;
        if (secretTokens.length > 0) {
          sEntropy = 40;
          secretScore += sEntropy;
          reasons.push(`Contains ${secretTokens.length} high-entropy secret token(s)`);
        } else if (peakEntropy >= this.options.fileEntropyThreshold) {
          sEntropy = 30;
          secretScore += sEntropy;
          reasons.push(`High peak sliding Shannon entropy: ${peakEntropy.toFixed(2)}`);
        } else if (fileEntropy >= this.options.fileEntropyThreshold) {
          sEntropy = 15;
          secretScore += sEntropy;
          reasons.push(`High whole-file Shannon entropy: ${fileEntropy.toFixed(2)}`);
        }

        let sPerms = 0;
        if (isPrivateMode) {
          sPerms = 35;
          secretScore += sPerms;
          reasons.push(`Owner-only private POSIX permissions (0600/0400)`);
        }

        let sGit = 0;
        if (isSensitiveGitIgnored) {
          sGit = 25;
          secretScore += sGit;
          reasons.push('Git-ignored private developer configuration');
        }
      }
    } else if (isPrivateMode) {
      secretScore += 35;
      reasons.push('Owner-only private POSIX permissions (0600/0400)');
    }

    secretScore = Math.min(100, secretScore);

    // Secret Decision Rule: isSecret if PEM block or S >= 70 or (rho_kv >= 0.50 and secret tokens exist)
    const isSecret = hasPemHeader ||
      (secretScore >= this.options.secretScoreThreshold) ||
      (kvDensity >= this.options.kvDensityThreshold && secretTokens.length > 0);

    let canaryDyeToken = null;
    let canaryProfile = null;

    if (isSecret) {
      canaryProfile = this.generateCanaryToken(realPath, stat);
      canaryDyeToken = canaryProfile.token;

      if (inode !== null && dev !== null) {
        this.protectedInodes.set(`${dev}:${inode}`, canaryProfile);
      }
      this.protectedPaths.set(realPath, canaryProfile);
      this.canaryMap.set(realPath, canaryProfile);
    }

    const effectiveEntropy = Math.max(fileEntropy, peakEntropy, maxTokenEntropy);

    return {
      path: realPath,
      relativePath: relPath,
      inode,
      dev,
      size: fileSize,
      isSecret,
      score: secretScore,
      secretScore,
      boundaryViolation: boundary.isViolation,
      boundaryScore: boundary.boundaryScore,
      boundaryReasons: boundary.reasons,
      traversalType: boundary.traversalType,
      entropy: parseFloat(effectiveEntropy.toFixed(3)),
      fileEntropy: parseFloat(fileEntropy.toFixed(3)),
      peakEntropy: parseFloat(peakEntropy.toFixed(3)),
      maxTokenEntropy: parseFloat(maxTokenEntropy.toFixed(3)),
      kvDensity: parseFloat(kvDensity.toFixed(3)),
      secretTokensFound: secretTokens.length,
      isPrivateMode,
      isGitIgnored,
      isSensitiveGitIgnored,
      isPem: hasPemHeader,
      isBinary: isBinaryFile,
      canaryDyeToken,
      canaryProfile,
      reasons
    };
  }

  /**
   * Recursively scans workspace files, tracking OS (dev, ino), and mapping canary dye tokens.
   * @param {object} [options={}]
   * @returns {object} WorkspaceProfileResult
   */
  profileWorkspace(options = {}) {
    const startTime = performance.now();
    const protectedFiles = [];
    let scannedFiles = 0;

    const walk = (dir, depth = 0) => {
      if (depth > 12) return;

      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          if (!this.options.ignoredDirs.includes(entry.name)) {
            walk(fullPath, depth + 1);
          }
        } else if (entry.isFile()) {
          scannedFiles++;
          const p = this.profile(fullPath);
          if (p.isSecret) {
            protectedFiles.push(p);
          }
        }
      }
    };

    walk(this.canonicalWorkspaceRoot);
    const durationMs = performance.now() - startTime;

    return {
      workspaceRoot: this.canonicalWorkspaceRoot,
      scannedFiles,
      protectedCount: protectedFiles.length,
      protectedFiles,
      durationMs
    };
  }
}

module.exports = {
  InodeProfiler,
  EntropyEngine
};
