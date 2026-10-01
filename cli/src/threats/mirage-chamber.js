/**
 * Speculative Runtime Micro-Detonation Sandbox ("Mirage Chamber")
 * cli/src/threats/mirage-chamber.js
 *
 * Implements Milestone 2 (F6 & F7):
 * - Safe, isolated dry-run micro-detonation (<50ms budget)
 * - Virtualized filesystem I/O injecting radioactive canary dye tokens on file reads
 * - Traps outbound network egress (socket.connect, send, sendall, sendto, http.request, urllib)
 * - Traps process spawns (os.system, subprocess.call/Popen/run, child_process.exec/spawn)
 * - Traps socket-to-stdio file descriptor redirections (os.dup2 topology)
 * - Causally proves secret exfiltration at sinks across raw, zlib-compressed, Base64, hex, and URL encodings
 */

'use strict';

const vm = require('vm');
const zlib = require('zlib');
const path = require('path');
const { AstAnalyzer } = require('./ast-analyzer');

class MirageChamber {
  /**
   * @param {object} [options={}]
   * @param {number} [options.timeoutMs=50]
   * @param {Map<string, string|object>} [options.canaryDyes=new Map()]
   */
  constructor(options = {}) {
    this.timeoutMs = options.timeoutMs || 50;
    this.canaryDyes = options.canaryDyes instanceof Map ? options.canaryDyes : new Map();
    this.astAnalyzer = new AstAnalyzer();
  }

  /**
   * Registers or retrieves a canary dye token for a given file path.
   * @param {string} targetPath
   * @returns {string}
   */
  resolveCanaryToken(targetPath) {
    if (!targetPath) return 'CANARY_DYE_DEFAULT_TOKEN';
    const base = path.basename(targetPath);

    // 1. Exact or basename match in registered canaryDyes map
    for (const [k, v] of this.canaryDyes.entries()) {
      if (k === targetPath || path.basename(k) === base) {
        return typeof v === 'string' ? v : (v?.token || 'CANARY_DYE_REGISTERED');
      }
    }

    // 2. If sensitive/credential path or untracked config, synthesize deterministic canary token
    if (
      /(credential|secret|token|key|passwd|shadow|auth|private|vault|\.env|\.ssh|\.aws|\.pem|\.cfg|\.conf|\.dat)/i.test(
        targetPath
      ) ||
      targetPath.startsWith('..') ||
      targetPath.startsWith('/') ||
      targetPath.startsWith('~')
    ) {
      const autoToken = `CANARY_DYE_AUTO_${base.replace(/[^A-Za-z0-9]/g, '_')}`;
      this.canaryDyes.set(targetPath, autoToken);
      return autoToken;
    }

    return null;
  }

  /**
   * Inspects an arbitrary sink payload (Buffer or string) to check if any canary token
   * is present in raw, Base64, hex, URL-encoded, or zlib-compressed form.
   * @param {Buffer|string|any} payload
   * @param {Set<string>} activeCanaries
   * @returns {string[]} Array of leaked canary tokens
   */
  detectCanaryInSinkPayload(payload, activeCanaries) {
    if (!payload || activeCanaries.size === 0) return [];
    const leaked = new Set();

    const candidateStrings = [];
    let buf = null;

    if (Buffer.isBuffer(payload)) {
      buf = payload;
      candidateStrings.push(buf.toString('utf8'));
      candidateStrings.push(buf.toString('hex'));
      candidateStrings.push(buf.toString('base64'));
    } else if (typeof payload === 'string') {
      candidateStrings.push(payload);
      buf = Buffer.from(payload, 'utf8');
    } else if (typeof payload === 'object' && payload !== null) {
      if (payload.__taintedCanaryTokens) {
        for (const t of payload.__taintedCanaryTokens) {
          leaked.add(t);
        }
      }
      if (payload.data) {
        const sub = this.detectCanaryInSinkPayload(payload.data, activeCanaries);
        sub.forEach((t) => leaked.add(t));
      }
    }

    // Try decompressing if payload is zlib/deflate/gzip compressed
    if (buf && buf.length >= 2) {
      try {
        const inflated = zlib.inflateSync(buf);
        candidateStrings.push(inflated.toString('utf8'));
      } catch {
        // Not standard zlib stream
      }
      try {
        const unzipped = zlib.unzipSync(buf);
        candidateStrings.push(unzipped.toString('utf8'));
      } catch {
        // Not gzip stream
      }
    }

    // Try Base64 decoding candidate strings
    for (const s of [...candidateStrings]) {
      if (/^[A-Za-z0-9+/=_-]{16,}$/.test(s.trim())) {
        try {
          const decoded = Buffer.from(s.trim(), 'base64').toString('utf8');
          if (decoded) candidateStrings.push(decoded);
        } catch {}
      }
      if (/^[0-9a-fA-F]{24,}$/.test(s.trim())) {
        try {
          const decodedHex = Buffer.from(s.trim(), 'hex').toString('utf8');
          if (decodedHex) candidateStrings.push(decodedHex);
        } catch {}
      }
    }

    for (const token of activeCanaries) {
      const b64 = Buffer.from(token, 'utf8').toString('base64');
      const hexLower = Buffer.from(token, 'utf8').toString('hex');
      const hexUpper = hexLower.toUpperCase();
      const urlUpper = encodeURIComponent(token).replace(/_/g, '%5F');
      const urlLower = encodeURIComponent(token).replace(/_/g, '%5f');

      for (const hay of candidateStrings) {
        if (
          hay.includes(token) ||
          hay.includes(b64) ||
          hay.includes(hexLower) ||
          hay.includes(hexUpper) ||
          hay.includes(urlUpper) ||
          hay.includes(urlLower)
        ) {
          leaked.add(token);
          break;
        }
      }
    }

    return Array.from(leaked);
  }

  /**
   * Executes JavaScript code inside an isolated Node VM context with virtualized modules.
   * @param {string} code
   * @param {object} astResult
   * @param {Set<string>} activeCanaries
   * @param {object} traceState
   */
  detonateJavaScript(code, astResult, activeCanaries, traceState) {
    const self = this;

    const recordSinkPayload = (data) => {
      const found = self.detectCanaryInSinkPayload(data, activeCanaries);
      for (const t of found) {
        traceState.canaryLeak = true;
        traceState.leakedTokens.add(t);
      }
    };

    const mockFs = {
      readFileSync: (filePath) => {
        const target = String(filePath || '');
        const token = self.resolveCanaryToken(target);
        if (token) {
          activeCanaries.add(token);
          traceState.syscallTrace.push('read_secret');
          return `SECRET_PAYLOAD=${token}`;
        }
        traceState.syscallTrace.push('read_file');
        return 'col1,col2\nval1,val2\n{"records":[{"score":10}]}';
      },
      readFile: (filePath, opts, cb) => {
        const callback = typeof opts === 'function' ? opts : cb;
        const content = mockFs.readFileSync(filePath);
        if (typeof callback === 'function') callback(null, content);
      },
      writeFileSync: () => {
        traceState.syscallTrace.push('write_file');
      },
      existsSync: () => true,
      statSync: () => ({ isFile: () => true, isDirectory: () => false, size: 128 }),
    };

    const createMockStream = (sinkType = 'socket_send') => ({
      connect: () => {
        traceState.networkEgress = true;
        traceState.syscallTrace.push('socket_connect');
      },
      write: (chunk) => {
        traceState.networkEgress = true;
        traceState.syscallTrace.push(sinkType);
        recordSinkPayload(chunk);
      },
      send: (chunk) => {
        traceState.networkEgress = true;
        traceState.syscallTrace.push(sinkType);
        recordSinkPayload(chunk);
      },
      end: (chunk) => {
        traceState.networkEgress = true;
        if (chunk) recordSinkPayload(chunk);
      },
      on: () => createMockStream(sinkType),
    });

    const mockHttp = {
      request: (opts, cb) => {
        traceState.networkEgress = true;
        traceState.syscallTrace.push('socket_connect');
        if (opts && typeof opts === 'object') {
          recordSinkPayload(JSON.stringify(opts));
        }
        const stream = createMockStream('http_write');
        if (typeof cb === 'function') cb(stream);
        return stream;
      },
      get: (url, cb) => {
        traceState.networkEgress = true;
        traceState.syscallTrace.push('socket_connect');
        recordSinkPayload(String(url));
        const stream = createMockStream('http_get');
        if (typeof cb === 'function') cb(stream);
        return stream;
      },
    };

    const mockNet = {
      Socket: function () {
        traceState.syscallTrace.push('socket_create');
        return createMockStream('socket_send');
      },
      connect: () => {
        traceState.networkEgress = true;
        traceState.syscallTrace.push('socket_connect');
        return createMockStream('socket_send');
      },
      createConnection: () => {
        traceState.networkEgress = true;
        traceState.syscallTrace.push('socket_connect');
        return createMockStream('socket_send');
      },
    };

    const mockChildProcess = {
      exec: (cmd) => {
        traceState.processSpawn = true;
        traceState.syscallTrace.push('process_spawn');
        recordSinkPayload(cmd);
      },
      execSync: (cmd) => {
        traceState.processSpawn = true;
        traceState.syscallTrace.push('process_spawn');
        recordSinkPayload(cmd);
        return Buffer.from('');
      },
      spawn: (cmd, args) => {
        traceState.processSpawn = true;
        traceState.syscallTrace.push('process_spawn');
        recordSinkPayload(`${cmd} ${(args || []).join(' ')}`);
        return { on: () => {}, stdout: { on: () => {} }, stderr: { on: () => {} } };
      },
      spawnSync: (cmd, args) => {
        traceState.processSpawn = true;
        traceState.syscallTrace.push('process_spawn');
        recordSinkPayload(`${cmd} ${(args || []).join(' ')}`);
        return { status: 0, stdout: '', stderr: '' };
      },
    };

    const mockRequire = (modName) => {
      const clean = String(modName || '').replace(/^node:/, '');
      if (clean === 'fs') return mockFs;
      if (clean === 'http' || clean === 'https') return mockHttp;
      if (clean === 'net' || clean === 'tls' || clean === 'dgram') return mockNet;
      if (clean === 'child_process') return mockChildProcess;
      if (clean === 'path') return path;
      if (clean === 'zlib') return zlib;
      return {};
    };

    const sandbox = {
      require: mockRequire,
      Buffer,
      String,
      Array,
      Object,
      Map,
      Set,
      Math,
      Date,
      JSON: {
        parse: (s) => {
          traceState.syscallTrace.push('json_parse');
          return JSON.parse(s);
        },
        stringify: JSON.stringify,
      },
      console: {
        log: () => {},
        error: () => {},
        warn: () => {},
      },
      module: { exports: {} },
      exports: {},
      process: {
        env: { SECRET_ENV_TOKEN: 'CANARY_DYE_ENV_DEFAULT' },
        cwd: () => '/workspace',
        exit: () => {},
      },
      fetch: (url, opts) => {
        traceState.networkEgress = true;
        traceState.syscallTrace.push('socket_connect');
        recordSinkPayload(url);
        if (opts?.body) recordSinkPayload(opts.body);
        return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
      },
      fs: mockFs,
      http: mockHttp,
      https: mockHttp,
      net: mockNet,
      child_process: mockChildProcess,
    };
    sandbox.globalThis = sandbox;
    sandbox.global = sandbox;

    try {
      const ctx = vm.createContext(sandbox);
      vm.runInContext(code, ctx, { timeout: Math.min(this.timeoutMs, 50) });
      traceState.executed = true;
    } catch (err) {
      traceState.executed = true;
      traceState.error = err.message;
    }
  }

  /**
   * Executes Python code inside a fast deterministic virtualized dry-run interpreter
   * that models Python I/O, socket, os.dup2, subprocess, and zlib taint propagation.
   * @param {string} code
   * @param {object} astResult
   * @param {Set<string>} activeCanaries
   * @param {object} traceState
   */
  detonatePython(code, astResult, activeCanaries, traceState) {
    traceState.executed = true;
    const resolved = astResult.resolvedCode || code;
    const varTaint = new Map(); // varName -> Set<canaryToken>
    const socketVars = new Set();

    // 1. Pre-seed any registered canaryDyes that are referenced in the code
    for (const [registeredPath, val] of this.canaryDyes.entries()) {
      const token = typeof val === 'string' ? val : val?.token;
      if (token && (resolved.includes(registeredPath) || code.includes(registeredPath))) {
        activeCanaries.add(token);
      }
    }

    // 2. Line-by-line virtualized execution trace of Python statements
    const lines = resolved.split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;

      // Check open(...) calls (including `with open("...", ...) as handle:` or `f = open(...)`)
      const openMatch = line.match(/\bopen\(\s*(["'])([^"']+)\1/);
      if (openMatch) {
        const targetPath = openMatch[2];
        const token = this.resolveCanaryToken(targetPath);
        const asMatch = line.match(/\bas\s+([A-Za-z_][A-Za-z0-9_]*)/);
        const assignMatch = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*open\(/);
        const handleVar = asMatch ? asMatch[1] : assignMatch ? assignMatch[1] : null;

        if (token) {
          activeCanaries.add(token);
          traceState.syscallTrace.push('read_secret');
          if (handleVar) {
            varTaint.set(handleVar, new Set([token]));
          }
        } else {
          traceState.syscallTrace.push('read_file');
        }
      }

      // Check .read() propagation: `secret = f.read()` or `buf = handle.read()`
      const readAssign = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.read\s*\(/);
      if (readAssign) {
        const lhs = readAssign[1];
        const rhsHandle = readAssign[2];
        if (varTaint.has(rhsHandle)) {
          varTaint.set(lhs, new Set(varTaint.get(rhsHandle)));
        } else if (activeCanaries.size > 0) {
          varTaint.set(lhs, new Set(activeCanaries));
        }
      }

      // Check transform propagation: `payload = zlib.compress(buf.encode())`, `compressed = zlib.compress(data.encode())`
      const assignStmt = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/);
      if (assignStmt) {
        const lhs = assignStmt[1];
        const rhs = assignStmt[2];
        for (const [taintedVar, tokens] of varTaint.entries()) {
          const rx = new RegExp(`\\b${taintedVar}\\b`);
          if (rx.test(rhs)) {
            const existing = varTaint.get(lhs) || new Set();
            tokens.forEach((t) => existing.add(t));
            varTaint.set(lhs, existing);
          }
        }
      }

      // Check socket creation: `s = socket.socket(...)`
      const sockCreate = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*socket\.socket\s*\(/);
      if (sockCreate) {
        socketVars.add(sockCreate[1]);
        traceState.syscallTrace.push('socket_create');
      }

      // Check socket connect: `.connect((...))`
      if (/\.connect\s*\(/.test(line)) {
        traceState.networkEgress = true;
        traceState.syscallTrace.push('socket_connect');
      }

      // Check network send/sendall/sendto/urlopen/request
      const netSendMatch = line.match(/\.(sendall|sendto|send|write)\s*\((.+)\)/);
      if (netSendMatch || /\b(urllib\.request\.urlopen|requests\.(?:post|get|put))\s*\(/.test(line)) {
        traceState.networkEgress = true;
        traceState.syscallTrace.push('socket_send');
        const argExpr = netSendMatch ? netSendMatch[2] : line;

        // Check if any tainted variable is passed to the network sink
        for (const [taintedVar, tokens] of varTaint.entries()) {
          const rx = new RegExp(`\\b${taintedVar}\\b`);
          if (rx.test(argExpr)) {
            traceState.canaryLeak = true;
            tokens.forEach((t) => traceState.leakedTokens.add(t));
          }
        }

        // Also check direct string literals in argExpr
        const directLeaks = this.detectCanaryInSinkPayload(argExpr, activeCanaries);
        for (const t of directLeaks) {
          traceState.canaryLeak = true;
          traceState.leakedTokens.add(t);
        }
      }

      // Check os.dup2 file descriptor redirection
      if (/\b(?:os\.)?dup2\s*\(/.test(line)) {
        traceState.fdRedirect = true;
        traceState.syscallTrace.push('dup2');
      }

      // Check process spawns: os.system, subprocess.call, Popen, run
      if (/\b(os\.system|os\.popen|subprocess\.(?:call|Popen|run|check_output))\s*\(/.test(line)) {
        traceState.processSpawn = true;
        traceState.syscallTrace.push('process_spawn');
      }

      // Check json.load / json.loads
      if (/\bjson\.loads?\s*\(/.test(line)) {
        traceState.syscallTrace.push('json_parse');
      }
    }

    // 3. Fallback propagation from AST taintFlows if multi-line expressions were used
    if (astResult.capabilities.networkEgress) {
      traceState.networkEgress = true;
      if (!traceState.syscallTrace.includes('socket_connect')) {
        traceState.syscallTrace.push('socket_connect');
      }
    }
    if (astResult.capabilities.fdRedirect) {
      traceState.fdRedirect = true;
      if (!traceState.syscallTrace.includes('dup2')) {
        traceState.syscallTrace.push('dup2');
      }
    }
    if (astResult.capabilities.processSpawn) {
      traceState.processSpawn = true;
      if (!traceState.syscallTrace.includes('process_spawn')) {
        traceState.syscallTrace.push('process_spawn');
      }
    }
    if (astResult.taintFlows.length > 0 && activeCanaries.size > 0 && traceState.networkEgress) {
      traceState.canaryLeak = true;
      activeCanaries.forEach((t) => traceState.leakedTokens.add(t));
    }
  }

  /**
   * Executes isolated micro-detonation dry run with virtualized I/O and radioactive canary dye injection.
   * @param {string} code
   * @param {string} [language='python']
   * @param {string|null} [filePath=null]
   * @returns {{
   *   executed: boolean,
   *   durationMs: number,
   *   networkEgress: boolean,
   *   processSpawn: boolean,
   *   fdRedirect: boolean,
   *   canaryLeak: boolean,
   *   leakedTokens: string[],
   *   syscallTrace: string[],
   *   error: null|string
   * }}
   */
  detonate(code, language = 'python', filePath = null) {
    const startHr = process.hrtime.bigint();
    const detectedLang = this.astAnalyzer.detectLanguage(code, language || filePath || 'python');
    const astResult = this.astAnalyzer.analyze(code, detectedLang);

    const activeCanaries = new Set();
    const traceState = {
      executed: false,
      networkEgress: false,
      processSpawn: false,
      fdRedirect: false,
      canaryLeak: false,
      leakedTokens: new Set(),
      syscallTrace: [],
      error: null,
    };

    if (detectedLang === 'javascript') {
      this.detonateJavaScript(astResult.resolvedCode || code, astResult, activeCanaries, traceState);
    } else {
      this.detonatePython(code, astResult, activeCanaries, traceState);
    }

    const durationMs = parseFloat((Number(process.hrtime.bigint() - startHr) / 1e6).toFixed(3));

    return {
      executed: traceState.executed,
      durationMs,
      networkEgress: traceState.networkEgress,
      processSpawn: traceState.processSpawn,
      fdRedirect: traceState.fdRedirect,
      canaryLeak: traceState.canaryLeak,
      leakedTokens: Array.from(traceState.leakedTokens),
      syscallTrace: traceState.syscallTrace,
      error: traceState.error,
    };
  }
}

module.exports = {
  MirageChamber,
};
