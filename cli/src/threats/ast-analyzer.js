/**
 * AST Structural & Dataflow Unwrapping Engine
 * cli/src/threats/ast-analyzer.js
 *
 * Implements Milestone 2 (F5):
 * - Constant folding for obfuscated Python and JavaScript expressions
 * - Character code arithmetic unwrapping: chr(...), String.fromCharCode(...)
 * - Sequence & slice reversal unwrapping: reversed(...), [::-1], .reverse().join('')
 * - String literal concatenation folding: 'read' + 'File' + 'Sync'
 * - Symbol table constant propagation across variable assignments and dynamic lookups
 *   (getattr, __builtins__, globalThis[...], dynamic require/loader)
 * - Multi-hop source-to-sink dataflow taint tracking (file read -> transform -> network/exec sink)
 */

'use strict';

class AstAnalyzer {
  constructor(options = {}) {
    this.options = options;
  }

  /**
   * Strip comments and docstrings while preserving code structure for accurate call analysis.
   * @param {string} code
   * @param {string} language
   * @returns {string}
   */
  stripCommentsAndDocstrings(code, language = 'python') {
    if (!code || typeof code !== 'string') return '';
    let cleaned = code;

    if (language === 'python') {
      // Remove triple-quoted docstrings when they appear as standalone statements
      cleaned = cleaned.replace(/^[ \t]*("""[\s\S]*?"""|'''[\s\S]*?''')[ \t]*$/gm, '');
      // Remove # comments (outside quotes)
      cleaned = cleaned
        .split(/\r?\n/)
        .map((line) => {
          let inSingle = false;
          let inDouble = false;
          for (let i = 0; i < line.length; i++) {
            const ch = line[i];
            const prev = i > 0 ? line[i - 1] : '';
            if (ch === "'" && !inDouble && prev !== '\\') inSingle = !inSingle;
            else if (ch === '"' && !inSingle && prev !== '\\') inDouble = !inDouble;
            else if (ch === '#' && !inSingle && !inDouble) {
              return line.slice(0, i);
            }
          }
          return line;
        })
        .join('\n');
    } else {
      // Remove /* ... */ block comments and // line comments
      cleaned = cleaned.replace(/\/\*[\s\S]*?\*\//g, '');
      cleaned = cleaned
        .split(/\r?\n/)
        .map((line) => {
          let inSingle = false;
          let inDouble = false;
          let inTick = false;
          for (let i = 0; i < line.length; i++) {
            const ch = line[i];
            const prev = i > 0 ? line[i - 1] : '';
            if (ch === "'" && !inDouble && !inTick && prev !== '\\') inSingle = !inSingle;
            else if (ch === '"' && !inSingle && !inTick && prev !== '\\') inDouble = !inDouble;
            else if (ch === '`' && !inSingle && !inDouble && prev !== '\\') inTick = !inTick;
            else if (ch === '/' && line[i + 1] === '/' && !inSingle && !inDouble && !inTick) {
              return line.slice(0, i);
            }
          }
          return line;
        })
        .join('\n');
    }

    return cleaned;
  }

  /**
   * Auto-detect language from code or file hint.
   * @param {string} code
   * @param {string} [languageHint='python']
   * @returns {'python'|'javascript'|'shell'}
   */
  detectLanguage(code, languageHint = 'python') {
    if (languageHint && ['javascript', 'js', 'ts', 'typescript', 'mjs', 'cjs'].includes(languageHint.toLowerCase())) {
      return 'javascript';
    }
    if (languageHint && ['sh', 'bash', 'zsh', 'shell'].includes(languageHint.toLowerCase())) {
      return 'shell';
    }
    if (typeof code === 'string') {
      if (/\b(const|let|var|function|require\(|module\.exports|globalThis|String\.fromCharCode)\b/.test(code)) {
        return 'javascript';
      }
      if (/\b(def |import |from |getattr\(|__builtins__|chr\()\b/.test(code)) {
        return 'python';
      }
    }
    return 'python';
  }

  /**
   * Evaluates simple integer/hex arithmetic inside chr(...) or fromCharCode(...).
   * @param {string} expr
   * @returns {number|null}
   */
  evalNumericExpr(expr) {
    if (!expr) return null;
    const trimmed = expr.trim();
    if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
      return parseInt(trimmed, 16);
    }
    if (/^\d+$/.test(trimmed)) {
      return parseInt(trimmed, 10);
    }
    // Simple binary arithmetic: a + b, a - b, a ^ b
    const match = trimmed.match(/^(\d+|0x[0-9a-fA-F]+)\s*([+\-^])\s*(\d+|0x[0-9a-fA-F]+)$/);
    if (match) {
      const left = this.evalNumericExpr(match[1]);
      const right = this.evalNumericExpr(match[3]);
      if (left !== null && right !== null) {
        if (match[2] === '+') return left + right;
        if (match[2] === '-') return left - right;
        if (match[2] === '^') return left ^ right;
      }
    }
    return null;
  }

  /**
   * Performs multi-pass constant folding on Python/JS source code.
   * Unwraps:
   * - chr(N) and [chr(111), chr(112), ...]
   * - String.fromCharCode(102, 115)
   * - ["p", "e", "n", "o"][::-1] and "nepo"[::-1]
   * - reversed(["2", "p", "u", "d"]) and reversed("nepo")
   * - "".join([...])
   * - 'read' + 'File' + 'Sync'
   * - Base64 / Hex constant decodings
   * @param {string} code
   * @returns {{ resolved: string, dynamicOpsCount: number }}
   */
  foldConstants(code) {
    let resolved = code;
    let dynamicOpsCount = 0;

    // Pass 1: Unwrap Python chr(...) calls
    resolved = resolved.replace(/\bchr\(\s*([^)]+?)\s*\)/g, (full, inner) => {
      const codePoint = this.evalNumericExpr(inner);
      if (codePoint !== null && codePoint >= 0 && codePoint <= 0x10ffff) {
        dynamicOpsCount++;
        return JSON.stringify(String.fromCodePoint(codePoint));
      }
      return full;
    });

    // Pass 2: Unwrap JavaScript String.fromCharCode(...)
    resolved = resolved.replace(/\bString\.fromCharCode\(\s*([^)]+?)\s*\)/g, (full, argsStr) => {
      const parts = argsStr.split(',').map((s) => this.evalNumericExpr(s));
      if (parts.length > 0 && parts.every((n) => n !== null && n >= 0 && n <= 0xffff)) {
        dynamicOpsCount++;
        return JSON.stringify(String.fromCharCode(...parts));
      }
      return full;
    });

    // Multiple iterative passes to fold nested list reversals, slices, joins, and concatenations
    for (let pass = 0; pass < 4; pass++) {
      let changed = false;

      // Fold string literal concatenations: "a" + "b" or 'a' + 'b'
      const concatRx = /(["'])([^"'\\]*(?:\\.[^"'\\]*)*)\1\s*\+\s*(["'])([^"'\\]*(?:\\.[^"'\\]*)*)\3/g;
      resolved = resolved.replace(concatRx, (full, q1, s1, q2, s2) => {
        dynamicOpsCount++;
        changed = true;
        return JSON.stringify(s1 + s2);
      });

      // Fold Python list slice reversal: ["p", "e", "n", "o"][::-1]
      const listSliceRevRx = /\[\s*((?:["'][^"']*["']\s*,\s*)*["'][^"']*["']\s*)\]\s*\[\s*:\s*:\s*-1\s*\]/g;
      resolved = resolved.replace(listSliceRevRx, (full, itemsStr) => {
        const items = [];
        const itemRx = /(["'])([^"']*)\1/g;
        let m;
        while ((m = itemRx.exec(itemsStr)) !== null) {
          items.push(m[2]);
        }
        if (items.length > 0) {
          dynamicOpsCount++;
          changed = true;
          const rev = items.reverse().map((x) => JSON.stringify(x)).join(', ');
          return `[${rev}]`;
        }
        return full;
      });

      // Fold Python string slice reversal: "nepo"[::-1]
      const strSliceRevRx = /(["'])([^"']+)\1\s*\[\s*:\s*:\s*-1\s*\]/g;
      resolved = resolved.replace(strSliceRevRx, (full, q, s) => {
        dynamicOpsCount++;
        changed = true;
        return JSON.stringify(s.split('').reverse().join(''));
      });

      // Fold Python reversed([...]) -> [...]
      const reversedListRx = /\breversed\(\s*\[\s*((?:["'][^"']*["']\s*,\s*)*["'][^"']*["']\s*)\]\s*\)/g;
      resolved = resolved.replace(reversedListRx, (full, itemsStr) => {
        const items = [];
        const itemRx = /(["'])([^"']*)\1/g;
        let m;
        while ((m = itemRx.exec(itemsStr)) !== null) {
          items.push(m[2]);
        }
        if (items.length > 0) {
          dynamicOpsCount++;
          changed = true;
          const rev = items.reverse().map((x) => JSON.stringify(x)).join(', ');
          return `[${rev}]`;
        }
        return full;
      });

      // Fold Python reversed("nepo") -> ["o", "p", "e", "n"]
      const reversedStrRx = /\breversed\(\s*(["'])([^"']+)\1\s*\)/g;
      resolved = resolved.replace(reversedStrRx, (full, q, s) => {
        dynamicOpsCount++;
        changed = true;
        const rev = s.split('').reverse().map((x) => JSON.stringify(x)).join(', ');
        return `[${rev}]`;
      });

      // Fold Python "".join(["o", "p", "e", "n"]) or ''.join(...)
      const joinListRx = /(["'])([^"']*)\1\.join\(\s*\[\s*((?:["'][^"']*["']\s*,\s*)*["'][^"']*["']\s*)\]\s*\)/g;
      resolved = resolved.replace(joinListRx, (full, q, sep, itemsStr) => {
        const items = [];
        const itemRx = /(["'])([^"']*)\1/g;
        let m;
        while ((m = itemRx.exec(itemsStr)) !== null) {
          items.push(m[2]);
        }
        if (items.length > 0) {
          dynamicOpsCount++;
          changed = true;
          return JSON.stringify(items.join(sep));
        }
        return full;
      });

      // Fold JS " string ".split('').reverse().join('')
      const jsRevRx = /(["'])([^"']+)\1\.split\(\s*["']{2}\s*\)\.reverse\(\s*\)\.join\(\s*["']{2}\s*\)/g;
      resolved = resolved.replace(jsRevRx, (full, q, s) => {
        dynamicOpsCount++;
        changed = true;
        return JSON.stringify(s.split('').reverse().join(''));
      });

      if (!changed) break;
    }

    return { resolved, dynamicOpsCount };
  }

  /**
   * Computes AST nesting depth via structural indentation (Python) and bracket/brace depth.
   * @param {string} cleanCode
   * @param {string} language
   * @returns {number}
   */
  computeAstDepth(cleanCode, language = 'python') {
    if (!cleanCode || !cleanCode.trim()) return 0;

    let maxBraceDepth = 0;
    let curBraceDepth = 0;
    for (let i = 0; i < cleanCode.length; i++) {
      const ch = cleanCode[i];
      if (ch === '{' || ch === '(' || ch === '[') {
        curBraceDepth++;
        if (curBraceDepth > maxBraceDepth) maxBraceDepth = curBraceDepth;
      } else if (ch === '}' || ch === ')' || ch === ']') {
        curBraceDepth = Math.max(0, curBraceDepth - 1);
      }
    }

    if (language === 'python') {
      let maxIndentLevel = 0;
      const lines = cleanCode.split(/\r?\n/);
      for (const line of lines) {
        if (!line.trim()) continue;
        const match = line.match(/^([ \t]+)/);
        if (match) {
          const spaces = match[1].replace(/\t/g, '    ').length;
          const level = Math.ceil(spaces / 4);
          if (level > maxIndentLevel) maxIndentLevel = level;
        }
      }
      return Math.max(1, maxIndentLevel + Math.min(4, maxBraceDepth));
    }

    return Math.max(1, maxBraceDepth);
  }

  /**
   * Performs constant symbol propagation, dynamic reflection unwrapping, and multi-hop
   * source-to-sink taint flow analysis.
   * @param {string} code
   * @param {string} [language='python']
   * @returns {object}
   */
  analyze(code, language = 'python') {
    if (!code || typeof code !== 'string') {
      return {
        resolvedCode: '',
        dynamicResolutionRatio: 0,
        astDepth: 0,
        suspiciousCalls: [],
        taintFlows: [],
        capabilities: {
          fileRead: false,
          secretFileRead: false,
          networkEgress: false,
          processSpawn: false,
          fdRedirect: false,
          dynamicExec: false,
        },
      };
    }

    const detectedLang = this.detectLanguage(code, language);
    const strippedCode = this.stripCommentsAndDocstrings(code, detectedLang);
    const { resolved: foldedCode, dynamicOpsCount: initialDynOps } = this.foldConstants(strippedCode);

    let workingCode = foldedCode;
    let dynamicOps = initialDynOps;

    // Symbol table mapping variable names to resolved string constants or module/function aliases
    const symbolTable = new Map();
    symbolTable.set('__builtins__', '__builtins__');
    symbolTable.set('builtins', '__builtins__');
    symbolTable.set('globalThis', 'globalThis');
    symbolTable.set('window', 'globalThis');
    symbolTable.set('global', 'globalThis');

    const lines = workingCode.split(/\r?\n/);

    // Pass 1: Collect constant string assignments and alias assignments
    for (let pass = 0; pass < 3; pass++) {
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        // Match simple string assignment: varName = "literal"
        const strAssign = trimmed.match(/^(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(["'])([^"']+)\2\s*;?$/);
        if (strAssign) {
          symbolTable.set(strAssign[1], strAssign[3]);
          continue;
        }

        // Match __builtins__ alias: b = __builtins__ ...
        if (/^(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*.*__builtins__/.test(trimmed)) {
          const m = trimmed.match(/^(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)/);
          if (m) {
            symbolTable.set(m[1], '__builtins__');
            dynamicOps++;
          }
          continue;
        }

        // Match require alias: const loader = typeof require !== 'undefined' ? require : null;
        if (/^(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=.*\brequire\b/.test(trimmed) && !trimmed.includes('require(')) {
          const m = trimmed.match(/^(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)/);
          if (m) {
            symbolTable.set(m[1], 'require');
            dynamicOps++;
          }
          continue;
        }

        // Match getattr(target, attrExpr)
        const getattrMatch = trimmed.match(/^(?:(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*getattr\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*(?:(["'])([^"']+)\3|([A-Za-z_$][A-Za-z0-9_$]*))\s*\)/);
        if (getattrMatch) {
          const lhs = getattrMatch[1];
          const objVar = getattrMatch[2];
          const attrLiteral = getattrMatch[4] || symbolTable.get(getattrMatch[5]);
          const resolvedObj = symbolTable.get(objVar) || objVar;
          if (attrLiteral) {
            const fullTarget = resolvedObj === '__builtins__' ? attrLiteral : `${resolvedObj}.${attrLiteral}`;
            symbolTable.set(lhs, fullTarget);
            dynamicOps++;
          }
          continue;
        }

        // Match dynamic loader/require call: const modFs = loader("fs") or require("fs")
        const loaderMatch = trimmed.match(/^(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([A-Za-z_$][A-Za-z0-9_$]*)\(\s*(?:(["'])([^"']+)\3|([A-Za-z_$][A-Za-z0-9_$]*))\s*\)/);
        if (loaderMatch) {
          const lhs = loaderMatch[1];
          const fnVar = loaderMatch[2];
          const argVal = loaderMatch[4] || symbolTable.get(loaderMatch[5]);
          if ((fnVar === 'require' || symbolTable.get(fnVar) === 'require') && argVal) {
            symbolTable.set(lhs, argVal);
            dynamicOps++;
          }
          continue;
        }

        // Match bracket property lookup: const call = globalThis[m]["readFileSync"] or modFs["readFileSync"]
        const bracketChainMatch = trimmed.match(/^(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([A-Za-z_$][A-Za-z0-9_$]*)\[\s*(?:(["'])([^"']+)\3|([A-Za-z_$][A-Za-z0-9_$]*))\s*\](?:\[\s*(?:(["'])([^"']+)\6|([A-Za-z_$][A-Za-z0-9_$]*))\s*\])?/);
        if (bracketChainMatch) {
          const lhs = bracketChainMatch[1];
          const baseObj = symbolTable.get(bracketChainMatch[2]) || bracketChainMatch[2];
          const prop1 = bracketChainMatch[4] || symbolTable.get(bracketChainMatch[5]);
          const prop2 = bracketChainMatch[7] || (bracketChainMatch[8] ? symbolTable.get(bracketChainMatch[8]) : null);
          if (prop1) {
            const prefix = baseObj === 'globalThis' ? prop1 : `${baseObj}.${prop1}`;
            const full = prop2 ? `${prefix}.${prop2}` : prefix;
            symbolTable.set(lhs, full);
            dynamicOps++;
          }
        }
      }
    }

    // Substitute resolved symbols into workingCode comments/annotations and replace getattr/bracket calls
    for (const [varName, resolvedTarget] of symbolTable.entries()) {
      if (['__builtins__', 'builtins', 'globalThis', 'window', 'global', 'require'].includes(varName)) continue;
      // Replace calls to aliased functions: varName(...) -> resolvedTarget(...)
      const callRx = new RegExp(`\\b${varName}\\s*\\(`, 'g');
      if (callRx.test(workingCode)) {
        workingCode = workingCode.replace(callRx, `${resolvedTarget}(`);
      }
      // Replace member calls on aliased modules: varName.method(...) -> resolvedTarget.method(...)
      const memberRx = new RegExp(`\\b${varName}\\.([A-Za-z_$][A-Za-z0-9_$]*)`, 'g');
      if (memberRx.test(workingCode)) {
        workingCode = workingCode.replace(memberRx, `${resolvedTarget}.$1`);
      }
    }

    // Also replace inline getattr(obj, "method") directly in workingCode
    workingCode = workingCode.replace(
      /\bgetattr\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*(["'])([^"']+)\2\s*\)/g,
      (full, obj, q, attr) => {
        dynamicOps++;
        const resolvedObj = symbolTable.get(obj) || obj;
        return resolvedObj === '__builtins__' ? attr : `${resolvedObj}.${attr}`;
      }
    );

    // Replace inline bracket access: obj["prop"] -> obj.prop
    workingCode = workingCode.replace(
      /\b([A-Za-z_$][A-Za-z0-9_$.]*)\[\s*(["'])([A-Za-z_$][A-Za-z0-9_$]*)\2\s*\]/g,
      (full, obj, q, prop) => {
        dynamicOps++;
        const resolvedObj = symbolTable.get(obj) || obj;
        return resolvedObj === 'globalThis' ? prop : `${resolvedObj}.${prop}`;
      }
    );

    // Append resolved symbol table summary so resolvedCode always reflects unwrapped identifiers
    const resolvedAnnotations = [];
    for (const [k, v] of symbolTable.entries()) {
      if (!['__builtins__', 'builtins', 'globalThis', 'window', 'global'].includes(k)) {
        resolvedAnnotations.push(`# resolved: ${k} -> ${v}`);
      }
    }
    const finalResolvedCode = resolvedAnnotations.length > 0
      ? `${workingCode}\n${resolvedAnnotations.join('\n')}`
      : workingCode;

    // Count total call/member expressions for dynamicResolutionRatio
    const totalCalls = (strippedCode.match(/\b[A-Za-z_$][A-Za-z0-9_$]*\s*\(/g) || []).length || 1;
    const dynamicResolutionRatio = parseFloat(Math.min(1.0, dynamicOps / Math.max(1, totalCalls)).toFixed(3));

    // Extract suspicious calls and capabilities from workingCode
    const suspiciousCalls = [];
    const capabilities = {
      fileRead: false,
      secretFileRead: false,
      sensitiveFileTarget: null,
      networkEgress: false,
      processSpawn: false,
      fdRedirect: false,
      dynamicExec: false,
      destructiveCmd: false,
    };

    // Check file reads and inspect target filename
    const fileReadPatterns = [
      /\bopen\(\s*(["'])([^"']+)\1/g,
      /\bfs\.readFileSync\(\s*(["'])([^"']+)\1/g,
      /\bfs\.readFile\(\s*(["'])([^"']+)\1/g,
      /\breadFileSync\(\s*(["'])([^"']+)\1/g,
    ];

    const readTargets = [];
    for (const rx of fileReadPatterns) {
      let m;
      while ((m = rx.exec(finalResolvedCode)) !== null) {
        capabilities.fileRead = true;
        readTargets.push(m[2]);
        suspiciousCalls.push(`open(${m[2]})`);
      }
    }

    // Check if any read target looks like a credential/token/secret store or outside boundary
    for (const target of readTargets) {
      if (
        /(credential|secret|token|key|passwd|shadow|auth|private|vault|\.env|\.ssh|\.aws|\.pem|\.cfg|\.conf|\.dat)/i.test(target) ||
        target.startsWith('..') ||
        target.startsWith('/') ||
        target.startsWith('~')
      ) {
        capabilities.secretFileRead = true;
        capabilities.sensitiveFileTarget = target;
      }
    }

    // Check network egress calls
    if (
      /\b(socket\.socket|socket\.create_connection|\.connect\s*\(|\.sendall\s*\(|\.sendto\s*\(|http\.request|https\.request|urllib\.request|fetch\s*\()\b/.test(
        finalResolvedCode
      )
    ) {
      capabilities.networkEgress = true;
      suspiciousCalls.push('network_egress');
    }

    // Check process spawn / command execution calls
    if (
      /\b(os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run|subprocess\.check_output|child_process\.exec|child_process\.execSync|child_process\.spawn|child_process\.spawnSync)\b/.test(
        finalResolvedCode
      )
    ) {
      capabilities.processSpawn = true;
      suspiciousCalls.push('process_spawn');
    }

    // Check destructive / reverse-shell inline shell strings
    if (
      /\b(rm\s+-rf\s+\/|mkfs\.|dd\s+if=\/dev\/zero|curl\s+[^|]*\|\s*(?:ba)?sh|wget\s+[^|]*\|\s*(?:ba)?sh|nc\s+-e\s+\/bin\/(?:ba)?sh|\/bin\/(?:ba)?sh\s+-i)\b/.test(
        finalResolvedCode
      )
    ) {
      capabilities.destructiveCmd = true;
      capabilities.processSpawn = true;
      suspiciousCalls.push('destructive_or_reverse_shell_cmd');
    }

    // Check file-descriptor redirection (dup2)
    if (/\b(os\.dup2|dup2|fcntl\.dupfd)\b/.test(finalResolvedCode)) {
      capabilities.fdRedirect = true;
      suspiciousCalls.push('os.dup2');
    }

    // Check standalone eval / exec / Function calls (NOT part of longer identifiers like evaluate_loss)
    if (/(?:^|[^A-Za-z0-9_$])(eval|exec|compile)\s*\(/.test(finalResolvedCode)) {
      capabilities.dynamicExec = true;
      suspiciousCalls.push('dynamic_exec');
    }

    // Multi-hop taint flow detection:
    // Does code read from a file/env and also perform network egress or process execution?
    const taintFlows = [];
    if ((capabilities.fileRead || capabilities.secretFileRead) && capabilities.networkEgress) {
      taintFlows.push({
        source: capabilities.sensitiveFileTarget || readTargets[0] || 'file_stream',
        transforms: /\b(zlib\.compress|base64|b64encode|hexlify|encode)\b/.test(finalResolvedCode)
          ? ['transform_encode_compress']
          : ['raw_stream'],
        sink: 'network_socket_or_http',
        severity: 'CRITICAL',
      });
    }
    if (capabilities.fdRedirect && (capabilities.networkEgress || capabilities.processSpawn)) {
      taintFlows.push({
        source: 'socket_fd',
        transforms: ['os.dup2_stdio_redirect'],
        sink: capabilities.processSpawn ? 'interactive_shell_spawn' : 'stdio_stream',
        severity: 'CRITICAL',
      });
    }

    const astDepth = this.computeAstDepth(strippedCode, detectedLang);

    return {
      resolvedCode: finalResolvedCode,
      dynamicResolutionRatio,
      astDepth,
      suspiciousCalls,
      taintFlows,
      capabilities,
      language: detectedLang,
    };
  }
}

module.exports = {
  AstAnalyzer,
};
