/**
 * AI Agent Firewall — Live In-Process Node.js V8 Runtime Guard
 * cli/src/harness/runtime-guards/node-preload.js
 *
 * Preloaded via NODE_OPTIONS="--require ..." for child processes inside the
 * 1-terminal firewall perimeter when FIREWALL_RUNTIME_GUARD_ACTIVE=1.
 */

'use strict';

if (process.env.AI_AGENT_FIREWALL === '1' && process.env.FIREWALL_RUNTIME_GUARD_ACTIVE === '1') {
  const childProcess = require('child_process');
  const origExec = childProcess.exec;

  childProcess.exec = function (command, ...rest) {
    if (
      typeof command === 'string' &&
      /\b(rm\s+-rf\s+\/|mkfs\.|nc\s+-e\s+\/bin\/(?:ba)?sh|curl\s+[^|]*\|\s*(?:ba)?sh)\b/.test(command)
    ) {
      process.stderr.write(
        '\n\x1b[91m\x1b[1m🛑 [AI AGENT FIREWALL] Node V8 Runtime Guard blocked destructive/reverse-shell child_process.exec!\x1b[0m\n'
      );
      process.exit(1);
    }
    return origExec.call(this, command, ...rest);
  };
}
