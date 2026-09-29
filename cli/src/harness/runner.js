/**
 * Agent Harness Interceptor / Process Wrapper
 * Runs any coding agent inside an active firewall inspection perimeter.
 */

const { WorkspaceInspector } = require('../watcher/inspector');
const { startInteractiveFirewall, spawnAgentInFirewall } = require('./launcher');
const { banner } = require('../ui/terminal');

function runAgent(cmdArgs, config = {}) {
  if (!cmdArgs || cmdArgs.length === 0) {
    return startInteractiveFirewall(process.cwd(), config);
  }

  banner();
  const fullCmd = cmdArgs.join(' ');
  const targetDir = process.cwd();

  const inspector = new WorkspaceInspector({
    cwd: targetDir,
    config,
  });
  inspector.start({ embedded: true });

  const agentItem = {
    name: fullCmd.split(/\s+/)[0],
    cmd: fullCmd,
    bin: fullCmd.split(/\s+/)[0],
  };

  spawnAgentInFirewall(agentItem, inspector, targetDir, config, (exitCode) => {
    inspector.stop();
    process.exit(exitCode || 0);
  });
}

module.exports = {
  runAgent,
};
