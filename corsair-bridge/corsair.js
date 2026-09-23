require('dotenv').config();
const Database = require('better-sqlite3');
const { createCorsair } = require('corsair');
const { github } = require('@corsair-dev/github');

const db = new Database('corsair.db');

const corsair = createCorsair({
  plugins: [
    github({
      authType: 'managed',
      webhookHooks: {
        pullRequest: {
          opened: {
            before: async (ctx, args) => {
              const payload = args.payload || args;
              if (payload.pull_request?.draft) {
                console.log('[firewall] Skipping draft PR');
                return { ctx, args, continue: false };
              }
              return { ctx, args };
            },
            after: async (ctx, result) => {
              await processPullRequest(ctx, result);
            },
          },
          synchronize: {
            before: async (ctx, args) => {
              const payload = args.payload || args;
              if (payload.pull_request?.draft) {
                console.log('[firewall] Skipping draft PR');
                return { ctx, args, continue: false };
              }
              return { ctx, args };
            },
            after: async (ctx, result) => {
              await processPullRequest(ctx, result);
            },
          },
          reopened: {
            before: async (ctx, args) => {
              const payload = args.payload || args;
              if (payload.pull_request?.draft) {
                console.log('[firewall] Skipping draft PR');
                return { ctx, args, continue: false };
              }
              return { ctx, args };
            },
            after: async (ctx, result) => {
              await processPullRequest(ctx, result);
            },
          },
        },
      },
    }),
  ],
  database: db,
  kek: process.env.CORSAIR_KEK,
  hub: {
    projectApiKey: process.env.CORSAIR_API_KEY,
    signingSecret: process.env.CORSAIR_SIGNING_SECRET,
    allowWorkflowExecution: true,
  },
});

async function processPullRequest(ctx, result) {
  const payload = result?.data || result?.payload || result || {};
  const pr = payload.pull_request || payload.pullRequest;
  const repo = payload.repository;
  if (!pr || !repo) {
    console.warn('[firewall] Webhook payload missing PR or repository:', JSON.stringify(result));
    return;
  }

  const owner = repo.owner?.login || repo.owner?.name || repo.owner;
  const repoName = repo.name;
  console.log(`[firewall] PR event received: "${pr.title}" (#${pr.number}) in ${owner}/${repoName}`);

  try {
    // 1. Fetch changed files in the PR
    let token = null;
    if (ctx?.keys && typeof ctx.keys.get_access_token === 'function') {
      token = await ctx.keys.get_access_token();
    }
    if (!token && corsair.github?.keys?.get_access_token) {
      token = await corsair.github.keys.get_access_token();
    }

    const filesRes = await fetch(`https://api.github.com/repos/${owner}/${repoName}/pulls/${pr.number}/files`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'ai-agent-firewall',
      },
    });

    if (!filesRes.ok) {
      console.error(`[firewall] Failed to fetch PR files: ${filesRes.status} ${filesRes.statusText}`);
      return;
    }

    const files = await filesRes.json();
    const codeFiles = (Array.isArray(files) ? files : []).filter(f =>
      f.filename?.endsWith('.rs') || f.filename?.endsWith('.py')
    );

    if (codeFiles.length === 0) {
      console.log('[firewall] No .rs or .py files found in PR. Skipping code execution analysis.');
      return;
    }

    console.log(`[firewall] Found ${codeFiles.length} file(s) to analyze:`, codeFiles.map(f => f.filename));

    for (const file of codeFiles) {
      const language = file.filename.endsWith('.py') ? 'python' : 'rust';
      console.log(`[firewall] Fetching content for: ${file.filename} (${language}) (ref: ${pr.head.sha})`);
      const fileContentRes = await corsair.github.api.repositories.getContent({
        owner,
        repo: repoName,
        path: file.filename,
        ref: pr.head.sha,
      });

      if (!fileContentRes || !fileContentRes.content) {
        console.warn(`[firewall] Could not retrieve content for ${file.filename}`);
        continue;
      }

      const code = Buffer.from(fileContentRes.content, fileContentRes.encoding || 'base64').toString('utf-8');

      console.log(`[firewall] Sending ${language} code from ${file.filename} to firewall backend (http://localhost:8000/api/execute-code)...`);
      let firewallData;
      try {
        const firewallRes = await fetch('http://localhost:8000/api/execute-code', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, language }),
        });
        firewallData = await firewallRes.json();
      } catch (err) {
        console.error(`[firewall] Backend connection error:`, err.message);
        firewallData = {
          status: 'error',
          message: `Firewall backend unreachable on port 8000: ${err.message}`,
        };
      }

      console.log(`[firewall] Backend response status:`, firewallData.status);

      // 2. Post review comment to GitHub PR
      let commentBody = '';
      const runnerLabel = language === 'python' ? 'Python Ephemeral Jail' : 'Rust WASI (Wasmtime 48.0)';

      if (firewallData.status === 'blocked') {
        const threatsList = (firewallData.threats || [])
          .map(t => `- 🚨 **${t.title}** (${t.severity}): ${t.detail}`)
          .join('\n');

        const divergenceNotice = firewallData.security?.semantic_divergence
          ? `\n> ⚠️ **CRITICAL SEMANTIC DIVERGENCE**: Unprompted high-risk capabilities detected outside intent boundaries.\n`
          : '';

        commentBody = `### 🚨 AI Agent Firewall: BLOCKED\n\n` +
          `The code changes in \`${file.filename}\` (${language.toUpperCase()}) were **blocked** by zero-trust security policy.\n\n` +
          `* **Risk Score**: \`${firewallData.security?.risk_score ?? 'High'}/100\`\n` +
          `* **Decision**: \`${firewallData.policy?.decision ?? 'BLOCK'}\`\n` +
          `* **Sandbox Architecture**: \`${runnerLabel}\`\n` +
          `${divergenceNotice}\n` +
          `#### Threats Detected:\n${threatsList || '- Untrusted capability detected.'}\n\n` +
          `*Execution was intercepted before CPU cycles were allocated.*`;
      } else if (firewallData.status === 'success') {
        commentBody = `### ✅ AI Agent Firewall: PASSED\n\n` +
          `The code changes in \`${file.filename}\` (${language.toUpperCase()}) passed policy preflight checks and executed safely in the sandbox.\n\n` +
          `* **Risk Score**: \`${firewallData.security?.risk_score ?? 0}/100\` (Low)\n` +
          `* **Decision**: \`ALLOW\`\n` +
          `* **Sandbox Architecture**: \`${runnerLabel}\`\n` +
          `* **Execution Fuel**: \`${firewallData.details?.fuelConsumed ?? 'N/A'}\`\n` +
          `* **Execution Time**: \`${firewallData.details?.executionTime ?? 'N/A'}\``;
      } else {
        commentBody = `### ⚠️ AI Agent Firewall: Warning\n\n` +
          `Analysis completed with status \`${firewallData.status}\` for \`${file.filename}\`.\n` +
          `Details: ${firewallData.logs || firewallData.message || 'Check firewall backend logs.'}`;
      }

      await corsair.github.api.issues.createComment({
        owner,
        repo: repoName,
        issueNumber: pr.number,
        body: commentBody,
      });

      console.log(`[firewall] Comment posted to PR #${pr.number}`);
    }
  } catch (err) {
    console.error('[firewall] Error during PR check:', err);
  }
}

module.exports = { corsair };
