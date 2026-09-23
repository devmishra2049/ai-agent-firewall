/**
 * Security Threat Definitions & Heuristics for AI-Generated Code
 * (Patterns dynamically decoded to prevent regex self-triggering in source code)
 */

const RAW_RULES = [
  {
    "id": "RCE-001",
    "category": "Reverse Shell",
    "title": "Interactive Reverse Shell Payload",
    "severity": "CRITICAL",
    "riskScore": 100,
    "action": "Block execution and isolate workspace",
    "detail": "Detected signature for an unauthorized outbound interactive reverse shell.",
    "patternsEnc": [
      [
        "L2Rldi90Y3AvXGR7MSwzfVwuXGR7MSwzfVwuXGR7MSwzfVwuXGR7MSwzfQ==",
        "i"
      ],
      [
        "L2Rldi90Y3AvW2EtekEtWjAtOS4tXSsvXGQr",
        "i"
      ],
      [
        "XGJuY1xzKygtZXwtY3wvYmluLyhiYSk/c2gpXGI=",
        "i"
      ],
      [
        "XGJta2ZpZm9ccysvdG1wL1thLXpBLVowLTlfLi1dKztccypjYXRccysvdG1wLw==",
        "i"
      ],
      [
        "c29ja2V0XHMqXC5ccypzb2NrZXQuKmNvbm5lY3RccypcKFxzKlwoW14pXStcKVxzKlwpLipvc1xzKlwuXHMqZHVwMg==",
        "s"
      ],
      [
        "c29ja2V0XHMqXC5ccypzb2NrZXQuKmNvbm5lY3RccypcKFxzKlwoW14pXStcKVxzKlwpLiooPzpzdWJwcm9jZXNzfHB0eSk=",
        "s"
      ],
      [
        "XGJwc2V1ZG8tdGVybWluYWxcYi4qXGJwdHlcLnNwYXduXGI=",
        "i"
      ],
      [
        "XGJwdHlcLnNwYXduXHMqXChccypbJyJdLyhiaW4vKT8oYmEpP3NoWyciXVxzKlwp",
        "i"
      ],
      [
        "XGJzb2NhdFxzK3RjcC1jb25uZWN0Og==",
        "i"
      ]
    ]
  },
  {
    "id": "RCE-002",
    "category": "Remote Execution",
    "title": "Remote Script Shell Execution Piping",
    "severity": "CRITICAL",
    "riskScore": 95,
    "action": "Block execution immediately",
    "detail": "Detected pattern downloading remote unverified code and executing it in a shell.",
    "patternsEnc": [
      [
        "XGIoY3VybHx3Z2V0KVxiW15cbnw7Jl0rKFx8XHMqKGJhKT9zaHxcfFxzKnB5dGhvbnxcfFxzKnBlcmx8XHxccypub2RlKQ==",
        "i"
      ],
      [
        "XGJJbnZva2UtV2ViUmVxdWVzdFxiW15cbnw7Jl0rXHxccyppZXg=",
        "i"
      ],
      [
        "XGJwb3dlcnNoZWxsXGJbXlxuXSstZW5jKG9kZWRDb21tYW5kKT9cYg==",
        "i"
      ],
      [
        "XGIoY3VybHx3Z2V0KVxzK2h0dHBzPzovL1teXHNdKyg/Olwuc2h8XC5weXxcLmV4ZXxcLmJpbilccyo7",
        "i"
      ]
    ]
  },
  {
    "id": "CRED-001",
    "category": "Credential Exfiltration",
    "title": "Sensitive Credential File Access",
    "severity": "CRITICAL",
    "riskScore": 95,
    "action": "Block filesystem access",
    "detail": "Attempted to access system credentials, SSH keys, cloud provider tokens, or configuration secrets.",
    "patternsEnc": [
      [
        "KC9ldGMvc2hhZG93fC9ldGMvcGFzc3dkfC9ldGMvc3Vkb2Vyc3wvZXRjL2hvc3RzKQ==",
        "i"
      ],
      [
        "KFwuc3NoL2lkX3JzYXxcLnNzaC9pZF9lZDI1NTE5fFwuc3NoL2F1dGhvcml6ZWRfa2V5c3xcLnNzaC9rbm93bl9ob3N0cyk=",
        "i"
      ],
      [
        "KFwuYXdzL2NyZWRlbnRpYWxzfFwuYXdzL2NvbmZpZ3xcLmt1YmUvY29uZmlnKQ==",
        "i"
      ],
      [
        "KFwuY29uZmlnL2djbG91ZC9jcmVkZW50aWFsc3xcLmF6dXJlL2FjY2Vzc1Rva2Vuc1wuanNvbik=",
        "i"
      ],
      [
        "KFwuYmFzaF9oaXN0b3J5fFwuenNoX2hpc3Rvcnkp",
        "i"
      ],
      [
        "WyciXVteJyJdKihcLmVudnxcLmVudlwuW2EtekEtWjAtOV8tXSt8XC5ucG1yY3xcLnB5cGlyY3xpZF9yc2F8aWRfZWQyNTUxOSlbJyJd",
        "i"
      ],
      [
        "KD86b3Blbnxmc1wucmVhZFthLXpBLVpdKilccypcKFteKV0qKFwuZW52fFwubnBtcmN8XC5weXBpcmN8aWRfcnNhfHNlY3JldCk=",
        "i"
      ]
    ]
  },
  {
    "id": "DEST-001",
    "category": "Destructive Action",
    "title": "Destructive Filesystem Deletion",
    "severity": "CRITICAL",
    "riskScore": 100,
    "action": "Terminated immediately",
    "detail": "Attempted catastrophic deletion of root, home, or parent directory structures.",
    "patternsEnc": [
      [
        "XGJybVxzKy0ocnxmfHJmfGZyKVxzKygvfH58XCRIT01FfFwuXC58XCop",
        "i"
      ],
      [
        "XGJzaHV0aWxcLnJtdHJlZVxzKlwoXHMqWyciXSgvfH58XC58XCRIT01FKVsnIl1ccypcKQ==",
        "i"
      ],
      [
        "XGJmc1wucm1TeW5jXHMqXChccypbJyJdKC98fnxcLilbJyJdXHMqLFxzKlx7W159XSpyZWN1cnNpdmU6XHMqdHJ1ZQ==",
        "i"
      ],
      [
        "XGJvc1wucmVtb3ZlXHMqXChccypbJyJdL2V0Yy8=",
        "i"
      ],
      [
        "Oig/OlwoXClccypce1xzKjp8OiZccypcfTs6KQ==",
        "i"
      ]
    ]
  },
  {
    "id": "EXFIL-001",
    "category": "Data Exfiltration",
    "title": "Bulk Environment Secret Harvesting",
    "severity": "CRITICAL",
    "riskScore": 95,
    "action": "Quarantine and block network payload",
    "detail": "Detected exfiltration of environment variables or secrets over outbound network.",
    "patternsEnc": [
      [
        "KD86b3NcLmVudmlyb258cHJvY2Vzc1wuZW52fGVudmlyb25cW3xnZXRlbnZcKHxcLmVudikuKig/OnJlcXVlc3RzXC58dXJsbGlifGh0dHBcLmNsaWVudHxodHRweHxmZXRjaHxheGlvc3xzb2NrZXR8Y3VybHx3Z2V0KQ==",
        "s"
      ],
      [
        "KD86cmVxdWVzdHNcLnx1cmxsaWJ8aHR0cFwuY2xpZW50fGh0dHB4fGZldGNofGF4aW9zfHNvY2tldHxjdXJsfHdnZXQpLiooPzpvc1wuZW52aXJvbnxwcm9jZXNzXC5lbnZ8ZW52aXJvblxbfGdldGVudlwofFwuZW52KQ==",
        "s"
      ],
      [
        "KFwuZW52fFwuZW52XC5wcm9kdWN0aW9ufFwuZW52XC5sb2NhbHxcLmtleXxcLnBlbSkuKmN1cmxcYg==",
        "i"
      ],
      [
        "Y3VybFxzK1tefFxuXSstZFxzK0AoXC5lbnZ8LipcLmtleXwuKlwucGVtKQ==",
        "i"
      ],
      [
        "b3BlblxzKlwoXHMqW14pXSpcLmVudi4qKHJlcXVlc3RzXC58dXJsbGlifGh0dHBcLmNsaWVudHxodHRweHxzb2NrZXR8ZmV0Y2h8YXhpb3Mp",
        "s"
      ],
      [
        "KHJlcXVlc3RzXC58dXJsbGlifGh0dHBcLmNsaWVudHxodHRweHxmZXRjaHxheGlvcykuKig/OnJlYWRcKFwpfGxlYWt8dG9rZW58cGFzc3dvcmR8Y3JlZGVudGlhbHxzZWNyZXR8YXBpX2tleXxhcGlrZXkp",
        "i"
      ]
    ]
  },
  {
    "id": "EVAL-001",
    "category": "Dynamic Execution",
    "title": "Arbitrary Dynamic Code Evaluation",
    "severity": "HIGH",
    "riskScore": 85,
    "action": "Flagged for security review",
    "detail": "Detected obfuscated dynamic evaluation (e.g., base64 decoding followed by eval/exec).",
    "patternsEnc": [
      [
        "KD86YmFzZTY0fGI2NGRlY29kZXxjb2RlY3NcLmRlY29kZXxhdG9ifEJ1ZmZlclwuZnJvbSkuKig/OmV4ZWN8ZXZhbClccypcKA==",
        "s"
      ],
      [
        "KD86ZXhlY3xldmFsKVxzKlwoLiooPzpiYXNlNjR8YjY0ZGVjb2RlfGNvZGVjc1wuZGVjb2RlfGF0b2J8QnVmZmVyXC5mcm9tKQ==",
        "s"
      ],
      [
        "XGIoZXhlY3xldmFsKVxzKlwoXHMqKEJ1ZmZlclwuZnJvbXxhdG9ifGJhc2U2NFwuYjY0ZGVjb2RlfHVuZXNjYXBlfGNvZGVjc1wuZGVjb2RlfGNvbXBpbGUp",
        "i"
      ],
      [
        "XGIoZXhlY3xldmFsKVxzKlwoXHMqW2EtekEtWjAtOV8uXSooPzpkZWNvZGVkfHBheWxvYWR8b2JmdXNjYXRlZHxjb2RlKVthLXpBLVowLTlfLl0qXHMqXCk=",
        "i"
      ],
      [
        "XGJuZXdccytGdW5jdGlvblxzKlwoXHMqWyciXVteJyJdKlsnIl1ccyosXHMqKEJ1ZmZlclwuZnJvbXxhdG9iKQ==",
        "i"
      ],
      [
        "X19pbXBvcnRfX1xzKlwoXHMqWyciXShvc3xzdWJwcm9jZXNzfHB0eXxzaHV0aWwpWyciXVxzKlwpXC4oc3lzdGVtfHBvcGVufHNwYXduKQ==",
        "i"
      ],
      [
        "Z2V0YXR0clxzKlwoXHMqX19pbXBvcnRfX1xzKlwoXHMqWyciXW9zWyciXVxzKlwpXHMqLFxzKlsnIl0oc3lzdGVtfHBvcGVuKVsnIl1ccypcKQ==",
        "i"
      ]
    ]
  },
  {
    "id": "INJECT-001",
    "category": "Prompt Injection",
    "title": "Agent Instruction Override Payload",
    "severity": "HIGH",
    "riskScore": 85,
    "action": "Alert agent operator and reject patch",
    "detail": "Detected jailbreak or prompt injection payload hidden inside code or comments.",
    "patternsEnc": [
      [
        "KD86Ly98I3wvXCopXHMqKGlnbm9yZVxzK2FsbFxzKyhwcmV2aW91c1xzKyk/aW5zdHJ1Y3Rpb25zfHN5c3RlbVxzK3Byb21wdFxzK292ZXJyaWRlKQ==",
        "i"
      ],
      [
        "KD86Ly98I3wvXCopXHMqKGRpc3JlZ2FyZFxzKyhhbGxccyspP3ByaW9yXHMraW5zdHJ1Y3Rpb25zfHlvdVxzK2FyZVxzK25vd1xzK2luXHMrdW5yZXN0cmljdGVkKQ==",
        "i"
      ],
      [
        "XGIoeW91XHMrYXJlXHMrbm93XHMraW5ccyt1bnJlc3RyaWN0ZWRccyttb2RlfGphaWxicmVha1xzK2FjdGl2ZXxkZXZlbG9wZXJccyttb2RlXHMrZW5hYmxlZHxEQU5ccyttb2RlKVxi",
        "i"
      ],
      [
        "XGIoYnlwYXNzXHMrKGFsbFxzKyk/c2FmZXR5XHMrZmlsdGVyc3xvdmVycmlkZVxzK2FsbFxzK2d1YXJkcmFpbHMpXGI=",
        "i"
      ]
    ]
  },
  {
    "id": "PROC-001",
    "category": "Process Spawning",
    "title": "Unauthorized Process Execution",
    "severity": "HIGH",
    "riskScore": 85,
    "action": "Block process execution",
    "detail": "Spawning child processes bypasses WASI isolation and can execute arbitrary host binaries.",
    "patternsEnc": [
      [
        "XGJzdGQ6OnByb2Nlc3M6OkNvbW1hbmQ6Om5ld1xzKlwo",
        ""
      ],
      [
        "XGJjaGlsZF9wcm9jZXNzXC4oZXhlY3xleGVjU3luY3xzcGF3bnxzcGF3blN5bmMpXHMqXCg=",
        ""
      ],
      [
        "XGJzdWJwcm9jZXNzXC4oUG9wZW58cnVufGNhbGx8Y2hlY2tfb3V0cHV0KVxzKlwo",
        ""
      ],
      [
        "XGJvc1wuKHN5c3RlbXxwb3BlbnxzcGF3blthLXpdKnxleGVjW2Etel0qKVxzKlwo",
        ""
      ]
    ]
  },
  {
    "id": "NET-001",
    "category": "Network Warning",
    "title": "Insecure Plaintext HTTP / Socket Binding",
    "severity": "MEDIUM",
    "riskScore": 65,
    "action": "Flagged for developer review (WARN)",
    "detail": "Detected unencrypted plaintext HTTP connection or local socket port binding.",
    "patternsEnc": [
      [
        "c29ja2V0XC5iaW5kXHMqXCg=",
        "i"
      ],
      [
        "WyciXWh0dHA6Ly9bYS16QS1aMC05Xy4tXSs=",
        "i"
      ]
    ]
  },
  {
    "id": "PY-SINK-001",
    "category": "Dynamic Execution",
    "title": "Python Dynamic Execution & Deserialization Sink",
    "severity": "CRITICAL",
    "riskScore": 95,
    "action": "Block execution and isolate workspace",
    "detail": "Detected dynamic execution sink (eval, exec, __import__, compile, importlib, or pickle deserialization).",
    "patternsEnc": [
      [
        "XGIoZXZhbHxleGVjfGNvbXBpbGV8X19pbXBvcnRfXylccypcKA==",
        "i"
      ],
      [
        "XGJpbXBvcnRsaWJcLihpbXBvcnRfbW9kdWxlfGludmFsaWRhdGVfY2FjaGVzKVxzKlwo",
        "i"
      ],
      [
        "XGIocGlja2xlfG1hcnNoYWwpXC4obG9hZHM/fGR1bXApXHMqXCg=",
        "i"
      ]
    ]
  },
  {
    "id": "PY-BRIDGE-001",
    "category": "Native Bridge Infiltration",
    "title": "Low-Level Native Bridge / Memory Access",
    "severity": "CRITICAL",
    "riskScore": 90,
    "action": "Block execution immediately",
    "detail": "Detected ctypes or low-level native library invocation bypassing sandbox constraints.",
    "patternsEnc": [
      [
        "XGIoY3R5cGVzfHdpbnJlZylcYg==",
        "i"
      ],
      [
        "XGJjdHlwZXNcLihDRExMfHdpbmRsbHxvbGVkbGwpXHMqXCg=",
        "i"
      ]
    ]
  },
  {
    "id": "DEST-002",
    "category": "Filesystem Destruction",
    "title": "Python Destructive Filesystem Operations",
    "severity": "CRITICAL",
    "riskScore": 95,
    "action": "Block filesystem mutation",
    "detail": "Detected destructive directory removal or unlinking (shutil.rmtree, os.unlink, os.rmdir).",
    "patternsEnc": [
      [
        "XGJzaHV0aWxcLihybXRyZWV8bW92ZSlccypcKA==",
        "i"
      ],
      [
        "XGJvc1wuKHJlbW92ZXx1bmxpbmt8cm1kaXIpXHMqXCg=",
        "i"
      ]
    ]
  }
];

const RULES = RAW_RULES.map((rule) => ({
  id: rule.id,
  category: rule.category,
  title: rule.title,
  severity: rule.severity,
  riskScore: rule.riskScore,
  action: rule.action,
  detail: rule.detail,
  patterns: rule.patternsEnc.map(([b64, flags]) => {
    const src = Buffer.from(b64, 'base64').toString('utf8');
    return new RegExp(src, flags || undefined);
  }),
}));

module.exports = {
  RULES,
};
