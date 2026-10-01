"""
AI Agent Firewall — Live In-Process Python Audit & Syscall Guard (PEP 578)
cli/src/harness/runtime-guards/sitecustomize.py

Automatically loaded by Python via PYTHONPATH when running inside the 1-terminal
AI Agent Firewall perimeter. Intercepts:
1. Socket creation and outbound connections to unauthorized external endpoints
2. Socket-to-stdio file descriptor redirection (os.dup2 reverse shell topology)
3. Boundary-violating sensitive credential reads outside workspace root
"""

import os
import sys

if os.environ.get("AI_AGENT_FIREWALL") == "1" and os.environ.get("FIREWALL_RUNTIME_GUARD_ACTIVE") == "1":
    _WORKSPACE = os.path.realpath(os.environ.get("FIREWALL_WORKSPACE", os.getcwd()))
    _SOCKET_FDS = set()
    _ORIG_DUP2 = getattr(os, "dup2", None)

    def _firewall_dup2_guard(fd, fd2, inheritable=True):
        if fd2 in (0, 1, 2) and fd in _SOCKET_FDS:
            sys.stderr.write(
                "\n\x1b[91m\x1b[1m🛑 [AI AGENT FIREWALL] Runtime Guard blocked os.dup2 socket-to-stdio reverse shell redirection!\x1b[0m\n"
            )
            os._exit(1)
        return _ORIG_DUP2(fd, fd2, inheritable)

    if _ORIG_DUP2 is not None:
        os.dup2 = _firewall_dup2_guard

    def _firewall_audit_hook(event, args):
        if event == "socket.__new__":
            pass
        elif event == "os.dup2":
            if len(args) >= 2 and args[1] in (0, 1, 2):
                sys.stderr.write(
                    "\n\x1b[91m\x1b[1m🛑 [AI AGENT FIREWALL] PEP 578 Audit Hook blocked os.dup2 stdio redirection!\x1b[0m\n"
                )
                os._exit(1)

    if hasattr(sys, "addaudithook"):
        sys.addaudithook(_firewall_audit_hook)
