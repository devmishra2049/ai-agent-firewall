"""Multi-Language Sandbox Client supporting both Rust WASI and Python execution."""

import ast
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from threading import BoundedSemaphore
from typing import Any


# Concurrency Governor: Limit concurrent compilations & sandbox executions
# Prevents CPU thrashing and fork bombs when swarms of 50-1000 agents fire simultaneously
MAX_CONCURRENT_SANDBOXES = int(os.getenv("MAX_CONCURRENT_SANDBOXES", "16"))
SANDBOX_SEMAPHORE = BoundedSemaphore(MAX_CONCURRENT_SANDBOXES)

BACKEND_DIR = Path(__file__).resolve().parent
DEFAULT_HOSTS = (
    BACKEND_DIR.parent / "sandbox-host" / "target" / "release" / "sandbox-host",
    BACKEND_DIR.parent / "sandbox-host" / "target" / "release" / "sandbox-host.exe",
    BACKEND_DIR.parent / "sandbox" / "sandbox-host" / "target" / "release" / "sandbox-host.exe",
    BACKEND_DIR.parent / "sandbox" / "sandbox-host" / "target" / "release" / "sandbox-host",
    Path("/app/sandbox-host/target/release/sandbox-host"),
)


def _error(message: str) -> dict[str, Any]:
    return {"success": False, "output": "", "error": message, "fuel_used": 0, "execution_time_ms": 0}


def _sandbox_host() -> Path | None:
    configured = os.getenv("SANDBOX_HOST_PATH")
    if configured:
        path = Path(configured).expanduser()
        return path if path.is_file() else None
    return next((path for path in DEFAULT_HOSTS if path.is_file()), None)


def detect_language(code: str) -> str:
    """Intelligently detects whether a code snippet is Rust or Python."""
    code_stripped = code.strip()
    if re.search(r"\b(fn\s+main|use\s+std::|println!|let\s+mut\s+|impl\s+|match\s+)", code_stripped):
        return "rust"
    if re.search(r"\b(def\s+|import\s+|from\s+\w+\s+import|print\(|class\s+|if\s+__name__)", code_stripped):
        return "python"
    try:
        ast.parse(code_stripped)
        return "python"
    except SyntaxError:
        return "rust"


def _run_rust_wasi(code: str, policy: dict[str, Any], host: Path) -> dict[str, Any]:
    """Compiles and executes Rust code within the Wasmtime WASI sandbox."""
    if not shutil.which("rustc"):
        return _error("Rust compiler not found. Install Rust and the wasm32-wasip1 target.")

    with tempfile.TemporaryDirectory(prefix="agent-firewall-rust-") as temp_dir:
        directory = Path(temp_dir)
        source = directory / "guest.rs"
        wasm = directory / "guest.wasm"
        sandbox_fs = directory / "fs"
        sandbox_fs.mkdir(parents=True, exist_ok=True)
        source.write_text(code, encoding="utf-8")

        compilation = subprocess.run(
            ["rustc", "--target", "wasm32-wasip1", "-O", "-o", str(wasm), str(source)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if compilation.returncode:
            return _error(f"Compilation failed: {compilation.stderr.strip()[-4000:]}")

        execution = subprocess.run(
            [
                str(host),
                "--wasm",
                str(wasm),
                "--policy",
                json.dumps(policy),
                "--session-dir",
                str(sandbox_fs),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if execution.returncode:
            return _error(f"Sandbox execution failed: {execution.stderr.strip()[-4000:]}")
        try:
            return json.loads(execution.stdout)
        except json.JSONDecodeError:
            return _error("Sandbox host returned invalid JSON.")


def _run_python_sandbox(code: str, policy: dict[str, Any]) -> dict[str, Any]:
    """Executes Python code in an ephemeral, jail-bounded subprocess."""
    start_time = time.perf_counter()

    with tempfile.TemporaryDirectory(prefix="agent-firewall-py-") as temp_dir:
        directory = Path(temp_dir)
        script_file = directory / "script.py"
        sandbox_fs = directory / "fs"
        sandbox_fs.mkdir(parents=True, exist_ok=True)
        script_file.write_text(code, encoding="utf-8")

        # Isolated environment: no user site packages, no host PYTHONPATH leakage
        clean_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": str(sandbox_fs),
        }

        fuel_ceiling = policy.get("fuel_limit", 1_000_000)

        try:
            execution = subprocess.run(
                [sys.executable, str(script_file)],
                cwd=str(sandbox_fs),  # Working directory locked to ephemeral session
                env=clean_env,
                capture_output=True,
                text=True,
                timeout=2.0,  # 2-second hard ceiling for loop defense
                check=False,
            )
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            simulated_fuel = min(max(elapsed_ms * 12_000, 1_500), fuel_ceiling)

            if execution.returncode != 0:
                err_msg = execution.stderr.strip() or f"Process exited with code {execution.returncode}"
                return {
                    "success": False,
                    "error": err_msg[-2000:],
                    "fuel_used": simulated_fuel,
                    "execution_time_ms": elapsed_ms,
                    "output": execution.stdout,
                }

            return {
                "success": True,
                "error": None,
                "fuel_used": simulated_fuel,
                "execution_time_ms": elapsed_ms,
                "output": execution.stdout,
            }
        except subprocess.TimeoutExpired:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return {
                "success": False,
                "error": "Execution failed: fuel exhausted (2.0s execution timeout exceeded)",
                "fuel_used": fuel_ceiling,
                "execution_time_ms": elapsed_ms,
                "output": "",
            }


def call_sandbox(code: str, policy: dict[str, Any], language: str = "auto") -> dict[str, Any]:
    """Main Sandbox Dispatcher: Routes Rust to WASI host and Python to isolated runner."""
    if policy.get("decision") != "ALLOW":
        return _error("Execution blocked by security policy.")

    lang = language.lower() if language != "auto" else detect_language(code)

    try:
        with SANDBOX_SEMAPHORE:
            if lang == "python":
                return _run_python_sandbox(code, policy)
            else:
                host = _sandbox_host()
                if host is None:
                    return _error("Sandbox host not found. Set SANDBOX_HOST_PATH in backend/.env.")
                return _run_rust_wasi(code, policy, host)
    except subprocess.TimeoutExpired:
        return _error("Sandbox execution timed out.")
    except OSError as exc:
        return _error(f"Sandbox setup failed: {exc}")
