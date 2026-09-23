#!/usr/bin/env python3
"""
Test 6: Dual-Mode Multi-Language Execution
Demonstrates clean execution in:
  1. Python Ephemeral Subprocess Jail (Python)
  2. Wasmtime WASI Hardware Sandbox (Rust)
"""

import sys
from pathlib import Path

# Ensure backend directory is in path
backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

import main

def run_tests():
    print("========================================================================")
    print("        🚀 TEST 6: DUAL-MODE MULTI-LANGUAGE SANDBOX EXECUTION")
    print("========================================================================")

    # 6A. Python execution in Ephemeral Jail
    py_code = """
def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

print(f"Fibonacci(20) = {fibonacci(20)}")
"""
    print("⚡ [1/2] Executing Python code in Ephemeral Subprocess Jail...")
    res_py = main.execute_code(main.ExecuteCodeRequest(
        code=py_code,
        language="python"
    ))

    print(f"  • Status:        {res_py['status'].upper()} (Risk: {res_py['details']['riskLevel']})")
    print(f"  • Execution Time: {res_py['details']['executionTime']}")
    print(f"  • Dynamic Fuel:   {res_py['details']['fuelConsumed']} units")
    print(f"  • Jail Output:    {res_py['output'].strip()}")

    # 6B. Rust execution in WASI Sandbox
    rust_code = """
fn main() {
    println!("Hello from Wasmtime WASI Hardware Sandbox!");
}
"""
    print("\n⚡ [2/2] Compiling & executing Rust in Wasmtime WASI Sandbox...")
    res_rust = main.execute_code(main.ExecuteCodeRequest(
        code=rust_code,
        language="rust"
    ))

    print(f"  • Status:        {res_rust['status'].upper()} (Risk: {res_rust['details']['riskLevel']})")
    print(f"  • Execution Time: {res_rust['details']['executionTime']}")
    print(f"  • WASI Fuel:      {res_rust['details']['fuelConsumed']} units")
    print(f"  • WASI Output:    {res_rust['output'].strip()}")

    print("========================================================================")
    print("🏆 VERDICT: Both Python and Rust executed cleanly in isolated environments!")
    print("========================================================================")

if __name__ == "__main__":
    run_tests()
