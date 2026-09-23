"""Convert security analysis into the capability policy consumed by sandbox-host."""

from typing import Any


def create_policy(security_result: dict[str, Any], code: str = "") -> dict[str, Any]:
    """Deny any request whose security analysis is not explicitly safe, and calculate dynamic fuel."""
    capabilities = set(security_result.get("capabilities", []))
    decision = "ALLOW" if security_result.get("safe", False) else "DENY"

    # Extract code if passed directly or inside security_result
    target_code = code or security_result.get("code", "")

    # Dynamic Complexity-Proportional Fuel Calculation:
    # Small tasks with no loops get a tight budget (e.g. 100,000 instructions)
    # Runaway loops trap deterministically in sub-millisecond time
    base_fuel = 100_000
    if target_code:
        lines = target_code.splitlines()
        loop_count = sum(1 for line in lines if any(kw in line for kw in ["for ", "while ", "loop {", "loop{"]))
        dynamic_fuel = min(base_fuel + (len(lines) * 500) + (loop_count * 500_000), 10_000_000)
    else:
        dynamic_fuel = 1_000_000

    return {
        "decision": decision,
        "fuel_limit": dynamic_fuel,
        "network": "network" in capabilities and decision == "ALLOW",
        "filesystem_read": "filesystem_read" in capabilities and decision == "ALLOW",
        "filesystem_write": "filesystem_write" in capabilities and decision == "ALLOW",
        "process_execution": "process_execution" in capabilities and decision == "ALLOW",
        "dynamic_execution": "dynamic_execution" in capabilities and decision == "ALLOW",
    }


generate_policy = create_policy
