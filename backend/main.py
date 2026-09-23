from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from openai import APIConnectionError, APIStatusError, AuthenticationError
from policy import create_policy
from pydantic import BaseModel

from llm import ask_ai
from sandbox_client import call_sandbox
from security import analyze_request

import json
import re

app = FastAPI()

import os

# Allow frontend requests from local dev servers, Vercel deployments, or custom domains
allowed_origins_env = os.getenv("CORS_ORIGINS")
if allowed_origins_env:
    allowed_origins = [o.strip() for o in allowed_origins_env.split(",") if o.strip()]
else:
    allowed_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if "*" not in allowed_origins else ["*"],
    allow_origin_regex=r"https://.*\.vercel\.app|http://localhost:.*|http://127\.0\.0\.1:.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ExecuteRequest(BaseModel):
    prompt: str


@app.get("/")
def home():
    return {
        "message": "AI Agent Firewall Backend is running"
    }


def parse_llm_json(raw: str) -> dict:
    text = raw.strip()
    # 1. Remove <think>...</think> reasoning tags
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    # 2. Remove markdown code block wrapping
    text = re.sub(r"^```(?:json|rust)?\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()

    # Direct JSON parse attempt
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Extract outermost JSON object { ... }
    match = re.search(r"(\{.*\})", text, flags=re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not extract valid JSON from LLM response:\n{raw[:300]}")


@app.post("/api/execute")
def execute(request: ExecuteRequest):

    # 1. Ask the AI to generate code
    try:
        print(f"[api/execute] Generating code for prompt: {request.prompt}", flush=True)
        ai_response = ask_ai(request.prompt)
        print(f"[api/execute] Raw AI response:\n{ai_response}", flush=True)
    except AuthenticationError as exc:
        print(f"[api/execute] LLM Auth Error: {exc}", flush=True)
        raise HTTPException(
            status_code=502,
            detail="LLM authentication failed. Replace GROQ_API_KEY in backend/.env and restart the server.",
        ) from exc
    except APIConnectionError as exc:
        print(f"[api/execute] LLM Connection Error: {exc}", flush=True)
        raise HTTPException(
            status_code=503,
            detail="Could not connect to the configured LLM provider.",
        ) from exc
    except APIStatusError as exc:
        print(f"[api/execute] LLM API Status Error: {exc.status_code} - {exc}", flush=True)
        raise HTTPException(
            status_code=502,
            detail=f"LLM provider request failed: {exc.status_code} ({getattr(exc, 'message', str(exc))})",
        ) from exc
    except Exception as exc:
        print(f"[api/execute] Unexpected LLM error: {exc}", flush=True)
        raise HTTPException(
            status_code=502,
            detail=f"LLM generation failed: {exc}",
        ) from exc

    # 2. Convert the LLM JSON response into a Python dictionary.
    try:
        result = parse_llm_json(ai_response)
        code = result["code"]
        language = result.get("language", "rust")
        explanation = result.get("explanation", "")
    except Exception as exc:
        print(f"[api/execute] JSON parsing failed: {exc}\nRaw response was:\n{ai_response}", flush=True)
        raise HTTPException(
            status_code=502,
            detail=f"LLM returned an invalid code-generation response: {exc}",
        ) from exc

    # 3. Analyze the Rust request/code and generate its capability policy.
    security = analyze_request(
        prompt=request.prompt,
        code=code,
    )
    policy = create_policy(security, code=code)

    # 4. Compile and execute only if the policy explicitly allows it.
    sandbox_result = call_sandbox(code, policy, language=language)
    return {
        "language": language,
        "code": code,
        "explanation": explanation,
        "security": security,
        "policy": policy,
        "execution": sandbox_result,
    }


class ExecuteCodeRequest(BaseModel):
    code: str
    preset: str | None = None
    language: str | None = None


def _risk_level(risk_score: int) -> str:
    if risk_score >= 80:
        return "Critical"
    if risk_score >= 50:
        return "High"
    if risk_score >= 1:
        return "Medium"
    return "Low"


def _capability_label(capability: str) -> str:
    return capability.replace("_", " ").title()


def _applied_policy(policy: dict) -> list[dict]:
    return [
        {"label": "Network Access", "value": "Allowed" if policy["network"] else "Disabled"},
        {"label": "Filesystem Read", "value": "Allowed" if policy["filesystem_read"] else "Disabled"},
        {"label": "Filesystem Write", "value": "Allowed" if policy["filesystem_write"] else "Disabled"},
        {"label": "Process Execution", "value": "Allowed" if policy["process_execution"] else "Disabled"},
        {"label": "Dynamic Execution", "value": "Allowed" if policy["dynamic_execution"] else "Disabled"},
    ]


@app.post("/api/execute-code")
def execute_code(request: ExecuteCodeRequest):
    # Skip LLM generation entirely: analyze and run the user's own code
    # directly, reusing the exact same security/policy/sandbox pipeline
    # that /api/execute uses for LLM-generated code.
    security = analyze_request(prompt="", code=request.code)
    policy = create_policy(security, code=request.code)

    risk_level = _risk_level(security["risk_score"])
    timestamp = datetime.utcnow().isoformat() + "Z"
    exec_id = f"exec_{int(datetime.utcnow().timestamp() * 1000)}"

    if policy["decision"] != "ALLOW":
        threats = [
            {
                "title": _capability_label(capability),
                "severity": risk_level,
                "detail": next(
                    (f for f in security["findings"] if capability.replace("_", " ") in f.lower()),
                    f"Detected capability: {_capability_label(capability)}",
                ),
            }
            for capability in security["capabilities"]
        ] or [{"title": "Blocked", "severity": risk_level, "detail": "Execution blocked by policy."}]

        return {
            "id": exec_id,
            "status": "blocked",
            "timestamp": timestamp,
            "message": "The code was blocked by the security policy before execution.",
            "codeSnapshot": request.code,
            "threats": threats,
            "preset": request.preset,
            "appliedPolicy": _applied_policy(policy),
            "security": security,
            "policy": policy,
        }

    sandbox_result = call_sandbox(request.code, policy, language=request.language or "auto")
    exec_time_ms = sandbox_result.get("execution_time_ms", 0)
    fuel = sandbox_result.get("fuel_used", 0)
    fs_access = "Allowed" if (policy["filesystem_read"] or policy["filesystem_write"]) else "Denied"
    net_access = "Allowed" if policy["network"] else "Denied"

    if not sandbox_result.get("success"):
        return {
            "id": exec_id,
            "status": "error",
            "timestamp": timestamp,
            "preset": request.preset,
            "output": sandbox_result.get("output", ""),
            "logs": sandbox_result.get("error") or "Execution failed.",
            "details": {
                "status": "Error",
                "riskLevel": risk_level,
                "executionTime": f"{exec_time_ms} ms",
                "memoryUsed": "n/a",
                "fuelConsumed": f"{fuel:,}",
                "filesystemAccess": fs_access,
                "networkAccess": net_access,
                "exitCode": 1,
            },
            "security": security,
            "policy": policy,
        }

    return {
        "id": exec_id,
        "status": "success",
        "timestamp": timestamp,
        "preset": request.preset,
        "output": sandbox_result.get("output", ""),
        "logs": "No warnings or errors were logged during this run.",
        "details": {
            "status": "Allowed",
            "riskLevel": risk_level,
            "executionTime": f"{exec_time_ms} ms",
            "memoryUsed": "n/a",
            "fuelConsumed": f"{fuel:,}",
            "filesystemAccess": fs_access,
            "networkAccess": net_access,
            "exitCode": 0,
        },
        "security": security,
        "policy": policy,
    }
