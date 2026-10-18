"""SafePrompt Security Policy and Threat Defense Service.

Provides server-side detection for:
- Prompt injection & instruction override attempts
- Enterprise safety filter and policy bypasses
- Internal system architecture and data extraction

Note on Defense-in-Depth:
Pattern-based detection serves as an immediate deterministic boundary layer to reject
known adversarial signatures before LLM inference. It is not an exhaustive safeguard against
all novel semantic injection techniques, but ensures blatant attacks are blocked early.
"""

from __future__ import annotations

import re
from typing import TypedDict


class ThreatDetail(TypedDict):
    threat_type: str
    policy: str
    reason: str


# Compiled threat patterns adapted from enterprise gateway policies
THREAT_RULES: list[dict] = [
    {
        "type": "PROMPT_INJECTION",
        "policy": "Block prompt injection",
        "reason": "The prompt attempts to override system instructions, assume privileged personas, or extract internal instructions.",
        "patterns": [
            re.compile(
                r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)",
                re.IGNORECASE,
            ),
            re.compile(
                r"disregard\s+(?:the\s+)?(?:system|previous)\s+(?:prompt|instructions)",
                re.IGNORECASE,
            ),
            re.compile(
                r"you\s+are\s+now\s+(?:dan|in\s+developer\s+mode|unrestricted)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:reveal|show|print|repeat|leak|dump)\b.{0,40}\b(?:system|hidden)\s+(?:prompt|instructions)",
                re.IGNORECASE,
            ),
        ],
    },
    {
        "type": "POLICY_BYPASS",
        "policy": "Block policy bypass",
        "reason": "The prompt attempts to circumvent safety filters, guardrails, or enterprise policies.",
        "patterns": [
            re.compile(
                r"(?:bypass|disable|turn\s+off|circumvent|jailbreak)\b.{0,40}\b(?:filters?|polic(?:y|ies)|safety|guardrails?|restrictions?)",
                re.IGNORECASE,
            ),
            re.compile(
                r"pretend\s+(?:there\s+are\s+)?no\s+(?:rules|restrictions|filters)",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:\bignore_security\s*=\s*(?:true|1)|override_safety\s*=\s*true)",
                re.IGNORECASE,
            ),
        ],
    },
    {
        "type": "SYSTEM_DATA_EXTRACTION",
        "policy": "Block system data extraction",
        "reason": "The prompt requests sensitive internal architecture, configuration, or environment secrets.",
        "patterns": [
            re.compile(
                r"(?:internal|backend)\s+(?:architecture|configuration|config)\b",
                re.IGNORECASE,
            ),
            re.compile(
                r"(?:list|show|dump|print)\b.{0,30}\b(?:environment\s+variables|env\s+vars|database\s+credentials|config\s+files?|api\s+keys?)",
                re.IGNORECASE,
            ),
        ],
    },
]


def evaluate_prompt_threats(prompt: str) -> ThreatDetail | None:
    """Evaluate a user prompt against threat rules before any downstream processing.
    
    Returns a ThreatDetail dictionary if a threat signature is detected, otherwise None.
    Never logs or exposes the raw prompt or any PII.
    """
    if not prompt:
        return None

    normalized = prompt.strip()

    for rule in THREAT_RULES:
        for pattern in rule["patterns"]:
            if pattern.search(normalized):
                return {
                    "threat_type": rule["type"],
                    "policy": rule["policy"],
                    "reason": rule["reason"],
                }

    return None
