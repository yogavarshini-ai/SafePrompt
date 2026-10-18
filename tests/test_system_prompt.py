"""SafePrompt System Prompt Validation Tests.

Verifies that SAFEPROMPT_SYSTEM_PROMPT in backend/main.py satisfies all Enterprise AI Security Gateway
requirements from the curriculum specification:
1. Architectural mission and core gateway purpose.
2. Mitigation of the 4 primary enterprise business risks:
   - Data Leakage
   - Regulatory Non-Compliance (PII, PHI, financial records)
   - Reputational Damage
   - Loss of Intellectual Property (code, keys, trade secrets)
3. Multi-stakeholder alignment (CISO, IT Admin, Compliance, HR/Finance, Engineering, Employees).
4. Detection, masking, and encrypted local lookup vault zero-knowledge preservation.
5. Strict prohibition against guessing/reconstructing sensitive values, requiring verbatim token retention.
6. Role-based access control (RBAC): allowing aggregate/departmental compensation analytics while blocking individual records.
7. Active defense against prompt injections, policy bypasses, and system data extraction.
8. End-to-end integration: ensuring POST /prompt supplies the system prompt to the AI service.
"""

from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.main import app, SAFEPROMPT_SYSTEM_PROMPT

client = TestClient(app)


def test_system_prompt_defines_mission_and_risks():
    """Verify system prompt addresses the 4 primary enterprise business risks."""
    prompt = SAFEPROMPT_SYSTEM_PROMPT
    assert "Enterprise AI Security Gateway" in prompt
    assert "Data Leakage" in prompt
    assert "Regulatory Non-Compliance" in prompt
    assert "Reputational Damage" in prompt
    assert "Loss of Intellectual Property" in prompt


def test_system_prompt_stakeholder_alignment():
    """Verify system prompt includes directives for all six key enterprise stakeholders."""
    prompt = SAFEPROMPT_SYSTEM_PROMPT
    assert "CISOs & Security Analysts" in prompt
    assert "IT Administrators" in prompt
    assert "Compliance & Legal Officers" in prompt
    assert "HR & Finance Teams" in prompt
    assert "Software Engineering Leaders" in prompt
    assert "Business Managers & Employees" in prompt


def test_system_prompt_detection_masking_vault_rules():
    """Verify system prompt specifies handling of tokens, prohibition of guessing, and verbatim retention."""
    prompt = SAFEPROMPT_SYSTEM_PROMPT
    # Detection scanning targets
    assert "direct identifiers" in prompt.lower()
    assert "technical credentials" in prompt.lower()
    assert "business identifiers" in prompt.lower()

    # Placeholders / tokens
    assert "{{TOKEN_" in prompt
    assert "[PERSON_1]" in prompt
    assert "[SALARY_1]" in prompt

    # Vaulting and prohibition
    assert "local lookup vault" in prompt.lower()
    assert "never attempt to infer, unmask, hallucinate, predict, or reconstruct" in prompt.lower()
    assert "verbatim" in prompt.lower()


def test_system_prompt_rbac_compensation_boundaries():
    """Verify system prompt distinguishes aggregate analytics from individual compensation records."""
    prompt = SAFEPROMPT_SYSTEM_PROMPT
    assert "average salary by department" in prompt.lower()
    assert "individual compensation" in prompt.lower()
    assert "restricted under enterprise rbac" in prompt.lower()


def test_system_prompt_threat_defenses():
    """Verify system prompt enforces defenses against prompt injection, policy bypass, and system extraction."""
    prompt = SAFEPROMPT_SYSTEM_PROMPT
    assert "Prompt Injections" in prompt
    assert "Policy Bypasses" in prompt
    assert "System Data Extraction" in prompt
    assert "audit" in prompt.lower()


def test_prompt_endpoint_prepends_system_prompt(monkeypatch, auth_headers_employee):
    """Verify POST /prompt passes SAFEPROMPT_SYSTEM_PROMPT along with masked user input to the AI model."""
    mock_gemini = MagicMock()
    mock_result = MagicMock()
    mock_result.text = "Here is the sanitized summary for {{TOKEN_test}}."
    mock_gemini.models.generate_content.return_value = mock_result
    monkeypatch.setattr("backend.main.genai.Client", MagicMock(return_value=mock_gemini))

    payload = {"prompt": "Please draft an announcement regarding project deadlines."}
    response = client.post("/prompt", json=payload, headers=auth_headers_employee)

    assert response.status_code == 200
    assert mock_gemini.models.generate_content.called

    call_args = mock_gemini.models.generate_content.call_args[1]
    contents_sent = call_args["contents"]

    assert SAFEPROMPT_SYSTEM_PROMPT in contents_sent
    assert "User request:\n" in contents_sent
    assert payload["prompt"] in contents_sent


def test_system_prompt_work_only_domain_restrictions():
    """Verify system prompt strictly confines the assistant to enterprise work and forbids weather, casual chat, and relationship advice."""
    prompt = SAFEPROMPT_SYSTEM_PROMPT
    assert "STRICT WORK-ONLY & ENTERPRISE DOMAIN RESTRICTIONS" in prompt
    assert "NO WEATHER FORECASTS OR REPORTS" in prompt
    assert "Never ask users for their city or region to provide a weather forecast" in prompt
    assert "NO CASUAL FRIEND CHIT-CHAT" in prompt
    assert "NO PERSONAL RELATIONSHIP OR LIFESTYLE ADVICE" in prompt
    assert "MANDATORY REDIRECTION TO WORK" in prompt

