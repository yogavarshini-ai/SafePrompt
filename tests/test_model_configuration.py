"""Unit tests for Gemini model configuration in SafePrompt.

Verifies:
1. get_configured_model() retrieves the model from GEMINI_MODEL in the environment.
2. get_configured_model() defaults to 'gemini-3.8-flash' when unset or blank.
3. POST /prompt passes the configured model string directly to client.models.generate_content.
4. Verifies that 'gemini-2.5-flash' is not passed or hardcoded as a fallback.
"""

import os
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from backend.main import app, get_configured_model

client = TestClient(app)


def test_get_configured_model_reads_env(monkeypatch):
    """Verify get_configured_model returns the environment-configured model name."""
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    assert get_configured_model() == "gemini-3.8-flash"

    monkeypatch.setenv("GEMINI_MODEL", "custom-enterprise-model")
    assert get_configured_model() == "custom-enterprise-model"

    # Strips whitespace
    monkeypatch.setenv("GEMINI_MODEL", "  gemini-3.8-flash  \n")
    assert get_configured_model() == "gemini-3.8-flash"


def test_get_configured_model_fallback_on_empty(monkeypatch):
    """Verify get_configured_model falls back to 'gemini-3.8-flash' when unset or empty."""
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    assert get_configured_model() == "gemini-3.8-flash"

    monkeypatch.setenv("GEMINI_MODEL", "")
    assert get_configured_model() == "gemini-3.8-flash"

    monkeypatch.setenv("GEMINI_MODEL", "   ")
    assert get_configured_model() == "gemini-3.8-flash"


def test_prompt_passes_configured_model_to_gemini(monkeypatch, auth_headers_employee):
    """Verify POST /prompt passes the configured model name to client.models.generate_content."""
    target_model = "gemini-3.8-flash"
    monkeypatch.setenv("GEMINI_MODEL", target_model)

    mock_gemini = MagicMock()
    mock_result = MagicMock()
    mock_result.text = "Model test response."
    mock_gemini.models.generate_content.return_value = mock_result
    monkeypatch.setattr("backend.main.genai.Client", MagicMock(return_value=mock_gemini))

    response = client.post(
        "/prompt",
        json={"prompt": "Summarize safe enterprise AI practices."},
        headers=auth_headers_employee,
    )

    assert response.status_code == 200
    assert mock_gemini.models.generate_content.called

    call_kwargs = mock_gemini.models.generate_content.call_args[1]
    assert call_kwargs["model"] == target_model
    assert call_kwargs["model"] != "gemini-2.5-flash"


def test_prompt_passes_custom_configured_model_to_gemini(monkeypatch, auth_headers_employee):
    """Verify POST /prompt dynamically respects a different configured model name."""
    target_model = "test-gemini-pro-special"
    monkeypatch.setenv("GEMINI_MODEL", target_model)

    mock_gemini = MagicMock()
    mock_result = MagicMock()
    mock_result.text = "Custom model response."
    mock_gemini.models.generate_content.return_value = mock_result
    monkeypatch.setattr("backend.main.genai.Client", MagicMock(return_value=mock_gemini))

    response = client.post(
        "/prompt",
        json={"prompt": "Check custom model routing."},
        headers=auth_headers_employee,
    )

    assert response.status_code == 200
    assert mock_gemini.models.generate_content.called

    call_kwargs = mock_gemini.models.generate_content.call_args[1]
    assert call_kwargs["model"] == target_model


def test_resilient_fallback_on_high_demand_503(monkeypatch, auth_headers_employee):
    """Verify that when primary model experiences high demand (503), it fails over to the next candidate model."""
    mock_gemini = MagicMock()
    
    # First call (primary model) fails with 503 high demand; second call (fallback model) succeeds
    mock_success_result = MagicMock()
    mock_success_result.text = "Recovered response from fallback model."
    
    mock_gemini.models.generate_content.side_effect = [
        RuntimeError("503 UNAVAILABLE: This model is currently experiencing high demand. Spikes in demand..."),
        mock_success_result,
    ]
    monkeypatch.setattr("backend.main.genai.Client", MagicMock(return_value=mock_gemini))

    response = client.post(
        "/prompt",
        json={"prompt": "Summarize project deliverables."},
        headers=auth_headers_employee,
    )

    assert response.status_code == 200
    assert response.json()["response"] == "Recovered response from fallback model."
    assert mock_gemini.models.generate_content.call_count == 2
    
    # Assert second call was made to fallback model
    second_call_model = mock_gemini.models.generate_content.call_args_list[1][1]["model"]
    assert second_call_model == "gemini-3.5-flash"


def test_resilient_fallback_on_404_deprecated(monkeypatch, auth_headers_employee):
    """Verify that when primary model returns 404 NOT_FOUND, it fails over to the fallback candidate."""
    mock_gemini = MagicMock()
    mock_success_result = MagicMock()
    mock_success_result.text = "Recovered from deprecated model."

    mock_gemini.models.generate_content.side_effect = [
        RuntimeError("404 NOT_FOUND: Model is no longer available."),
        mock_success_result,
    ]
    monkeypatch.setattr("backend.main.genai.Client", MagicMock(return_value=mock_gemini))

    response = client.post(
        "/prompt",
        json={"prompt": "Analyze risk assessment."},
        headers=auth_headers_employee,
    )

    assert response.status_code == 200
    assert response.json()["response"] == "Recovered from deprecated model."
    assert mock_gemini.models.generate_content.call_count == 2

