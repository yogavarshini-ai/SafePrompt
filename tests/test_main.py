import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

@pytest.fixture
def sample_prompt():
    return "Contact John Smith at john.smith@example.com or call 9876543210"

def test_name_email_phone_masking(sample_prompt, auth_headers_employee):
    response = client.post("/prompt", json={"prompt": sample_prompt}, headers=auth_headers_employee)
    assert response.status_code == 200
    data = response.json()
    # Ensure the masked field contains vault token placeholders {{TOKEN_<hash>}}
    import re
    assert re.search(r"\{\{TOKEN_[0-9a-fA-F]+\}\}", data["masked"]) is not None
    # Name, email, and phone should be redacted
    assert "John Smith" not in data["masked"]
    assert "john.smith@example.com" not in data["masked"]
    assert "9876543210" not in data["masked"]
    # Ensure response does not expose original prompt
    assert "John Smith" not in data["response"]
    assert "john.smith@example.com" not in data["response"]
    assert "9876543210" not in data["response"]
