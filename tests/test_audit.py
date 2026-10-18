"""Focused tests for SafePrompt Structured Audit Logging with SHA-256 Hash Chaining (Step 3B).

Tests:
1. Event schema compliance (docs/architecture.md Section F).
2. Cryptographic hash chain creation and end-to-end verification.
3. Tamper detection:
   - Mutating a payload field breaks the chain.
   - Modifying prev_hash breaks the chain.
   - Deleting a middle record breaks the chain.
4. Concurrent write safety (multi-threaded concurrent logging produces a valid unbroken chain).
5. Privacy verification (assert zero raw prompts, PII, API keys, or plaintext stored in audit db).
"""

import concurrent.futures
import sqlite3
import pytest

from backend.audit_service import AuditService, GENESIS_HASH


@pytest.fixture
def temp_audit(tmp_path):
    """Provide an isolated AuditService instance backed by a temporary SQLite file."""
    db_file = tmp_path / "test_audit.db"
    return AuditService(db_path=db_file)


def test_audit_event_schema_compliance(temp_audit):
    """Verify generated audit events match the Section F schema."""
    event = temp_audit.log_event(
        request_id="req-schema-001",
        event_type="mask_applied",
        policy_decision="allow",
        outcome="success",
        user_id="user_123",
        role="Employee",
        metadata={
            "redacted_prompt": "Contact {{TOKEN_abcdef123456}} for details.",
            "placeholders": ["{{TOKEN_abcdef123456}}"],
            "details": "Applied masking to 1 entity.",
        },
    )

    # Required Section F top-level keys
    required_keys = {
        "event_id",
        "timestamp",
        "request_id",
        "user_id",
        "role",
        "event_type",
        "policy_decision",
        "outcome",
        "metadata",
        "prev_hash",
        "integrity_hash",
    }
    assert required_keys.issubset(event.keys())
    assert event["prev_hash"] == GENESIS_HASH
    assert len(event["integrity_hash"]) == 64
    assert event["policy_decision"] == "allow"
    assert event["outcome"] == "success"


def test_hash_chain_verification_sequential(temp_audit):
    """Verify hash chaining across multiple sequential events."""
    events = []
    for i in range(5):
        ev = temp_audit.log_event(
            request_id=f"req-seq-{i}",
            event_type="prompt_processed" if i % 2 == 0 else "mask_applied",
            metadata={"details": f"Event sequence index {i}"},
        )
        events.append(ev)

    # Verify link-by-link
    assert events[0]["prev_hash"] == GENESIS_HASH
    for i in range(1, len(events)):
        assert events[i]["prev_hash"] == events[i - 1]["integrity_hash"]

    # Verify entire chain using verification utility
    valid, message = temp_audit.verify_chain()
    assert valid is True
    assert "5 events successfully verified" in message


def test_tamper_detection_payload_mutation(temp_audit):
    """Verify that tampering with any payload field is detected by verify_chain."""
    for i in range(4):
        temp_audit.log_event(
            request_id=f"req-tamper-{i}",
            event_type="policy_block" if i == 2 else "prompt_processed",
            metadata={"details": f"Record {i}"},
        )

    # Initially valid
    valid, _ = temp_audit.verify_chain()
    assert valid is True

    # Tamper with record #2 in SQLite database (mutate metadata_json)
    conn = sqlite3.connect(str(temp_audit.db_path))
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE audit_events SET metadata_json = ? WHERE id = 2",
        ('{"details": "TAMPERED_CONTENT"}',),
    )
    conn.commit()
    conn.close()

    # Re-verify: must fail
    valid, reason = temp_audit.verify_chain()
    assert valid is False
    assert "Tampered record detected" in reason


def test_tamper_detection_prev_hash_mutation(temp_audit):
    """Verify that altering a prev_hash pointer is detected."""
    for i in range(3):
        temp_audit.log_event(request_id=f"req-{i}", event_type="prompt_processed")

    conn = sqlite3.connect(str(temp_audit.db_path))
    cursor = conn.cursor()
    cursor.execute("UPDATE audit_events SET prev_hash = ? WHERE id = 2", ("a" * 64,))
    conn.commit()
    conn.close()

    valid, reason = temp_audit.verify_chain()
    assert valid is False
    assert "Chain broken" in reason


def test_tamper_detection_record_deletion(temp_audit):
    """Verify that deleting a record from the middle of the chain is detected."""
    for i in range(4):
        temp_audit.log_event(request_id=f"req-del-{i}", event_type="prompt_processed")

    conn = sqlite3.connect(str(temp_audit.db_path))
    cursor = conn.cursor()
    cursor.execute("DELETE FROM audit_events WHERE id = 2")
    conn.commit()
    conn.close()

    valid, reason = temp_audit.verify_chain()
    assert valid is False
    assert "Chain broken" in reason


def test_concurrent_writes_safety(temp_audit):
    """Verify multi-threaded concurrent writes maintain strict chain integrity without conflicts."""
    total_events = 25

    def writer(idx):
        return temp_audit.log_event(
            request_id=f"req-concurrent-{idx}",
            event_type="prompt_processed",
            metadata={"details": f"Concurrent thread record #{idx}"},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(writer, i) for i in range(total_events)]
        concurrent.futures.wait(futures)

    # Confirm all events written
    events = temp_audit.get_events()
    assert len(events) == total_events

    # Verify the entire chain is unbroken and mathematically valid
    valid, message = temp_audit.verify_chain()
    assert valid is True, f"Concurrent chain verification failed: {message}"
    assert f"{total_events} events successfully verified" in message


def test_privacy_guarantees_no_raw_prompts_or_secrets(temp_audit):
    """Confirm raw prompts, original PII, API keys, and vault plaintext are stripped/absent."""
    # Attempt to log with raw sensitive fields in metadata
    temp_audit.log_event(
        request_id="req-privacy-check",
        event_type="mask_applied",
        metadata={
            "prompt": "Raw secret prompt should be stripped",
            "api_key": "sk-1234567890",
            "redacted_prompt": "Sanitized {{TOKEN_123}} prompt",
            "placeholders": ["{{TOKEN_123}}"],
        },
    )

    # Inspect SQLite database directly
    conn = sqlite3.connect(str(temp_audit.db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT metadata_json FROM audit_events WHERE request_id = 'req-privacy-check'")
    metadata_json = cursor.fetchone()[0]
    conn.close()

    assert "Raw secret prompt should be stripped" not in metadata_json
    assert "sk-1234567890" not in metadata_json
    assert "Sanitized {{TOKEN_123}} prompt" in metadata_json
