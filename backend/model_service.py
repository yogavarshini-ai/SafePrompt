
"""SafePrompt PII model service."""
import json
from pathlib import Path

import numpy as np
from tensorflow import keras

BACKEND_DIR = Path(__file__).resolve().parent
MODEL_PATH = BACKEND_DIR / "models" / "pii_only_test.keras"
METADATA_PATH = BACKEND_DIR / "models" / "pii_employee_model.json"

_model = None
_metadata = None


def detect_pii(text: str) -> list[dict]:
    """Detect PII using the trained token-classification model."""
    global _model, _metadata

    if _model is None:
        if not MODEL_PATH.is_file() or not METADATA_PATH.is_file():
            raise FileNotFoundError("PII model or metadata file is missing.")

        _model = keras.models.load_model(MODEL_PATH, compile=False)
        _metadata = json.loads(
            METADATA_PATH.read_text(encoding="utf-8")
        )

    cfg = _metadata["pii"]
    token_to_id = cfg["token_to_id"]
    label_to_id = {v: k for k, v in cfg["label_to_id"].items()}
    max_len = cfg.get("max_sequence_length", 128)

    # Tokenize and truncate
    tokens = text.split()[:max_len]
    if not tokens:
        return []

    # Prepare input IDs (1 for unknown tokens)
    x = np.zeros((1, max_len), dtype=np.int32)
    x[0, :len(tokens)] = [token_to_id.get(tok, 1) for tok in tokens]

    predictions = _model.predict(x, verbose=0)[0]
    results = []
    i = 0
    while i < len(tokens):
        scores = predictions[i]
        label_id = int(np.argmax(scores))
        label = label_to_id.get(label_id, "O")
        confidence = round(float(np.max(scores)), 3)
        if label.startswith("B-"):
            # Begin multi‑token entity
            span_tokens = [tokens[i]]
            span_confidences = [confidence]
            j = i + 1
            while j < len(tokens):
                next_scores = predictions[j]
                next_label_id = int(np.argmax(next_scores))
                next_label = label_to_id.get(next_label_id, "O")
                if next_label.startswith("I-"):
                    span_tokens.append(tokens[j])
                    span_confidences.append(round(float(np.max(next_scores)), 3))
                    j += 1
                else:
                    break
            results.append({
                "token": " ".join(span_tokens),
                "label": label,  # keep original B- prefix
                "confidence": max(span_confidences),
            })
            i = j
        elif label != "O":
            # Single‑token entity (e.g., email, phone)
            results.append({
                "token": tokens[i],
                "label": label,
                "confidence": confidence,
            })
            i += 1
        else:
            i += 1
    return results
