from Content.config import settings
from Content.model_loader import load_model, ModelUnavailableError
from Content.preprocessing import email_to_text


def classify_email(subject: str, body: str) -> dict:
    """Classify locally; uncertain predictions fail closed as RESTRICTED."""
    path = settings.resolve_path(settings.MODEL_PATH)
    try:
        model = load_model(str(path))
        text = email_to_text(subject, body)
        prediction = str(model.predict([text])[0]).strip().upper()
        if prediction not in {"SAFE", "RESTRICTED", "HAM", "SPAM"}:
            return {"available": False, "completed": False, "finding": None,
                    "reason": f"Unsupported model label: {prediction}"}

        label = "RESTRICTED" if prediction in {"RESTRICTED", "SPAM"} else "SAFE"
        confidence = None
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba([text])[0]
            classes = [str(item).strip().upper() for item in getattr(model, "classes_", [])]
            if len(classes) == len(probabilities) and len(probabilities):
                confidence = float(max(probabilities))
                predicted_index = max(range(len(probabilities)), key=lambda index: probabilities[index])
                predicted_class = classes[predicted_index]
                label = "RESTRICTED" if predicted_class in {"RESTRICTED", "SPAM"} else "SAFE"

        finding = None
        reason = None
        if confidence is not None and confidence < settings.ML_MIN_CONFIDENCE:
            label = "RESTRICTED"
            reason = "The classifier confidence was below the configured minimum; manual review is required."
            finding = {
                "code": "ML_CLASSIFIER_LOW_CONFIDENCE",
                "category": "ML_CLASSIFICATION",
                "severity": "MEDIUM",
                "confidence": 0.5,
                "message": reason,
            }
        elif label == "RESTRICTED":
            finding = {
                "code": "ML_CLASSIFIER_RESTRICTED",
                "category": "ML_CLASSIFICATION",
                "severity": "HIGH",
                "confidence": round(confidence, 4) if confidence is not None else 0.6,
                "message": "The trained local text classifier classified this email as restricted.",
            }

        result = {
            "available": True,
            "completed": True,
            "label": label,
            "model_version": "local-sklearn-word-char-v2",
            "finding": finding,
        }
        if confidence is not None:
            result["confidence"] = round(confidence, 4)
        if reason:
            result["reason"] = reason
        return result
    except ModelUnavailableError as exc:
        return {"available": False, "completed": False, "finding": None, "reason": str(exc)}
    except Exception as exc:
        return {"available": True, "completed": False, "finding": None,
                "reason": f"Local classifier failed: {type(exc).__name__}"}
