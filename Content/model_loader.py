from functools import lru_cache
from pathlib import Path
import joblib


class ModelUnavailableError(RuntimeError):
    pass


@lru_cache(maxsize=4)
def load_model(model_path: str):
    path = Path(model_path)
    if not path.is_file():
        raise ModelUnavailableError(f"No trained model found at {path}. Train one with model_training/train_model.py.")
    try:
        model = joblib.load(path)
    except Exception as exc:
        raise ModelUnavailableError(f"Could not load the model at {path}: {exc}") from exc
    if not hasattr(model, "predict"):
        raise ModelUnavailableError("The model file does not provide a predict() method.")
    return model


def clear_model_cache() -> None:
    load_model.cache_clear()
