import os
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    APP_NAME = "OMG - Outbound Mail Gatekeeper"
    APP_VERSION = "3.2.0"
    API_PREFIX = os.getenv("OMG_API_PREFIX", "/api/v1").rstrip("/") or "/api/v1"
    ENVIRONMENT = os.getenv("OMG_ENVIRONMENT", os.getenv("OMG_ENV", "development")).strip().lower()
    RULES_PATH = Path(os.getenv("OMG_RULES_PATH", "Content/data/omg_rules.json"))
    MODEL_PATH = Path(os.getenv("OMG_MODEL_PATH", "Content/models/email_classifier.joblib"))
    REQUIRE_ML = _as_bool(os.getenv("OMG_REQUIRE_ML"), default=False)
    ENABLE_ML = _as_bool(os.getenv("OMG_ENABLE_ML"), default=False)
    ENABLE_EXPERIMENTAL_TFIDF = _as_bool(os.getenv("OMG_ENABLE_EXPERIMENTAL_TFIDF"), default=False)
    ML_MIN_CONFIDENCE = float(os.getenv("OMG_ML_MIN_CONFIDENCE", "0.60"))
    API_KEY = os.getenv("OMG_API_KEY", "").strip()
    LOG_LEVEL = os.getenv("OMG_LOG_LEVEL", "INFO").upper()
    MAX_REQUEST_BYTES = int(os.getenv("OMG_MAX_REQUEST_BYTES", "65000000"))

    @staticmethod
    def resolve_path(path: Path) -> Path:
        return path if path.is_absolute() else PROJECT_ROOT / path

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT in {"production", "prod"}

    def validate_production_configuration(self) -> None:
        """Reject unsafe/incomplete production configuration before serving traffic."""
        if not self.is_production:
            return

        errors = []
        if not 0.5 <= self.ML_MIN_CONFIDENCE <= 0.99:
            errors.append("OMG_ML_MIN_CONFIDENCE must be between 0.50 and 0.99")
        if len(self.API_KEY) < 32:
            errors.append("OMG_API_KEY must be configured with at least 32 characters")
        if not self.REQUIRE_ML:
            errors.append("OMG_REQUIRE_ML must be true in production")
        if not self.resolve_path(self.MODEL_PATH).is_file():
            errors.append(f"trained ML model not found: {self.resolve_path(self.MODEL_PATH)}")
        if not self.resolve_path(self.RULES_PATH).is_file():
            errors.append(f"runtime rules file not found: {self.resolve_path(self.RULES_PATH)}")
        if self.MAX_REQUEST_BYTES < 1024:
            errors.append("OMG_MAX_REQUEST_BYTES must be at least 1024")
        if errors:
            raise RuntimeError("Invalid production configuration: " + "; ".join(errors))


settings = Settings()
