"""Load and validate the OMG pattern catalog."""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "Content" / "data" / "omg_pattern_catalog.json"


class PatternCatalogError(RuntimeError):
    """Raised when the pattern catalog is missing or invalid."""


@lru_cache(maxsize=1)
def load_pattern_catalog() -> dict[str, Any]:
    """Load the catalog and validate its structure and unique identifiers."""

    if not CATALOG_PATH.is_file():
        raise PatternCatalogError(
            f"Pattern catalog file not found: {CATALOG_PATH}"
        )

    try:
        with CATALOG_PATH.open("r", encoding="utf-8") as file:
            catalog = json.load(file)
    except (OSError, json.JSONDecodeError) as exc:
        raise PatternCatalogError(
            f"Unable to read the pattern catalog: {exc}"
        ) from exc

    if not isinstance(catalog, dict):
        raise PatternCatalogError("Catalog root must be a JSON object.")

    patterns = catalog.get("patterns")
    if not isinstance(patterns, list):
        raise PatternCatalogError(
            "Catalog must contain a 'patterns' list."
        )

    declared_count = catalog.get("pattern_count")
    if declared_count != len(patterns):
        raise PatternCatalogError(
            f"Declared pattern_count ({declared_count}) does not "
            f"match the actual count ({len(patterns)})."
        )

    required_fields = {"id", "code", "name", "category"}
    ids: list[str] = []
    codes: list[str] = []

    for index, pattern in enumerate(patterns):
        if not isinstance(pattern, dict):
            raise PatternCatalogError(
                f"Pattern at index {index} must be an object."
            )

        missing = required_fields - pattern.keys()
        if missing:
            raise PatternCatalogError(
                f"Pattern at index {index} is missing fields: "
                f"{', '.join(sorted(missing))}."
            )

        pattern_id = pattern["id"]
        code = pattern["code"]

        if not isinstance(pattern_id, str) or not pattern_id.strip():
            raise PatternCatalogError(
                f"Pattern at index {index} has an invalid ID."
            )

        if not isinstance(code, str) or not code.strip():
            raise PatternCatalogError(
                f"Pattern at index {index} has an invalid code."
            )

        ids.append(pattern_id)
        codes.append(code)

    if len(ids) != len(set(ids)):
        raise PatternCatalogError("Duplicate pattern IDs found.")

    if len(codes) != len(set(codes)):
        raise PatternCatalogError("Duplicate pattern codes found.")

    return catalog


def get_patterns() -> list[dict[str, Any]]:
    """Return all registered catalog definitions."""
    return load_pattern_catalog()["patterns"]


def get_catalog_summary() -> dict[str, int]:
    """Return catalog counts without implying detector implementation."""

    patterns = get_patterns()

    implemented_count = sum(
        1
        for pattern in patterns
        if pattern.get("implementation_status") == "implemented"
    )

    return {
        "total_patterns": len(patterns),
        "implemented_patterns": implemented_count,
        "catalog_only_patterns": len(patterns) - implemented_count,
    }