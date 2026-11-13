
"""
MongoDB repository for OMG email analysis records.
"""

from datetime import datetime, timezone
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

from database import get_database


COLLECTION_NAME = "email_analysis"


def get_analysis_collection():
    db = get_database()
    collection = db[COLLECTION_NAME]

    # Create indexes for account-specific history and lookup.
    collection.create_index(
        [("account_id", ASCENDING), ("created_at", DESCENDING)],
        name="account_history_index"
    )

    collection.create_index(
        [("request_id", ASCENDING)],
        name="request_id_index",
        sparse=True
    )

    return collection


def save_analysis(account_id: str, analysis_result: dict,
                  email_data: dict = None,
                  request_id: str = None):
    """
    Save an analysis result.

    account_id must come from your existing authenticated user,
    not from an untrusted request body.
    """

    if not account_id:
        raise ValueError("Authenticated account_id is required")

    if not isinstance(analysis_result, dict):
        raise ValueError("analysis_result must be a dictionary")

    email_data = email_data or {}

    document = {
        "account_id": str(account_id),
        "request_id": request_id,
        "email": {
            "from": email_data.get("from"),
            "to": email_data.get("to"),
            "subject": email_data.get("subject"),
            "body": email_data.get("body"),
        },
        "status": analysis_result.get("status"),
        "confidence_score": analysis_result.get("confidence_score"),
        "can_send": analysis_result.get("can_send"),
        "requires_acknowledgement": analysis_result.get(
            "requires_acknowledgement"
        ),
        "score_contributions": analysis_result.get(
            "score_contributions"
        ),
        "text": analysis_result.get("text", "empty"),
        "url": analysis_result.get("URL", analysis_result.get("url", "empty")),
        "attachments": analysis_result.get("attachments", "empty"),
        "errors": analysis_result.get(
            "Error", analysis_result.get("errors", [])
        ),
        "created_at": datetime.now(timezone.utc),
    }

    try:
        collection = get_analysis_collection()
        result = collection.insert_one(document)

        return {
            "saved": True,
            "record_id": str(result.inserted_id)
        }

    except PyMongoError:
        raise


def get_account_history(account_id: str, limit: int = 50):
    """Return only the authenticated account's analysis history."""

    if not account_id:
        raise ValueError("Authenticated account_id is required")

    limit = max(1, min(int(limit), 200))

    collection = get_analysis_collection()

    records = collection.find(
        {"account_id": str(account_id)},
        {"account_id": 0}
    ).sort(
        "created_at", DESCENDING
    ).limit(limit)

    output = []

    for record in records:
        record["_id"] = str(record["_id"])
        output.append(record)

    return output


def get_analysis_by_id(account_id: str, record_id):
    """Retrieve one record belonging to the authenticated account."""

    from bson import ObjectId
    from bson.errors import InvalidId

    if not account_id:
        raise ValueError("Authenticated account_id is required")

    try:
        object_id = ObjectId(record_id)
    except (InvalidId, TypeError):
        return None

    record = get_analysis_collection().find_one({
        "_id": object_id,
        "account_id": str(account_id)
    })

    if record:
        record["_id"] = str(record["_id"])

    return record
