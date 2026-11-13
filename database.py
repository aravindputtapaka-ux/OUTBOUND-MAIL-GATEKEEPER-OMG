
"""
MongoDB connection manager for OMG.
Uses MONGODB_URI from the .env file.
"""

import os
import logging
from pymongo import MongoClient
from pymongo.errors import PyMongoError
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DB = os.getenv("MONGODB_DB", "OMG_Database")

_client = None
_database = None


def connect_to_mongodb():
    """Connect to MongoDB and return the database."""
    global _client, _database

    if not MONGODB_URI:
        raise RuntimeError("MONGODB_URI is missing from the .env file")

    if _database is not None:
        return _database

    try:
        _client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=10000,
        )

        _client.admin.command("ping")
        _database = _client[MONGODB_DB]

        logger.info("MongoDB connection established")
        return _database

    except PyMongoError:
        logger.exception("MongoDB connection failed")
        _client = None
        _database = None
        raise


def get_database():
    """Return the active database."""
    if _database is None:
        return connect_to_mongodb()

    return _database


def close_mongodb_connection():
    """Close MongoDB connection during application shutdown."""
    global _client, _database

    if _client is not None:
        _client.close()

    _client = None
    _database = None
    logger.info("MongoDB connection closed")


def check_mongodb_connection():
    """Check MongoDB connectivity."""
    try:
        db = get_database()
        db.command("ping")
        return True
    except Exception:
        logger.exception("MongoDB health check failed")
        return False
