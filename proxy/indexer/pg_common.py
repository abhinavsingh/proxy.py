import psycopg2
import os

from typing import Any

POSTGRES_DB = os.environ["POSTGRES_DB"]
POSTGRES_USER = os.environ["POSTGRES_USER"]
POSTGRES_PASSWORD = os.environ["POSTGRES_PASSWORD"]
POSTGRES_HOST = os.environ["POSTGRES_HOST"]

try:
    from cPickle import dumps, loads, HIGHEST_PROTOCOL as PICKLE_PROTOCOL
except ImportError:
    from pickle import dumps, loads, HIGHEST_PROTOCOL as PICKLE_PROTOCOL


def encode(obj: Any):
    """Serialize an object using pickle to a binary format accepted by SQLite."""
    return psycopg2.Binary(dumps(obj, protocol=PICKLE_PROTOCOL))


def decode(obj: Any):
    """Deserialize objects retrieved from SQLite."""
    return loads(bytes(obj))


def dummy(obj):
    """Does nothing"""
    return obj
