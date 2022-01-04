import psycopg2
import os

POSTGRES_DB = os.environ.get("POSTGRES_DB", "neon-db")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "neon-proxy")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "neon-proxy-pass")
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")

try:
    from cPickle import dumps, loads, HIGHEST_PROTOCOL as PICKLE_PROTOCOL
except ImportError:
    from pickle import dumps, loads, HIGHEST_PROTOCOL as PICKLE_PROTOCOL


def encode(obj):
    """Serialize an object using pickle to a binary format accepted by SQLite."""
    return psycopg2.Binary(dumps(obj, protocol=PICKLE_PROTOCOL))


def decode(obj):
    """Deserialize objects retrieved from SQLite."""
    return loads(bytes(obj))


def dummy(obj):
    """Does nothing"""
    return obj
