from typing import Dict, Optional, Any


def get_from_dict(src: Dict, *path) -> Optional[Any]:
    """Provides smart getting values from python dictionary"""
    val = src
    for key in path:
        if not isinstance(val, dict):
            return None
        val = val.get(key)
        if val is None:
            return None
    return val
