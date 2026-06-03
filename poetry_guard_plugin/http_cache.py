import hashlib
import json
import random
import time
from pathlib import Path
from typing import Any

import aiohttp

CACHE_TTL_SECONDS = 60 * 60 * 24  # 24h
RANDOM_BUST_FACTOR = 0.9  # ~10% chance to refresh on each hit


def _key(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def _is_stale(path: Path) -> bool:
    age = time.time() - path.stat().st_mtime
    if age > CACHE_TTL_SECONDS:
        return True
    return random.random() > RANDOM_BUST_FACTOR


async def fetch_json(
    session: aiohttp.ClientSession,
    url: str,
    cache_dir: Path,
    timeout: float = 10.0,
) -> dict[str, Any] | None:
    cache_path = cache_dir / f"{_key(url)}.json"
    if cache_path.is_file() and not _is_stale(cache_path):
        try:
            return json.loads(cache_path.read_text())  # type: ignore[no-any-return]
        except json.JSONDecodeError:
            pass
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            if r.status != 200:
                return None
            data: dict[str, Any] = await r.json()
    except aiohttp.ClientError:
        if cache_path.is_file():
            try:
                return json.loads(cache_path.read_text())  # type: ignore[no-any-return]
            except json.JSONDecodeError:
                return None
        return None
    cache_dir.mkdir(parents=True, exist_ok=True)
    tmp = cache_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(cache_path)
    return data
