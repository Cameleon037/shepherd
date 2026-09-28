"""Shared technology detection for web scanners.

Uses wappalyzer-python3 (Wappalyzer fingerprints, bundled technologies.json,
no network) to detect technologies from already-captured HTML and response
headers. Never raises; callers receive an empty list on any failure so a
detection problem can never break a scan.
"""
from __future__ import annotations

import logging
import threading
from typing import Mapping, Optional

logger = logging.getLogger(__name__)

_WAPPALYZER = None
_LOCK = threading.Lock()
_MAX_TECHNOLOGIES = 50
_MAX_HTML_CHARS = 50_000  # scripts/meta/head live at the front; bounds runtime


def detect_technologies(url: str, html: str = '',
                        headers: Optional[Mapping[str, str]] = None) -> list:
    """Sorted, deduped technology names detected from html + headers.

    Empty input is a fast path. Analysis is CPU-bound over a regex DB, so
    callers running an event loop must call this via asyncio.to_thread.
    """
    if not html and not headers:
        return []
    try:
        from Wappalyzer import Wappalyzer, WebPage  # optional dep, lazy import
        global _WAPPALYZER
        with _LOCK:
            if _WAPPALYZER is None:
                _WAPPALYZER = Wappalyzer.latest()  # bundled fingerprints, offline
            webpage = WebPage(str(url), html=html[:_MAX_HTML_CHARS],
                              headers=dict(headers or {}))
            detected = _WAPPALYZER.analyze(webpage)
            _WAPPALYZER.detected_technologies.clear()  # names already extracted; bound memory
            return sorted(detected)[:_MAX_TECHNOLOGIES]
    except Exception as exc:
        logger.warning('technology detection failed for %s: %s', url, exc, exc_info=True)
        return []