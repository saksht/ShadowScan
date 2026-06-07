"""
ShadowScan - Core Scanner Engine
Handles HTTP requests, session management, and response normalization.
"""

import requests
import urllib3
import time
import random
from typing import Optional, Dict, Any
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}


class ScanResponse:
    """Normalized response object passed between modules."""

    def __init__(self, url: str, response: requests.Response, elapsed: float):
        self.url = url
        self.status_code = response.status_code
        self.headers = dict(response.headers)
        self.body = self._safe_text(response)
        self.elapsed = elapsed
        self.content_type = response.headers.get("Content-Type", "")
        self.content_length = len(response.content)
        self.history = response.history  # redirects

    def _safe_text(self, response: requests.Response) -> str:
        try:
            return response.text
        except Exception:
            return ""

    def contains(self, keyword: str) -> bool:
        return keyword.lower() in self.body.lower()

    def header_exists(self, header: str) -> bool:
        return header.lower() in {k.lower() for k in self.headers}

    def get_header(self, header: str) -> Optional[str]:
        for k, v in self.headers.items():
            if k.lower() == header.lower():
                return v
        return None

    def is_json(self) -> bool:
        return "application/json" in self.content_type

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "elapsed": round(self.elapsed, 3),
            "headers": self.headers,
            "body_snippet": self.body[:500],
        }


class Scanner:
    """
    Core HTTP scanner with session management, rate limiting, and retry logic.
    Used by all modules as the base request engine.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(DEFAULT_HEADERS)

        # Apply custom headers if provided
        if config.get("headers"):
            self.session.headers.update(config["headers"])

        # Apply cookies if provided
        if config.get("cookies"):
            self.session.cookies.update(config["cookies"])

        # Proxy support
        if config.get("proxy"):
            self.session.proxies = {
                "http": config["proxy"],
                "https": config["proxy"],
            }

        self.timeout = config.get("timeout", 10)
        self.delay = config.get("delay", 0.3)
        self.retries = config.get("retries", 2)
        self.base_url = config.get("target", "")

    def get(self, url: str, **kwargs) -> Optional[ScanResponse]:
        return self._request("GET", url, **kwargs)

    def post(self, url: str, data=None, json=None, **kwargs) -> Optional[ScanResponse]:
        return self._request("POST", url, data=data, json=json, **kwargs)

    def _request(self, method: str, url: str, **kwargs) -> Optional[ScanResponse]:
        # Normalize URL
        if not url.startswith("http"):
            url = urljoin(self.base_url, url)

        for attempt in range(self.retries + 1):
            try:
                time.sleep(self.delay + random.uniform(0, 0.1))  # jitter
                start = time.time()
                response = self.session.request(
                    method,
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    **kwargs,
                )
                elapsed = time.time() - start
                return ScanResponse(url, response, elapsed)

            except requests.exceptions.Timeout:
                if attempt == self.retries:
                    return None
            except requests.exceptions.ConnectionError:
                if attempt == self.retries:
                    return None
            except Exception:
                return None

        return None

    def resolve_url(self, path: str) -> str:
        if path.startswith("http"):
            return path
        return urljoin(self.base_url, path)

    def get_base_domain(self) -> str:
        parsed = urlparse(self.base_url)
        return f"{parsed.scheme}://{parsed.netloc}"
