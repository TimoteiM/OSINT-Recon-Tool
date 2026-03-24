"""
Brave Search API-backed Google dork provider.

This module generates bounded dork queries, executes them via Brave Search API,
and normalizes results into a reusable provider-level structure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import requests
from typing import Callable, Dict, List


BRAVE_SEARCH_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"
DEFAULT_TIMEOUT = 12


def generate_dorks(domain: str, mode: str = "light") -> Dict[str, List[str]]:
    """
    Return categorized dorks for the provided domain.

    `light` keeps the query set bounded for interactive scans.
    `full` expands each category with additional, still-curated dorks.
    """
    dorks: Dict[str, List[str]] = {
        "subdomains": [
            f"site:{domain} -www",
        ],
        "emails": [
            f'"@{domain}"',
            f'"@{domain}" contact',
        ],
        "social": [
            f'site:linkedin.com "{domain.split(".")[0]}"',
            f'site:facebook.com "{domain.split(".")[0]}"',
        ],
        "sensitive": [
            f"site:{domain} filetype:pdf",
            f"site:{domain} ext:xls OR ext:xlsx OR ext:csv",
        ],
        "admin_panels": [
            f"site:{domain} inurl:login",
            f"site:{domain} intitle:admin",
        ],
    }

    if mode == "full":
        dorks["subdomains"].extend([
            f"site:*.{domain} -www",
            f"site:{domain} inurl:subdomain",
        ])
        dorks["emails"].extend([
            f'"@{domain}" email',
            f'"@{domain}" support',
        ])
        dorks["social"].extend([
            f'site:x.com "{domain.split(".")[0]}"',
            f'site:instagram.com "{domain.split(".")[0]}"',
            f'site:github.com "{domain.split(".")[0]}"',
        ])
        dorks["sensitive"].extend([
            f"site:{domain} filetype:doc OR filetype:docx",
            f"site:{domain} filetype:ppt OR filetype:pptx",
            f"site:{domain} ext:sql OR ext:env",
        ])
        dorks["admin_panels"].extend([
            f"site:{domain} inurl:admin",
            f"site:{domain} inurl:dashboard",
            f"site:{domain} inurl:portal",
        ])

    return dorks


def search_dork(query: str, api_key: str, timeout: int = DEFAULT_TIMEOUT) -> List[Dict[str, str]]:
    """
    Execute a dork query via Brave Search API and return parsed result items.
    """
    if not api_key:
        raise ValueError("Brave Search API key is required")

    response = requests.get(
        BRAVE_SEARCH_ENDPOINT,
        params={"q": query, "count": 10},
        headers={
            "Accept": "application/json",
            "X-Subscription-Token": api_key,
            "User-Agent": "OSINT-Recon/1.0",
        },
        timeout=timeout,
    )
    response.raise_for_status()

    results = response.json().get("web", {}).get("results", [])
    parsed: List[Dict[str, str]] = []
    for item in results:
        parsed.append(
            {
                "title": str(item.get("title", "") or ""),
                "url": str(item.get("url", "") or ""),
                "snippet": str(item.get("description", "") or ""),
            }
        )
    return parsed


@dataclass
class GoogleDorkProvider:
    """
    Search-based intelligence provider using Brave Search API as the execution backend.
    """

    api_key: str
    max_dorks_per_category: Dict[str, int] = field(default_factory=lambda: {
        "subdomains": 1,
        "emails": 2,
        "social": 2,
        "sensitive": 2,
        "admin_panels": 2,
    })
    notes: List[str] = field(default_factory=list)

    def run(
        self,
        domain: str,
        mode: str = "light",
        search_fn: Callable[[str, str], List[Dict[str, str]]] = search_dork,
    ) -> List[Dict[str, str]]:
        """
        Generate, execute, and aggregate dork findings for a domain.
        """
        aggregated: List[Dict[str, str]] = []
        seen_urls = set()
        self.notes = []

        for category, queries in generate_dorks(domain, mode=mode).items():
            limit = self.max_dorks_per_category.get(category, len(queries))
            for query in queries[:limit]:
                try:
                    results = search_fn(query, self.api_key)
                except requests.Timeout:
                    self.notes.append(f"Timeout while executing dork: {query}")
                    continue
                except requests.HTTPError as exc:
                    status_code = getattr(exc.response, "status_code", "unknown")
                    self.notes.append(f"HTTP {status_code} while executing dork: {query}")
                    continue
                except Exception as exc:
                    self.notes.append(f"{exc} while executing dork: {query}")
                    continue

                for item in results:
                    url = (item.get("url") or "").strip()
                    if not url or url in seen_urls:
                        continue
                    seen_urls.add(url)
                    aggregated.append(
                        {
                            "category": category,
                            "query": query,
                            "title": (item.get("title") or "").strip(),
                            "url": url,
                            "snippet": (item.get("snippet") or "").strip(),
                        }
                    )

        return aggregated

    def normalize(self, results: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Convert raw dork results into the unified findings shape.
        """
        normalized: List[Dict[str, str]] = []
        for item in results:
            normalized.append(
                {
                    "source": "google_dork",
                    "category": str(item.get("category", "") or ""),
                    "query": str(item.get("query", "") or ""),
                    "url": str(item.get("url", "") or ""),
                    "title": str(item.get("title", "") or ""),
                    "snippet": str(item.get("snippet", "") or ""),
                }
            )
        return normalized
