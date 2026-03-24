#!/usr/bin/env python3
"""
OSINT Reconnaissance Engine
Performs passive/active reconnaissance: DNS, WHOIS, SSL certs, email harvesting,
technology fingerprinting, breach detection, and social media discovery.
"""

import json
import sys
import socket
import ssl
import re
import subprocess
import shutil
import os
import ipaddress
import hashlib
import time
import tempfile
import concurrent.futures
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from typing import Optional

import requests
import dns.resolver
import dns.zone
import dns.query
import whois as whois_lib
from ipwhois import IPWhois

try:
    from rocketreach import Gateway as RocketReachGateway
except Exception:
    RocketReachGateway = None

# ── helpers ──────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
TIMEOUT = 10


def _selected_sources() -> Optional[set]:
    raw = os.environ.get("OSINT_SELECTED_SOURCES", "").strip()
    if not raw:
        return None

    try:
        parsed = json.loads(raw)
    except Exception:
        return None

    if not isinstance(parsed, list):
        return None

    return {item for item in parsed if isinstance(item, str)}


def source_enabled(source_id: str) -> bool:
    selected = _selected_sources()
    if selected is None:
        return True
    return source_id in selected


def source_explicitly_selected(source_id: str) -> bool:
    selected = _selected_sources()
    if not selected:
        return False
    return source_id in selected


def any_source_enabled(*source_ids: str) -> bool:
    return any(source_enabled(source_id) for source_id in source_ids)


def ensure_provider_result(provider_results: dict, provider_id: str) -> dict:
    if provider_id not in provider_results:
        provider_results[provider_id] = {
            "status": "ok",
            "notes": [],
            "duration_ms": None,
            "emails": [],
            "social_profiles": [],
            "impersonation_candidates": [],
            "subdomains": [],
            "repos": [],
            "breach_hints": [],
            "dns_records": [],
            "whois": [],
            "ssl": [],
            "tech": [],
            "ports": [],
            "hosting": [],
            "mentions": [],
        }
    return provider_results[provider_id]


def record_provider_timing(provider_results: Optional[dict], provider_id: str, duration_ms: int) -> None:
    if provider_results is None:
        return
    entry = ensure_provider_result(provider_results, provider_id)
    entry["duration_ms"] = duration_ms


def _elapsed_ms(start_time: float) -> int:
    return int(round((time.perf_counter() - start_time) * 1000))


def record_provider_result(provider_results: dict, provider_id: str, field: str, values) -> None:
    entry = ensure_provider_result(provider_results, provider_id)
    if field not in entry:
        entry[field] = []
    if isinstance(values, list):
        entry[field].extend(values)
    else:
        entry[field].append(values)


def record_provider_note(provider_results: dict, provider_id: str, note: str) -> None:
    entry = ensure_provider_result(provider_results, provider_id)
    if note not in entry["notes"]:
        entry["notes"].append(note)


def mark_provider_skipped(provider_results: dict, provider_id: str, note: str) -> None:
    entry = ensure_provider_result(provider_results, provider_id)
    entry["status"] = "skipped"
    entry["notes"].append(note)


def mark_provider_error(provider_results: dict, provider_id: str, error: str) -> None:
    entry = ensure_provider_result(provider_results, provider_id)
    entry["status"] = "error"
    if error not in entry["notes"]:
        entry["notes"].append(error)


def note_provider_status(provider_results: Optional[dict], provider_id: str, message: str, *, error: bool = False) -> None:
    if provider_results is None:
        return
    if error:
        mark_provider_error(provider_results, provider_id, message)
    else:
        record_provider_note(provider_results, provider_id, message)


def github_api_headers() -> dict:
    headers = {**HEADERS, "Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _first_env(*keys: str) -> str:
    for key in keys:
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return ""


def hibp_api_headers() -> dict:
    headers = {**HEADERS}
    api_key = _first_env("HaveIBeenPwned_API_KEY", "HIBP_API_KEY")
    if api_key:
        headers["hibp-api-key"] = api_key
    return headers


def hunter_api_key() -> str:
    return _first_env("Hunter_API_KEY", "HunterIO_API_KEY")


def project_discovery_api_key() -> str:
    return _first_env("Project_Discovery_API_KEY")


def censys_token() -> str:
    return _first_env("Censys_Token")


def censys_organization_id() -> str:
    return _first_env("Censys_Organization_ID")


def rocketreach_company_variants(domain: str, company_name: str) -> list[str]:
    variants = []
    base_domain = domain.lower().strip()
    bare = base_domain.split(".")[0]
    cleaned_company = company_name.strip()
    candidates = [
        cleaned_company,
        cleaned_company.replace(".", " "),
        cleaned_company.replace("-", " "),
        base_domain,
        bare,
        bare.replace("-", " "),
    ]
    for candidate in candidates:
        normalized = candidate.strip()
        if normalized and normalized not in variants:
            variants.append(normalized)
    return variants


def initialize_selected_provider_results(provider_results: dict) -> None:
    selected = _selected_sources() or set()
    for provider_id in selected:
        ensure_provider_result(provider_results, provider_id)


def _response_detail(response) -> str:
    if response is None:
        return ""

    try:
        payload = response.json()
    except Exception:
        payload = None

    if payload == {}:
        body = (response.text or "").strip()
        if body.startswith("{") or body.startswith("["):
            try:
                payload = json.loads(body)
            except Exception:
                payload = None

    if isinstance(payload, dict):
        for key in ("message", "error", "detail", "details"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        errors = payload.get("errors")
        if isinstance(errors, list):
            for item in errors:
                if isinstance(item, dict):
                    for key in ("details", "message", "error"):
                        value = item.get(key)
                        if isinstance(value, str) and value.strip():
                            return value.strip()
                elif isinstance(item, str) and item.strip():
                    return item.strip()

    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", (response.text or ""))).strip()
    return text[:160] if text else ""


def _hibp_api_key() -> str:
    return _first_env("HaveIBeenPwned_API_KEY", "HIBP_API_KEY")


def hibp_subscribed_domains(provider_results: Optional[dict] = None) -> Optional[set[str]]:
    if not _hibp_api_key():
        mark_provider_skipped(provider_results, "hibp", "API key not configured")
        return None

    response = safe_get(
        "https://haveibeenpwned.com/api/v3/subscribeddomains",
        headers=hibp_api_headers(),
        timeout=10,
    )
    if response is None:
        note_provider_status(provider_results, "hibp", "HIBP subscribed-domains lookup failed", error=True)
        return None
    if response.status_code == 200:
        domains = set()
        payload = response.json()
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    candidate = item.get("DomainName") or item.get("domainName") or item.get("domain")
                    if isinstance(candidate, str) and candidate.strip():
                        domains.add(candidate.strip().lower())
                elif isinstance(item, str) and item.strip():
                    domains.add(item.strip().lower())
        return domains
    if response.status_code == 401:
        note_provider_status(provider_results, "hibp", "HIBP rejected the configured API key", error=True)
        return None
    detail = _response_detail(response)
    message = f"HTTP {response.status_code} from HIBP subscribed domains"
    if detail:
        message = f"{message}: {detail}"
    note_provider_status(provider_results, "hibp", message, error=response.status_code >= 400)
    return None


def hibp_domain_breaches(domain: str, provider_results: Optional[dict] = None) -> list:
    subscribed_domains = hibp_subscribed_domains(provider_results)
    if subscribed_domains is None:
        return []

    normalized = domain.lower().strip()
    if normalized not in subscribed_domains:
        note_provider_status(
            provider_results,
            "hibp",
            f"API key is valid, but {domain} is not a verified/subscribed HIBP domain",
        )
        return []

    response = safe_get(
        f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
        headers=hibp_api_headers(),
        timeout=10,
    )
    if response is None:
        note_provider_status(provider_results, "hibp", "HIBP domain lookup failed", error=True)
        return []
    if response.status_code == 200:
        payload = response.json()
        return payload if isinstance(payload, list) else []
    if response.status_code == 404:
        note_provider_status(provider_results, "hibp", "No breach records returned")
        return []
    if response.status_code == 401:
        note_provider_status(provider_results, "hibp", "HIBP rejected the configured API key for domain lookup", error=True)
        return []
    detail = _response_detail(response)
    message = f"HTTP {response.status_code} from HIBP domain lookup"
    if detail:
        message = f"{message}: {detail}"
    note_provider_status(provider_results, "hibp", message, error=response.status_code >= 400)
    return []


def classify_search_mention(item: dict, matched_domain: str, query: str) -> dict:
    url = item.get("url", "")
    title = item.get("title", "")
    snippet = item.get("description", "")
    source_domain = _extract_domain_from_url(url).lower()
    haystack = " ".join([source_domain, url.lower(), title.lower(), snippet.lower()])

    category = "web"
    forum_markers = ("reddit.com", "stackoverflow.com", "stackexchange.com", "tieba.baidu.com", "forum", "community", "discuss", "thread")
    social_markers = ("linkedin.com", "facebook.com", "instagram.com", "x.com", "twitter.com", "youtube.com", "tiktok.com")
    news_markers = ("news", "/news", "press", "article", "media")
    docs_markers = (".pdf", ".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx", "docs", "document", "whitepaper")
    jobs_markers = ("jobs", "careers", "vacancy", "recruit", "hiring")

    if any(marker in haystack for marker in forum_markers):
        category = "forum"
    elif any(marker in haystack for marker in social_markers):
        category = "social"
    elif any(marker in haystack for marker in jobs_markers):
        category = "jobs"
    elif any(marker in haystack for marker in docs_markers):
        category = "docs"
    elif any(marker in haystack for marker in news_markers):
        category = "news"
    elif not source_domain:
        category = "other"

    return {
        "category": category,
        "title": title,
        "url": url,
        "snippet": snippet,
        "source_domain": source_domain,
        "matched_domain": matched_domain,
        "query": query,
    }


def _extract_http_urls(text: str) -> list[str]:
    urls = []
    seen = set()
    for raw in re.findall(r"https?://[^\s\"'<>]+", text or ""):
        cleaned = raw.rstrip(".,);]")
        if cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)
    return urls


def _strip_html(text: str) -> str:
    cleaned = re.sub(r"<script[^>]*>.*?</script>", " ", text or "", flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"<style[^>]*>.*?</style>", " ", cleaned, flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    cleaned = re.sub(r"&nbsp;|&#160;", " ", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"&amp;", "&", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"&quot;", '"', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _trim_snippet(text: str, limit: int = 220) -> str:
    snippet = re.sub(r"\s+", " ", (text or "").strip())
    if len(snippet) <= limit:
        return snippet
    return snippet[: limit - 3].rstrip() + "..."


def _is_google_internal_url(url: str) -> bool:
    domain = _extract_domain_from_url(url).lower()
    if domain in {"google.com", "www.google.com", "support.google.com"}:
        return True
    return any(marker in url.lower() for marker in ("/search?", "/url?", "/imgres?", "/sorry/", "/preferences?"))


def _extract_google_results(html: str) -> list[dict]:
    results = []
    seen_urls = set()
    anchor_pattern = re.compile(r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)

    for index, match in enumerate(anchor_pattern.finditer(html or "")):
        url = match.group(1).strip()
        if _is_google_internal_url(url) or url in seen_urls:
            continue

        title = _strip_html(match.group(2))
        next_match = anchor_pattern.search(html or "", match.end())
        snippet_region = (html or "")[match.end() : next_match.start() if next_match else len(html or "")]
        snippet = _trim_snippet(_strip_html(snippet_region))

        if not title and not snippet:
            continue

        seen_urls.add(url)
        results.append({"url": url, "title": title, "description": snippet})
        if len(results) >= 12:
            break

    return results


def _record_search_provider_evidence(
    provider_id: str,
    response_text: str,
    domain: str,
    query: str,
    provider_results: Optional[dict] = None,
) -> set:
    emails = {email.lower() for email in EMAIL_RE.findall(response_text or "") if domain in email.lower()}
    mentions = [
        classify_search_mention({"url": url, "title": "", "description": response_text[:280]}, domain, query)
        for url in _extract_http_urls(response_text)
    ]

    if provider_results is not None:
        record_provider_result(provider_results, provider_id, "emails", sorted(emails))
        record_provider_result(provider_results, provider_id, "mentions", mentions)
        if not emails and not mentions:
            note_provider_status(provider_results, provider_id, f"No matching evidence found in {provider_id} results")

    return emails


def _record_google_provider_evidence(
    response_text: str,
    domain: str,
    query: str,
    provider_results: Optional[dict] = None,
) -> set:
    emails = set()
    mentions = []
    mentions_per_category = {}

    for item in _extract_google_results(response_text):
        haystack = " ".join([item.get("url", ""), item.get("title", ""), item.get("description", "")]).lower()
        matched = {email.lower() for email in EMAIL_RE.findall(haystack) if domain in email.lower()}
        if domain not in haystack and not matched:
            continue

        mention = classify_search_mention(item, domain, query)
        category = mention.get("category", "other")
        if mentions_per_category.get(category, 0) < 3:
            mentions.append(mention)
            mentions_per_category[category] = mentions_per_category.get(category, 0) + 1
        emails.update(matched)

    if provider_results is not None:
        record_provider_result(provider_results, "google", "emails", sorted(emails))
        record_provider_result(provider_results, "google", "mentions", mentions)
        if not emails and not mentions:
            note_provider_status(provider_results, "google", "No matching evidence found in Google results")

    return emails


def _extract_matching_subdomains(text: str, domain: str) -> list[str]:
    matches = set()
    pattern = re.compile(rf"(?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)}", re.IGNORECASE)
    for match in pattern.findall(text or ""):
        candidate = match.strip().strip(".").lower().lstrip("*.")
        if candidate.endswith(domain) and candidate != domain:
            matches.add(candidate)
    return sorted(matches)


def brave_search(query: str, provider_results: Optional[dict] = None, count: int = 10) -> list[dict]:
    if not source_enabled("brave"):
        if provider_results is not None:
            mark_provider_skipped(provider_results, "brave", "Provider not selected")
        return []

    api_key = os.environ.get("BRAVE_SEARCH_API_KEY", "").strip()
    if not api_key:
        if provider_results is not None:
            mark_provider_skipped(provider_results, "brave", "API key not configured")
        return []

    try:
        response = safe_get(
            f"https://api.search.brave.com/res/v1/web/search?q={requests.utils.quote(query)}&count={count}",
            headers={
                **HEADERS,
                "Accept": "application/json",
                "X-Subscription-Token": api_key,
            },
            timeout=12,
        )
        if response is not None and response.status_code == 200:
            return response.json().get("web", {}).get("results", [])
    except Exception as exc:
        log(f"Brave search failed: {exc}")

    return []


class RocketReachAPI:
    @staticmethod
    def search(api_key: str, company_name: str, size: int = 10):
        if RocketReachGateway is None:
            raise RuntimeError("rocketreach SDK is not installed")

        gateway = RocketReachGateway(api_key=api_key)
        result = (
            gateway.person.search()
            .filter(current_employer=company_name)
            .params(size=size)
            .execute()
        )
        if getattr(result, "is_success", False):
            return result.data
        return {}


def safe_get(url, **kwargs):
    request_kwargs = {
        "headers": HEADERS,
        "timeout": TIMEOUT,
        "allow_redirects": True,
        "verify": True,
    }
    request_kwargs.update(kwargs)

    try:
        r = requests.get(url, **request_kwargs)
        return r
    except requests.exceptions.SSLError:
        if kwargs.get("verify") is False:
            return None
        try:
            insecure_kwargs = dict(request_kwargs)
            insecure_kwargs["verify"] = False
            return requests.get(url, **insecure_kwargs)
        except Exception:
            return None
    except Exception:
        return None


def safe_post(url, **kwargs):
    request_kwargs = {
        "headers": HEADERS,
        "timeout": TIMEOUT,
        "allow_redirects": True,
        "verify": True,
    }
    request_kwargs.update(kwargs)

    try:
        return requests.post(url, **request_kwargs)
    except requests.exceptions.SSLError:
        if kwargs.get("verify") is False:
            return None
        try:
            insecure_kwargs = dict(request_kwargs)
            insecure_kwargs["verify"] = False
            return requests.post(url, **insecure_kwargs)
        except Exception:
            return None
    except Exception:
        return None


def log(msg):
    print(f"[*] {msg}", file=sys.stderr)


# ── 1. Website discovery ──────────────────────────────────────────────────────

def _is_valid_domain(domain: str) -> bool:
    """Check domain resolves in DNS."""
    try:
        socket.getaddrinfo(domain, None, socket.AF_INET)
        return True
    except Exception:
        return False


def _extract_domain_from_url(url: str) -> str:
    """Extract bare domain (no www.) from a URL."""
    parsed = urlparse(url)
    netloc = parsed.netloc or url
    # strip port
    netloc = netloc.split(":")[0]
    return re.sub(r"^www\.", "", netloc).strip("/")


def _probe_url(url: str) -> tuple:
    """Return (final_url, domain) if URL is reachable, else (None, None)."""
    r = safe_get(url, timeout=8)
    if r is not None and r.status_code in (200, 201, 301, 302, 403, 429):
        final = r.url
        original_domain = _extract_domain_from_url(url)
        domain = _extract_domain_from_url(final)
        same_domain_family = (
            domain == original_domain
            or domain.endswith(f".{original_domain}")
            or original_domain.endswith(f".{domain}")
        )
        if domain and "." in domain and same_domain_family:
            return final, domain
    return None, None


def find_website(company_name: str) -> dict:
    """
    Multi-strategy website discovery.
    1. Direct domain input detection  (user typed "example.com")
    2. Pattern-based slug candidates  (many TLD + hyphen variants)
    3. DuckDuckGo Instant Answer API  (JSON)
    4. DuckDuckGo HTML search         (scrape first organic result)
    5. Bing search API (no key needed via web scrape)
    6. DNS-only fallback              (no HTTP, just slug + DNS)
    """
    result = {"company": company_name, "domain": None, "url": None, "found_via": None}

    # ── Strategy 0: user already passed a domain/URL directly ──
    direct = company_name.strip().lower()
    if re.match(r"^[a-z0-9][a-z0-9\-\.]+\.[a-z]{2,}$", direct):
        url, domain = _probe_url(f"https://{direct}")
        if domain:
            result.update({"url": url, "domain": domain, "found_via": "direct_input"})
            log(f"Direct domain input: {domain}")
            return result

    # ── Build slug variants ──
    # plain slug (no spaces/punctuation)
    slug_plain = re.sub(r"[^a-z0-9]", "", company_name.lower())
    # hyphenated slug
    slug_hyphen = re.sub(r"[^a-z0-9]+", "-", company_name.lower()).strip("-")
    # first word only
    slug_first = company_name.lower().split()[0]
    slug_first = re.sub(r"[^a-z0-9]", "", slug_first)

    tlds = [".com", ".io", ".org", ".net", ".co", ".eu", ".de", ".fr",
            ".be", ".nl", ".uk", ".us", ".ca", ".ai", ".tech", ".security"]

    candidates = []
    for slug in dict.fromkeys([slug_plain, slug_hyphen, slug_first]):  # dedup, preserve order
        if not slug:
            continue
        for tld in tlds:
            candidates.append(f"https://www.{slug}{tld}")
            candidates.append(f"https://{slug}{tld}")

    # ── Strategy 1: parallel probe all candidates ──
    log(f"Probing {len(candidates)} URL candidates for '{company_name}'")
    ranked_matches = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_probe_url, url): idx for idx, url in enumerate(candidates)}
        for f in concurrent.futures.as_completed(futures):
            url, domain = f.result()
            if url and domain:
                ranked_matches.append((futures[f], url, domain))

    if ranked_matches:
        _, best_url, best_domain = min(ranked_matches, key=lambda item: item[0])
        result.update({"url": best_url, "domain": best_domain, "found_via": "pattern_match"})
        log(f"Pattern match: {best_url}")
        return result

    if source_enabled("brave"):
        try:
            brave_results = brave_search(f"{company_name} official website")
            skip = {"brave.com", "google.com", "bing.com", "duckduckgo.com", "facebook.com", "linkedin.com"}
            for item in brave_results:
                raw_url = item.get("url", "")
                if not raw_url:
                    continue
                domain = _extract_domain_from_url(raw_url)
                if domain and "." in domain and domain not in skip and _is_valid_domain(domain):
                    result.update({"url": raw_url, "domain": domain, "found_via": "brave_search"})
                    log(f"Brave search: {domain}")
                    return result
        except Exception as e:
            log(f"Brave search failed: {e}")

    # ── Strategy 2: DuckDuckGo Instant Answer JSON ──
    if source_enabled("duckduckgo"):
        try:
            q = requests.utils.quote(company_name + " official website")
            r = safe_get(f"https://api.duckduckgo.com/?q={q}&format=json&no_html=1", timeout=10)
            if r is not None:
                data = r.json()
                for key in ("AbstractURL", "Redirect"):
                    raw = data.get(key, "")
                    if raw and "." in raw:
                        url, domain = _probe_url(raw) if not raw.startswith("http") else (raw, _extract_domain_from_url(raw))
                        if domain:
                            result.update({"url": raw, "domain": domain, "found_via": "duckduckgo_api"})
                            log(f"DuckDuckGo API: {domain}")
                            return result
        except Exception as e:
            log(f"DDG API failed: {e}")

    # ── Strategy 3: DuckDuckGo HTML scrape ──
    if source_enabled("duckduckgo"):
        try:
            q = requests.utils.quote(f"{company_name} official site")
            r = safe_get(f"https://html.duckduckgo.com/html/?q={q}", timeout=12)
            if r is not None:
                # Extract first organic result URL from DDG HTML
                urls_found = re.findall(r'class="result__url"[^>]*>\s*([^<]+)', r.text)
                if not urls_found:
                    # Try another pattern
                    urls_found = re.findall(r'href="https?://([a-zA-Z0-9._/-]+)"', r.text)
                for raw_url in urls_found[:10]:
                    raw_url = raw_url.strip()
                    if not raw_url.startswith("http"):
                        raw_url = "https://" + raw_url
                    domain = _extract_domain_from_url(raw_url)
                    # Skip search engines, social media in results
                    skip = {"duckduckgo", "google", "bing", "facebook",
                            "twitter", "linkedin", "wikipedia", "youtube", "reddit"}
                    if domain and "." in domain and not any(s in domain for s in skip):
                        if _is_valid_domain(domain):
                            result.update({"url": raw_url, "domain": domain, "found_via": "duckduckgo_html"})
                            log(f"DuckDuckGo HTML: {domain}")
                            return result
        except Exception as e:
            log(f"DDG HTML scrape failed: {e}")

    # ── Strategy 4: Bing HTML scrape ──
    if source_enabled("bing"):
        try:
            q = requests.utils.quote(f"{company_name} official website")
            r = safe_get(f"https://www.bing.com/search?q={q}", timeout=12)
            if r is not None:
                hrefs = re.findall(r'<cite[^>]*>([^<]+)</cite>', r.text)
                if not hrefs:
                    hrefs = re.findall(r'href="(https?://[^"&]+)"', r.text)
                skip = {"bing", "microsoft", "google", "facebook", "twitter",
                        "linkedin", "wikipedia", "youtube", "reddit", "amazon"}
                for href in hrefs[:15]:
                    domain = _extract_domain_from_url(href)
                    if domain and "." in domain and not any(s in domain for s in skip):
                        if _is_valid_domain(domain):
                            result.update({"url": f"https://{domain}", "domain": domain, "found_via": "bing_search"})
                            log(f"Bing search: {domain}")
                            return result
        except Exception as e:
            log(f"Bing scrape failed: {e}")

    if source_enabled("google"):
        try:
            q = requests.utils.quote(f"{company_name} official website")
            r = safe_get(f"https://www.google.com/search?q={q}", timeout=12)
            if r is not None and r.status_code == 200:
                for item in _extract_google_results(r.text):
                    href = item.get("url", "")
                    domain = _extract_domain_from_url(href)
                    if domain and "." in domain and _is_valid_domain(domain):
                        result.update({"url": href, "domain": domain, "found_via": "google_search"})
                        log(f"Google search: {domain}")
                        return result
        except Exception as e:
            log(f"Google scrape failed: {e}")

    if source_enabled("windvane"):
        try:
            q = requests.utils.quote(f"{company_name} official website")
            r = safe_get(f"https://windvane.licho.in/search?q={q}", timeout=12)
            if r is not None and r.status_code == 200:
                for href in _extract_http_urls(r.text)[:15]:
                    domain = _extract_domain_from_url(href)
                    if domain and "." in domain and _is_valid_domain(domain):
                        result.update({"url": href, "domain": domain, "found_via": "windvane_search"})
                        log(f"Windvane search: {domain}")
                        return result
        except Exception as e:
            log(f"Windvane scrape failed: {e}")

    # ── Strategy 5: DNS-only fallback (no HTTP needed) ──
    # At this point just try to resolve the slug as a domain — no HTTP probe
    for slug in dict.fromkeys([slug_plain, slug_hyphen, slug_first]):
        if not slug:
            continue
        for tld in [".com", ".org", ".net", ".io", ".eu"]:
            candidate_domain = f"{slug}{tld}"
            if _is_valid_domain(candidate_domain):
                result.update({
                    "url": f"https://{candidate_domain}",
                    "domain": candidate_domain,
                    "found_via": "dns_only",
                })
                log(f"DNS-only fallback: {candidate_domain}")
                return result

    log(f"All strategies exhausted for '{company_name}'")
    return result


# ── 2. DNS enumeration ────────────────────────────────────────────────────────

def _collect_free_provider_subdomains(domain: str, provider_results: Optional[dict] = None) -> dict[str, list[str]]:
    findings = {}

    if source_enabled("bufferoverun"):
        try:
            response = safe_get(f"https://tls.bufferover.run/dns?q=.{domain}", timeout=12)
            if response is not None and response.status_code == 200:
                data = response.json()
                buffer_subdomains = set()
                for value in data.get("Results", []):
                    buffer_subdomains.update(_extract_matching_subdomains(value, domain))
                for value in data.get("FDNS_A", []):
                    buffer_subdomains.update(_extract_matching_subdomains(value, domain))
                findings["bufferoverun"] = sorted(buffer_subdomains)
                if provider_results is not None:
                    record_provider_result(provider_results, "bufferoverun", "subdomains", findings["bufferoverun"])
                if not findings["bufferoverun"]:
                    note_provider_status(provider_results, "bufferoverun", "No matching subdomains returned")
            elif response is not None:
                note_provider_status(provider_results, "bufferoverun", f"HTTP {response.status_code} from BufferOverrun", error=response.status_code >= 400)
        except Exception as exc:
            log(f"BufferOverrun failed: {exc}")
            note_provider_status(provider_results, "bufferoverun", str(exc), error=True)

    if source_enabled("rapiddns"):
        try:
            response = safe_get(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout=12)
            if response is not None and response.status_code == 200:
                findings["rapiddns"] = _extract_matching_subdomains(response.text, domain)
                if provider_results is not None:
                    record_provider_result(provider_results, "rapiddns", "subdomains", findings["rapiddns"])
                if not findings["rapiddns"]:
                    note_provider_status(provider_results, "rapiddns", "No matching subdomains returned")
        except Exception as exc:
            log(f"RapidDNS failed: {exc}")
            note_provider_status(provider_results, "rapiddns", str(exc), error=True)

    if source_enabled("hackertarget"):
        try:
            response = safe_get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=12)
            if response is not None and response.status_code == 200:
                findings["hackertarget"] = _extract_matching_subdomains(response.text, domain)
                if provider_results is not None:
                    record_provider_result(provider_results, "hackertarget", "subdomains", findings["hackertarget"])
                if not findings["hackertarget"]:
                    note_provider_status(provider_results, "hackertarget", "No matching hosts returned")
        except Exception as exc:
            log(f"Hackertarget failed: {exc}")
            note_provider_status(provider_results, "hackertarget", str(exc), error=True)

    if source_enabled("subdomaincenter"):
        try:
            response = safe_get(f"https://api.subdomain.center/?domain={domain}", timeout=12)
            if response is not None and response.status_code == 200:
                payload = response.json()
                findings["subdomaincenter"] = sorted(
                    {
                        item.strip().lower()
                        for item in payload
                        if isinstance(item, str) and item.strip().lower().endswith(domain)
                    }
                )
                if provider_results is not None:
                    record_provider_result(provider_results, "subdomaincenter", "subdomains", findings["subdomaincenter"])
                if not findings["subdomaincenter"]:
                    note_provider_status(provider_results, "subdomaincenter", "No matching subdomains returned")
            elif response is not None:
                note_provider_status(provider_results, "subdomaincenter", f"HTTP {response.status_code} from Subdomain Center", error=response.status_code >= 400)
        except Exception as exc:
            note_provider_status(provider_results, "subdomaincenter", str(exc), error=True)

    if source_enabled("subdomainfinderc99"):
        try:
            response = safe_get(f"https://subdomainfinder.c99.nl/scans/{domain}", timeout=12)
            if response is not None and response.status_code == 200:
                findings["subdomainfinderc99"] = _extract_matching_subdomains(response.text, domain)
                if provider_results is not None:
                    record_provider_result(provider_results, "subdomainfinderc99", "subdomains", findings["subdomainfinderc99"])
                if not findings["subdomainfinderc99"]:
                    note_provider_status(provider_results, "subdomainfinderc99", "No matching subdomains returned")
            elif response is not None:
                note_provider_status(provider_results, "subdomainfinderc99", f"HTTP {response.status_code} from C99 Subdomain Finder", error=response.status_code >= 400)
        except Exception as exc:
            note_provider_status(provider_results, "subdomainfinderc99", str(exc), error=True)

    if source_enabled("projectdiscovery"):
        api_key = project_discovery_api_key()
        if not api_key:
            if provider_results is not None:
                mark_provider_skipped(provider_results, "projectdiscovery", "API key not configured")
        else:
            try:
                response = safe_get(
                    f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
                    headers={**HEADERS, "Authorization": api_key},
                    timeout=12,
                )
                if response is not None and response.status_code == 200:
                    payload = response.json()
                    findings["projectdiscovery"] = sorted(
                        {
                            f"{item.strip().lower()}.{domain}"
                            for item in payload.get("subdomains", [])
                            if isinstance(item, str) and item.strip()
                        }
                    )
                    if provider_results is not None:
                        record_provider_result(provider_results, "projectdiscovery", "subdomains", findings["projectdiscovery"])
                    if not findings["projectdiscovery"]:
                        note_provider_status(provider_results, "projectdiscovery", "No matching subdomains returned")
                elif response is not None:
                    detail = _response_detail(response)
                    message = f"HTTP {response.status_code} from ProjectDiscovery"
                    if detail:
                        message = f"{message}: {detail}"
                    note_provider_status(provider_results, "projectdiscovery", message, error=response.status_code >= 400)
            except Exception as exc:
                note_provider_status(provider_results, "projectdiscovery", str(exc), error=True)

    if source_enabled("thc"):
        try:
            response = safe_get(f"https://ip.thc.org/?q={domain}", timeout=12)
            if response is not None and response.status_code == 200:
                findings["thc"] = _extract_matching_subdomains(response.text, domain)
                if provider_results is not None:
                    record_provider_result(provider_results, "thc", "subdomains", findings["thc"])
                if not findings["thc"]:
                    note_provider_status(provider_results, "thc", "No matching subdomains returned")
            elif response is not None:
                note_provider_status(provider_results, "thc", f"HTTP {response.status_code} from THC", error=response.status_code >= 400)
        except Exception as exc:
            note_provider_status(provider_results, "thc", str(exc), error=True)

    if source_enabled("threatminer"):
        try:
            response = safe_get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=12)
            if response is not None and response.status_code == 200:
                data = response.json()
                findings["threatminer"] = sorted(
                    {
                        item.lower()
                        for item in data.get("results", [])
                        if isinstance(item, str) and item.lower().endswith(domain) and item.lower() != domain
                    }
                )
                if provider_results is not None:
                    record_provider_result(provider_results, "threatminer", "subdomains", findings["threatminer"])
                if not findings["threatminer"]:
                    note_provider_status(provider_results, "threatminer", "No matching subdomains returned")
            elif response is not None:
                note_provider_status(provider_results, "threatminer", f"HTTP {response.status_code} from ThreatMiner", error=response.status_code >= 400)
        except Exception as exc:
            log(f"ThreatMiner failed: {exc}")
            note_provider_status(provider_results, "threatminer", str(exc), error=True)

    if source_enabled("urlscan"):
        try:
            response = safe_get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", timeout=12)
            if response is not None and response.status_code == 200:
                urlscan_subdomains = set()
                for item in response.json().get("results", []):
                    page = item.get("page", {})
                    urlscan_subdomains.update(_extract_matching_subdomains(page.get("domain", ""), domain))
                    urlscan_subdomains.update(_extract_matching_subdomains(page.get("url", ""), domain))
                findings["urlscan"] = sorted(urlscan_subdomains)
                if provider_results is not None:
                    record_provider_result(provider_results, "urlscan", "subdomains", findings["urlscan"])
                if not findings["urlscan"]:
                    note_provider_status(provider_results, "urlscan", "No matching results returned")
        except Exception as exc:
            log(f"Urlscan failed: {exc}")
            note_provider_status(provider_results, "urlscan", str(exc), error=True)

    if source_enabled("censys"):
        token = censys_token()
        if not token:
            if provider_results is not None:
                mark_provider_skipped(provider_results, "censys", "PAT not configured")
        else:
            try:
                headers = {**HEADERS, "Authorization": f"Bearer {token}"}
                organization_id = censys_organization_id()
                if organization_id:
                    headers["X-Organization-ID"] = organization_id

                response = safe_post(
                    "https://api.platform.censys.io/v3/global/search/query",
                    headers=headers,
                    json={"query": f'names: "{domain}"', "per_page": 25},
                    timeout=12,
                )
                if response is not None and response.status_code == 200:
                    hits = response.json().get("result", {}).get("hits", [])
                    censys_subdomains = set()
                    for hit in hits:
                        for name in hit.get("names", []):
                            normalized = str(name).strip().lower().lstrip("*.")
                            if normalized.endswith(domain) and normalized != domain:
                                censys_subdomains.add(normalized)
                    findings["censys"] = sorted(censys_subdomains)
                    if provider_results is not None:
                        record_provider_result(provider_results, "censys", "subdomains", findings["censys"])
                    if not findings["censys"]:
                        note_provider_status(provider_results, "censys", "No matching certificate names returned")
                elif response is not None:
                    detail = _response_detail(response)
                    if response.status_code == 401:
                        message = "Censys rejected the configured PAT"
                    elif response.status_code == 403:
                        if "organization id" in detail.lower():
                            message = "Censys requires Censys_Organization_ID for Platform API access"
                        else:
                            message = "Censys accepted the PAT but denied access"
                    else:
                        message = f"HTTP {response.status_code} from Censys"
                    if detail:
                        message = f"{message}: {detail}"
                    note_provider_status(provider_results, "censys", message, error=response.status_code >= 400)
            except Exception as exc:
                note_provider_status(provider_results, "censys", str(exc), error=True)

    return findings


def dns_enumerate(domain: str, provider_results: Optional[dict] = None) -> dict:
    log(f"DNS enumeration: {domain}")
    results = {
        "domain": domain,
        "records": {},
        "subdomains": [],
        "nameservers": [],
        "mx_records": [],
        "txt_records": [],
        "spf": None,
        "dmarc": None,
        "dkim_hint": None,
    }

    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]
    direct_dns_enabled = source_enabled("direct_dns")

    def build_resolvers():
        resolvers = []

        default_resolver = dns.resolver.Resolver()
        default_resolver.timeout = 5
        default_resolver.lifetime = 8
        resolvers.append(default_resolver)

        public_nameserver_sets = [
            ["1.1.1.1", "1.0.0.1"],
            ["8.8.8.8", "8.8.4.4"],
        ]
        for nameservers in public_nameserver_sets:
            fallback = dns.resolver.Resolver(configure=False)
            fallback.nameservers = nameservers
            fallback.timeout = 4
            fallback.lifetime = 6
            resolvers.append(fallback)

        return resolvers

    resolvers = build_resolvers()

    def resolve_with_fallback(name: str, rtype: str):
        last_error = None
        for resolver in resolvers:
            try:
                answers = resolver.resolve(name, rtype)
                return answers
            except Exception as exc:
                last_error = exc
        if last_error:
            raise last_error
        raise RuntimeError(f"No DNS resolvers available for {name} {rtype}")

    if direct_dns_enabled:
        for rtype in record_types:
            try:
                answers = resolve_with_fallback(domain, rtype)
                records = [str(r) for r in answers]
                results["records"][rtype] = records

                if rtype == "NS":
                    results["nameservers"] = records
                elif rtype == "MX":
                    results["mx_records"] = [{"priority": r.preference, "host": str(r.exchange)} for r in answers]
                elif rtype == "TXT":
                    results["txt_records"] = records
                    for rec in records:
                        if "v=spf1" in rec:
                            results["spf"] = rec
                        if "DKIM" in rec.upper():
                            results["dkim_hint"] = rec
            except Exception:
                pass

        # DMARC
        try:
            dmarc_answers = resolve_with_fallback(f"_dmarc.{domain}", "TXT")
            for r in dmarc_answers:
                s = str(r)
                if "v=DMARC1" in s:
                    results["dmarc"] = s
        except Exception:
            pass

    # Subdomain enumeration (wordlist-based)
    common_subs = [
        "www", "mail", "smtp", "pop", "imap", "ftp", "vpn", "remote", "dev",
        "staging", "test", "api", "admin", "portal", "app", "dashboard", "monitor",
        "webmail", "owa", "autodiscover", "secure", "sso", "auth", "login",
        "jira", "confluence", "gitlab", "github", "jenkins", "sonar", "vault",
        "kibana", "grafana", "prometheus", "elastic", "splunk", "siem",
        "backup", "db", "mysql", "postgres", "redis", "mongo", "ldap", "dc",
        "cdn", "static", "assets", "upload", "files", "docs", "help", "support",
        "blog", "news", "shop", "store", "checkout", "payment", "billing",
        "m", "mobile", "wap", "ns1", "ns2", "mx1", "mx2",
    ]

    found_subdomains = []

    def check_subdomain(sub):
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolve_with_fallback(fqdn, "A")
            ips = [str(r) for r in answers]
            return {"subdomain": fqdn, "ips": ips, "type": "A"}
        except Exception:
            pass
        try:
            answers = resolve_with_fallback(fqdn, "CNAME")
            cnames = [str(r) for r in answers]
            return {"subdomain": fqdn, "cname": cnames, "type": "CNAME"}
        except Exception:
            pass
        return None

    if direct_dns_enabled:
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(check_subdomain, sub): sub for sub in common_subs}
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if r is not None:
                    found_subdomains.append(r)

    results["subdomains"] = found_subdomains

    # Certificate Transparency (crt.sh) for additional subdomains
    if source_enabled("crtsh"):
        try:
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            r = safe_get(ct_url, timeout=15)
            if r and r.status_code == 200:
                ct_data = r.json()
                ct_names = set()
                for entry in ct_data[:200]:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain) and name != domain:
                            ct_names.add(name)
                # Add unique crt.sh findings to subdomains
                existing = {s["subdomain"] for s in found_subdomains}
                for name in sorted(ct_names):
                    if name not in existing:
                        found_subdomains.append({"subdomain": name, "source": "crt.sh", "type": "CT_LOG"})
                results["subdomains"] = found_subdomains
                results["ct_log_count"] = len(ct_names)
        except Exception as e:
            log(f"crt.sh failed: {e}")

    free_provider_subdomains = _collect_free_provider_subdomains(domain, provider_results)
    if free_provider_subdomains:
        existing = {s["subdomain"] for s in found_subdomains}
        for provider_id, names in free_provider_subdomains.items():
            for name in names:
                if name not in existing:
                    found_subdomains.append({"subdomain": name, "source": provider_id, "type": "PASSIVE"})
                    existing.add(name)
        results["subdomains"] = found_subdomains

    return results


# ── 3. WHOIS ──────────────────────────────────────────────────────────────────

def get_whois(domain: str) -> dict:
    log(f"WHOIS: {domain}")
    result = {
        "domain": domain,
        "registrar": None,
        "registered": None,
        "expires": None,
        "updated": None,
        "registrant": None,
        "admin": None,
        "tech": None,
        "nameservers": [],
        "status": [],
        "raw": None,
    }
    try:
        w = whois_lib.whois(domain)
        result["registrar"] = str(w.registrar) if w.registrar else None
        result["registered"] = str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date) if w.creation_date else None
        result["expires"] = str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date) if w.expiration_date else None
        result["updated"] = str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date) if w.updated_date else None
        result["registrant"] = str(w.registrant_name) if hasattr(w, "registrant_name") and w.registrant_name else None
        result["org"] = str(w.org) if w.org else None
        result["country"] = str(w.country) if w.country else None
        result["status"] = w.status if isinstance(w.status, list) else ([w.status] if w.status else [])
        result["nameservers"] = w.name_servers if isinstance(w.name_servers, list) else ([w.name_servers] if w.name_servers else [])
        result["raw"] = str(w.text)[:2000] if hasattr(w, "text") else None
    except Exception as e:
        result["error"] = str(e)
    return result


# ── 4. SSL Certificate inspection ────────────────────────────────────────────

def get_ssl_info(domain: str) -> dict:
    log(f"SSL inspection: {domain}")
    result = {
        "domain": domain,
        "valid": False,
        "subject": None,
        "issuer": None,
        "san": [],
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "version": None,
        "serial": None,
        "signature_algo": None,
        "ocsp_url": None,
        "crl_distribution": [],
        "policy_oids": [],
        "extended_validation": False,
        "wildcard": False,
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result["valid"] = True
                result["version"] = ssock.version()

                # Subject
                subj = dict(x[0] for x in cert.get("subject", []))
                result["subject"] = subj

                # Issuer
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["issuer"] = issuer
                result["issuer_cn"] = issuer.get("commonName", "Unknown")

                # SAN
                sans = cert.get("subjectAltName", [])
                result["san"] = [v for _, v in sans]
                result["wildcard"] = any(v.startswith("*.") for _, v in sans)

                # Dates
                nb = cert.get("notBefore")
                na = cert.get("notAfter")
                result["not_before"] = nb
                result["not_after"] = na
                if na:
                    try:
                        exp = datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        result["days_remaining"] = (exp - now).days
                    except Exception:
                        pass

                # Serial
                result["serial"] = str(cert.get("serialNumber", ""))

                # OCSP / CRL
                for ext_key, ext_val in cert.get("OCSP", []):
                    result["ocsp_url"] = ext_val
                for item in cert.get("crlDistributionPoints", []):
                    result["crl_distribution"].append(item)

                # EV detection
                for policy in cert.get("certificatePolicies", []):
                    oid = policy[0] if isinstance(policy, tuple) else str(policy)
                    result["policy_oids"].append(str(oid))
                    if "2.23.140.1.1" in str(oid):
                        result["extended_validation"] = True

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL verification failed: {e}"
    except Exception as e:
        result["error"] = str(e)

    # Also fetch from crt.sh for historical certs
    try:
        r = safe_get(f"https://crt.sh/?q={domain}&output=json", timeout=15)
        if r is not None:
            ct = r.json()
            if ct:
                result["ct_entries"] = len(ct)
                result["earliest_cert"] = min(e.get("not_before", "9999") for e in ct[:100] if e.get("not_before"))
    except Exception:
        pass

    return result


# ── 5. IP & Hosting info ─────────────────────────────────────────────────────

def get_hosting_info(domain: str) -> dict:
    log(f"Hosting/IP info: {domain}")
    result = {
        "domain": domain,
        "ipv4": [],
        "ipv6": [],
        "reverse_dns": [],
        "asn": None,
        "asn_description": None,
        "isp": None,
        "org": None,
        "country": None,
        "city": None,
        "cloud_provider": None,
        "cdn": None,
        "open_ports": [],
    }

    # Resolve IPs
    try:
        infos = socket.getaddrinfo(domain, None)
        ips_v4 = list({i[4][0] for i in infos if i[0] == socket.AF_INET})
        ips_v6 = list({i[4][0] for i in infos if i[0] == socket.AF_INET6})
        result["ipv4"] = ips_v4
        result["ipv6"] = ips_v6
    except Exception:
        pass

    if not result["ipv4"]:
        return result

    ip = result["ipv4"][0]

    # Reverse DNS
    try:
        rdns = socket.gethostbyaddr(ip)
        result["reverse_dns"] = [rdns[0]]
    except Exception:
        pass

    # IP WHOIS / ASN
    if source_enabled("ipwhois"):
        try:
            obj = IPWhois(ip)
            rdap = obj.lookup_rdap(depth=1)
            asn_data = rdap.get("asn_description", "")
            result["asn"] = rdap.get("asn")
            result["asn_description"] = asn_data
            result["isp"] = rdap.get("network", {}).get("name")
            result["org"] = rdap.get("network", {}).get("remarks", [{}])[0].get("description") if rdap.get("network", {}).get("remarks") else None
            result["country"] = rdap.get("asn_country_code")
        except Exception:
            pass

    # Detect cloud/CDN by IP range patterns & ASN
    cloud_patterns = {
        "Amazon AWS": ["amazonaws.com", "aws", "AMAZON"],
        "Cloudflare": ["cloudflare", "CLOUDFLARE"],
        "Google Cloud": ["google", "GOOGLE"],
        "Microsoft Azure": ["microsoft", "MICROSOFT", "azure"],
        "Akamai": ["akamai", "AKAMAI"],
        "Fastly": ["fastly", "FASTLY"],
        "Hetzner": ["hetzner", "HETZNER"],
        "OVH": ["ovh", "OVH"],
        "DigitalOcean": ["digitalocean", "DIGITALOCEAN"],
        "Linode/Akamai": ["linode", "LINODE"],
    }
    combined = " ".join([
        result.get("asn_description") or "",
        result.get("isp") or "",
        " ".join(result.get("reverse_dns", [])),
    ]).upper()

    for provider, patterns in cloud_patterns.items():
        if any(p.upper() in combined for p in patterns):
            result["cloud_provider"] = provider
            break

    # CDN detection via headers
    try:
        r = safe_get(f"https://{domain}", timeout=8)
        if r:
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            if "cf-ray" in hdrs or "cloudflare" in hdrs.get("server", "").lower():
                result["cdn"] = "Cloudflare"
            elif "x-amz" in " ".join(hdrs.keys()):
                result["cdn"] = "AWS CloudFront"
            elif "x-akamai" in " ".join(hdrs.keys()):
                result["cdn"] = "Akamai"
            elif "fastly" in hdrs.get("x-served-by", "").lower():
                result["cdn"] = "Fastly"
            elif "via" in hdrs and "varnish" in hdrs["via"].lower():
                result["cdn"] = "Varnish/Custom"
    except Exception:
        pass

    # Port scan (common ports, fast)
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
                    3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]

    def check_port(port):
        try:
            with socket.create_connection((ip, port), timeout=1.5):
                return port
        except Exception:
            return None

    if source_enabled("port_scan"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            results_ports = list(ex.map(check_port, common_ports))
        result["open_ports"] = [p for p in results_ports if p]

    return result


# ── 6. Technology fingerprinting ──────────────────────────────────────────────

def fingerprint_technologies(url: str) -> dict:
    log(f"Tech fingerprinting: {url}")
    result = {
        "url": url,
        "server": None,
        "powered_by": None,
        "technologies": [],
        "frameworks": [],
        "cms": None,
        "analytics": [],
        "security_headers": {},
        "cookies": [],
        "headers": {},
    }

    r = safe_get(url, timeout=12)
    if r is None:
        return result

    headers = {k.lower(): v for k, v in r.headers.items()}
    body = r.text[:100000] if r.text else ""

    result["server"] = headers.get("server")
    result["powered_by"] = headers.get("x-powered-by")
    result["headers"] = dict(list(headers.items())[:30])

    # Security headers audit
    sec_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "x-xss-protection": "X-XSS-Protection",
    }
    for h, label in sec_headers.items():
        result["security_headers"][label] = {
            "present": h in headers,
            "value": headers.get(h, None),
        }

    # Technology detection rules (simplified Wappalyzer-like)
    tech_rules = [
        # CMS
        {"pattern": r"wp-content|wp-includes|wordpress", "name": "WordPress", "category": "CMS"},
        {"pattern": r"joomla", "name": "Joomla", "category": "CMS"},
        {"pattern": r"drupal", "name": "Drupal", "category": "CMS"},
        {"pattern": r"typo3", "name": "TYPO3", "category": "CMS"},
        {"pattern": r"ghost/", "name": "Ghost", "category": "CMS"},
        {"pattern": r"squarespace", "name": "Squarespace", "category": "CMS"},
        {"pattern": r"webflow", "name": "Webflow", "category": "CMS"},
        {"pattern": r"shopify", "name": "Shopify", "category": "E-Commerce"},
        {"pattern": r"woocommerce", "name": "WooCommerce", "category": "E-Commerce"},
        {"pattern": r"magento", "name": "Magento", "category": "E-Commerce"},
        {"pattern": r"prestashop", "name": "PrestaShop", "category": "E-Commerce"},
        # Frameworks
        {"pattern": r"react|__NEXT_DATA__|next\.js", "name": "React/Next.js", "category": "JS Framework"},
        {"pattern": r"angular|ng-version", "name": "Angular", "category": "JS Framework"},
        {"pattern": r"vue\.js|vuejs|__vue", "name": "Vue.js", "category": "JS Framework"},
        {"pattern": r"nuxt|nuxtjs", "name": "Nuxt.js", "category": "JS Framework"},
        {"pattern": r"svelte", "name": "Svelte", "category": "JS Framework"},
        {"pattern": r"gatsby", "name": "Gatsby", "category": "JS Framework"},
        {"pattern": r"jquery", "name": "jQuery", "category": "JS Library"},
        {"pattern": r"bootstrap", "name": "Bootstrap", "category": "CSS Framework"},
        {"pattern": r"tailwind", "name": "Tailwind CSS", "category": "CSS Framework"},
        # Analytics
        {"pattern": r"google-analytics|ga\.js|gtag|UA-\d+|G-\w+", "name": "Google Analytics", "category": "Analytics"},
        {"pattern": r"segment\.com|analytics\.js", "name": "Segment", "category": "Analytics"},
        {"pattern": r"mixpanel", "name": "Mixpanel", "category": "Analytics"},
        {"pattern": r"hotjar", "name": "Hotjar", "category": "Analytics"},
        {"pattern": r"intercom", "name": "Intercom", "category": "CRM/Support"},
        {"pattern": r"zendesk", "name": "Zendesk", "category": "CRM/Support"},
        {"pattern": r"salesforce|pardot", "name": "Salesforce", "category": "CRM"},
        {"pattern": r"hubspot", "name": "HubSpot", "category": "Marketing"},
        # Servers / Hosting
        {"pattern": r"nginx", "name": "Nginx", "category": "Web Server", "in": "server"},
        {"pattern": r"apache", "name": "Apache", "category": "Web Server", "in": "server"},
        {"pattern": r"iis|microsoft-iis", "name": "IIS", "category": "Web Server", "in": "server"},
        {"pattern": r"express", "name": "Express.js", "category": "Backend", "in": "x-powered-by"},
        {"pattern": r"php", "name": "PHP", "category": "Backend", "in": "x-powered-by"},
        {"pattern": r"django", "name": "Django", "category": "Backend"},
        {"pattern": r"rails|rubyonrails", "name": "Ruby on Rails", "category": "Backend"},
        {"pattern": r"laravel", "name": "Laravel", "category": "Backend"},
        # CDN/Security
        {"pattern": r"cloudflare", "name": "Cloudflare", "category": "CDN/WAF", "in": "server"},
        {"pattern": r"varnish", "name": "Varnish Cache", "category": "CDN"},
        {"pattern": r"recaptcha", "name": "Google reCAPTCHA", "category": "Security"},
        {"pattern": r"turnstile", "name": "Cloudflare Turnstile", "category": "Security"},
        # Cloud
        {"pattern": r"amazonaws", "name": "AWS S3/CloudFront", "category": "Cloud"},
        {"pattern": r"vercel", "name": "Vercel", "category": "Hosting"},
        {"pattern": r"netlify", "name": "Netlify", "category": "Hosting"},
        {"pattern": r"heroku", "name": "Heroku", "category": "Hosting"},
    ]

    found_techs = []
    found_names = set()
    search_in = body.lower() + " " + " ".join(f"{k}: {v}" for k, v in headers.items())

    for rule in tech_rules:
        target = search_in
        if rule.get("in") == "server":
            target = (headers.get("server") or "").lower()
        elif rule.get("in") == "x-powered-by":
            target = (headers.get("x-powered-by") or "").lower()

        if re.search(rule["pattern"], target, re.IGNORECASE) and rule["name"] not in found_names:
            found_names.add(rule["name"])
            tech = {"name": rule["name"], "category": rule["category"]}
            found_techs.append(tech)
            if rule["category"] == "CMS":
                result["cms"] = rule["name"]
            elif rule["category"] == "Analytics":
                result["analytics"].append(rule["name"])

    result["technologies"] = found_techs

    # Cookies
    for cookie in r.cookies:
        result["cookies"].append({
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": getattr(cookie, "_rest", {}).get("HttpOnly", False),
            "samesite": getattr(cookie, "_rest", {}).get("SameSite", None),
            "domain": cookie.domain,
        })

    return result


# ── 7. Social media discovery ────────────────────────────────────────────────

def _make_slugs(company_name: str, domain: str) -> list:
    """Generate candidate handle slugs from company name and domain."""
    name = company_name.lower().strip()
    # bare domain label (e.g. 'paloaltonetworks' from 'paloaltonetworks.com')
    domain_slug = domain.split(".")[0] if domain else ""
    slugs = [
        re.sub(r"[^a-z0-9]", "", name),          # nospaces, nohyphens
        re.sub(r"[^a-z0-9-]", "", name.replace(" ", "-")),  # hyphenated
        re.sub(r"[^a-z0-9_]", "", name.replace(" ", "_")),  # underscored
        domain_slug,
    ]
    # also try first word only (e.g. 'palo' from 'palo alto networks')
    words = re.sub(r"[^a-z0-9 ]", "", name).split()
    if words:
        slugs.append(words[0])
        if len(words) >= 2:
            slugs.append(words[0] + words[1])
    return list(dict.fromkeys(s for s in slugs if s and len(s) >= 2))


def _ddg_social_search(query: str) -> Optional[str]:
    """Use DuckDuckGo to search for a social profile URL."""
    if not source_enabled("duckduckgo"):
        return None
    try:
        r = safe_get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json", "no_redirect": "1", "no_html": "1"},
            timeout=8,
        )
        if r and r.status_code == 200:
            data = r.json()
            # AbstractURL is often the official page
            if data.get("AbstractURL"):
                return data["AbstractURL"]
            # RelatedTopics first result
            for topic in data.get("RelatedTopics", [])[:3]:
                url = topic.get("FirstURL", "")
                if url:
                    return url
    except Exception:
        pass
    return None


def _extract_social_from_homepage(domain: str) -> dict:
    """Scrape homepage/footer for social media links."""
    found = {}
    patterns = {
        "LinkedIn":   r'https?://(?:www\.)?linkedin\.com/company/[\w\-]+',
        "Twitter/X":  r'https?://(?:www\.)?(?:twitter|x)\.com/[\w]+',
        "GitHub":     r'https?://(?:www\.)?github\.com/[\w\-]+',
        "Facebook":   r'https?://(?:www\.)?facebook\.com/[\w\.\-]+',
        "Instagram":  r'https?://(?:www\.)?instagram\.com/[\w\.]+',
        "YouTube":    r'https?://(?:www\.)?youtube\.com/(?:@[\w]+|c/[\w]+|user/[\w]+|channel/[\w]+)',
        "TikTok":     r'https?://(?:www\.)?tiktok\.com/@[\w\.]+',
        "Reddit":     r'https?://(?:www\.)?reddit\.com/r/[\w]+',
        "Mastodon":   r'https?://[\w\.]+/@[\w]+',
        "Bluesky":    r'https?://(?:www\.)?bsky\.app/profile/[\w\.]+',
    }
    for scheme in ["https", "http"]:
        r = safe_get(f"{scheme}://{domain}", timeout=10)
        if r is None:
            continue
        text = r.text
        for platform, pat in patterns.items():
            if platform not in found:
                m = re.search(pat, text, re.IGNORECASE)
                if m:
                    url = m.group(0).rstrip("/")
                    found[platform] = url
        # Also check /contact and /about for social links
        for path in ["/contact", "/about", "/footer"]:
            r2 = safe_get(f"{scheme}://{domain}{path}", timeout=7)
            if r2 is not None and r2.status_code == 200:
                for platform, pat in patterns.items():
                    if platform not in found:
                        m = re.search(pat, r2.text, re.IGNORECASE)
                        if m:
                            found[platform] = m.group(0).rstrip("/")
        break
    return found


def _wikidata_social(company_name: str, domain: str) -> dict:
    """Query Wikidata for official social media accounts."""
    found = {}
    try:
        # Search for entity by name
        search_r = safe_get(
            "https://www.wikidata.org/w/api.php",
            params={"action": "wbsearchentities", "search": company_name,
                    "language": "en", "format": "json", "limit": "3"},
            timeout=8,
        )
        if search_r is None or search_r.status_code != 200:
            return found
        items = search_r.json().get("search", [])
        if not items:
            return found
        qid = items[0]["id"]
        # Fetch claims for that entity
        entity_r = safe_get(
            "https://www.wikidata.org/wiki/Special:EntityData/{}.json".format(qid),
            timeout=8,
        )
        if entity_r is None or entity_r.status_code != 200:
            return found
        claims = entity_r.json().get("entities", {}).get(qid, {}).get("claims", {})
        # Wikidata property IDs for social accounts
        prop_map = {
            "P2002": ("Twitter/X",  "https://twitter.com/{}"),
            "P4264": ("LinkedIn",   "https://www.linkedin.com/company/{}"),
            "P2003": ("Instagram",  "https://www.instagram.com/{}"),
            "P2397": ("YouTube",    "https://www.youtube.com/channel/{}"),
            "P2671": ("GitHub",     "https://github.com/{}"),
            "P4015": ("Facebook",   "https://www.facebook.com/{}"),
            "P3984": ("Reddit",     "https://www.reddit.com/r/{}"),
            "P9677": ("TikTok",     "https://www.tiktok.com/@{}"),
            "P7085": ("TikTok",     "https://www.tiktok.com/@{}"),
        }
        for prop, (platform, url_tmpl) in prop_map.items():
            if prop in claims and platform not in found:
                val = claims[prop][0]["mainsnak"].get("datavalue", {}).get("value", "")
                if val:
                    found[platform] = url_tmpl.format(val)
    except Exception:
        pass
    return found


def _verify_profile(platform: str, url: str) -> dict:
    """
    Verify a candidate social profile URL actually exists.
    Each platform has its own 404-detection heuristic because most return HTTP 200
    even for non-existent profiles.
    """
    r = safe_get(url, timeout=10)
    if r is None:
        return {"url": url, "status": "unreachable"}

    status = r.status_code
    text = r.text.lower()

    # Hard 404
    if status == 404:
        return {"url": url, "status": "not_found"}

    # Platform-specific not-found signals in page body
    not_found_signals = {
        "LinkedIn":  ["page not found", "this page doesn't exist", "profile not found",
                      "isn't available", "no longer available"],
        "Twitter/X": ["this account doesn't exist", "caution: this account",
                      "account suspended", "page doesn't exist"],
        "GitHub":    ["not found", "this is not the web page you are looking for"],
        "Facebook":  ["page not found", "this content isn't available",
                      "the link you followed may have expired"],
        "Instagram": ["page not found", "sorry, this page", "isn't available"],
        "YouTube":   ["this page isn't available", "channel not found"],
        "CrunchBase":["page not found", "doesn't exist"],
        "TikTok":    ["couldn't find this account", "this account is private"],
        "Reddit":    ["page not found", "this community", "banned"],
    }
    signals = not_found_signals.get(platform, ["not found", "doesn't exist", "no such"])
    for sig in signals:
        if sig in text[:8000]:
            return {"url": url, "status": "not_found"}

    return {"url": url, "status": "found"}


def discover_social_profiles(domain: str, company_name: str) -> dict:
    """
    Multi-strategy social media discovery:
    1. Extract links directly from company homepage/footer
    2. Query Wikidata for authoritative handles
    3. Probe slug variants on each platform + verify with page-content heuristics
    4. DuckDuckGo search as fallback for missing platforms
    """
    log(f"Social media discovery: {company_name} / {domain}")
    profiles = {}  # platform -> {url, status, source}

    # ── Strategy 1: homepage link extraction ──
    try:
        hp_found = _extract_social_from_homepage(domain)
        for platform, url in hp_found.items():
            profiles[platform] = {"url": url, "status": "found", "source": "homepage"}
        log(f"  Homepage links found: {list(hp_found.keys())}")
    except Exception as e:
        log(f"  Homepage extraction failed: {e}")

    # ── Strategy 2: Wikidata authoritative handles ──
    if source_enabled("wikidata"):
        try:
            wd_found = _wikidata_social(company_name, domain)
            for platform, url in wd_found.items():
                if platform not in profiles:
                    verified = _verify_profile(platform, url)
                    if verified["status"] == "found":
                        profiles[platform] = {"url": url, "status": "found", "source": "wikidata"}
            log(f"  Wikidata handles found: {list(wd_found.keys())}")
        except Exception as e:
            log(f"  Wikidata lookup failed: {e}")

    # ── Strategy 3: slug probing with page-content verification ──
    slugs = _make_slugs(company_name, domain)
    log(f"  Probing slugs: {slugs}")

    platform_templates = {
        "LinkedIn":   [("https://www.linkedin.com/company/{s}", "LinkedIn")],
        "Twitter/X":  [("https://twitter.com/{s}", "Twitter/X"),
                       ("https://x.com/{s}", "Twitter/X")],
        "GitHub":     [("https://github.com/{s}", "GitHub")],
        "Facebook":   [("https://www.facebook.com/{s}", "Facebook")],
        "Instagram":  [("https://www.instagram.com/{s}", "Instagram")],
        "YouTube":    [("https://www.youtube.com/@{s}", "YouTube"),
                       ("https://www.youtube.com/c/{s}", "YouTube"),
                       ("https://www.youtube.com/user/{s}", "YouTube")],
        "CrunchBase": [("https://www.crunchbase.com/organization/{s}", "CrunchBase")],
        "TikTok":     [("https://www.tiktok.com/@{s}", "TikTok")],
        "Reddit":     [("https://www.reddit.com/r/{s}", "Reddit")],
    }

    def probe_platform(args):
        platform, slug = args
        if platform in profiles:  # already confirmed from homepage/wikidata
            return
        for tmpl, plat in platform_templates[platform]:
            url = tmpl.format(s=slug)
            result = _verify_profile(plat, url)
            if result["status"] == "found":
                return platform, {"url": url, "status": "found", "source": f"slug:{slug}"}
        return platform, {"url": platform_templates[platform][0][0].format(s=slugs[0]),
                          "status": "not_found", "source": "probe"}

    if source_enabled("social_probe"):
        probe_tasks = [
            (platform, slug)
            for platform in platform_templates
            if platform not in profiles
            for slug in slugs
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(probe_platform, task) for task in probe_tasks]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    platform, data = res
                    # Only upgrade: if not found yet, or if this is a positive match
                    if platform not in profiles or data["status"] == "found":
                        profiles[platform] = data

    # ── Strategy 4: DuckDuckGo search for platforms still not found ──
    missing = [p for p, d in profiles.items() if d["status"] != "found"]
    missing += [p for p in platform_templates if p not in profiles]

    ddg_queries = {
        "LinkedIn":   f"{company_name} site:linkedin.com/company",
        "Twitter/X":  f"{company_name} official Twitter OR X account site:twitter.com OR site:x.com",
        "GitHub":     f"{company_name} official GitHub organization site:github.com",
        "YouTube":    f"{company_name} official YouTube channel site:youtube.com",
        "Instagram":  f"{company_name} official Instagram site:instagram.com",
        "TikTok":     f"{company_name} official TikTok site:tiktok.com",
        "Reddit":     f"{company_name} subreddit site:reddit.com",
    }

    def ddg_search_platform(platform):
        query = ddg_queries.get(platform)
        if not query:
            return None
        # DuckDuckGo HTML search
        try:
            r = safe_get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                timeout=10,
            )
            if r is not None and r.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.select("a.result__url, .result__title a, a[href]"):
                    href = a.get("href", "")
                    # DuckDuckGo wraps links in redirect, extract uddg param
                    uddg = re.search(r'uddg=([^&]+)', href)
                    if uddg:
                        import urllib.parse
                        href = urllib.parse.unquote(uddg.group(1))
                    platform_domains = {
                        "LinkedIn":  "linkedin.com/company",
                        "Twitter/X": ["twitter.com/", "x.com/"],
                        "GitHub":    "github.com/",
                        "YouTube":   "youtube.com/",
                        "Instagram": "instagram.com/",
                        "TikTok":    "tiktok.com/@",
                        "Reddit":    "reddit.com/r/",
                    }
                    check = platform_domains.get(platform, "")
                    checks = check if isinstance(check, list) else [check]
                    for c in checks:
                        if c in href:
                            verified = _verify_profile(platform, href)
                            if verified["status"] == "found":
                                return platform, {"url": href, "status": "found", "source": "duckduckgo"}
        except Exception:
            pass
        return None

    if source_enabled("duckduckgo"):
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            futures = [ex.submit(ddg_search_platform, p) for p in missing]
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    platform, data = res
                    if platform not in profiles or profiles[platform]["status"] != "found":
                        profiles[platform] = data

    if source_enabled("brave"):
        for platform in list(missing):
            query = ddg_queries.get(platform)
            if not query:
                continue
            try:
                for item in brave_search(query):
                    href = item.get("url", "")
                    if not href:
                        continue
                    verified = _verify_profile(platform, href)
                    if verified["status"] == "found":
                        profiles[platform] = {"url": href, "status": "found", "source": "brave"}
                        break
            except Exception:
                pass

    # Final pass: mark platforms with no result as not_found
    for platform in platform_templates:
        if platform not in profiles:
            profiles[platform] = {"url": "", "status": "not_found", "source": "none"}

    found_count = sum(1 for d in profiles.values() if d["status"] == "found")
    log(f"  Social profiles found: {found_count}/{len(profiles)}")
    return profiles


# ── 8. Email harvesting ───────────────────────────────────────────────────────

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")


def _which(cmd: str) -> Optional[str]:
    """Return full path to cmd if it exists on PATH, else None."""
    found = shutil.which(cmd)
    if found:
        return found

    scripts_dir = os.path.dirname(sys.executable)
    candidates = [os.path.join(scripts_dir, cmd)]
    if sys.platform == "win32":
        candidates.extend(
            [
                os.path.join(scripts_dir, f"{cmd}.exe"),
                os.path.join(scripts_dir, f"{cmd}.bat"),
                os.path.join(scripts_dir, f"{cmd}.cmd"),
            ]
        )

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    return None


def _repo_tool_path(*parts: str) -> Optional[str]:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(base_dir, *parts)
    if os.path.exists(candidate):
        return candidate
    return None


def _timeout_seconds_from_env(key: str, default_seconds: int) -> int:
    raw = os.environ.get(key, "").strip()
    if not raw:
        return default_seconds
    try:
        parsed_ms = int(raw)
    except ValueError:
        return default_seconds
    if parsed_ms <= 0:
        return default_seconds
    return max(1, parsed_ms // 1000)


def _terminate_process_tree(process: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def _run_command_with_timeout(command: list[str], timeout: int) -> subprocess.CompletedProcess:
    popen_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["start_new_session"] = True

    process = subprocess.Popen(command, **popen_kwargs)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_tree(process)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except Exception:
            stdout, stderr = "", ""
        raise subprocess.TimeoutExpired(exc.cmd, timeout, output=stdout, stderr=stderr)

    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def sherlock_handle_candidates(domain: str, company_name: str) -> list[str]:
    candidates = []
    for item in rocketreach_company_variants(domain, company_name):
        normalized = re.sub(r"[^a-z0-9_\.]", "", item.lower().replace(" ", ""))
        if normalized and normalized not in candidates:
            candidates.append(normalized)
    return candidates[:3]


def sherlock_impersonation_candidates(candidates: list[str]) -> list[tuple[str, str]]:
    suspicious = []
    suffixes = [
        ("_official", "official suffix variation"),
        ("_support", "support suffix variation"),
        ("_help", "help suffix variation"),
        ("_ro", "regional suffix variation"),
        (".ro", "regional suffix variation"),
    ]
    for candidate in candidates[:3]:
        for suffix, reason in suffixes:
            variant = f"{candidate}{suffix}"
            if variant != candidate:
                suspicious.append((variant, reason))
    return suspicious[:4]


def _normalize_sherlock_site(site_name: str) -> Optional[str]:
    mapping = {
        "twitter": "Twitter/X",
        "x": "Twitter/X",
        "github": "GitHub",
        "facebook": "Facebook",
        "instagram": "Instagram",
        "youtube": "YouTube",
        "tiktok": "TikTok",
        "reddit": "Reddit",
        "linkedin": "LinkedIn",
    }
    cleaned = re.sub(r"[^a-z]", "", (site_name or "").lower())
    return mapping.get(cleaned)


def _parse_sherlock_stdout(stdout: str, username: str) -> dict[str, str]:
    found = {}
    pattern = re.compile(r"^\[\+\]\s+([^:]+):\s+(https?://\S+)\s*$")
    for line in (stdout or "").splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        site_name = match.group(1).strip()
        url = match.group(2).strip()
        platform = _normalize_sherlock_site(site_name) or site_name
        found[platform] = url
    return found


SHERLOCK_SITES = [
    "GitHub",
    "Twitter",
    "Facebook",
    "Instagram",
    "YouTube",
    "TikTok",
    "Reddit",
    "LinkedIn",
]


def _social_profile_from_url(url: str, source: str) -> Optional[tuple[str, dict]]:
    if not url:
        return None
    normalized = url.rstrip("/")
    patterns = [
        ("LinkedIn", r"https?://(?:www\.)?linkedin\.com/company/[\w\-]+"),
        ("Twitter/X", r"https?://(?:www\.)?(?:twitter|x)\.com/[\w]+"),
        ("GitHub", r"https?://(?:www\.)?github\.com/[\w\-]+"),
        ("Facebook", r"https?://(?:www\.)?facebook\.com/[\w\.\-]+"),
        ("Instagram", r"https?://(?:www\.)?instagram\.com/[\w\.]+"),
        ("YouTube", r"https?://(?:www\.)?youtube\.com/(?:@[\w]+|c/[\w]+|user/[\w]+|channel/[\w]+)"),
        ("TikTok", r"https?://(?:www\.)?tiktok\.com/@[\w\.]+"),
        ("Reddit", r"https?://(?:www\.)?reddit\.com/(?:r|user)/[\w]+"),
        ("CrunchBase", r"https?://(?:www\.)?crunchbase\.com/organization/[\w\-]+"),
    ]
    for platform, pattern in patterns:
        if re.match(pattern, normalized, re.IGNORECASE):
            return platform, {"url": normalized, "status": "found", "source": source}
    return None


def _parse_spiderfoot_stdout(stdout: str, domain: str) -> dict:
    findings = {
        "emails": set(),
        "subdomains": set(),
        "social_profiles": {},
        "mentions": [],
        "hosting": [],
    }
    try:
        payload = json.loads(stdout or "[]")
    except Exception:
        return findings

    if isinstance(payload, dict):
        payload = payload.get("records", [])
    if not isinstance(payload, list):
        return findings

    for item in payload:
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type", "")).upper()
        data = str(item.get("data", "")).strip()
        if not data:
            continue

        lowered = data.lower()
        if item_type == "EMAILADDR" and lowered.endswith(f"@{domain}"):
            findings["emails"].add(lowered)
            continue

        if item_type in {"INTERNET_NAME", "DOMAIN_NAME"} and lowered.endswith(domain) and lowered != domain:
            findings["subdomains"].add(lowered)
            continue

        if item_type in {"SOCIAL_MEDIA", "LINKED_URL_EXTERNAL", "URL_STATIC", "WEBSERVER_HTTPHEADERS"}:
            social_match = _social_profile_from_url(data, "spiderfoot")
            if social_match:
                platform, profile = social_match
                findings["social_profiles"].setdefault(platform, profile)
            elif data.startswith("http"):
                mention = classify_search_mention(
                    {"title": data, "url": data, "description": item.get("module", "SpiderFoot")},
                    domain,
                    domain,
                )
                findings["mentions"].append(
                    {
                        "category": mention.get("category"),
                        "title": data,
                        "url": data,
                        "snippet": item.get("module", "SpiderFoot"),
                        "source_domain": urlparse(data).netloc.lower(),
                        "matched_domain": domain,
                        "query": domain,
                    }
                )
            continue

        if item_type in {"IP_ADDRESS", "AFFILIATE_INTERNET_NAME"}:
            findings["hosting"].append({"value": data, "type": item_type})

    return findings


def run_spiderfoot(domain: str, company_name: str, provider_results: Optional[dict] = None) -> dict:
    empty = {
        "emails": set(),
        "subdomains": set(),
        "social_profiles": {},
        "mentions": [],
        "hosting": [],
    }
    if not source_explicitly_selected("spiderfoot"):
        if provider_results is not None:
            mark_provider_skipped(provider_results, "spiderfoot", "Provider not selected")
        return empty

    spiderfoot_cmd = _which("sf.py") or _which("spiderfoot") or _repo_tool_path("tools", "spiderfoot", "sf.py")
    if not spiderfoot_cmd:
        if provider_results is not None:
            mark_provider_skipped(provider_results, "spiderfoot", "SpiderFoot not found on PATH")
        return empty

    command = [
        "-s",
        domain,
        "-u",
        "passive",
        "-t",
        "EMAILADDR,INTERNET_NAME,DOMAIN_NAME,SOCIAL_MEDIA,LINKED_URL_EXTERNAL,IP_ADDRESS,AFFILIATE_INTERNET_NAME",
        "-f",
        "-o",
        "json",
        "-q",
    ]
    if spiderfoot_cmd.lower().endswith(".py"):
        command = [sys.executable, spiderfoot_cmd, *command]
    else:
        command = [spiderfoot_cmd, *command]
    timeout_seconds = _timeout_seconds_from_env("SPIDERFOOT_TIMEOUT_MS", 120)
    started_at = time.perf_counter()
    try:
        completed = _run_command_with_timeout(command, timeout=timeout_seconds)
        if completed.returncode not in (0, 1) and provider_results is not None:
            record_provider_note(provider_results, "spiderfoot", f"SpiderFoot exited with code {completed.returncode}")
        findings = _parse_spiderfoot_stdout(completed.stdout, domain)
        if provider_results is not None:
            record_provider_result(provider_results, "spiderfoot", "emails", sorted(findings["emails"]))
            record_provider_result(provider_results, "spiderfoot", "subdomains", sorted(findings["subdomains"]))
            record_provider_result(
                provider_results,
                "spiderfoot",
                "social_profiles",
                [{platform: profile} for platform, profile in findings["social_profiles"].items()],
            )
            record_provider_result(provider_results, "spiderfoot", "mentions", findings["mentions"])
            record_provider_result(provider_results, "spiderfoot", "hosting", findings["hosting"])
            if not any(
                [
                    findings["emails"],
                    findings["subdomains"],
                    findings["social_profiles"],
                    findings["mentions"],
                    findings["hosting"],
                ]
            ):
                record_provider_note(provider_results, "spiderfoot", "Scan completed but no relevant findings were captured")
        return findings
    except subprocess.TimeoutExpired:
        if provider_results is not None:
            mark_provider_error(provider_results, "spiderfoot", f"Timed out after {timeout_seconds}s")
        return empty
    except Exception as exc:
        if provider_results is not None:
            mark_provider_error(provider_results, "spiderfoot", str(exc))
        return empty
    finally:
        record_provider_timing(provider_results, "spiderfoot", _elapsed_ms(started_at))


def run_sherlock(domain: str, company_name: str, provider_results: Optional[dict] = None) -> dict:
    if not source_explicitly_selected("sherlock"):
        if provider_results is not None:
            mark_provider_skipped(provider_results, "sherlock", "Provider not selected")
        return {"profiles": {}, "impersonation_candidates": []}

    sherlock_cmd = _which("sherlock")
    if not sherlock_cmd:
        if provider_results is not None:
            mark_provider_skipped(provider_results, "sherlock", "Sherlock not found on PATH")
        return {"profiles": {}, "impersonation_candidates": []}

    candidates = sherlock_handle_candidates(domain, company_name)
    suspicious_candidates = sherlock_impersonation_candidates(candidates)
    legitimate_profiles = {}
    impersonation = []
    verification_cache = {}

    def run_query(username: str):
        command = [
            sherlock_cmd,
            username,
            "--print-found",
            "--timeout",
            "20",
        ]
        for site in SHERLOCK_SITES:
            command.extend(["--site", site])
        completed = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        return completed, _parse_sherlock_stdout(completed.stdout, username)

    def is_verified(platform: str, url: str) -> bool:
        cache_key = (platform, url)
        if cache_key not in verification_cache:
            verification_cache[cache_key] = _verify_profile(platform, url).get("status") == "found"
        return verification_cache[cache_key]

    timed_out = False
    started_at = time.perf_counter()
    try:
        for username in candidates:
            try:
                completed, payload = run_query(username)
            except subprocess.TimeoutExpired:
                timed_out = True
                break
            if completed.returncode not in (0, 1) and provider_results is not None:
                record_provider_note(provider_results, "sherlock", f"Sherlock exited with code {completed.returncode} for {username}")
            for platform, url in payload.items():
                if platform and url and platform not in legitimate_profiles and is_verified(platform, url):
                    legitimate_profiles[platform] = {"url": url, "status": "found", "source": "sherlock"}

        if not timed_out:
            for username, reason in suspicious_candidates:
                try:
                    completed, payload = run_query(username)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    break
                if completed.returncode not in (0, 1):
                    continue
                for platform, url in payload.items():
                    if url and is_verified(platform, url):
                        impersonation.append(
                            {
                                "platform": platform,
                                "username": username,
                                "url": url,
                                "matched_candidate": username,
                                "reason": reason,
                                "source": "sherlock",
                            }
                        )
        if provider_results is not None:
            record_provider_result(
                provider_results,
                "sherlock",
                "social_profiles",
                [{platform: profile} for platform, profile in legitimate_profiles.items()],
            )
            record_provider_result(provider_results, "sherlock", "impersonation_candidates", impersonation)
            if timed_out and (legitimate_profiles or impersonation):
                record_provider_note(provider_results, "sherlock", "Timed out after partial scan; returning collected Sherlock hits")
            elif timed_out:
                mark_provider_error(provider_results, "sherlock", "Timed out after 90s")
            if not legitimate_profiles and not impersonation and not timed_out:
                record_provider_note(provider_results, "sherlock", "No Sherlock social hits found")
    except Exception as exc:
        if provider_results is not None:
            mark_provider_error(provider_results, "sherlock", str(exc))
    finally:
        record_provider_timing(provider_results, "sherlock", _elapsed_ms(started_at))

    return {"profiles": legitimate_profiles, "impersonation_candidates": impersonation}


def run_theharvester(domain: str, provider_results: Optional[dict] = None) -> set:
    """Run theHarvester and extract emails from its output."""
    emails = set()
    if not source_enabled("theharvester"):
        if provider_results is not None:
            mark_provider_skipped(provider_results, "theharvester", "Provider not selected")
        return emails
    binary = _which("theHarvester") or _which("theharvester")
    if not binary:
        log("  theHarvester: not found on PATH, skipping")
        if provider_results is not None:
            mark_provider_skipped(provider_results, "theharvester", "theHarvester not found on PATH")
        return emails
    log(f"  theHarvester: running against {domain}")
    # Use multiple sources: anubis (no key), certspotter (no key),
    # crtsh (no key), otx (no key), rapiddns (no key), urlscan (no key)
    sources = "hunter,certspotter,crtsh,otx,rapiddns,urlscan"
    output_base = os.path.join(tempfile.gettempdir(), "harvester_out")
    try:
        proc = subprocess.run(
            [binary, "-d", domain, "-b", sources, "-f", output_base],
            capture_output=True, text=True, timeout=60
        )
        output = proc.stdout + proc.stderr
        # Parse emails from stdout
        found = EMAIL_RE.findall(output)
        emails.update(e.lower() for e in found if domain in e.lower())
        # Also try JSON output if written
        for ext in [".json", ".xml"]:
            try:
                with open(f"{output_base}{ext}") as fh:
                    content = fh.read()
                found2 = EMAIL_RE.findall(content)
                emails.update(e.lower() for e in found2 if domain in e.lower())
            except Exception:
                pass
        log(f"  theHarvester: found {len(emails)} emails")
        if provider_results is not None:
            record_provider_result(provider_results, "theharvester", "emails", sorted(emails))
    except subprocess.TimeoutExpired:
        log("  theHarvester: timed out after 60s")
        if provider_results is not None:
            mark_provider_error(provider_results, "theharvester", "Timed out after 60s")
    except Exception as e:
        log(f"  theHarvester: error — {e}")
        if provider_results is not None:
            mark_provider_error(provider_results, "theharvester", str(e))
    return emails


def run_recon_ng(domain: str, provider_results: Optional[dict] = None) -> set:
    """Run recon-ng email harvesting modules via its CLI."""
    emails = set()
    if not source_enabled("recon_ng"):
        if provider_results is not None:
            mark_provider_skipped(provider_results, "recon_ng", "Provider not selected")
        return emails
    binary = _which("recon-ng")
    if not binary:
        log("  recon-ng: not found on PATH, skipping")
        if provider_results is not None:
            mark_provider_skipped(provider_results, "recon_ng", "recon-ng not found on PATH")
        return emails
    log(f"  recon-ng: running against {domain}")
    # Build a recon-ng resource script
    script = (
        f"workspaces create osint_tmp\n"
        f"db insert domains domain={domain}\n"
        f"modules load recon/domains-contacts/whois_pocs\n"
        f"run\n"
        f"modules load recon/domains-contacts/pgp_search\n"
        f"run\n"
        f"modules load recon/domains-contacts/hunter_io\n"
        f"run\n"
        f"show contacts\n"
        f"exit\n"
    )
    script_path = os.path.join(tempfile.gettempdir(), "recon_ng_script.rc")
    try:
        with open(script_path, "w") as f:
            f.write(script)
        proc = subprocess.run(
            [binary, "-r", script_path],
            capture_output=True, text=True, timeout=60
        )
        output = proc.stdout + proc.stderr
        found = EMAIL_RE.findall(output)
        emails.update(e.lower() for e in found if domain in e.lower())
        log(f"  recon-ng: found {len(emails)} emails")
        if provider_results is not None:
            record_provider_result(provider_results, "recon_ng", "emails", sorted(emails))
            if not emails:
                record_provider_note(provider_results, "recon_ng", "No matching emails found")
    except subprocess.TimeoutExpired:
        log("  recon-ng: timed out after 60s")
        if provider_results is not None:
            mark_provider_error(provider_results, "recon_ng", "Timed out after 60s")
    except Exception as e:
        log(f"  recon-ng: error — {e}")
        if provider_results is not None:
            mark_provider_error(provider_results, "recon_ng", str(e))
    return emails


def run_rocketreach(domain: str, company_name: str, provider_results: Optional[dict] = None) -> set:
    emails = set()
    if not source_enabled("rocketreach"):
        if provider_results is not None:
            mark_provider_skipped(provider_results, "rocketreach", "Provider not selected")
        return emails

    api_key = os.environ.get("ROCKETREACH_API_KEY", "").strip()
    if not api_key:
        log("  RocketReach: API key not configured, skipping")
        if provider_results is not None:
            mark_provider_skipped(provider_results, "rocketreach", "API key not configured")
        return emails

    try:
        for company_variant in rocketreach_company_variants(domain, company_name):
            data = RocketReachAPI.search(api_key=api_key, company_name=company_variant, size=10) or {}
            for profile in data.get("profiles", []):
                work_email = profile.get("current_work_email")
                if work_email and domain in work_email.lower():
                    emails.add(work_email.lower())
                for entry in profile.get("emails", []):
                    email = entry.get("email", "")
                    if email and domain in email.lower():
                        emails.add(email.lower())
        log(f"  RocketReach: found {len(emails)} emails")
        if provider_results is not None:
            record_provider_result(provider_results, "rocketreach", "emails", sorted(emails))
            if not emails:
                record_provider_note(provider_results, "rocketreach", "No matching emails found")
    except Exception as e:
        log(f"  RocketReach: error — {e}")

    return emails


def run_emailharvest_passive(domain: str, provider_results: Optional[dict] = None) -> set:
    """
    Passive email harvesting without external tools:
    - crt.sh certificate emails
    - GitHub code search
    - Hunter.io public page
    - Phonebook.cz
    - IntelligenceX public
    - Google/Bing dork via DuckDuckGo HTML
    """
    emails = set()

    # crt.sh — certificates often contain admin emails
    if source_enabled("crtsh"):
        try:
            r = safe_get(f"https://crt.sh/?q={domain}&output=json", timeout=10)
            if r is not None and r.status_code == 200:
                crtsh_emails = set()
                for entry in r.json():
                    name = entry.get("name_value", "")
                    found = EMAIL_RE.findall(name)
                    matched = {e.lower() for e in found if domain in e.lower()}
                    emails.update(matched)
                    crtsh_emails.update(matched)
                if provider_results is not None:
                    record_provider_result(provider_results, "crtsh", "emails", sorted(crtsh_emails))
        except Exception:
            pass
    elif provider_results is not None:
        mark_provider_skipped(provider_results, "crtsh", "Provider not selected")

    # Hunter.io public domain search page
    if source_enabled("hunter"):
        try:
            r = safe_get(f"https://hunter.io/search/{domain}", timeout=10)
            if r is not None and r.status_code == 200:
                found = EMAIL_RE.findall(r.text)
                matched = {e.lower() for e in found if domain in e.lower()}
                emails.update(matched)
                if provider_results is not None:
                    record_provider_result(provider_results, "hunter", "emails", sorted(matched))
                if not matched:
                    note_provider_status(provider_results, "hunter", "No matching emails found on public Hunter page")
            elif r is not None and r.status_code != 404:
                note_provider_status(provider_results, "hunter", f"HTTP {r.status_code} from Hunter public page", error=r.status_code >= 400)
        except Exception:
            pass

    # Hunter.io API
    if source_enabled("hunter"):
        try:
            configured_keys = []
            for key in [os.environ.get("Hunter_API_KEY", "").strip(), os.environ.get("HunterIO_API_KEY", "").strip()]:
                if key and key not in configured_keys:
                    configured_keys.append(key)

            hunter_api_emails = []
            unauthorized_keys = 0
            last_status = None
            last_detail = ""

            for key in configured_keys or [""]:
                hunter_url = f"https://api.hunter.io/v2/domain-search?domain={domain}&limit=10"
                if key:
                    hunter_url = f"{hunter_url}&api_key={requests.utils.quote(key)}"
                r = safe_get(
                    hunter_url,
                    headers=HEADERS,
                    timeout=10,
                )
                if r is not None and r.status_code == 200:
                    data = r.json().get("data", {})
                    for item in data.get("emails", []):
                        e = item.get("value", "")
                        if e:
                            emails.add(e.lower())
                            hunter_api_emails.append(e.lower())
                    break
                if r is not None and r.status_code == 401 and key:
                    unauthorized_keys += 1
                    last_status = r.status_code
                    last_detail = _response_detail(r)
                    continue
                if r is not None:
                    last_status = r.status_code
                    last_detail = _response_detail(r)
                    break

            if provider_results is not None:
                record_provider_result(provider_results, "hunter", "emails", hunter_api_emails)
            if hunter_api_emails:
                pass
            elif configured_keys and unauthorized_keys == len(configured_keys):
                note_provider_status(provider_results, "hunter", "Hunter rejected both configured API keys", error=True)
            elif configured_keys and last_status == 401:
                message = "Hunter rejected the configured API key"
                if last_detail:
                    message = f"{message}: {last_detail}"
                note_provider_status(provider_results, "hunter", message, error=True)
            elif last_status is not None:
                message = f"HTTP {last_status} from Hunter API"
                if last_detail:
                    message = f"{message}: {last_detail}"
                note_provider_status(provider_results, "hunter", message, error=last_status >= 400)
            else:
                note_provider_status(provider_results, "hunter", "Hunter API returned no matching emails")
        except Exception:
            pass
    elif provider_results is not None:
        mark_provider_skipped(provider_results, "hunter", "Provider not selected")

    # Phonebook.cz (public email search)
    if source_enabled("phonebook_cz"):
        try:
            r = safe_get(
                "https://phonebook.cz/api/v1/query",
                params={"term": domain, "type": "email", "apikey": ""},
                timeout=10,
            )
            if r is not None and r.status_code == 200:
                if "text/html" in (r.headers.get("content-type", "").lower()) or r.text.lstrip().startswith("<"):
                    note_provider_status(provider_results, "phonebook_cz", "Unexpected HTML response from Phonebook.cz")
                    r = None
                if r is None:
                    pass
                else:
                    phonebook_emails = []
                    for item in r.json().get("resultsList", []):
                        e = item.get("data", "")
                        if "@" in e and domain in e:
                            emails.add(e.lower())
                            phonebook_emails.append(e.lower())
                    if provider_results is not None:
                        record_provider_result(provider_results, "phonebook_cz", "emails", phonebook_emails)
                    if not phonebook_emails:
                        note_provider_status(provider_results, "phonebook_cz", "No matching emails found")
            elif r is not None:
                note_provider_status(provider_results, "phonebook_cz", f"HTTP {r.status_code} from Phonebook.cz", error=r.status_code >= 400)
        except Exception:
            pass
    elif provider_results is not None:
        mark_provider_skipped(provider_results, "phonebook_cz", "Provider not selected")

    # DuckDuckGo email dork: "@domain.com"
    if source_enabled("duckduckgo"):
        try:
            r = safe_get(
                "https://html.duckduckgo.com/html/",
                params={"q": f'"@{domain}" email contact'},
                timeout=10,
            )
            if r is not None and r.status_code == 200:
                found = EMAIL_RE.findall(r.text)
                matched = {e.lower() for e in found if domain in e.lower()}
                emails.update(matched)
                if provider_results is not None:
                    record_provider_result(provider_results, "duckduckgo", "emails", sorted(matched))
                if not matched:
                    note_provider_status(provider_results, "duckduckgo", "No matching emails found in DuckDuckGo results")
        except Exception:
            pass
    elif provider_results is not None:
        mark_provider_skipped(provider_results, "duckduckgo", "Provider not selected")

    if source_enabled("brave"):
        api_key = os.environ.get("BRAVE_SEARCH_API_KEY", "").strip()
        if not api_key:
            if provider_results is not None:
                mark_provider_skipped(provider_results, "brave", "API key not configured")
        else:
            try:
                brave_emails = set()
                brave_mentions = []
                mention_query = f'"{domain}"'
                for item in brave_search(mention_query, provider_results):
                    mention = classify_search_mention(item, domain, mention_query)
                    if mention["url"] or mention["title"] or mention["snippet"]:
                        brave_mentions.append(mention)
                for item in brave_search(f'"@{domain}" email contact', provider_results):
                    haystack = " ".join(
                        [
                            item.get("title", ""),
                            item.get("description", ""),
                            item.get("url", ""),
                        ]
                    )
                    matched = {e.lower() for e in EMAIL_RE.findall(haystack) if domain in e.lower()}
                    emails.update(matched)
                    brave_emails.update(matched)
                if provider_results is not None:
                    record_provider_result(provider_results, "brave", "mentions", brave_mentions)
                    record_provider_result(provider_results, "brave", "emails", sorted(brave_emails))
                if not brave_emails:
                    note_provider_status(provider_results, "brave", "No matching emails found in Brave results")
            except Exception:
                pass
    elif provider_results is not None:
        mark_provider_skipped(provider_results, "brave", "Provider not selected")

    if source_enabled("google"):
        try:
            query = f'"{domain}"'
            response = safe_get("https://www.google.com/search", params={"q": query}, timeout=10)
            if response is not None and response.status_code == 200:
                emails.update(_record_google_provider_evidence(response.text, domain, query, provider_results))
            elif response is not None:
                note_provider_status(provider_results, "google", f"HTTP {response.status_code} from google", error=response.status_code >= 400)
        except Exception as exc:
            note_provider_status(provider_results, "google", str(exc), error=True)
    elif provider_results is not None:
        mark_provider_skipped(provider_results, "google", "Provider not selected")

    for provider_id, base_url, param_name, query in [
        ("windvane", "https://windvane.licho.in/search", "q", f'"{domain}"'),
    ]:
        if source_enabled(provider_id):
            try:
                response = safe_get(base_url, params={param_name: query}, timeout=10)
                if response is not None and response.status_code == 200:
                    matched = _record_search_provider_evidence(provider_id, response.text, domain, query, provider_results)
                    emails.update(matched)
                elif response is not None:
                    note_provider_status(provider_results, provider_id, f"HTTP {response.status_code} from {provider_id}", error=response.status_code >= 400)
            except Exception as exc:
                note_provider_status(provider_results, provider_id, str(exc), error=True)
        elif provider_results is not None:
            mark_provider_skipped(provider_results, provider_id, "Provider not selected")

    # GitHub code search for domain emails
    if source_enabled("github_code"):
        try:
            r = safe_get(
                f"https://api.github.com/search/code?q=%40{domain}&per_page=10",
                headers=github_api_headers(),
                timeout=10,
            )
            if r is not None and r.status_code == 200:
                github_emails = set()
                for item in r.json().get("items", []):
                    text_url = item.get("url", "")
                    raw_headers = {**github_api_headers(), "Accept": "application/vnd.github.v3.raw+json"}
                    r2 = safe_get(text_url, headers=raw_headers, timeout=8)
                    if r2 is not None and r2.status_code == 200:
                        found = EMAIL_RE.findall(r2.text)
                        matched = {e.lower() for e in found if domain in e.lower()}
                        emails.update(matched)
                        github_emails.update(matched)
                if provider_results is not None:
                    record_provider_result(provider_results, "github_code", "emails", sorted(github_emails))
                if not github_emails:
                    note_provider_status(provider_results, "github_code", "No matching emails found in GitHub code search")
            elif r is not None:
                detail = "Requires authentication" if r.status_code == 401 else f"HTTP {r.status_code} from GitHub code search"
                note_provider_status(provider_results, "github_code", detail, error=r.status_code >= 400)
        except Exception:
            pass
    elif provider_results is not None:
        mark_provider_skipped(provider_results, "github_code", "Provider not selected")

    log(f"  Passive harvest: {len(emails)} emails found")
    return emails


def harvest_emails(domain: str, company_name: str) -> dict:
    log(f"Email harvesting: {domain}")
    result = {
        "domain": domain,
        "emails": [],
        "email_format": None,
        "github_repos": [],
        "linkedin_presence": None,
        "social_profiles": {},
        "impersonation_candidates": [],
        "provider_results": {},
    }
    emails = set()
    provider_results = result["provider_results"]
    spiderfoot_findings = {
        "emails": set(),
        "subdomains": set(),
        "social_profiles": {},
        "mentions": [],
        "hosting": [],
    }
    selected_sources = _selected_sources() or set()
    spiderfoot_only = selected_sources == {"spiderfoot"}

    # Run theHarvester, recon-ng, and passive harvest in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        f_harvester = ex.submit(run_theharvester, domain, provider_results)
        f_reconng   = ex.submit(run_recon_ng, domain, provider_results)
        f_rocketreach = ex.submit(run_rocketreach, domain, company_name, provider_results)
        f_passive   = ex.submit(run_emailharvest_passive, domain, provider_results)
        for f, name in [
            (f_harvester, "theHarvester"),
            (f_reconng, "recon-ng"),
            (f_rocketreach, "rocketreach"),
            (f_passive, "passive"),
        ]:
            try:
                emails.update(f.result(timeout=90))
            except concurrent.futures.TimeoutError:
                log(f"  {name}: thread timed out")
            except Exception as e:
                log(f"  {name} error: {e}")

    if source_enabled("recon_ng") and not provider_results.get("recon_ng", {}).get("emails"):
        record_provider_note(provider_results, "recon_ng", "No matching emails found")
    if source_enabled("rocketreach") and not provider_results.get("rocketreach", {}).get("emails"):
        record_provider_note(provider_results, "rocketreach", "No matching emails found")

    spiderfoot_findings = run_spiderfoot(domain, company_name, provider_results)
    emails.update(spiderfoot_findings.get("emails", set()))

    # 4. Crawl homepage + common pages directly unless the operator requested SpiderFoot only.
    if not spiderfoot_only:
        for scheme in ["https", "http"]:
            r = safe_get(f"{scheme}://{domain}", timeout=10)
            if r is not None:
                found = EMAIL_RE.findall(r.text)
                homepage_emails = {e.lower() for e in found if domain in e.lower()}
                emails.update(homepage_emails)
                record_provider_result(provider_results, "website_crawl", "emails", sorted(homepage_emails))
                for path in ["/contact", "/about", "/team", "/people", "/careers",
                             "/jobs", "/support", "/press", "/media", "/investors"]:
                    r2 = safe_get(f"{scheme}://{domain}{path}", timeout=8)
                    if r2 is not None and r2.status_code == 200:
                        found2 = EMAIL_RE.findall(r2.text)
                        page_emails = {e.lower() for e in found2 if domain in e.lower()}
                        emails.update(page_emails)
                        record_provider_result(provider_results, "website_crawl", "emails", sorted(page_emails))
                break

    # 5. HIBP domain breach check
    breaches_found = []
    if source_enabled("hibp"):
        try:
            breaches_found = hibp_domain_breaches(domain, provider_results)
            record_provider_result(provider_results, "hibp", "breach_hints", breaches_found)
        except Exception:
            pass
    else:
        mark_provider_skipped(provider_results, "hibp", "Provider not selected")

    # 6. GitHub repo search
    github_repos = []
    if source_enabled("github_repos"):
        try:
            repo_queries = []
            for candidate in rocketreach_company_variants(domain, company_name):
                if candidate not in repo_queries:
                    repo_queries.append(candidate)
            repo_queries.extend([f'"{domain}"', f'"{domain.split(".")[0]}"'])
            seen_repos = set()
            for query in repo_queries:
                gh_search = safe_get(
                    f"https://api.github.com/search/repositories?q={requests.utils.quote(query)}&sort=stars&per_page=5",
                    headers=github_api_headers(),
                    timeout=10,
                )
                if gh_search is not None and gh_search.status_code == 200:
                    repos_data = gh_search.json().get("items", [])
                    for repo in repos_data[:5]:
                        full_name = repo.get("full_name")
                        if not full_name or full_name in seen_repos:
                            continue
                        seen_repos.add(full_name)
                        github_repos.append({
                            "name": full_name,
                            "url": repo.get("html_url"),
                            "stars": repo.get("stargazers_count"),
                            "description": repo.get("description"),
                        })
                elif gh_search is not None:
                    note_provider_status(provider_results, "github_repos", f"HTTP {gh_search.status_code} from GitHub repo search", error=gh_search.status_code >= 400)
                    break
            record_provider_result(provider_results, "github_repos", "repos", github_repos)
            if not github_repos:
                note_provider_status(provider_results, "github_repos", "No matching repositories found")
        except Exception:
            pass
    else:
        mark_provider_skipped(provider_results, "github_repos", "Provider not selected")

    log(f"Email harvesting complete: {len(emails)} unique emails found")
    result["emails"] = sorted(emails)
    result["github_repos"] = github_repos
    result["breaches"] = breaches_found

    # 5. Social media presence detection (multi-strategy)
    result["social_profiles"] = {} if spiderfoot_only else discover_social_profiles(domain, company_name)
    sherlock_result = {"profiles": {}, "impersonation_candidates": []} if spiderfoot_only else run_sherlock(domain, company_name, provider_results)
    result["impersonation_candidates"] = sherlock_result.get("impersonation_candidates", [])
    for platform, profile in sherlock_result.get("profiles", {}).items():
        if platform not in result["social_profiles"] or result["social_profiles"][platform].get("status") != "found":
            result["social_profiles"][platform] = profile
    for platform, profile in spiderfoot_findings.get("social_profiles", {}).items():
        if platform not in result["social_profiles"] or result["social_profiles"][platform].get("status") != "found":
            result["social_profiles"][platform] = profile
    if sherlock_result.get("profiles"):
        record_provider_result(
            provider_results,
            "sherlock",
            "social_profiles",
            [{platform: profile} for platform, profile in sherlock_result.get("profiles", {}).items()],
        )
    if result["impersonation_candidates"]:
        record_provider_result(
            provider_results,
            "sherlock",
            "impersonation_candidates",
            result["impersonation_candidates"],
        )
    for platform, profile in result["social_profiles"].items():
        source = profile.get("source")
        if source == "brave":
            record_provider_result(provider_results, "brave", "social_profiles", [{platform: profile}])
        if source == "duckduckgo":
            record_provider_result(provider_results, "duckduckgo", "social_profiles", [{platform: profile}])
        if source == "wikidata":
            record_provider_result(provider_results, "wikidata", "social_profiles", [{platform: profile}])
        if source_enabled("social_probe") and source and (source.startswith("slug:") or source == "probe" or source == "homepage"):
            record_provider_result(provider_results, "social_probe", "social_profiles", [{platform: profile}])
    if source_enabled("wikidata") and not result["provider_results"].get("wikidata", {}).get("social_profiles"):
        record_provider_note(provider_results, "wikidata", "No authoritative social handles found")
    if source_enabled("social_probe") and not result["provider_results"].get("social_probe", {}).get("social_profiles"):
        record_provider_note(provider_results, "social_probe", "No social profiles confirmed by direct probing")

    # Email format guessing
    if emails:
        first_email = next(iter(emails))
        local = first_email.split("@")[0]
        if "." in local:
            parts = local.split(".")
            if len(parts) == 2:
                result["email_format"] = "firstname.lastname@domain"
        elif "_" in local:
            result["email_format"] = "firstname_lastname@domain"
        elif len(local) <= 2:
            result["email_format"] = "initials@domain"
        else:
            result["email_format"] = "firstname@domain"

    return result


# ── 8. Breach check ───────────────────────────────────────────────────────────

def check_breaches(domain: str, emails: list, provider_results: Optional[dict] = None) -> dict:
    log(f"Breach check: {domain}")
    result = {
        "domain": domain,
        "domain_breaches": [],
        "email_breaches": {},
        "paste_exposure": False,
    }

    # Check domain via HIBP domain-search API
    if source_enabled("hibp"):
        try:
            result["domain_breaches"] = hibp_domain_breaches(domain, provider_results)
        except Exception:
            pass

    # Check individual emails (requires API key for v3, but try)
    # We can check the password hash endpoint (k-anonymity model)
    # Instead, check email validity and return metadata
    validated = []
    for email in emails[:10]:
        # SMTP validation (check MX exists)
        validated.append({"email": email, "format_valid": bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))})
    result["email_validation"] = validated

    # DeHashed public search (scrape)
    if source_enabled("dehashed"):
        try:
            dh = safe_get(f"https://dehashed.com/search?query={domain}", timeout=10)
            body = dh.text.lower() if dh is not None and dh.text else ""
            if dh and dh.status_code == 200 and "results" in body and "no results" not in body:
                result["dehashed_hint"] = "Public DeHashed hint found (full results require authentication)"
                note_provider_status(provider_results, "dehashed", "Public DeHashed hint found but no results without authentication")
            elif dh is not None and dh.status_code == 200:
                note_provider_status(provider_results, "dehashed", "No public DeHashed hint found")
            elif dh is not None:
                note_provider_status(provider_results, "dehashed", f"HTTP {dh.status_code} from DeHashed", error=dh.status_code >= 400)
        except Exception:
            pass

    return result


# ── MAIN orchestrator ─────────────────────────────────────────────────────────

def _empty_dns(domain: str) -> dict:
    return {"domain": domain, "records": {}, "subdomains": [], "nameservers": [],
            "mx_records": [], "txt_records": [], "spf": None, "dmarc": None, "dkim_hint": None}

def _empty_whois(domain: str) -> dict:
    return {"domain": domain, "registrar": None, "registered": None, "expires": None,
            "updated": None, "org": None, "country": None, "status": [], "nameservers": []}

def _empty_ssl(domain: str) -> dict:
    return {"domain": domain, "valid": False, "subject": None, "issuer": None,
            "issuer_cn": "Unknown", "san": [], "not_before": None, "not_after": None,
            "days_remaining": None, "version": None, "serial": None,
            "extended_validation": False, "wildcard": False, "error": "Not inspected"}

def _empty_hosting(domain: str) -> dict:
    return {"domain": domain, "ipv4": [], "ipv6": [], "reverse_dns": [], "asn": None,
            "asn_description": None, "isp": None, "country": None,
            "cloud_provider": None, "cdn": None, "open_ports": []}

def _empty_tech(url: str) -> dict:
    return {"url": url, "server": None, "powered_by": None, "technologies": [],
            "cms": None, "analytics": [], "security_headers": {}, "cookies": [], "headers": {}}

def _empty_identities(domain: str) -> dict:
    return {"domain": domain, "emails": [], "email_format": None,
            "github_repos": [], "social_profiles": {}, "impersonation_candidates": [], "breaches": [], "provider_results": {}}

def _empty_breaches(domain: str) -> dict:
    return {"domain": domain, "domain_breaches": [], "email_validation": []}


def run_recon(company_name: str) -> dict:
    recon_started_at = time.perf_counter()
    report = {
        "meta": {
            "company": company_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "version": "1.0",
            "selected_sources": sorted(_selected_sources() or []),
        },
        "timings": {
            "total_ms": 0,
            "stages": {},
            "providers": {},
        },
        "website": {},
        "dns": {},
        "whois": {},
        "ssl": {},
        "hosting": {},
        "technologies": {},
        "identities": {},
        "breaches": {},
        "provider_results": {},
        "errors": [],
        "warnings": [],
    }
    initialize_selected_provider_results(report["provider_results"])

    # ── Step 1: Find website ──
    stage_started_at = time.perf_counter()
    try:
        website_info = find_website(company_name)
        report["website"] = website_info
    except Exception as e:
        report["errors"].append(f"Website discovery crashed: {e}")
        website_info = {"company": company_name, "domain": None, "url": None, "found_via": None}
        report["website"] = website_info
    report["timings"]["stages"]["website"] = _elapsed_ms(stage_started_at)

    domain = website_info.get("domain")
    url = website_info.get("url")
    found_via = website_info.get("found_via")

    discovery_provider_map = {
        "brave_search": "brave",
        "duckduckgo_api": "duckduckgo",
        "duckduckgo_html": "duckduckgo",
        "bing_search": "bing",
        "google_search": "google",
        "windvane_search": "windvane",
    }
    discovery_provider_id = discovery_provider_map.get(found_via)
    if discovery_provider_id:
        record_provider_result(
            report["provider_results"],
            discovery_provider_id,
            "hosting",
            {"domain": domain, "url": url, "found_via": found_via},
        )
    for provider_id in ("bing", "duckduckgo", "brave", "google", "windvane"):
        if source_enabled(provider_id) and provider_id != discovery_provider_id:
            record_provider_note(report["provider_results"], provider_id, "Not used for final website match")

    # ── Step 1b: Domain not found — try treating input as a domain hint ──
    if not domain:
        report["warnings"].append(
            f"Could not automatically resolve a website for '{company_name}'. "
            "Try entering the domain directly (e.g. 'example.com') for better results."
        )
        # Last-ditch: if input contains a dot it might literally be a domain
        if "." in company_name and " " not in company_name:
            candidate = re.sub(r'^https?://', '', company_name.strip().lower())
            candidate = re.sub(r'^www\.', '', candidate).split("/")[0]
            if _is_valid_domain(candidate):
                domain = candidate
                url = f"https://{domain}"
                report["website"].update({"domain": domain, "url": url, "found_via": "direct_fallback"})
                log(f"Direct domain fallback: {domain}")

    if not domain:
        # Fill empty structures so the frontend always has valid objects
        placeholder = company_name.lower().replace(" ", ".")
        report["dns"] = _empty_dns(placeholder)
        report["whois"] = _empty_whois(placeholder)
        report["ssl"] = _empty_ssl(placeholder)
        report["hosting"] = _empty_hosting(placeholder)
        report["technologies"] = _empty_tech("")
        report["identities"] = _empty_identities(placeholder)
        report["breaches"] = _empty_breaches(placeholder)
        report["timings"]["total_ms"] = _elapsed_ms(recon_started_at)
        return report

    log(f"Target domain: {domain}, URL: {url}")

    # ── Steps 2-5: Run in parallel, each wrapped individually ──
    def safe_run(label, fn, *args, empty_fn=None, empty_args=None):
        started_at = time.perf_counter()
        try:
            return fn(*args)
        except Exception as e:
            fn_name = getattr(fn, "__name__", fn.__class__.__name__)
            report["errors"].append(f"{fn_name} failed: {e}")
            return (empty_fn or (lambda: {}))(*( empty_args or []))
        finally:
            report["timings"]["stages"][label] = _elapsed_ms(started_at)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        f_dns = ex.submit(safe_run, "dns", dns_enumerate, domain, report["provider_results"], empty_fn=_empty_dns, empty_args=[domain])
        f_whois = (
            ex.submit(safe_run, "whois", get_whois, domain, empty_fn=_empty_whois, empty_args=[domain])
            if source_enabled("whois")
            else None
        )
        f_ssl = (
            ex.submit(safe_run, "ssl", get_ssl_info, domain, empty_fn=_empty_ssl, empty_args=[domain])
            if source_enabled("ssl_inspection")
            else None
        )
        f_hosting = (
            ex.submit(safe_run, "hosting", get_hosting_info, domain, empty_fn=_empty_hosting, empty_args=[domain])
            if any_source_enabled("ipwhois", "port_scan")
            else None
        )

        report["dns"] = f_dns.result()
        report["whois"] = f_whois.result() if f_whois is not None else _empty_whois(domain)
        report["ssl"] = f_ssl.result() if f_ssl is not None else _empty_ssl(domain)
        report["hosting"] = f_hosting.result() if f_hosting is not None else _empty_hosting(domain)
        if f_whois is None:
            report["timings"]["stages"]["whois"] = 0
        if f_ssl is None:
            report["timings"]["stages"]["ssl"] = 0
        if f_hosting is None:
            report["timings"]["stages"]["hosting"] = 0

    if source_enabled("direct_dns"):
        direct_dns_records = []
        for record_type, values in report["dns"].get("records", {}).items():
            for value in values:
                direct_dns_records.append({"type": record_type, "value": value})
        record_provider_result(report["provider_results"], "direct_dns", "dns_records", direct_dns_records)
        record_provider_result(
            report["provider_results"],
            "direct_dns",
            "subdomains",
            [item.get("subdomain") for item in report["dns"].get("subdomains", []) if item.get("subdomain")],
        )

    if source_enabled("whois"):
        record_provider_result(report["provider_results"], "whois", "whois", report["whois"])

    if source_enabled("ssl_inspection"):
        record_provider_result(report["provider_results"], "ssl_inspection", "ssl", report["ssl"])

    if source_enabled("ipwhois"):
        hosting_details = {
            "ipv4": report["hosting"].get("ipv4", []),
            "ipv6": report["hosting"].get("ipv6", []),
            "reverse_dns": report["hosting"].get("reverse_dns", []),
            "asn": report["hosting"].get("asn"),
            "asn_description": report["hosting"].get("asn_description"),
            "isp": report["hosting"].get("isp"),
            "country": report["hosting"].get("country"),
            "cloud_provider": report["hosting"].get("cloud_provider"),
            "cdn": report["hosting"].get("cdn"),
        }
        record_provider_result(report["provider_results"], "ipwhois", "hosting", hosting_details)

    if source_enabled("port_scan"):
        record_provider_result(
            report["provider_results"],
            "port_scan",
            "ports",
            [str(port) for port in report["hosting"].get("open_ports", [])],
        )

    # ── Step 6: Tech fingerprinting ──
    stage_started_at = time.perf_counter()
    try:
        report["technologies"] = (
            fingerprint_technologies(url or f"https://{domain}")
            if source_enabled("tech_fingerprint")
            else _empty_tech(url or "")
        )
    except Exception as e:
        report["errors"].append(f"Tech fingerprinting failed: {e}")
        report["technologies"] = _empty_tech(url or "")
    report["timings"]["stages"]["technologies"] = _elapsed_ms(stage_started_at)

    if source_enabled("tech_fingerprint"):
        tech_details = []
        if report["technologies"].get("server"):
            tech_details.append({"server": report["technologies"]["server"]})
        if report["technologies"].get("powered_by"):
            tech_details.append({"powered_by": report["technologies"]["powered_by"]})
        tech_details.extend(report["technologies"].get("technologies", []))
        record_provider_result(report["provider_results"], "tech_fingerprint", "tech", tech_details)

    # ── Step 7: Identity harvesting ──
    stage_started_at = time.perf_counter()
    try:
        if any_source_enabled(
            "theharvester",
            "recon_ng",
            "rocketreach",
            "hunter",
            "phonebook_cz",
            "github_code",
            "github_repos",
            "wikidata",
            "social_probe",
            "sherlock",
            "spiderfoot",
            "duckduckgo",
            "google",
            "brave",
        ):
            report["identities"] = harvest_emails(domain, company_name)
        else:
            report["identities"] = _empty_identities(domain)
        identity_provider_results = report["identities"].get("provider_results", {})
        for provider_id, details in identity_provider_results.items():
            report["provider_results"][provider_id] = details
        spiderfoot_subdomains = report["provider_results"].get("spiderfoot", {}).get("subdomains", [])
        if spiderfoot_subdomains:
            existing_subdomains = {item.get("subdomain") for item in report["dns"].get("subdomains", []) if item.get("subdomain")}
            for name in spiderfoot_subdomains:
                if name and name not in existing_subdomains:
                    report["dns"].setdefault("subdomains", []).append({"subdomain": name, "type": "SpiderFoot"})
                    existing_subdomains.add(name)
    except Exception as e:
        report["errors"].append(f"Email harvesting failed: {e}")
        report["identities"] = _empty_identities(domain)
    report["timings"]["stages"]["identities"] = _elapsed_ms(stage_started_at)

    # ── Step 8: Breach check ──
    stage_started_at = time.perf_counter()
    try:
        if any_source_enabled("hibp", "dehashed"):
            report["breaches"] = check_breaches(domain, report["identities"].get("emails", []), report["provider_results"])
        else:
            report["breaches"] = _empty_breaches(domain)
    except Exception as e:
        report["errors"].append(f"Breach check failed: {e}")
        report["breaches"] = _empty_breaches(domain)
    report["timings"]["stages"]["breaches"] = _elapsed_ms(stage_started_at)

    for provider_id, details in report["provider_results"].items():
        duration_ms = details.get("duration_ms")
        if isinstance(duration_ms, int):
            report["timings"]["providers"][provider_id] = duration_ms

    report["timings"]["total_ms"] = _elapsed_ms(recon_started_at)

    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: python3 osint_engine.py <company_name>"}))
        sys.exit(1)

    company = " ".join(sys.argv[1:])
    result = run_recon(company)
    print(json.dumps(result, default=str, indent=2))
