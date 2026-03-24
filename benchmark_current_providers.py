import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(r"c:\Users\tmoscaliuc\Downloads\osint-recon1\osint-recon")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ[key.strip()] = value.strip().strip('"').strip("'")


load_env(ROOT / ".env")

import osint_engine

PROVIDERS = [
    "direct_dns",
    "crtsh",
    "whois",
    "ssl_inspection",
    "ipwhois",
    "port_scan",
    "tech_fingerprint",
    "duckduckgo",
    "bing",
    "google",
    "wikidata",
    "theharvester",
    "recon_ng",
    "hunter",
    "phonebook_cz",
    "github_code",
    "github_repos",
    "hibp",
    "hackertarget",
    "dehashed",
    "brave",
    "bufferoverun",
    "censys",
    "projectdiscovery",
    "rapiddns",
    "rocketreach",
    "subdomaincenter",
    "subdomainfinderc99",
    "thc",
    "threatminer",
    "urlscan",
    "windvane",
]

DOMAINS = [
    "apple.com",
    "microsoft.com",
    "google.com",
    "amazon.com",
    "meta.com",
    "netflix.com",
    "openai.com",
    "salesforce.com",
    "oracle.com",
    "ibm.com",
    "adobe.com",
    "cloudflare.com",
    "zoom.us",
    "slack.com",
    "dropbox.com",
    "uber.com",
    "airbnb.com",
    "booking.com",
    "paypal.com",
    "stripe.com",
    "visa.com",
    "mastercard.com",
    "jpmorganchase.com",
    "goldmansachs.com",
    "citi.com",
    "wellsfargo.com",
    "coca-cola.com",
    "pepsico.com",
    "walmart.com",
    "target.com",
    "costco.com",
    "homedepot.com",
    "nike.com",
    "adidas.com",
    "ford.com",
    "tesla.com",
    "toyota.com",
    "siemens.com",
    "samsung.com",
    "sony.com",
    "nvidia.com",
    "amd.com",
    "intel.com",
    "qualcomm.com",
    "atlassian.com",
    "shopify.com",
    "spotify.com",
    "reddit.com",
    "github.com",
    "linkedin.com",
]

FIELDS_TO_COUNT = [
    "emails",
    "mentions",
    "social_profiles",
    "subdomains",
    "repos",
    "breach_hints",
    "dns_records",
    "whois",
    "ssl",
    "tech",
    "ports",
    "hosting",
]


def count_value(value):
    if isinstance(value, list):
        return len(value)
    if value in (None, "", False):
        return 0
    return 1


def main() -> None:
    os.environ["OSINT_SELECTED_SOURCES"] = json.dumps(PROVIDERS)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    json_path = ROOT / f"benchmark-provider-results-current-{stamp}.json"
    long_csv_path = ROOT / f"provider-hits-by-domain-current-{stamp}.csv"
    wide_csv_path = ROOT / f"provider-hits-by-domain-current-{stamp}-wide.csv"
    status_path = ROOT / "benchmark-current-status.json"

    results = []
    for index, domain in enumerate(DOMAINS, start=1):
        status_path.write_text(
            json.dumps(
                {
                    "completed": False,
                    "current_index": index,
                    "current_domain": domain,
                    "domains": len(DOMAINS),
                    "providers": len(PROVIDERS),
                    "started_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        try:
            report = osint_engine.run_recon(domain)
            results.append(
                {
                    "domain": domain,
                    "provider_results": report.get("provider_results", {}),
                    "errors": report.get("warnings", []),
                }
            )
        except Exception as exc:
            results.append(
                {
                    "domain": domain,
                    "provider_results": {},
                    "errors": [repr(exc)],
                }
            )

    payload = {
        "domains": DOMAINS,
        "providers": PROVIDERS,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    long_rows = []
    for result in results:
        provider_results = result.get("provider_results", {})
        for provider in PROVIDERS:
            details = provider_results.get(provider, {})
            counts = {field: count_value(details.get(field, [])) for field in FIELDS_TO_COUNT}
            long_rows.append(
                {
                    "domain": result["domain"],
                    "provider": provider,
                    "status": details.get("status", "missing"),
                    "total_hits": sum(counts.values()),
                    **counts,
                    "notes_count": len(details.get("notes", [])) if isinstance(details.get("notes", []), list) else 0,
                    "notes": " | ".join(str(note) for note in details.get("notes", []))
                    if isinstance(details.get("notes", []), list)
                    else "",
                }
            )

    with long_csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(long_rows[0].keys()))
        writer.writeheader()
        writer.writerows(long_rows)

    wide_rows = []
    for result in results:
        provider_results = result.get("provider_results", {})
        row = {"domain": result["domain"]}
        for provider in PROVIDERS:
            details = provider_results.get(provider, {})
            row[provider] = sum(count_value(details.get(field, [])) for field in FIELDS_TO_COUNT)
            row[f"{provider}__status"] = details.get("status", "missing")
        wide_rows.append(row)

    wide_fieldnames = ["domain"] + PROVIDERS + [f"{provider}__status" for provider in PROVIDERS]
    with wide_csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=wide_fieldnames)
        writer.writeheader()
        writer.writerows(wide_rows)

    status_path.write_text(
        json.dumps(
            {
                "completed": True,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "json": str(json_path),
                "long_csv": str(long_csv_path),
                "wide_csv": str(wide_csv_path),
                "domains": len(DOMAINS),
                "providers": len(PROVIDERS),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
