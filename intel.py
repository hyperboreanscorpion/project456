#!/usr/bin/env python3
"""
AI & Cybersecurity Intelligence Collector - Version 1.0

Collection-only MVP:
- Google News RSS discovery (no Google API key required)
- GitHub release monitoring (token optional)
- Hugging Face public model discovery (no token required for public metadata)
- CISA Known Exploited Vulnerabilities (KEV) additions
- Seven-day filtering, deduplication, preliminary relevance scoring
- Markdown, CSV, and JSON outputs

This script collects metadata and short descriptions only. It does not execute
downloaded code, install tools, or perform security testing.
"""

from __future__ import annotations

import csv
import hashlib
import html
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus, urlparse, urlunparse

import feedparser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ----------------------------- CONFIGURATION -----------------------------

DAYS_BACK = max(1, int(os.getenv("DAYS_BACK", "7")))  # Override with pipeline variable if needed
MAX_GOOGLE_ITEMS_PER_QUERY = int(os.getenv("MAX_GOOGLE_ITEMS_PER_QUERY", "30"))
MAX_HF_MODELS_PER_ORG = int(os.getenv("MAX_HF_MODELS_PER_ORG", "15"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "25"))
REQUEST_DELAY_SECONDS = float(os.getenv("REQUEST_DELAY_SECONDS", "0.25"))

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "reports"))
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()

# Researchers with ambiguous names are intentionally not searched as standalone
# terms until the team supplies a profile, employer, or URL.
RESEARCHERS = [
    "Simon Willison",
    "Johann Rehberger",
    "Nicholas Carlini",
    "Leon Cerczynski",
    "Hamel Husain",
    "Riley Goodside",
    "Pliny the Prompter",
    "Briland Hitaj",
    "Dan McInerney",
]

UNRESOLVED_RESEARCHER_IDENTITIES = [
    "Nathan (insufficient identifying information)",
    "Hamiel (insufficient identifying information)",
]

ORGANIZATIONS = [
    "UK AI Security Institute",
    "UK AISI",
    "NIST CAISI",
    "Vals AI",
    "Artificial Analysis",
    "Hugging Face",
    "Gray Swan AI",
    "Microsoft AI Red Team",
    "Microsoft PyRIT",
    "NVIDIA AI Red Team",
    "NVIDIA garak",
    "MITRE ATLAS",
    "OWASP GenAI Security Project",
    "Anthropic",
    "OpenAI",
    "Google DeepMind",
    "xAI",
    "Microsoft AI",
    "Mistral AI",
    "DeepSeek",
    "Z.ai GLM",
    "Alibaba Qwen",
    "Moonshot AI Kimi",
    "Meta Llama",
    "NVIDIA Nemotron",
]

# Search queries are intentionally broad enough to discover new sources, but
# the local relevance scorer ranks results rather than silently dropping them.
GOOGLE_NEWS_QUERIES = [
    ("researchers", '"Simon Willison" OR "Johann Rehberger" OR "Nicholas Carlini" AI security'),
    ("researchers", '"Hamel Husain" OR "Riley Goodside" OR "Pliny the Prompter"'),
    ("researchers", '"Leon Cerczynski" OR "Briland Hitaj" OR "Dan McInerney" AI security'),
    ("evaluations", '"UK AI Security Institute" OR "NIST CAISI" OR "Vals AI"'),
    ("evaluations", '"Artificial Analysis" OR "Gray Swan AI" AI evaluation'),
    ("red_team", '"Microsoft PyRIT" OR "Microsoft AI Red Team"'),
    ("red_team", '"NVIDIA garak" OR "NVIDIA AI red team"'),
    ("red_team", '"MITRE ATLAS" OR "OWASP GenAI Security Project"'),
    ("models", '"Anthropic" OR "OpenAI" OR "Google DeepMind" model release'),
    ("models", '"xAI" OR "Mistral AI" OR "DeepSeek" model release'),
    ("models", '"Z.ai" OR "GLM" OR "Qwen" OR "Alibaba" AI model'),
    ("models", '"Moonshot AI" OR "Kimi" OR "Meta Llama" OR "NVIDIA Nemotron"'),
    ("threats", '"autonomous AI agents" cybersecurity attack OR threat'),
    ("threats", '"AI-assisted vulnerability discovery" OR autonomous exploitation'),
    ("threats", '"indirect prompt injection" OR agent prompt injection'),
    ("threats", '"MCP server" vulnerability OR security'),
    ("threats", '"AI agent" privilege escalation OR credential theft OR data exfiltration'),
    ("threats", '"AI-generated malware" OR AI-enabled phishing cybersecurity'),
    ("defense", '"AI red teaming" OR LLM security testing OR agent security'),
    ("defense", '"AI security" detection OR mitigation OR defensive tool'),
    ("benchmarks", 'AI cyber capability benchmark OR cybersecurity evaluation model'),
]

GITHUB_REPOSITORIES = [
    ("microsoft/PyRIT", "Microsoft PyRIT"),
    ("NVIDIA/garak", "NVIDIA garak"),
    ("mitre-atlas/atlas-data", "MITRE ATLAS data"),
    ("OWASP/www-project-top-10-for-large-language-model-applications", "OWASP LLM Top 10"),
    ("GenAI-Security-Project/GenAI-LLM-Top10", "OWASP GenAI LLM Top 10"),
    ("GenAI-Security-Project/GenAI-Red-Team-Lab", "OWASP GenAI Red Team Lab"),
]

# Public Hugging Face organization IDs. The API may return no results for an
# organization or may expose only a subset of its models.
HUGGINGFACE_ORGS = [
    "anthropic", "openai", "google", "xai", "mistralai", "deepseek-ai",
    "zai-org", "Qwen", "moonshotai", "meta-llama", "nvidia",
]

KEYWORD_WEIGHTS = {
    "autonomous": 5, "agentic": 5, "agent": 2, "computer use": 4,
    "tool use": 3, "prompt injection": 5, "indirect prompt injection": 6,
    "mcp": 4, "model context protocol": 4, "privilege escalation": 6,
    "credential": 4, "identity": 2, "exfiltration": 6, "vulnerability": 4,
    "exploit": 5, "exploitation": 5, "malware": 4, "phishing": 3,
    "red team": 4, "red teaming": 4, "jailbreak": 3, "data leakage": 5,
    "data poisoning": 5, "supply chain": 4, "sandbox": 2,
    "cybersecurity": 3, "security": 1, "benchmark": 2, "evaluation": 2,
    "model release": 2, "weights": 1, "guardrail": 3, "safeguard": 3,
    "ransomware": 4, "cloud": 1, "endpoint": 1, "lateral movement": 5,
}

CATEGORY_TERMS = {
    "Autonomous agents & tool use": ["autonomous", "agentic", "agent", "computer use", "tool use"],
    "Prompt injection & jailbreaks": ["prompt injection", "jailbreak", "indirect prompt"],
    "AI vulnerability discovery & exploitation": ["vulnerability", "exploit", "exploitation", "privilege escalation"],
    "AI-enabled malware & social engineering": ["malware", "phishing", "ransomware", "social engineering"],
    "MCP & agent infrastructure": ["mcp", "model context protocol", "agent framework"],
    "Identity, credentials & data access": ["credential", "identity", "exfiltration", "data leakage"],
    "AI red teaming & evaluation": ["red team", "red teaming", "benchmark", "evaluation", "garak", "pyrit"],
    "Models & capabilities": ["model release", "new model", "weights", "reasoning", "computer use"],
    "Defensive tools & mitigations": ["mitigation", "detection", "defense", "defensive", "guardrail", "safeguard"],
}


# ----------------------------- HTTP SETUP --------------------------------

def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=4,
        connect=4,
        read=4,
        backoff_factor=0.7,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": "AICyberIntelligenceCollector/1.0 (research monitoring; contact: internal-team)"
    })
    if GITHUB_TOKEN:
        session.headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return session


SESSION = build_session()
UTC_NOW = datetime.now(timezone.utc)
CUTOFF = UTC_NOW - timedelta(days=DAYS_BACK)
COLLECTION_ERRORS: list[dict[str, str]] = []


# ----------------------------- UTILITIES ---------------------------------

def parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text_value = str(value).strip()
        try:
            dt = datetime.fromisoformat(text_value.replace("Z", "+00:00"))
        except ValueError:
            try:
                dt = parsedate_to_datetime(text_value)
            except Exception:
                return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def clean_text(value: Any) -> str:
    text_value = html.unescape(str(value or ""))
    text_value = re.sub(r"<[^>]+>", " ", text_value)
    return re.sub(r"\s+", " ", text_value).strip()


def normalize_url(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip())
        # Remove common tracking parameters while preserving meaningful query data.
        query_parts = [
            part for part in parsed.query.split("&")
            if part and not part.lower().startswith(("utm_", "fbclid=", "gclid=", "ocid="))
        ]
        return urlunparse((
            parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"),
            "", "&".join(query_parts), ""
        ))
    except Exception:
        return url.strip()


def stable_id(item: dict[str, Any]) -> str:
    key = normalize_url(item.get("url", "")) or (
        clean_text(item.get("title", "")).lower() + "|" + item.get("source", "")
    )
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def record_error(source: str, error: Exception | str) -> None:
    message = str(error)[:500]
    COLLECTION_ERRORS.append({"source": source, "error": message})
    logging.warning("%s: %s", source, message)


def is_recent(published: datetime | None) -> bool:
    return published is not None and CUTOFF <= published <= UTC_NOW + timedelta(days=1)


def make_item(
    *, title: str, url: str, source: str, source_type: str, published: datetime | None,
    summary: str = "", category_hint: str = ""
) -> dict[str, Any]:
    return {
        "title": clean_text(title),
        "url": normalize_url(url),
        "source": clean_text(source),
        "source_type": source_type,
        "published_utc": published.isoformat() if published else "",
        "summary": clean_text(summary)[:1800],
        "category_hint": category_hint,
    }


# ----------------------------- COLLECTORS --------------------------------

def collect_google_news() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for category, query in GOOGLE_NEWS_QUERIES:
        url = (
            "https://news.google.com/rss/search?"
            + f"q={quote_plus(query + ' when:' + str(DAYS_BACK) + 'd')}"
            + "&hl=en-US&gl=US&ceid=US:en"
        )
        try:
            response = SESSION.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            feed = feedparser.parse(response.content)
            for entry in feed.entries[:MAX_GOOGLE_ITEMS_PER_QUERY]:
                published = parse_datetime(
                    getattr(entry, "published", None) or getattr(entry, "updated", None)
                )
                if not is_recent(published):
                    continue
                source_name = ""
                if getattr(entry, "source", None):
                    source_name = clean_text(entry.source.get("title", ""))
                item = make_item(
                    title=getattr(entry, "title", ""),
                    url=getattr(entry, "link", ""),
                    source=source_name or "Google News",
                    source_type="Google News RSS",
                    published=published,
                    summary=getattr(entry, "summary", ""),
                    category_hint=category,
                )
                if item["title"] and item["url"]:
                    results.append(item)
            time.sleep(REQUEST_DELAY_SECONDS)
        except Exception as exc:
            record_error(f"Google News [{category}: {query[:70]}]", exc)
    return results


def collect_github_releases() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for repo, label in GITHUB_REPOSITORIES:
        url = f"https://api.github.com/repos/{repo}/releases"
        try:
            response = SESSION.get(url, params={"per_page": 10}, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            for release in response.json():
                published = parse_datetime(release.get("published_at") or release.get("created_at"))
                if not is_recent(published):
                    continue
                results.append(make_item(
                    title=f"{label}: {release.get('name') or release.get('tag_name') or 'New release'}",
                    url=release.get("html_url", ""),
                    source=repo,
                    source_type="GitHub Release",
                    published=published,
                    summary=release.get("body", ""),
                    category_hint="red_team",
                ))
            time.sleep(REQUEST_DELAY_SECONDS)
        except Exception as exc:
            record_error(f"GitHub releases [{repo}]", exc)
    return results


def collect_huggingface_models() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for org in HUGGINGFACE_ORGS:
        url = "https://huggingface.co/api/models"
        try:
            response = SESSION.get(
                url,
                params={
                    "author": org,
                    "sort": "lastModified",
                    "direction": "-1",
                    "limit": MAX_HF_MODELS_PER_ORG,
                },
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            for model in response.json():
                published = parse_datetime(model.get("lastModified"))
                if not is_recent(published):
                    continue
                model_id = model.get("modelId") or model.get("id") or ""
                if not model_id:
                    continue
                results.append(make_item(
                    title=f"Model update: {model_id}",
                    url=f"https://huggingface.co/{model_id}",
                    source=f"Hugging Face / {org}",
                    source_type="Hugging Face Model",
                    published=published,
                    summary="Recently modified public model metadata. Review the model card, license, files, and change history before considering adoption.",
                    category_hint="models",
                ))
            time.sleep(REQUEST_DELAY_SECONDS)
        except Exception as exc:
            record_error(f"Hugging Face [{org}]", exc)
    return results


def collect_cisa_kev() -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        response = SESSION.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
        for vuln in vulnerabilities:
            published = parse_datetime(vuln.get("dateAdded"))
            if not is_recent(published):
                continue
            title = f"CISA KEV: {vuln.get('cveID', 'Unknown CVE')} — {vuln.get('vulnerabilityName', '')}"
            summary = (
                f"Vendor: {vuln.get('vendorProject', '')}. Product: {vuln.get('product', '')}. "
                f"Required action: {vuln.get('requiredAction', '')}. "
                f"Due date: {vuln.get('dueDate', '')}."
            )
            results.append(make_item(
                title=title,
                url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                source="CISA Known Exploited Vulnerabilities Catalog",
                source_type="Security Advisory",
                published=published,
                summary=summary,
                category_hint="threats",
            ))
    except Exception as exc:
        record_error("CISA KEV", exc)
    return results


# ----------------------------- ANALYSIS ----------------------------------

def classify_item(item: dict[str, Any]) -> tuple[list[str], int, str]:
    text_value = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    categories = []
    for category, terms in CATEGORY_TERMS.items():
        if any(term in text_value for term in terms):
            categories.append(category)

    score = 0
    matched = []
    for term, weight in KEYWORD_WEIGHTS.items():
        if term in text_value:
            score += weight
            matched.append(term)

    # Source-type and source-category context provides a modest baseline, not
    # an assertion that the finding is important or confirmed.
    if item.get("source_type") in ("GitHub Release", "Security Advisory"):
        score += 2
    if item.get("category_hint") in ("threats", "red_team"):
        score += 2

    score = min(score, 100)
    if score >= 15:
        priority = "P2 - High"
    elif score >= 8:
        priority = "P3 - Emerging"
    else:
        priority = "P4 - Situational"

    return categories or ["General AI / cybersecurity"], score, priority


def deduplicate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for item in items:
        item["id"] = stable_id(item)
        key = item["url"] or hashlib.sha256(item["title"].lower().encode()).hexdigest()
        if key not in by_key:
            by_key[key] = item
        else:
            existing = by_key[key]
            if len(item.get("summary", "")) > len(existing.get("summary", "")):
                existing["summary"] = item["summary"]
            if existing.get("source") == "Google News" and item.get("source") != "Google News":
                existing["source"] = item["source"]
                existing["source_type"] = item["source_type"]

    output = list(by_key.values())
    for item in output:
        categories, score, priority = classify_item(item)
        item["categories"] = categories
        item["relevance_score"] = score
        item["preliminary_priority"] = priority
        item["matched_terms"] = [
            term for term in KEYWORD_WEIGHTS
            if term in (item.get("title", "") + " " + item.get("summary", "")).lower()
        ]
    output.sort(
        key=lambda x: (
            x.get("relevance_score", 0),
            x.get("published_utc", ""),
        ),
        reverse=True,
    )
    return output


# ----------------------------- REPORTING ---------------------------------

def write_json(items: list[dict[str, Any]], path: Path) -> None:
    payload = {
        "generated_utc": UTC_NOW.isoformat(),
        "window_days": DAYS_BACK,
        "cutoff_utc": CUTOFF.isoformat(),
        "item_count": len(items),
        "collection_error_count": len(COLLECTION_ERRORS),
        "items": items,
        "collection_errors": COLLECTION_ERRORS,
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(items: list[dict[str, Any]], path: Path) -> None:
    fields = [
        "id", "title", "source", "source_type", "published_utc", "url",
        "relevance_score", "preliminary_priority", "categories", "matched_terms",
        "summary",
    ]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in items:
            row = dict(item)
            row["categories"] = "; ".join(row.get("categories", []))
            row["matched_terms"] = "; ".join(row.get("matched_terms", []))
            writer.writerow({field: row.get(field, "") for field in fields})


def write_markdown(items: list[dict[str, Any]], path: Path) -> None:
    counts: dict[str, int] = {}
    for item in items:
        for category in item.get("categories", []):
            counts[category] = counts.get(category, 0) + 1

    lines = [
        "# AI & Cybersecurity Intelligence — Collection Summary",
        "",
        f"- Generated (UTC): {UTC_NOW.strftime('%Y-%m-%d %H:%M')}",
        f"- Collection window: last {DAYS_BACK} days",
        f"- Findings collected after deduplication: **{len(items)}**",
        f"- Collection errors: **{len(COLLECTION_ERRORS)}**",
        "",
        "> This is a collection-stage report, not an AI-generated threat assessment. "
        "Relevance scores are preliminary keyword-based triage and require analyst review.",
        "",
        "## Collection health",
        "",
        f"- Researcher search terms: {len(RESEARCHERS)} identified names",
        f"- Organization names: {len(ORGANIZATIONS)}",
        f"- Google News queries: {len(GOOGLE_NEWS_QUERIES)}",
        f"- GitHub repositories: {len(GITHUB_REPOSITORIES)}",
        f"- Hugging Face organizations: {len(HUGGINGFACE_ORGS)}",
        "- CISA KEV: attempted",
        "",
        "## Findings by category",
        "",
    ]
    if counts:
        for category, count in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- {category}: {count}")
    else:
        lines.append("- No categorized findings collected.")

    lines.extend(["", "## Highest-scoring findings", ""])
    for index, item in enumerate(items[:50], start=1):
        lines.extend([
            f"### {index}. {item.get('title', 'Untitled')}",
            "",
            f"- **Priority:** {item.get('preliminary_priority', '')}",
            f"- **Relevance score:** {item.get('relevance_score', 0)} (preliminary)",
            f"- **Category:** {', '.join(item.get('categories', []))}",
            f"- **Source:** {item.get('source', '')} ({item.get('source_type', '')})",
            f"- **Published:** {item.get('published_utc', 'Unknown')}",
            f"- **URL:** {item.get('url', '')}",
            "",
            item.get("summary", "") or "_No summary supplied by source._",
            "",
        ])

    lines.extend(["## Collection errors", ""])
    if COLLECTION_ERRORS:
        for error in COLLECTION_ERRORS:
            lines.append(f"- **{error['source']}:** {error['error']}")
    else:
        lines.append("- No collection errors recorded.")

    lines.extend([
        "",
        "## Researcher identity follow-up",
        "",
        "The following names were not searched as standalone identities because "
        "they are ambiguous and could generate unrelated results:",
        "",
    ])
    lines.extend([f"- {name}" for name in UNRESOLVED_RESEARCHER_IDENTITIES])
    lines.extend([
        "",
        "## Next-stage analyst questions",
        "",
        "1. What is genuinely new compared with established knowledge?",
        "2. Does this enable or materially change an AI-enabled threat?",
        "3. Which enterprise assets or control areas could be affected?",
        "4. Is the finding demonstrated, independently validated, vendor-claimed, or speculative?",
        "5. Can the team access and safely evaluate the tool, model, or technique?",
        "6. What defensive control, detection, test, or policy should be considered?",
        "",
    ])
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    logging.info("Starting AI & Cybersecurity Intelligence collection")
    logging.info("Window: last %s days; cutoff: %s", DAYS_BACK, CUTOFF.isoformat())

    collected: list[dict[str, Any]] = []
    collectors = [
        ("Google News RSS", collect_google_news),
        ("GitHub releases", collect_github_releases),
        ("Hugging Face models", collect_huggingface_models),
        ("CISA KEV", collect_cisa_kev),
    ]

    for label, collector in collectors:
        logging.info("Collecting: %s", label)
        try:
            batch = collector()
            logging.info("%s returned %s recent records", label, len(batch))
            collected.extend(batch)
        except Exception as exc:
            record_error(label, exc)

    items = deduplicate(collected)
    date_tag = UTC_NOW.strftime("%Y-%m-%d")

    json_path = OUTPUT_DIR / f"collected_intelligence_{date_tag}.json"
    csv_path = OUTPUT_DIR / f"collected_intelligence_{date_tag}.csv"
    md_path = OUTPUT_DIR / f"collection_summary_{date_tag}.md"

    write_json(items, json_path)
    write_csv(items, csv_path)
    write_markdown(items, md_path)

    logging.info("Finished. Raw records: %s; unique findings: %s; errors: %s",
                 len(collected), len(items), len(COLLECTION_ERRORS))
    logging.info("Reports written to: %s", OUTPUT_DIR.resolve())

    # Collection failures are visible in the report. Return non-zero only if
    # nothing at all was collected, so a single unavailable source doesn't
    # fail the entire scheduled pipeline.
    if not items:
        logging.error("No findings collected. Review collection errors and network access.")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
