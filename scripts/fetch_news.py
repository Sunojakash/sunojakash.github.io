#!/usr/bin/env python3
"""
Pulls the latest items from a curated list of cybersecurity RSS feeds and
writes them to data/news.json, which the static site reads client-side.

Run manually:   python scripts/fetch_news.py
Run on schedule: .github/workflows/fetch-news.yml (every 4 hours)

Design notes:
- Each feed is fetched independently and wrapped in try/except so one dead
  or blocked feed never breaks the whole run.
- Items are de-duplicated by link against what's already in news.json, so
  re-running the script is always safe and never creates duplicates.
- The merged list is capped (MAX_ARTICLES) and sorted newest-first.
- A couple of feeds (noted below) block requests coming from cloud/CI IP
  ranges (they return HTTP 403 to GitHub Actions runners specifically,
  even though the same URL works fine from a home connection). Those are
  disabled by default -- flip ENABLED to True to try them anyway.
"""

import json
import re
import sys
import time
import html
import calendar
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import feedparser
import requests

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = ROOT / "data" / "news.json"
MAX_ARTICLES = 150
SUMMARY_MAX_CHARS = 280
REQUEST_TIMEOUT = 15
USER_AGENT = (
    "Mozilla/5.0 (compatible; AkashSunojPortfolioBot/1.0; "
    "+https://github.com/) news-aggregator for a personal site"
)

FEEDS = [
    # name                        url                                                   enabled
    ("The Hacker News",  "https://feeds.feedburner.com/TheHackersNews",                  True),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/",                           True),
    ("Dark Reading",     "https://www.darkreading.com/rss.xml",                          True),
    ("SecurityWeek",     "https://www.securityweek.com/feed/",                           True),
    ("The Record",       "https://therecord.media/feed/",                                True),
    ("CISA Advisories",  "https://www.cisa.gov/cybersecurity-advisories/all.xml",        True),
    ("SANS ISC",         "https://isc.sans.edu/rssfeed_full.xml",                        True),
    # Known to 403 GitHub Actions / other datacenter IP ranges -- works fine
    # from a home connection or a self-hosted runner. Disabled by default.
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/",                       False),
]

TAG_RE = re.compile(r"<[^>]+>")


def clean_summary(raw: str) -> str:
    if not raw:
        return ""
    text = TAG_RE.sub(" ", raw)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > SUMMARY_MAX_CHARS:
        text = text[:SUMMARY_MAX_CHARS].rsplit(" ", 1)[0] + "…"
    return text


def parse_published(entry) -> Optional[str]:
    for key in ("published_parsed", "updated_parsed"):
        value = getattr(entry, key, None)
        if value:
            ts = calendar.timegm(value)
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    return None


def fetch_feed(name: str, url: str) -> list[dict]:
    items = []
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)
    except Exception as exc:  # noqa: BLE001 - a bad feed should never kill the run
        print(f"[warn] {name}: fetch failed ({exc})", file=sys.stderr)
        return items

    for entry in parsed.entries:
        link = getattr(entry, "link", None)
        title = getattr(entry, "title", None)
        if not link or not title:
            continue
        items.append({
            "id": getattr(entry, "id", link) or link,
            "title": html.unescape(title).strip(),
            "link": link,
            "summary": clean_summary(getattr(entry, "summary", "")),
            "source": name,
            "published": parse_published(entry),
        })

    print(f"[ok] {name}: {len(items)} items")
    return items


def load_existing() -> list[dict]:
    if not OUTPUT_PATH.exists():
        return []
    try:
        data = json.loads(OUTPUT_PATH.read_text())
        return data.get("articles", [])
    except Exception:  # noqa: BLE001
        return []


def main() -> None:
    existing = load_existing()
    seen_links = {a["link"] for a in existing if a.get("link")}

    fresh = []
    for name, url, enabled in FEEDS:
        if not enabled:
            continue
        fresh.extend(fetch_feed(name, url))
        time.sleep(0.5)  # be a polite, sequential requester

    new_items = [a for a in fresh if a["link"] not in seen_links]
    merged = new_items + existing

    def sort_key(article):
        return article.get("published") or ""

    merged.sort(key=sort_key, reverse=True)
    merged = merged[:MAX_ARTICLES]

    output = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "sources": sorted({a["source"] for a in merged}),
        "articles": merged,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(output, indent=2, ensure_ascii=False))
    print(f"[done] wrote {len(merged)} articles ({len(new_items)} new) -> {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
