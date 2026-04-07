import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parsedate_to_datetime

from flask import Flask, render_template, jsonify

app = Flask(__name__)

FEEDS = [
    {
        "name": "CyberSecurity News",
        "url": "https://cybersecuritynews.com/feed/",
        "lang": "en",
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "lang": "en",
    },
    {
        "name": "Security NEXT",
        "url": "https://www.security-next.com/feed",
        "lang": "ja",
    },
]

# Keywords: exploitation observed
EXPLOIT_PATTERNS_EN = re.compile(
    r"\b(exploit(ed|ing|ation)?|actively exploited|in the wild|zero.?day|"
    r"poc|proof.of.concept|ransomware|malware|threat actor|backdoor|"
    r"remote code execution|\brce\b|attack(ed|ing|s)?)\b",
    re.IGNORECASE,
)
EXPLOIT_WORDS_JA = ["悪用", "エクスプロイト", "攻撃が確認", "攻撃を確認", "野放し", "ゼロデイ",
                    "PoC", "ランサムウェア", "マルウェア", "バックドア", "リモートコード実行", "標的型攻撃"]

# Keywords: vulnerability information
VULN_PATTERNS_EN = re.compile(
    r"(CVE-\d{4}-\d+|vulnerabilit(y|ies)|patch(ed|ing|es)?|"
    r"security (update|advisory|fix|flaw|bulletin)|critical|high.severity)",
    re.IGNORECASE,
)
VULN_WORDS_JA = ["脆弱性", "CVE-", "パッチ", "セキュリティアップデート", "セキュリティ更新",
                 "セキュリティ修正", "深刻度", "危険度", "アドバイザリ"]


def _has_match(text, pattern_en, words_ja, lang):
    if pattern_en.search(text):
        return True
    if lang == "ja":
        tl = text.lower()
        return any(w.lower() in tl for w in words_ja)
    return False


def _strip_tags(html: str) -> str:
    return re.sub(r"<[^>]+>", "", html or "").strip()


def _parse_date(raw: str) -> datetime:
    """Parse RFC-2822 or ISO-8601 date strings."""
    if not raw:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        return parsedate_to_datetime(raw)
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.min.replace(tzinfo=timezone.utc)


# XML namespaces commonly used in RSS/Atom feeds
_NS = {
    "content": "http://purl.org/rss/1.0/modules/content/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "atom": "http://www.w3.org/2005/Atom",
}


def fetch_feed(cfg: dict) -> tuple[list, str | None]:
    """Returns (articles, error_message_or_None)."""
    articles = []
    error = None
    try:
        req = urllib.request.Request(
            cfg["url"],
            headers={"User-Agent": "CSIRT-SecurityNews-Monitor/1.0 (RSS reader)"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()

        root = ET.fromstring(raw)
        lang = cfg["lang"]

        # Support RSS 2.0 and Atom
        items = root.findall(".//item")  # RSS
        if not items:
            items = root.findall(".//{http://www.w3.org/2005/Atom}entry")  # Atom

        for item in items[:60]:
            def g(tag, ns=None):
                el = item.find(ns + tag if ns else tag)
                return (el.text or "").strip() if el is not None and el.text else ""

            title = g("title") or item.findtext("{http://www.w3.org/2005/Atom}title", "")
            link = g("link") or ""
            if not link:
                # Atom <link href="..."/>
                lel = item.find("{http://www.w3.org/2005/Atom}link")
                link = lel.get("href", "") if lel is not None else ""

            summary = (
                g("description")
                or item.findtext(_NS["content"] + "encoded", "")
                or item.findtext("{http://www.w3.org/2005/Atom}summary", "")
                or item.findtext("{http://www.w3.org/2005/Atom}content", "")
            )
            summary = _strip_tags(summary)

            pub_raw = (
                g("pubDate")
                or item.findtext(_NS["dc"] + "date", "")
                or item.findtext("{http://www.w3.org/2005/Atom}published", "")
                or item.findtext("{http://www.w3.org/2005/Atom}updated", "")
            )
            pub_dt = _parse_date(pub_raw)

            text = f"{title} {summary}"
            is_exploit = _has_match(text, EXPLOIT_PATTERNS_EN, EXPLOIT_WORDS_JA, lang)
            is_vuln = _has_match(text, VULN_PATTERNS_EN, VULN_WORDS_JA, lang)

            if not (is_exploit or is_vuln):
                continue

            articles.append({
                "source": cfg["name"],
                "title": title,
                "link": link,
                "summary": summary[:300],
                "published": pub_dt.strftime("%Y-%m-%d %H:%M UTC") if pub_dt != datetime.min.replace(tzinfo=timezone.utc) else "",
                "published_ts": pub_dt.timestamp(),
                "is_exploit": is_exploit,
                "is_vuln": is_vuln,
            })
    except Exception as e:
        error = str(e)
        print(f"[ERROR] {cfg['name']}: {e}")
    return articles, error


def fetch_all_feeds() -> dict:
    articles = []
    source_status = {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {ex.submit(fetch_feed, cfg): cfg for cfg in FEEDS}
        for f in as_completed(futures):
            cfg = futures[f]
            result, err = f.result()
            articles.extend(result)
            source_status[cfg["name"]] = {"ok": err is None, "error": err, "count": len(result)}
    articles.sort(key=lambda x: x["published_ts"], reverse=True)
    return {"articles": articles, "sources": source_status}


@app.route("/")
def index():
    return render_template("index.html", feeds=FEEDS)


@app.route("/api/news")
def api_news():
    return jsonify(fetch_all_feeds())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
