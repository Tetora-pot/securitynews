import re
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parsedate_to_datetime
from zoneinfo import ZoneInfo

from flask import Flask, render_template, jsonify

app = Flask(__name__)

JST = ZoneInfo("Asia/Tokyo")
# Scheduled update hours in JST
SCHEDULE_HOURS = (9, 15)

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

# In-memory cache
_cache: dict = {
    "articles": [],
    "sources": {},
    "fetched_at": None,   # datetime in JST
    "is_fetching": False,
}
_cache_lock = threading.Lock()


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


_NS = {
    "content": "http://purl.org/rss/1.0/modules/content/",
    "dc": "http://purl.org/dc/elements/1.1/",
}


def fetch_feed(cfg: dict) -> tuple[list, str | None]:
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

        items = root.findall(".//item")
        if not items:
            items = root.findall(".//{http://www.w3.org/2005/Atom}entry")

        for item in items[:60]:
            def g(tag, ns=None):
                el = item.find(ns + tag if ns else tag)
                return (el.text or "").strip() if el is not None and el.text else ""

            title = g("title") or item.findtext("{http://www.w3.org/2005/Atom}title", "")
            link = g("link") or ""
            if not link:
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


def refresh_cache():
    with _cache_lock:
        if _cache["is_fetching"]:
            return
        _cache["is_fetching"] = True

    print(f"[{datetime.now(JST).strftime('%Y-%m-%d %H:%M JST')}] Fetching feeds...")
    articles = []
    source_status = {}
    try:
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {ex.submit(fetch_feed, cfg): cfg for cfg in FEEDS}
            for f in as_completed(futures):
                cfg = futures[f]
                result, err = f.result()
                articles.extend(result)
                source_status[cfg["name"]] = {
                    "ok": err is None,
                    "error": err,
                    "count": len(result),
                }
        articles.sort(key=lambda x: x["published_ts"], reverse=True)
        now_jst = datetime.now(JST)
        with _cache_lock:
            _cache["articles"] = articles
            _cache["sources"] = source_status
            _cache["fetched_at"] = now_jst.strftime("%Y-%m-%d %H:%M JST")
            _cache["is_fetching"] = False
        print(f"[{now_jst.strftime('%Y-%m-%d %H:%M JST')}] Done. {len(articles)} articles.")
    except Exception as e:
        print(f"[ERROR] refresh_cache: {e}")
        with _cache_lock:
            _cache["is_fetching"] = False


def _next_schedule_str() -> str:
    """Return JST time string of the next scheduled update."""
    now = datetime.now(JST)
    for h in sorted(SCHEDULE_HOURS):
        if now.hour < h:
            return f"{h:02d}:00 JST"
    return f"{sorted(SCHEDULE_HOURS)[0]:02d}:00 JST (翌日)"


def _scheduler_thread():
    triggered = set()
    while True:
        now = datetime.now(JST)
        key = (now.date(), now.hour)
        if now.hour in SCHEDULE_HOURS and key not in triggered:
            triggered.add(key)
            # Prune old keys to avoid unbounded growth
            today_keys = {k for k in triggered if k[0] == now.date()}
            triggered.clear()
            triggered.update(today_keys)
            threading.Thread(target=refresh_cache, daemon=True).start()
        time.sleep(30)


@app.route("/")
def index():
    return render_template("index.html", feeds=FEEDS, schedule_hours=SCHEDULE_HOURS)


@app.route("/api/news")
def api_news():
    with _cache_lock:
        data = {
            "articles": _cache["articles"],
            "sources": _cache["sources"],
            "fetched_at": _cache["fetched_at"],
            "is_fetching": _cache["is_fetching"],
            "next_update": _next_schedule_str(),
        }
    return jsonify(data)


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"status": "started"})


# Start background scheduler and initial fetch on startup
threading.Thread(target=_scheduler_thread, daemon=True, name="scheduler").start()
threading.Thread(target=refresh_cache, daemon=True, name="initial-fetch").start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
