"""
Static site generator for CSIRT Security News Monitor.
Fetches RSS feeds and writes docs/index.html with all articles embedded as JSON.
Run manually or via CI (GitHub/Gitea Actions).
"""

import json
import os
import re
import shutil
import sys
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from zoneinfo import ZoneInfo

JST = ZoneInfo("Asia/Tokyo")
DOCS_DIR = os.path.join(os.path.dirname(__file__), "docs")

FEEDS = [
    {"name": "CyberSecurity News", "url": "https://cybersecuritynews.com/feed/", "lang": "en"},
    {"name": "BleepingComputer",   "url": "https://www.bleepingcomputer.com/feed/", "lang": "en"},
    {"name": "Security NEXT",      "url": "https://www.security-next.com/feed", "lang": "ja"},
]

EXPLOIT_PATTERNS_EN = re.compile(
    r"\b(exploit(ed|ing|ation)?|actively exploited|in the wild|zero.?day|"
    r"poc|proof.of.concept|ransomware|malware|threat actor|backdoor|"
    r"remote code execution|\brce\b|attack(ed|ing|s)?)\b",
    re.IGNORECASE,
)
EXPLOIT_WORDS_JA = ["悪用", "エクスプロイト", "攻撃が確認", "攻撃を確認", "野放し", "ゼロデイ",
                    "PoC", "ランサムウェア", "マルウェア", "バックドア", "リモートコード実行", "標的型攻撃"]

VULN_PATTERNS_EN = re.compile(
    r"(CVE-\d{4}-\d+|vulnerabilit(y|ies)|patch(ed|ing|es)?|"
    r"security (update|advisory|fix|flaw|bulletin)|critical|high.severity)",
    re.IGNORECASE,
)
VULN_WORDS_JA = ["脆弱性", "CVE-", "パッチ", "セキュリティアップデート", "セキュリティ更新",
                 "セキュリティ修正", "深刻度", "危険度", "アドバイザリ"]

_NS = {
    "content": "http://purl.org/rss/1.0/modules/content/",
    "dc":      "http://purl.org/dc/elements/1.1/",
}


def _has_match(text, pattern_en, words_ja, lang):
    if pattern_en.search(text):
        return True
    if lang == "ja":
        tl = text.lower()
        return any(w.lower() in tl for w in words_ja)
    return False


def _strip_tags(html):
    return re.sub(r"<[^>]+>", "", html or "").strip()


def _parse_date(raw):
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


def fetch_feed(cfg):
    articles, error = [], None
    try:
        req = urllib.request.Request(
            cfg["url"],
            headers={"User-Agent": "CSIRT-SecurityNews-Monitor/1.0 (RSS reader)"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()

        root = ET.fromstring(raw)
        lang = cfg["lang"]
        items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")

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
            is_vuln    = _has_match(text, VULN_PATTERNS_EN,    VULN_WORDS_JA,    lang)

            if not (is_exploit or is_vuln):
                continue

            articles.append({
                "source":       cfg["name"],
                "title":        title,
                "link":         link,
                "summary":      summary[:300],
                "published":    pub_dt.strftime("%Y-%m-%d %H:%M UTC")
                                if pub_dt != datetime.min.replace(tzinfo=timezone.utc) else "",
                "published_ts": pub_dt.timestamp(),
                "is_exploit":   is_exploit,
                "is_vuln":      is_vuln,
            })
    except Exception as e:
        error = str(e)
        print(f"[ERROR] {cfg['name']}: {e}", file=sys.stderr)
    return articles, error, cfg["name"]


def fetch_all():
    articles, source_status = [], {}
    with ThreadPoolExecutor(max_workers=3) as ex:
        for result, err, name in ex.map(lambda c: fetch_feed(c), FEEDS):
            articles.extend(result)
            source_status[name] = {"ok": err is None, "error": err, "count": len(result)}
    articles.sort(key=lambda x: x["published_ts"], reverse=True)
    return articles, source_status


def build_html(articles, source_status, generated_at):
    sources_json   = json.dumps(source_status, ensure_ascii=False)
    articles_json  = json.dumps(articles,       ensure_ascii=False)
    feed_names_json = json.dumps([f["name"] for f in FEEDS], ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CSIRT Security News Monitor</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" />
  <link rel="stylesheet" href="style.css" />
</head>
<body>

  <nav class="navbar navbar-dark bg-dark px-3 sticky-top">
    <span class="navbar-brand fw-bold fs-6">&#9888; CSIRT News Monitor</span>
    <span class="text-light" style="font-size:0.72rem">生成: {generated_at}</span>
  </nav>

  <div class="schedule-bar text-center py-1 small">
    自動更新: 毎日 <strong>09:00 JST</strong> / <strong>15:00 JST</strong>
  </div>

  <div class="container-fluid py-2 px-2 px-md-3">

    <div class="filter-bar mb-2">
      <div class="filter-row">
        <span class="filter-label">種別</span>
        <div class="filter-scroll">
          <div class="btn-group btn-group-sm" role="group">
            <input type="radio" class="btn-check" name="filter" id="filter-all" value="all" checked />
            <label class="btn btn-outline-secondary" for="filter-all">すべて</label>
            <input type="radio" class="btn-check" name="filter" id="filter-exploit" value="exploit" />
            <label class="btn btn-outline-danger" for="filter-exploit">&#9888; 悪用観測</label>
            <input type="radio" class="btn-check" name="filter" id="filter-vuln" value="vuln" />
            <label class="btn btn-outline-warning" for="filter-vuln">&#128274; 脆弱性</label>
          </div>
        </div>
      </div>

      <div class="filter-row">
        <span class="filter-label">ソース</span>
        <div class="filter-scroll">
          <div class="btn-group btn-group-sm" id="source-filters" role="group">
            <input type="radio" class="btn-check" name="source" id="src-all" value="all" checked />
            <label class="btn btn-outline-secondary" for="src-all">全て</label>
          </div>
        </div>
      </div>

      <div class="filter-row">
        <span class="filter-label">検索</span>
        <input type="text" class="form-control form-control-sm flex-grow-1" id="search-input" placeholder="キーワード..." />
        <span class="text-secondary small ms-2 text-nowrap" id="article-count"></span>
      </div>
    </div>

    <div id="source-status" class="d-flex gap-2 mb-2 flex-wrap"></div>

    <div id="articles-container" class="row g-2 g-md-3"></div>
    <div id="empty-state" class="text-center py-5 d-none text-secondary">
      <div style="font-size:2.5rem">&#128269;</div>
      <p class="small">条件に一致する記事はありません</p>
    </div>
  </div>

  <div class="pb-4 d-md-none"></div>

  <script>
    const ALL_ARTICLES = {articles_json};
    const SOURCE_STATUS = {sources_json};
    const FEED_NAMES = {feed_names_json};

    // Build source filter buttons dynamically
    (function() {{
      const grp = document.getElementById('source-filters');
      FEED_NAMES.forEach((name, i) => {{
        const id = `src-${{i+1}}`;
        grp.insertAdjacentHTML('beforeend',
          `<input type="radio" class="btn-check" name="source" id="${{id}}" value="${{escHtml(name)}}" />` +
          `<label class="btn btn-outline-info" for="${{id}}">${{escHtml(name)}}</label>`
        );
      }});
    }})();

    // Source status
    (function() {{
      const bar = document.getElementById('source-status');
      Object.entries(SOURCE_STATUS).forEach(([name, s]) => {{
        const cls = s.ok ? 'bg-success' : 'bg-danger';
        const tip = s.ok ? `${{s.count}}件取得` : `エラー: ${{s.error}}`;
        bar.insertAdjacentHTML('beforeend',
          `<span class="badge ${{cls}} source-badge" title="${{escHtml(tip)}}">${{s.ok ? '✓' : '✗'}} ${{escHtml(name)}}</span>`
        );
      }});
    }})();

    function renderArticles() {{
      const filter  = document.querySelector('input[name="filter"]:checked').value;
      const source  = document.querySelector('input[name="source"]:checked').value;
      const keyword = document.getElementById('search-input').value.trim().toLowerCase();

      const filtered = ALL_ARTICLES.filter(a => {{
        if (filter === 'exploit' && !a.is_exploit) return false;
        if (filter === 'vuln'   && !a.is_vuln)    return false;
        if (source !== 'all'    && a.source !== source) return false;
        if (keyword && !`${{a.title}} ${{a.summary}}`.toLowerCase().includes(keyword)) return false;
        return true;
      }});

      const container = document.getElementById('articles-container');
      container.innerHTML = '';
      document.getElementById('article-count').textContent = `${{filtered.length}} 件`;

      if (filtered.length === 0) {{
        document.getElementById('empty-state').classList.remove('d-none');
        return;
      }}
      document.getElementById('empty-state').classList.add('d-none');

      filtered.forEach(a => {{
        const col = document.createElement('div');
        col.className = 'col-12 col-sm-6 col-xl-4';
        const exploitBadge = a.is_exploit ? '<span class="badge bg-danger me-1">&#9888; 悪用観測</span>' : '';
        const vulnBadge    = a.is_vuln    ? '<span class="badge bg-warning text-dark me-1">&#128274; 脆弱性</span>' : '';
        col.innerHTML = `
          <div class="card h-100 shadow-sm article-card ${{a.is_exploit ? 'border-danger' : ''}}">
            <div class="card-body d-flex flex-column p-3">
              <div class="mb-2">${{exploitBadge}}${{vulnBadge}}<span class="badge bg-secondary">${{escHtml(a.source)}}</span></div>
              <h6 class="card-title article-title">
                <a href="${{escHtml(a.link)}}" target="_blank" rel="noopener noreferrer"
                   class="text-decoration-none link-dark stretched-link">${{escHtml(a.title)}}</a>
              </h6>
              <p class="card-text text-secondary article-summary flex-grow-1">${{escHtml(a.summary)}}${{a.summary.length >= 300 ? '...' : ''}}</p>
              <div class="text-muted article-date mt-2">${{escHtml(a.published)}}</div>
            </div>
          </div>`;
        container.appendChild(col);
      }});
    }}

    function escHtml(s) {{
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }}

    document.querySelectorAll('input[name="filter"], input[name="source"]').forEach(el =>
      el.addEventListener('change', renderArticles)
    );
    document.getElementById('search-input').addEventListener('input', renderArticles);

    renderArticles();
  </script>
</body>
</html>
"""


def main():
    print("Fetching RSS feeds...")
    articles, source_status = fetch_all()
    total = sum(s["count"] for s in source_status.values())
    print(f"Fetched {total} matching articles from {len(FEEDS)} sources.")

    os.makedirs(DOCS_DIR, exist_ok=True)

    # Copy CSS
    src_css = os.path.join(os.path.dirname(__file__), "static", "style.css")
    dst_css = os.path.join(DOCS_DIR, "style.css")
    shutil.copy2(src_css, dst_css)

    generated_at = datetime.now(JST).strftime("%Y-%m-%d %H:%M JST")
    html = build_html(articles, source_status, generated_at)

    out_path = os.path.join(DOCS_DIR, "index.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Generated: {out_path}")
    print(f"Timestamp: {generated_at}")


if __name__ == "__main__":
    main()
