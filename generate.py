"""
Static site generator for CSIRT Security News Monitor.
Fetches RSS feeds, translates English articles to Japanese via Claude API,
and writes docs/index.html with all articles embedded as JSON.
Run manually or via CI (GitHub/Gitea Actions).
"""

import json
import os
import re
import shutil
import sys
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
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

TRANSLATE_BATCH_SIZE = 15


# ---------------------------------------------------------------------------
# RSS Fetching
# ---------------------------------------------------------------------------

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
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": "application/rss+xml, application/xml, text/xml, */*",
                "Accept-Language": "ja,en;q=0.9",
                "Cache-Control": "no-cache",
            },
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

            pub_jst = pub_dt.astimezone(JST) if pub_dt != datetime.min.replace(tzinfo=timezone.utc) else None
            articles.append({
                "source":       cfg["name"],
                "lang":         lang,
                "title":        title,
                "title_en":     title,
                "link":         link,
                "summary":      summary[:300],
                "summary_en":   summary[:300],
                "published":    pub_jst.strftime("%Y-%m-%d %H:%M JST") if pub_jst else "",
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


# ---------------------------------------------------------------------------
# Translation (Claude API)
# ---------------------------------------------------------------------------

# 利用可能なモデルを順に試す（新しい順）
TRANSLATION_MODELS = [
    "claude-haiku-4-5-20251001",
    "claude-3-5-haiku-20241022",
    "claude-3-haiku-20240307",
]


def _detect_model(client):
    """Use the first available translation model."""
    for model in TRANSLATION_MODELS:
        try:
            client.messages.create(
                model=model,
                max_tokens=10,
                messages=[{"role": "user", "content": "hi"}],
            )
            print(f"[INFO] Using translation model: {model}")
            return model
        except Exception as e:
            msg = str(e)
            if "not_found_error" in msg or "model" in msg.lower():
                print(f"[INFO] Model {model} not available, trying next...", file=sys.stderr)
                continue
            # Other errors (auth, rate limit) — re-raise
            raise
    raise RuntimeError(f"No available translation model found. Tried: {TRANSLATION_MODELS}")


def _translate_batch(client, model, batch):
    """
    batch: [{"idx": int, "title": str, "summary": str}, ...]
    Returns dict of {idx: translated_item} on success, {} on failure.
    """
    prompt = (
        "以下はセキュリティニュースの英語記事リストです。\n"
        "各記事のtitleとsummaryを自然な日本語に翻訳してください。\n"
        "ルール:\n"
        "- CVE番号・製品名・固有名詞はそのまま残す\n"
        "- 入力と同じJSON配列形式で返す（idxフィールドは変更しない）\n"
        "- JSONのみ返す（前置きや説明は不要）\n\n"
        + json.dumps(batch, ensure_ascii=False)
    )
    try:
        msg = client.messages.create(
            model=model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text.strip()
        # Extract JSON array (handle markdown code blocks too)
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if not m:
            print(f"[WARN] No JSON array found in response: {text[:200]}", file=sys.stderr)
            return {}
        translated = json.loads(m.group())
        return {item["idx"]: item for item in translated}
    except json.JSONDecodeError as e:
        print(f"[WARN] JSON parse error in translation response: {e}", file=sys.stderr)
        return {}
    except Exception as e:
        print(f"[ERROR] Translation API call failed: {e}", file=sys.stderr)
        raise


def translate_articles(articles):
    """Translate English articles to Japanese using Claude API.
    Skips silently if ANTHROPIC_API_KEY is not set.
    Raises on API auth errors so the CI job fails visibly.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("[INFO] ANTHROPIC_API_KEY not set — skipping translation.")
        return articles

    try:
        import anthropic
    except ImportError:
        print("[ERROR] anthropic package not installed. Run: pip install anthropic", file=sys.stderr)
        sys.exit(1)

    print("[INFO] Initializing Anthropic client...")
    client = anthropic.Anthropic(api_key=api_key)

    try:
        model = _detect_model(client)
    except Exception as e:
        print(f"[ERROR] Failed to connect to Anthropic API: {e}", file=sys.stderr)
        sys.exit(1)

    en_indices = [i for i, a in enumerate(articles) if a.get("lang") == "en"]
    if not en_indices:
        print("[INFO] No English articles to translate.")
        return articles

    total_batches = (len(en_indices) + TRANSLATE_BATCH_SIZE - 1) // TRANSLATE_BATCH_SIZE
    print(f"Translating {len(en_indices)} English articles ({total_batches} batches)...")

    translated_count = 0
    for start in range(0, len(en_indices), TRANSLATE_BATCH_SIZE):
        batch_indices = en_indices[start:start + TRANSLATE_BATCH_SIZE]
        batch = [
            {"idx": i, "title": articles[i]["title"], "summary": articles[i]["summary"]}
            for i in batch_indices
        ]
        batch_num = start // TRANSLATE_BATCH_SIZE + 1
        try:
            translated_map = _translate_batch(client, model, batch)
            for i in batch_indices:
                if i in translated_map:
                    t = translated_map[i]
                    # Save Japanese translation; keep originals in _en fields
                    articles[i]["title"]   = t.get("title",   articles[i]["title"])
                    articles[i]["summary"] = t.get("summary", articles[i]["summary"])
                    translated_count += 1
            print(f"  Batch {batch_num}/{total_batches} done ({len(translated_map)}/{len(batch)} translated).")
        except Exception:
            print(f"  Batch {batch_num}/{total_batches} failed — keeping English.", file=sys.stderr)

    print(f"Translation complete: {translated_count}/{len(en_indices)} articles translated.")
    return articles


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------

def build_html(articles, source_status, generated_at):
    sources_json    = json.dumps(source_status, ensure_ascii=False)
    articles_json   = json.dumps(articles,      ensure_ascii=False)
    feed_names_json = json.dumps([f["name"] for f in FEEDS], ensure_ascii=False)

    return f"""<!DOCTYPE html>
<html lang="ja" data-bs-theme="light">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CSIRT Security News Monitor</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" />
  <link rel="stylesheet" href="style.css" />
</head>
<body>

  <!-- ===== Navbar ===== -->
  <nav class="navbar navbar-dark bg-dark sticky-top">
    <div class="container-fluid px-3">
      <span class="navbar-brand fw-bold me-auto">&#9888; CSIRT News Monitor</span>
      <div class="d-flex align-items-center gap-2 flex-shrink-0">
        <span class="text-light d-none d-sm-inline" style="font-size:0.7rem">生成: {generated_at}</span>
        <!-- 言語トグル (コンパクト) -->
        <div class="btn-group btn-group-sm" role="group">
          <input type="radio" class="btn-check" name="lang-mode" id="lang-ja" value="ja" />
          <label class="btn btn-outline-light" for="lang-ja">JA</label>
          <input type="radio" class="btn-check" name="lang-mode" id="lang-en" value="en" />
          <label class="btn btn-outline-light" for="lang-en">EN</label>
        </div>
        <!-- ダークモードトグル -->
        <button class="btn btn-sm btn-outline-light" id="dark-toggle" title="ダーク/ライト切替">&#9790;</button>
      </div>
    </div>
  </nav>

  <!-- ===== Schedule bar ===== -->
  <div class="schedule-bar text-center py-1 small">
    最終更新: <strong>{generated_at}</strong>
  </div>

  <!-- ===== Main ===== -->
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
        <span class="filter-label">確認</span>
        <div class="filter-scroll">
          <div class="btn-group btn-group-sm" role="group">
            <input type="radio" class="btn-check" name="read-filter" id="rf-all" value="all" checked />
            <label class="btn btn-outline-secondary" for="rf-all">すべて</label>
            <input type="radio" class="btn-check" name="read-filter" id="rf-unread" value="unread" />
            <label class="btn btn-outline-primary" for="rf-unread">未確認のみ</label>
            <input type="radio" class="btn-check" name="read-filter" id="rf-read" value="read" />
            <label class="btn btn-outline-success" for="rf-read">確認済みのみ</label>
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

    // ===== Persistence keys =====
    const KEY_THEME   = 'csirt:theme';
    const KEY_LANG    = 'csirt:lang';
    const KEY_CHECKED = 'csirt:checked'; // JSON array of checked URLs

    // ===== Dark mode =====
    let checkedSet = new Set(JSON.parse(localStorage.getItem(KEY_CHECKED) || '[]'));

    function applyTheme(theme) {{
      document.documentElement.setAttribute('data-bs-theme', theme);
      document.getElementById('dark-toggle').textContent = theme === 'dark' ? '☀' : '☾';
    }}
    function toggleTheme() {{
      const next = document.documentElement.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
      localStorage.setItem(KEY_THEME, next);
      applyTheme(next);
    }}
    document.getElementById('dark-toggle').addEventListener('click', toggleTheme);
    applyTheme(localStorage.getItem(KEY_THEME) || 'light');

    // ===== Language mode =====
    (function() {{
      const saved = localStorage.getItem(KEY_LANG) || 'ja';
      const el = document.getElementById('lang-' + saved);
      if (el) el.checked = true;
    }})();
    document.querySelectorAll('input[name="lang-mode"]').forEach(el =>
      el.addEventListener('change', () => {{
        localStorage.setItem(KEY_LANG, el.value);
        renderArticles();
      }})
    );

    function getLangMode() {{
      return document.querySelector('input[name="lang-mode"]:checked')?.value || 'ja';
    }}
    function getTitle(a) {{
      return (a.lang === 'en' && getLangMode() === 'en') ? (a.title_en || a.title) : a.title;
    }}
    function getSummary(a) {{
      return (a.lang === 'en' && getLangMode() === 'en') ? (a.summary_en || a.summary) : a.summary;
    }}

    // ===== Source filters =====
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

    // ===== Source status =====
    (function() {{
      const bar = document.getElementById('source-status');
      const errors = [];
      Object.entries(SOURCE_STATUS).forEach(([name, s]) => {{
        const cls = s.ok ? 'bg-success' : 'bg-danger';
        const tip = s.ok ? `${{s.count}}件取得` : `エラー: ${{s.error}}`;
        bar.insertAdjacentHTML('beforeend',
          `<span class="badge ${{cls}} source-badge" title="${{escHtml(tip)}}">${{s.ok ? '✓' : '✗'}} ${{escHtml(name)}}</span>`
        );
        if (!s.ok) errors.push(`${{name}}: ${{s.error}}`);
      }});
      if (errors.length) {{
        bar.insertAdjacentHTML('beforeend',
          `<span class="text-danger small ms-1" style="font-size:0.72rem">⚠ ${{escHtml(errors.join(' / '))}}</span>`
        );
      }}
    }})();

    // ===== Checked articles =====
    function saveChecked() {{
      localStorage.setItem(KEY_CHECKED, JSON.stringify([...checkedSet]));
    }}
    function toggleChecked(url) {{
      if (checkedSet.has(url)) checkedSet.delete(url); else checkedSet.add(url);
      saveChecked();
      // Update card style without full re-render
      document.querySelectorAll(`.article-check[data-url="${{CSS.escape(url)}}"]`).forEach(cb => {{
        cb.checked = checkedSet.has(url);
        cb.closest('.article-card').classList.toggle('is-checked', checkedSet.has(url));
      }});
      // Re-count if filtering by read/unread
      const rf = document.querySelector('input[name="read-filter"]:checked')?.value;
      if (rf !== 'all') renderArticles();
      else document.getElementById('article-count').textContent = `${{document.querySelectorAll('#articles-container .col-12').length}} 件`;
    }}

    // ===== Render =====
    function renderArticles() {{
      const filter   = document.querySelector('input[name="filter"]:checked').value;
      const source   = document.querySelector('input[name="source"]:checked').value;
      const keyword  = document.getElementById('search-input').value.trim().toLowerCase();
      const langMode = getLangMode();
      const rf       = document.querySelector('input[name="read-filter"]:checked').value;

      const filtered = ALL_ARTICLES.filter(a => {{
        if (filter === 'exploit' && !a.is_exploit) return false;
        if (filter === 'vuln'   && !a.is_vuln)    return false;
        if (source !== 'all'    && a.source !== source) return false;
        if (rf === 'unread' &&  checkedSet.has(a.link)) return false;
        if (rf === 'read'   && !checkedSet.has(a.link)) return false;
        if (keyword) {{
          const t = `${{getTitle(a)}} ${{getSummary(a)}}`.toLowerCase();
          if (!t.includes(keyword)) return false;
        }}
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
        const isChecked  = checkedSet.has(a.link);
        const col        = document.createElement('div');
        col.className    = 'col-12 col-sm-6 col-xl-4';
        const exploitBadge = a.is_exploit ? '<span class="badge bg-danger me-1">&#9888; 悪用観測</span>' : '';
        const vulnBadge    = a.is_vuln    ? '<span class="badge bg-warning text-dark me-1">&#128274; 脆弱性</span>' : '';
        const transBadge   = (a.lang === 'en' && langMode === 'ja')
          ? '<span class="badge bg-info text-dark me-1" title="機械翻訳">翻訳</span>' : '';
        const title   = escHtml(getTitle(a));
        const summary = escHtml(getSummary(a));
        const url     = escHtml(a.link);
        const cbId    = 'cb-' + btoa(encodeURIComponent(a.link)).replace(/[^a-z0-9]/gi,'').slice(0,12);

        col.innerHTML = `
          <div class="card h-100 shadow-sm article-card${{a.is_exploit ? ' border-danger' : ''}}${{isChecked ? ' is-checked' : ''}}">
            <div class="card-body d-flex flex-column p-3">
              <div class="d-flex justify-content-between align-items-start mb-2">
                <div class="article-badges">${{exploitBadge}}${{vulnBadge}}<span class="badge bg-secondary">${{escHtml(a.source)}}</span>${{transBadge}}</div>
                <label class="checked-label flex-shrink-0 ms-2" title="確認済みとしてマーク">
                  <input type="checkbox" class="form-check-input article-check" id="${{cbId}}"
                         data-url="${{url}}" ${{isChecked ? 'checked' : ''}} />
                </label>
              </div>
              <h6 class="card-title article-title">
                <a href="${{url}}" target="_blank" rel="noopener noreferrer"
                   class="text-decoration-none link-body-emphasis">${{title}}</a>
              </h6>
              <p class="card-text text-secondary article-summary flex-grow-1">${{summary}}${{a.summary.length >= 300 ? '...' : ''}}</p>
              <div class="text-muted article-date mt-2">${{escHtml(a.published)}}</div>
            </div>
          </div>`;

        // Attach checkbox event (after DOM insert)
        col.querySelector('.article-check').addEventListener('change', function() {{
          toggleChecked(this.dataset.url);
        }});
        container.appendChild(col);
      }});
    }}

    function escHtml(s) {{
      return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }}

    document.querySelectorAll('input[name="filter"], input[name="source"], input[name="read-filter"]').forEach(el =>
      el.addEventListener('change', renderArticles)
    );
    document.getElementById('search-input').addEventListener('input', renderArticles);

    renderArticles();
  </script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print("Fetching RSS feeds...")
    articles, source_status = fetch_all()
    total = sum(s["count"] for s in source_status.values())
    print(f"Fetched {total} matching articles from {len(FEEDS)} sources.")

    articles = translate_articles(articles)

    os.makedirs(DOCS_DIR, exist_ok=True)

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
