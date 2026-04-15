================================================================
 CSIRT Security News Monitor
================================================================

セキュリティニュースを自動収集・分類・翻訳して表示するツールです。
複数のRSSフィードから記事を取得し、悪用観測 (Exploitation) と
脆弱性 (Vulnerability) の2カテゴリに分類します。英語記事は
Claude API を使って日本語に自動翻訳されます。

----------------------------------------------------------------
 機能 (Features)
----------------------------------------------------------------

- RSSフィード自動収集（3ソース）
- キーワードによる自動分類
    - 悪用観測 (Exploitation): exploit, zero-day, ransomware 等
    - 脆弱性 (Vulnerability): CVE, patch, security advisory 等
- Claude API による英語→日本語自動翻訳
- 既読管理（ブラウザの localStorage に保存）
- ダークモード / 表示言語（日本語・英語）切替
- GitHub Actionsからの手動実行ボタン（GitHub PAT 設定時）

----------------------------------------------------------------
 ニュースソース (Sources)
----------------------------------------------------------------

- CyberSecurity News   https://cybersecuritynews.com/       (英語)
- BleepingComputer     https://www.bleepingcomputer.com/    (英語)
- Security NEXT        https://www.security-next.com/       (日本語)

----------------------------------------------------------------
 動作モード (Modes)
----------------------------------------------------------------

【動的モード (app.py) — Flask サーバー】

  起動:
    pip install flask
    python app.py

  アクセス: http://localhost:5000

  フィード更新タイミング:
    - 自動: 毎日 9:00 / 15:00 JST
    - 手動: POST /api/refresh

  翻訳が不要な場合は ANTHROPIC_API_KEY の設定は不要です。
  ただしその場合、英語記事は翻訳されません。


【静的生成モード (generate.py) — GitHub Pages / CI 向け】

  起動:
    pip install anthropic
    export ANTHROPIC_API_KEY=sk-...
    python generate.py

  出力: docs/index.html（依存なしで単体動作するHTMLファイル）

  GitHub Pages の公開設定で docs/ ディレクトリを指定することで
  そのまま公開できます。

----------------------------------------------------------------
 環境変数 (Environment Variables)
----------------------------------------------------------------

  ANTHROPIC_API_KEY   Claude API キー（翻訳に使用）
                      未設定時は翻訳をスキップし、英語のまま表示

----------------------------------------------------------------
 ファイル構成 (File Structure)
----------------------------------------------------------------

  app.py                    Flask サーバー（動的モード）
  generate.py               静的 HTML 生成スクリプト（CI モード）
  requirements.txt          Python 依存パッケージ（Flask）
  templates/index.html      Jinja2 テンプレート
  static/style.css          スタイルシート
  docs/                     生成された静的サイト（GitHub Pages 用）
  .github/workflows/        GitHub Actions ワークフロー
  .gitea/workflows/         Gitea Actions ワークフロー

----------------------------------------------------------------
 CI/CD
----------------------------------------------------------------

GitHub Actions および Gitea Actions に対応しています。
ワークフローは以下のタイミングで実行されます:

  - スケジュール実行: 毎時（JST 6:00〜22:00）
  - push トリガー
  - 手動実行（workflow_dispatch）

実行後、generate.py で生成された docs/ ディレクトリが
自動的にコミットされます。

================================================================
