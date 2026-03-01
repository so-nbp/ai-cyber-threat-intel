# AI Cyber Threat Intelligence Collector

AI×サイバーセキュリティに特化した脅威インテリジェンス収集基盤。
MITRE ATT&CK / ATLAS フレームワークに基づく自動分類機能付き。

---

## セットアップ手順（Mac / Linux）

### Step 1: GitHubリポジトリを作成してclone

```bash
# GitHub で新しいリポジトリ "ai-cyber-threat-intel" を作成（README無し）

# ローカルに clone（もしくは既存フォルダで git init）
cd ~/programming/python
git clone https://github.com/<your-username>/ai-cyber-threat-intel.git
cd ai-cyber-threat-intel

# このプロジェクトのファイルを全てここに配置
```

### Step 2: セットアップ実行

```bash
# setup.sh に実行権限を付与して実行
chmod +x scripts/setup.sh
bash scripts/setup.sh
```

### Step 3: 仮想環境を有効化（最重要）

> **⚠️ ここが最も重要なステップです。**
> 
> `setup.sh` は仮想環境 `.venv` を作成しますが、
> **新しいターミナルを開くたびに以下のコマンドが必要です。**
> Anaconda の `(base)` 環境のままでは正しく動きません。

```bash
# プロジェクトフォルダに移動
cd ~/programming/python/ai-cyber-threat-intel

# 仮想環境を有効化
source .venv/bin/activate
```

有効化できると、ターミナルの表示が以下のように変わります:

```
# Before（NG）:
(base) MacBook-Air-2:ai-cyber-threat-intel som$

# After（OK）:
(.venv) MacBook-Air-2:ai-cyber-threat-intel som$
```

**`(.venv)` が先頭に表示されていることを必ず確認してください。**

### Step 4: 動作確認

```bash
# ソース一覧を表示
python -m src.main sources

# データベースの状態を確認
python -m src.main status
```

### Step 5: データ収集の実行

```bash
# 全ソースから一括収集（APIキーなしでも動作する）
python -m src.main collect --all

# 特定のソースだけ収集（APIキー不要のもの）
python -m src.main collect -s cisa_kev
python -m src.main collect -s arxiv
python -m src.main collect -s rss_feeds

# 収集結果を確認
python -m src.main status
```

### Step 6: GitHubにpush

```bash
git add -A
git commit -m "Initial commit: threat intel collection pipeline"
git push origin main
```

---

## API キーの設定（任意・あるとより多くのデータを取得可能）

`config/settings.yaml` を編集するか、環境変数で設定します:

| ソース | 環境変数 | 取得先 | 必須？ |
|--------|----------|--------|--------|
| NVD | `ACTI_NVD_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key | 任意（あるとレート制限緩和） |
| GitHub | `ACTI_GITHUB_TOKEN` | https://github.com/settings/tokens | 任意（あるとレート制限緩和） |
| OTX | `ACTI_OTX_API_KEY` | https://otx.alienvault.com/ | OTX利用時は必須 |

環境変数での設定例:
```bash
export ACTI_NVD_API_KEY="your-key-here"
export ACTI_GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
```

---

## コマンド一覧

| コマンド | 説明 |
|----------|------|
| `python -m src.main sources` | 利用可能なコレクター一覧 |
| `python -m src.main collect --all` | 全ソースから収集 |
| `python -m src.main collect -s <name>` | 指定ソースから収集 |
| `python -m src.main collect --all -d 30` | 過去30日分を収集 |
| `python -m src.main status` | DB統計と収集履歴 |
| `python -m src.main summary` | 日次サマリー表示 |
| `python -m src.main summary -j` | JSON形式で出力 |
| `python -m src.main init` | DB初期化 |
| `python -m src.main schedule` | 日次スケジューラ起動 |

---

## プロジェクト構造

```
ai-cyber-threat-intel/
├── src/
│   ├── collectors/        # ソース別コレクター
│   │   ├── base.py        # 抽象基底クラス
│   │   ├── nvd.py         # NVD/CVE
│   │   ├── cisa_kev.py    # CISA KEV
│   │   ├── github_advisory.py  # GitHub Advisory
│   │   ├── arxiv.py       # arXiv論文
│   │   ├── rss_feeds.py   # RSSフィード
│   │   └── otx.py         # AlienVault OTX
│   ├── models/            # データモデル
│   │   ├── threat.py      # 統一脅威スキーマ
│   │   └── enums.py       # 分類定義
│   ├── storage/           # ストレージ
│   │   ├── database.py    # SQLite
│   │   └── file_store.py  # 生データJSON保存
│   ├── analysis/          # 分析
│   │   └── trends.py      # トレンド分析
│   ├── utils/             # ユーティリティ
│   ├── main.py            # CLI
│   └── scheduler.py       # スケジューラ
├── config/
│   ├── settings.example.yaml
│   └── rss_sources.yaml
├── data/                  # ローカルデータ（Git管理外）
├── tests/
├── scripts/setup.sh
├── requirements.txt
└── README.md
```

## License

MIT
