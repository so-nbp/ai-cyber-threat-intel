# 意思決定記録（Architecture Decision Records）

> ビジネス判断・技術判断の記録。
> `/ba` と `/sde` の両方が追記する。

## ADR の書き方

```markdown
## ADR-NNN: タイトル

- **日付**: YYYY-MM-DD
- **決定者**: /ba or /sde or ユーザー
- **ステータス**: 提案 / 承認 / 却下 / 取消

### 背景
（なぜこの決定が必要になったか）

### 決定
（何を決めたか）

### 根拠
（なぜこの選択肢を選んだか。他の選択肢との比較）

### 影響
（この決定がプロジェクトに与える影響）
```

---

## ADR-001: Pydantic v2 で computed_field を使わない

- **日付**: 2026-03-01
- **決定者**: /sde
- **ステータス**: 承認

### 背景
Anaconda base 環境に Pydantic v1 が入っている Mac 環境で `computed_field`（v2 専用）が ImportError を起こした。

### 決定
`computed_field` は使用せず、`__init__` 内で通常フィールドとして計算する。

### 根拠
- ユーザーの環境で venv 未有効化時にもわかりやすいエラーにしたい
- `computed_field` の利便性より互換性を優先

### 影響
- `item_hash` と `is_ai_related` は `__init__` で手動計算
- Pydantic v2 の `model_dump()` にこれらの値が含まれる（`computed_field` と同等の結果）

---

## ADR-003: 脅威分類 taxonomy を 4カテゴリから 7カテゴリに拡張

- **日付**: 2026-03-01
- **決定者**: /ba
- **ステータス**: 承認

### 背景
Phase 1 では AI-as-Target / AI-as-Weapon / AI-Enabled / AI-Adjacent の4軸で分類していたが、
以下の重要な脅威領域がカバーされていないことが判明した。

### 決定
以下の3カテゴリを追加し、計7軸の taxonomy とする。

1. **AI-Physical**: AI が制御する物理系システム（自動運転、産業ロボット、医療AIデバイス、ドローン等）への脅威。
   既存4カテゴリはデジタル空間完結だが、物理被害・生命安全リスクという質的に異なる結果を持つため独立カテゴリとする。

2. **AI-Supply-Chain**: モデルリポジトリ汚染・学習データポイズニング等、デプロイ前に仕込まれる脅威。
   AI-Enabled はフレームワーク CVE（稼働中の脆弱性）であり、Supply Chain（デプロイ前汚染）とは攻撃フェーズが異なる。

3. **AI-Agentic**: LLMエージェントがツール・外部APIを操作する構成を悪用した脅威。
   プロンプトインジェクションと重複するように見えるが、エージェントは「実行権限」を持つため被害規模・波及範囲が桁違いであり独立カテゴリとする。

### 根拠
- EU AI Act（2025年施行）が高リスクAIとして物理系AIを明示的に規定 → AI-Physical は規制対応の観点でも必須
- HuggingFace 等モデルハブの普及により Supply Chain 汚染リスクが現実の脅威に
- LLMエージェント（Claude, GPT-4 with tools, AutoGPT 等）の急速な普及により Agentic 脅威が急増中
- **AI-Privacy**（モデル逆転・メンバーシップ推定）は既存 AI-as-Target のキーワードセットに含まれるため独立カテゴリ化は見送り

### 影響
- `src/models/enums.py` の ThreatCategory enum に 3値追加が必要（`/sde` への依頼事項）
- 各カテゴリのキーワードセット設計が必要（`/sde` との協議事項）
- BR-2 の成功指標を「4軸」から「7軸」に更新済み
- 将来の情報収集ソース選定において、AI-Physical / AI-Supply-Chain 特化ソースの調査が必要

---

## ADR-005: Webダッシュボードの技術スタックに Streamlit + Plotly を採用

- **日付**: 2026-03-02
- **決定者**: /sde
- **ステータス**: 承認

### 背景

BR-4（Webダッシュボード）の実装技術スタックを選定する必要があった。
ADR-004 で /ba がページ構成と UX 要件を定義済み。

### 決定

**Streamlit** + **Plotly** を採用する。
- エントリポイント: `src/dashboard/app.py`（概要ページ）
- マルチページ: `src/dashboard/pages/1_脅威一覧.py`, `2_脅威詳細.py`
- 起動: `python -m src.main dashboard`（`streamlit run` をラップ）

### 根拠

- `docs/architecture/system-design.md` に Streamlit が記載済みであり、プロジェクトの技術方針と一致
- JavaScript/CSS の記述不要。Python のみで完結する
- Plotly は Streamlit とネイティブ統合。ドーナツ・棒・折れ線グラフが数行で実装可能
- `st.query_params["id"]` を活用することで `/2_脅威詳細?id=<ID>` の一意URLを実現（BR-4-3 の要件を満たす）
- FastAPI + Jinja2 も検討したが、ローカル単一ユーザー前提（ADR-002）では Streamlit のシンプルさが勝る

### 影響

- `requirements.txt` に `streamlit>=1.32.0`, `plotly>=5.18.0` を追加
- `src/storage/database.py` に `get_item_by_id()`, `get_adjacent_ids()`, `search_items()`, `get_daily_trend()` を追加
- `src/main.py` に `dashboard` サブコマンドを追加
- マルチユーザー対応が必要になった際は FastAPI への移行を検討（ADR-002 の方針と整合）

---

## ADR-004: Webダッシュボードのページ構成と設計方針

- **日付**: 2026-03-01
- **決定者**: /ba
- **ステータス**: 承認

### 背景

BR-4（Webダッシュボード）を実装するにあたり、ページ構成と各ページの責務を明確化する必要があった。
ユーザーペルソナが「CISO（全体把握）」「CTIアナリスト（詳細調査）」「AI/MLエンジニア（個別確認）」と異なるため、
一画面では全ニーズを満たせない。

### 決定

以下の3ページ構成（+将来のトレンドページ）とする。

1. **概要ダッシュボード（ホーム）**: KPIカード + 4種類のグラフで全体俯瞰
2. **脅威一覧**: フィルタ・検索・ソート付きテーブル。調査の起点
3. **脅威詳細**: 1件ずつの全情報表示。前後ナビゲーションで連続調査が可能

### 根拠

- CISOは数分でリスク把握を完了したい → 概要ページに集約
- CTIアナリストは毎朝数十件をスキャンしてから数件を深掘りする → 一覧→詳細の導線
- 詳細ページのURLを一意にすることで、SlackやメールでURLを共有してチーム内で脅威を議論できる
- トレンドページはV1での必須度が低いため「V2以降オプション」とした

### 影響

- `/sde` はこの3ページ構成で実装を開始する
- 詳細ページのURL設計: `/threats/{id}` 形式を推奨（/sde の判断）
- テーブルの前後ナビゲーションにはソート・フィルタ条件を引き継ぐことが望ましい（UX上の重要事項）

---

## ADR-006: 産業セクター区分に CISA/NISC/NIS2 共通 12 セクターを採用

- **日付**: 2026-03-02
- **決定者**: /ba
- **ステータス**: 承認

### 背景

BR-9（産業セクター別脅威ダッシュボード）の実装にあたり、どの産業セクター分類標準を採用するかを決定する必要があった。現在 `AffectedSector` enum は 12値（ENERGY, FINANCIAL, HEALTHCARE 等）を定義済みだが、国際標準との整合性は明示されていなかった。

また、このプロダクトを Webサービスとして公開する場合、日本・米国・欧州のユーザーに対応できる汎用的なセクター区分が必要。

### 選択肢として検討した標準

| 標準 | 策定機関 | セクター数 | 特徴 |
|---|---|---|---|
| CISA 重要インフラセクター | 米国国土安全保障省 | 16 | サイバーセキュリティ文脈で最も権威あり |
| NISC 重要インフラ分野 | 日本内閣サイバーセキュリティセンター | 15 | 日本ユーザーに対応 |
| NIS2 Annex I (Essential) | EU欧州委員会 | 11 | 2024年10月施行。EU規制対応に必須 |
| GICS | S&P / MSCI | 11 | 金融業界標準。脅威インテリジェンス文脈には不向き |

### 決定

**CISA・NISC・NIS2 の3標準に共通して登場するセクターを基準に、12セクターを採用する。**

これは現在の `AffectedSector` enum（12値）と一致しており、既存実装との整合性を維持できる。

採用セクター:
1. **ENERGY** — CISA / NISC / NIS2 全て掲載
2. **FINANCIAL** — CISA / NISC / NIS2 全て掲載（銀行・証券・保険・金融市場統合）
3. **HEALTHCARE** — CISA / NISC / NIS2 全て掲載
4. **TELECOMMUNICATIONS** — CISA / NISC / NIS2 全て掲載（通信・デジタルインフラ）
5. **TRANSPORTATION** — CISA / NISC / NIS2 全て掲載（航空・鉄道・港湾・物流含む）
6. **GOVERNMENT** — CISA / NISC / NIS2 全て掲載（行政・緊急サービス統合）
7. **DEFENSE** — CISA（Defense Industrial Base）掲載。NIS2 Space はここに含める
8. **TECHNOLOGY** — CISA（IT）/ NIS2（ICT Service Management, Digital Infrastructure）掲載
9. **MANUFACTURING** — CISA（Critical Manufacturing）/ NIS2 Annex II / NISC（化学・石油含む）
10. **EDUCATION** — NIS2 Annex II（Research）相当。攻撃頻度が高く独立カテゴリ化を維持
11. **GENERAL** — 小売・食品・農業・水道・その他（CISA: Commercial Facilities, Food & Agriculture, Water 等を統合した汎用カテゴリ）
12. **UNKNOWN** — セクター未特定

### 根拠

- **3標準の共通部分を採用**: 特定国の規制に偏らず、グローバルに通用するセクター区分となる
- **既存実装との整合**: `AffectedSector` enum の 12値とほぼ一致しており、データモデル変更を最小化できる
- **サイバーセキュリティ特化**: GICS（金融業界）ではなく CISA ベースにすることで、脅威インテリジェンス文脈での意味合いが自然になる
- **ENISA 実データとの整合**: 2024年の実際の被害セクター上位（行政・交通・金融・製造）が全てカバーされている

### 将来の拡張候補（Phase 3以降）

以下はMVPでは `TRANSPORTATION` / `GENERAL` に統合するが、将来的に独立セクターとして分離を検討:
- **AUTOMOTIVE** — 自動車・自律走行。AI攻撃面として急拡大（Auto-ISAC活動中）
- **WATER** — 水道・廃水。CISA/NISC/NIS2 全てで独立セクター指定済み
- **SPACE** — 宇宙インフラ。NIS2 Annex I に追加。Space ISAC 設立済み（2019）

### 影響

- `src/models/enums.py` の `AffectedSector` enum の各値に日本語ラベル・スコープ定義を付加（`/sde` への依頼事項）
- ダッシュボードに「セクター別ビュー」を追加（BR-9-1〜BR-9-3）
- `classify_affected_sector()` 関数の実装品質確認と強化が必要（現在の自動分類がどの程度機能しているか）
- 将来的な多言語対応時に日本語セクター名の表示ラベルを整備する

---

## ADR-002: 初期ストレージに SQLite を採用

- **日付**: 2026-03-01
- **決定者**: /sde
- **ステータス**: 承認

### 背景
MVP 段階でのストレージ選定。

### 決定
プライマリストレージに SQLite を採用。PostgreSQL 等への移行パスは残す。

### 根拠
- 外部サーバー不要でセットアップが簡単
- 単一ユーザーでの利用には十分な性能
- SQL でのクエリ・集計が可能
- 将来の移行時は ORM 導入で吸収可能

### 影響
- 同時書き込みは制限される（単一ユーザー前提なら問題なし）
- Web UI でマルチユーザー対応する際は PostgreSQL 移行を検討
