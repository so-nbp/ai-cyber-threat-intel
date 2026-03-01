# システム要件一覧

> このドキュメントは `/sde` エージェントが維持管理する。
> ビジネス要件（`docs/requirements/business-requirements.md`）を技術仕様に変換したもの。
> 最終更新: 2026-03-01（初版）

## SR-1: パイプラインアーキテクチャ ✅

| 項目 | 内容 |
|---|---|
| 対応BR | BR-1, BR-2 |
| 仕様 | 収集 → 正規化 → 分類 → 保存 → 分析/表示 |
| 実装状態 | 完了 |

## SR-2: 統一データモデル ✅

| 項目 | 内容 |
|---|---|
| 対応BR | BR-1, BR-2, BR-3 |
| 仕様 | 全ソースのデータを `ThreatIntelItem` スキーマに正規化 |
| 技術選定 | Pydantic v2（`computed_field` 不使用） |
| 重複排除 | `SHA256(source:source_id)[:16]` |
| 実装状態 | 完了（taxonomy v2: 7カテゴリ対応済み） |
| 設計詳細 | `docs/architecture/data-model.md` |

**脅威分類 taxonomy（7軸）:**

| カテゴリ値 | enum 定数 | キーワードセット | 実装状態 |
|---|---|---|---|
| `ai-as-target` | `AI_AS_TARGET` | `AI_TARGET_KEYWORDS` | ✅ |
| `ai-as-weapon` | `AI_AS_WEAPON` | `AI_WEAPON_KEYWORDS` | ✅ |
| `ai-enabled` | `AI_ENABLED` | `AI_ENABLED_KEYWORDS` | ✅ |
| `ai-adjacent` | `AI_ADJACENT` | `AI_ADJACENT_KEYWORDS` | ✅ |
| `ai-physical` | `AI_PHYSICAL` | `AI_PHYSICAL_KEYWORDS` | ✅ |
| `ai-supply-chain` | `AI_SUPPLY_CHAIN` | `AI_SUPPLY_CHAIN_KEYWORDS` | ✅ |
| `ai-agentic` | `AI_AGENTIC` | `AI_AGENTIC_KEYWORDS` | ✅ |
| `traditional` | `TRADITIONAL` | — | ✅ |
| `unknown` | `UNKNOWN` | — | ✅ |

## SR-3: プラグイン型コレクター ✅

| 項目 | 内容 |
|---|---|
| 対応BR | BR-1 |
| 仕様 | `BaseCollector` 抽象クラスを継承、ソース追加が容易 |
| 非同期 | aiohttp + asyncio |
| 障害分離 | 1ソースの失敗が他に波及しない |
| 実装状態 | 完了（6コレクター） |

## SR-4: ストレージ ✅

| 項目 | 内容 |
|---|---|
| 対応BR | BR-1, BR-3 |
| プライマリ | SQLite（構造化クエリ、統計、upsert） |
| セカンダリ | JSON ファイル（生データ保存、再処理用） |
| 実装状態 | 完了 |

## SR-5: CLI インターフェース ✅

| 項目 | 内容 |
|---|---|
| 対応BR | BR-3 |
| 技術選定 | Click + Rich |
| コマンド | collect, show, status, summary, sources, init, schedule |
| 実装状態 | 完了 |

## SR-6: Web ダッシュボード 📋

| 項目 | 内容 |
|---|---|
| 対応BR | BR-4 |
| 技術選定（候補） | Streamlit |
| 画面 | 統計サマリー、トレンドグラフ、アイテム一覧、検索 |
| 実装状態 | 未着手 |

## SR-7: エクスポート機能 📋

| 項目 | 内容 |
|---|---|
| 対応BR | BR-5 |
| フォーマット | CSV, JSON, Markdown |
| 起動方法 | CLI `show --export csv` またはダッシュボードからダウンロード |
| 実装状態 | JSON のみ（`show -j`）。CSV, Markdown 未対応 |

## SR-8: テスト ✅（継続改善）

| 項目 | 内容 |
|---|---|
| フレームワーク | pytest + pytest-asyncio |
| 現状 | 15テスト通過（models のみ） |
| 目標 | カバレッジ 80% 以上 |

## 技術スタック

| 区分 | 技術 |
|---|---|
| 言語 | Python 3.10+ |
| HTTP | aiohttp |
| バリデーション | Pydantic v2 |
| CLI | Click + Rich |
| DB | SQLite（aiosqlite） |
| スケジューラ | APScheduler |
| ログ | structlog |
| テスト | pytest, pytest-asyncio |
| Web UI（予定） | Streamlit |
| API（予定） | FastAPI |
