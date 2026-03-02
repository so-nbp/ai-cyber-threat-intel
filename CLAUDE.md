# CLAUDE.md

## プロジェクト概要

AI×サイバーセキュリティに特化した脅威インテリジェンス収集・分析基盤。
詳細は **PROJECT.md** を参照。

## エージェント体制

このプロジェクトでは2つの専門エージェントが役割分担して開発を進める。

| コマンド | 役割 | 管轄ドキュメント |
|---|---|---|
| `/ba` | ビジネスアナリスト — 市場分析・要件定義・ビジネス戦略 | `docs/business/`, `docs/requirements/business-requirements.md` |
| `/sde` | ソフトウェアデザインエンジニア — 設計・実装・テスト | `docs/requirements/system-requirements.md`, `docs/architecture/`, `src/` |

### エージェント間の連携ルール

- `/ba` はビジネス要件を定義し、`docs/requirements/business-requirements.md` に記載する
- `/sde` はビジネス要件を読み取り、`docs/requirements/system-requirements.md` に技術仕様として変換してから実装する
- ビジネス判断が必要な場面では `/sde` は実装を保留し、`/ba` への相談を促す
- 技術判断が必要な場面では `/ba` は仕様策定を保留し、`/sde` への相談を促す
- 重要な意思決定は `docs/decisions/DECISIONS.md` に ADR として記録する

## ドキュメント構成

```
PROJECT.md                              ← プロジェクト全体定義（Why / What）
CLAUDE.md                               ← このファイル（開発ルール）
docs/
├── business/                           ← /ba が管理
│   ├── market-analysis.md              ← 市場・競合分析
│   ├── user-personas.md                ← ターゲットユーザー像
│   └── monetization.md                 ← 収益化戦略
├── requirements/                       ← /ba と /sde が共同管理
│   ├── business-requirements.md        ← ビジネス要件一覧（/ba が管理）
│   └── system-requirements.md          ← システム要件一覧（/sde が管理）
├── architecture/                       ← /sde が管理
│   ├── system-design.md                ← システム設計
│   └── data-model.md                   ← データモデル設計
└── decisions/
    └── DECISIONS.md                    ← 意思決定記録（ADR）
```

## 開発ルール

### 言語・環境
- Python 3.10+
- 型ヒント（type hints）を全ての関数・メソッドに付与する
- Pydantic v2 を使用。`computed_field` は使わない（ADR-001）

### コードスタイル
- import は `from __future__ import annotations` を先頭に置く
- 非同期処理は `aiohttp` / `asyncio` を使用
- エラーハンドリング: 各コレクターは例外を握りつぶさず、BaseCollector の run() で統一的にキャッチ
- 1つのソースの失敗が他のソースの収集を阻害してはならない

### テスト
- テストは `tests/` に配置
- pytest + pytest-asyncio を使用
- コード変更後は `python -m pytest tests/ -v` で全テスト通過を確認
- モックを使いすぎない。コアロジックは実際のデータで検証する

### Git
- コミットメッセージは日本語
- 例: `showコマンドにCSVエクスポート機能を追加`

### データモデル変更時の注意
- `ThreatIntelItem` を変更したら以下も確認:
  - `src/storage/database.py` の SCHEMA_SQL とマッピング
  - `tests/test_models.py`
  - `docs/architecture/data-model.md`

### 設定・シークレット
- API キーは `config/settings.yaml` または環境変数（`ACTI_` プレフィックス）
- シークレットをコードにハードコードしない
