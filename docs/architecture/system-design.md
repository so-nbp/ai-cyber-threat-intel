# システム設計

> このドキュメントは `/sde` エージェントが維持管理する。
> 最終更新: 2026-03-01（初版）

## アーキテクチャ概要

```
┌─────────────────────────────────────────────────────┐
│                    CLI / Web UI                      │
│              (Click+Rich / Streamlit)                │
├─────────────────────────────────────────────────────┤
│                  Analysis Layer                      │
│            (trends.py, future: LLM)                  │
├─────────────────────────────────────────────────────┤
│                  Storage Layer                       │
│          (SQLite DB + JSON File Store)               │
├─────────────────────────────────────────────────────┤
│               Normalization Layer                    │
│  (ThreatIntelItem + classify_threat_category())     │
├─────────────────────────────────────────────────────┤
│               Collection Layer                       │
│  ┌─────┐ ┌────────┐ ┌────────┐ ┌──────┐ ┌───┐ ┌───┐│
│  │ NVD │ │CISA KEV│ │ GitHub │ │arXiv │ │RSS│ │OTX││
│  └─────┘ └────────┘ └────────┘ └──────┘ └───┘ └───┘│
└─────────────────────────────────────────────────────┘
```

## ディレクトリ構成

```
ai-cyber-threat-intel/
├── .claude/commands/        ← エージェント定義（/ba, /sde）
├── docs/                    ← プロジェクトドキュメント
│   ├── business/            ← ビジネス分析（/ba が管理）
│   ├── requirements/        ← 要件定義（/ba と /sde で共有）
│   ├── architecture/        ← 設計ドキュメント（/sde が管理）
│   └── decisions/           ← 意思決定記録（ADR）
├── src/
│   ├── collectors/          ← ソース別コレクター
│   │   └── base.py          ← BaseCollector 抽象クラス
│   ├── models/              ← Pydantic データモデル
│   ├── storage/             ← DB + ファイルストレージ
│   ├── analysis/            ← 分析ロジック
│   ├── utils/               ← 設定、ログ
│   ├── main.py              ← CLI エントリポイント
│   └── scheduler.py         ← 日次スケジューラ
├── config/                  ← YAML 設定ファイル
├── tests/                   ← テスト
├── PROJECT.md               ← プロジェクト全体定義
├── CLAUDE.md                ← Claude Code 設定
└── README.md                ← セットアップ手順
```

## データフロー

1. **収集**: 各 Collector が外部 API/フィードからデータ取得
2. **正規化**: 全データを `ThreatIntelItem` スキーマに変換
3. **分類**: `classify_threat_category()` で AI 脅威カテゴリを付与
4. **保存**: SQLite に upsert + JSON ファイルに生データ保存
5. **分析**: 統計集計、日次サマリー生成
6. **表示**: CLI `show` / `status` / `summary` で出力

## コレクター追加方法

1. `src/collectors/` に新ファイルを作成
2. `BaseCollector` を継承し `collect()` メソッドを実装
3. `src/collectors/__init__.py` の `COLLECTOR_REGISTRY` に登録
4. `config/settings.example.yaml` に設定セクションを追加
5. テストを追加

## 設計原則

- **障害分離**: 1 コレクターの失敗が他に波及しない
- **べき等性**: 同じデータを再収集しても重複しない（upsert）
- **拡張性**: 新ソース追加はコレクター1ファイル + レジストリ登録のみ
- **型安全**: Pydantic v2 による入力検証
- **監査性**: collection_runs テーブルで全収集履歴を記録
