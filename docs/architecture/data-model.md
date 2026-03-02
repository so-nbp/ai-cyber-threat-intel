# データモデル設計

> このドキュメントは `/sde` エージェントが維持管理する。
> 最終更新: 2026-03-01（初版）

## コアモデル: ThreatIntelItem

全ソースから収集されたデータはこのスキーマに正規化される。

### フィールド一覧

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| source | str | ✅ | ソース名（nvd, cisa_kev 等） |
| source_type | SourceType | ✅ | ソース種別 |
| source_id | str | ✅ | ソース側のID（CVE-XXXX等） |
| source_url | str | - | 原文URL |
| title | str | ✅ | タイトル |
| description | str | - | 説明文 |
| threat_category | ThreatCategory | ✅ | AI脅威分類 |
| severity | Severity | ✅ | 深刻度 |
| cvss_score | float | - | CVSSスコア（0.0-10.0） |
| confidence | ConfidenceLevel | ✅ | 情報の信頼度 |
| tags | List[str] | - | タグ |
| keywords | List[str] | - | キーワード |
| cve_ids | List[str] | - | 関連CVE |
| affected_products | List[AffectedProduct] | - | 影響を受ける製品 |
| references | List[ThreatReference] | - | 参考リンク |
| published_at | datetime | - | 公開日時 |
| collected_at | datetime | ✅ | 収集日時（自動） |
| item_hash | str | ✅ | 重複排除キー（自動計算） |
| is_ai_related | bool | ✅ | AI関連フラグ（自動計算） |

### 重複排除ロジック

```
item_hash = SHA256("{source}:{source_id}")[:16]
```

同じ `item_hash` が存在する場合は UPDATE（upsert）。

## 分類体系

### ThreatCategory（MITRE ATLAS ベース）

| 値 | 意味 | 判定キーワード例 |
|---|---|---|
| ai-as-target | AIシステムへの攻撃 | adversarial, prompt injection, jailbreak |
| ai-as-weapon | AIを悪用した攻撃 | deepfake, ai-generated malware |
| ai-enabled | AIインフラの脆弱性 | tensorflow, pytorch, langchain |
| ai-adjacent | AIエコシステムの脅威 | gpu cluster, cuda, vector database |
| traditional | AI非関連 | （上記に該当しない） |
| unknown | 未分類 | キーワード該当なし |

### Severity（CVSS準拠）

| 値 | CVSSスコア範囲 |
|---|---|
| critical | 9.0 - 10.0 |
| high | 7.0 - 8.9 |
| medium | 4.0 - 6.9 |
| low | 0.1 - 3.9 |
| info | 0.0 |
| unknown | スコアなし |

## SQLite テーブル

### threat_items

メインテーブル。`item_hash` にUNIQUE制約。
インデックス: source, threat_category, severity, published_at, collected_at, is_ai_related

### collection_runs

収集実行の監査ログ。ソース、開始/終了時刻、件数、成否を記録。

## 変更履歴

| 日付 | 変更内容 | 担当 |
|---|---|---|
| 2026-03-01 | 初版作成 | /sde |
