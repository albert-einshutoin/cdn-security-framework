# Findingリファレンス

Security CompilerのFindingは内部`SecurityFindingV1` Contractと、安定した
`SC-<CATEGORY>-<3桁>`形式のRule IDを使います。

## Rule ID allocation

| Category | Prefix | Example |
| --- | --- | --- |
| Inventory drift | `SC-INVENTORY` | `SC-INVENTORY-001`: Sourceにのみ存在するRoute |
| Exposure | `SC-EXPOSURE` | `SC-EXPOSURE-001`: 未宣言MethodをPolicyが許可 |
| Authentication | `SC-AUTHN` | `SC-AUTHN-001`: Authentication Contract mismatch |
| Authorization | `SC-AUTHZ` | `SC-AUTHZ-001`: Authorization Contract mismatch |
| Resource limits | `SC-LIMIT` | `SC-LIMIT-001`: 不要に広いRequest limit |
| Misconfiguration | `SC-MISCONFIG` | `SC-MISCONFIG-001`: Security設定の不整合 |
| Governance | `SC-GOVERNANCE` | `SC-GOVERNANCE-001`: 必要なReview evidenceの欠落 |
| Runtime evidence | `SC-RUNTIME` | `SC-RUNTIME-001`: 観測されたContract drift候補 |

各Prefixの`001`〜`099`はv1組み込みRule、`100`〜`899`は将来の組み込みRule、
`900`〜`999`はLocal Rule用に予約し、Core Compilerからは出力しません。公開済みIDを
再利用してはなりません。

## Stability and safety

- `instanceId`はRule ID、正規化Route、Canonical Evidence IdentityのSHA-256
  Digestです。EvidenceにはURI、Content Digest、Analyzer、宣言Capability、Completenessが
  必須です。絶対File System Pathには明示的なWorkspace Rootを要求し、そこからの
  相対URIとして保存します。Message文言、
  Evidence順序、Timestamp、Workspace位置には依存しません。
- FindingはSeverity、Rule ID、Path、Method、Instance IDの順に並べます。
- SensitiveなObject Key、Authorization値、Bearer値、Cookie、API Key、URL Query値は
  Findingを返す前にRedactします。
- Confidence値は[ADR 0003](adr/0003-security-contract-trust-model.ja.md)に従い、
  `deterministic`、`high-confidence`、`heuristic`を使います。

このContractはv1では内部専用で、PackageのPublic APIからExportしません。具体的な
Rule実装は後続のSecurity Compiler Phaseで追加します。
