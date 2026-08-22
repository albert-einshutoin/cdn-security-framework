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
| Resource limits | `SC-LIMIT` | `SC-LIMIT-001`: 有限要件を下回るRequest Limit |
| Request validation | `SC-REQUEST` | `SC-REQUEST-001`: 宣言済み必須HeaderをEdgeで確認しない |
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

ContractとDrift Comparatorは`cdn-security-framework/contract`からExportします。

## OpenAPIとPolicyのDrift Rule

`compareSecurityContracts({ declared, allowed, target }, options)`は、正規化済みの
OpenAPI Security Contractと実効Allowed Surface Modelを比較します。AWSとCloudflareでは
Policy Capabilityの実効範囲が異なるため、Targetは必須です。Monitor Modeは`actual`へ
保持し、Enforce ModeでのみBlockするControlをEnforce時と同じErrorにはしません。

| Rule | Severity | Deterministicな条件 |
| --- | --- | --- |
| `SC-EXPOSURE-001` | Error、MonitorではWarning | 実効Method Surfaceが完全なRoute宣言にないMethodを許可する。MonitorではMethod拒否を記録するがRequestを通す。 |
| `SC-EXPOSURE-002` | Error、MonitorではWarning | OpenAPI Operationが実効Method集合の外にある。 |
| `SC-INVENTORY-002` | Error、Route InventoryがPartialならWarning | Exact Policy Routeと同ShapeのOpenAPI Routeがない。Parameter名はShape一致に影響しない。 |
| `SC-EXPOSURE-003` | Warning | Broad Prefix Ruleが宣言Surfaceを超える可能性がある。Unknown overlapをErrorへ昇格しない。 |
| `SC-AUTHN-001` | Warning | 認証必須OperationをEnforceするEdge Auth Gateがない。 |
| `SC-AUTHN-002` | Error | 明示Public OperationをEnforce済みEdge Auth Gateが確実に覆う。 |
| `SC-AUTHN-003` | Warning | CredentialのKind、Location、Nameが確実に非互換である。 |
| `SC-AUTHN-004` | Info | Auth互換性を証明できない。 |
| `SC-LIMIT-001` | Error、Monitorまたは条件付きCORSプリフライトではWarning | 実効Limitが有限のExactまたはUpper-bound Recommendation未満である。 |
| `SC-LIMIT-002` | Warning | 実効Limitが正の有限Recommendationの`materiallyBroaderRatio`倍を超える。既定値は`2`で、Recommendationには既定Safety Marginが既に含まれる。 |
| `SC-REQUEST-001` | Info | OpenAPI必須HeaderをEdgeで必須化していない。 |
| `SC-REQUEST-002` | Error、Monitorまたは条件付きCORSプリフライトではWarning | 完全なOpenAPI Parameter ContractにないHeaderをEdgeが要求する。Runtime Defaultも実効値に含む。 |
| `SC-REQUEST-003` | Info | OpenAPIはRequest Content Typeを宣言するが、現行Policy SchemaにはEdge Content-Type Allowlistがない。 |

### Authentication Compatibility

OpenAPI AlternativeはOR Branchのまま、Alternative内のSchemeはAND要件のまま扱います。
完全なAlternativeを1つ満たす場合だけCompatibleと判定します。

| OpenAPI Scheme | Edge Gate | 判定 |
| --- | --- | --- |
| API Key | HeaderのLocationとNameが同じStatic Token | Compatible |
| API Key | Kind、Location、Nameのいずれかが異なる | Incompatible |
| HTTP Basic | Basic Auth | Compatible |
| HTTP Basic | その他のSupported Gate | Incompatible |
| Bearer | JWT | Unknown。BearerからJWTを推論しない |
| Unsupportedまたは不完全なScheme | 任意 | Unknown |

すべてのAuthentication Findingは選択TargetのEdge Contractだけを対象とし、Application
Authenticationが存在しないとは判定しません。Expected/Actual EvidenceにはCredentialの
Metadataだけを含め、Credential Valueは含めません。

### False Positive境界とRemediation

- Partial、Unsupported、Pattern、UnknownのRoute RelationからDeterministic Errorを
  生成しません。Policyを厳格化する前にEvidenceを確認し、ContractをCompleteにします。
- Recommendationが0の場合はBroad-limit Warningを出しません。PartialまたはUnknownの
  Request EstimateからLimit Errorを生成しません。
- Header名はCase-insensitiveで比較します。`SC-REQUEST-001`は意図したApplication-only
  Validationの場合があります。`SC-REQUEST-002`はEdge要件をClient向けに宣言するか削除します。
- Policy Schemaと選択TargetがCapabilityを提供するまでは、Content-Type Validationを
  Application側で維持します。
