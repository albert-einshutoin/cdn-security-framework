# Source AST と OpenAPI の差分

`compareSourceOpenApiContracts` は OpenAPI の `SecurityContractV1` と Source AST contract を、入力を変更せず比較します。正規化済みroute shapeを再利用し、path parameter名の違いを無視し、Finding Contract v1を重複排除して決定的順序で返します。

## Ruleとconfidence

- `SC-INVENTORY-001`（error / deterministic）: 静的に検出した実装route shapeが、完全なOpenAPI inventoryに存在しない。OpenAPI routes capabilityが不完全ならheuristic warningへ落とす。
- `SC-INVENTORY-003`（error / deterministic）: 宣言operationが、完全なSource route解析に存在しない。Source routes capabilityがpartial/unsupportedなら、未解決routeを不存在と断定せずheuristic warningへ落とす。
- `SC-INVENTORY-004`（error / deterministic）: 同じ正規化route shapeでSourceとOpenAPIのmethod setが異なる。どちらかのroutes capabilityが不完全ならheuristic warningへ落とす。
- `SC-AUTHN-005`（warning / high-confidence）: OpenAPIの明示public/authenticatedと、高confidenceなSourceの`Public`またはmapped Guard metadataが矛盾する。OpenAPIの複数authentication alternativeをAND集合へ平坦化しない。
- `SC-AUTHZ-001`（warning / high-confidence）: 明示設定した`declaredPrivilegedRoles`と、高confidenceなSource role metadataが異なる。route名やtag名からprivilegeを推測しない。

比較する両rootにはEvidenceが必要です。対応operationのFindingは双方のoperation evidenceを持ち、不存在Findingは存在するoperation evidenceと、不存在側のroot evidenceを組み合わせます。

## 証明しないもの

Source metadataの静的解析は、Guardの実動作、business authorization、BOLA安全性、dynamic route registration、未解決global prefix、runtime module compositionを証明しません。Guard不在をpublicとは扱いません。Source capabilityがpartialまたはauthentication confidenceがunknownなら、決定的なauthentication claimを出さず、不存在Findingをdowngradeします。
