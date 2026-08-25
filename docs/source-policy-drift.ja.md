# Source ASTとPolicyのDrift

Validated Policyを`projectPolicyToAllowedSurface`で投影した後、`compareSourcePolicyContracts`を使います。正規化済み`source-ast` Contract、Project-level Evidence、Allowed Surface Model、選択Target（`aws`または`cloudflare`）を渡します。

Comparatorは`SC-EXPOSURE-004/005`、`SC-INVENTORY-005`、`SC-AUTHN-006`、`SC-AUTHZ-002`をFinding Contract v1として安定順序で返します。ExactまたはDefinitely CoveredなRouteだけをDeterministic Findingの根拠にし、Prefix、Partial、Unsupported、UnknownはWarningへ落とすか、安全に比較できなければ省略します。Monitor ModeでMethodが現在Blockされるとは判定しません。

Source Decorator Metadataが証明するのは、設定済みSymbolと静的引数を検出したことだけです。Guard動作、Global Guardの有無、Role Enforcement、Application Securityは証明しません。Dynamic Route、Partial Project Graph、Runtime Prefix、設定外Custom Wrapper、Runtime Route Discoveryは比較対象外です。
