# OpenAPI Policy Candidate

`cdn-security openapi generate-policy`は、人間がレビューするためのPolicy
Candidateと、決定的なmeta sidecarを生成します。`policy/security.yml`の読込・
merge・上書きは行わず、生成物をdeployすることもありません。

## Mapping Contract

| OpenAPI / Recommendation | Policy Candidate | 規則 |
| --- | --- | --- |
| operation methodの和集合 | `request.allow_methods` | globalに採用します。現行route matcherはOpenAPI pathを完全一致で表現できないため、route別method制約は省略として報告します。 |
| 全operationで必須のheader | `request.block.header_missing` | 共通部分を選択profileのbaselineへ追加します。route固有の必須headerは省略として報告します。 |
| 有限なquery・URI limit Recommendation | metaの`omittedRecommendations` | OpenAPIは未宣言query parameterを禁止しないため、宣言済みparameterを閉じた上限とみなさず、選択profileのlimitを保持します。 |
| route固有のmethodまたはheader | metaの`omittedRecommendations` | Policyのpath prefixは子pathにも一致するため、OpenAPIの完全一致pathより広くなります。 |
| request content type、body size、parameter制約 | metaの`omittedRecommendations` | 現行Policy schemaに同等のrequest controlがありません。架空fieldや近似controlは出力しません。 |
| Bearer、OAuth2、API key等の認証宣言 | metaの`omittedRecommendations` | 将来の明示mapping contractですべてのPolicy値が与えられない限りRecommendationに留めます。JWT issuer、audience、JWKS、algorithm、secretは推測しません。 |

選択したbuilt-in profileは、レビュー済みのbaseline controlを提供します。ただし、
例示routeにはapplication固有のpath・認証仮定があるため削除します。OpenAPI由来の
fieldは、上表のmapping対象だけを置き換えます。
limit Recommendationは省略として報告し、選択profileの値を保持します。将来、追加query
inputが禁止されることを証明できるcontractが導入された場合にだけ適用対象にできます。

## 生成とレビュー

```bash
npx cdn-security openapi generate-policy \
  --input openapi.yaml \
  --profile balanced \
  --out policy/openapi.candidate.yml
```

同時に`policy/openapi.candidate.meta.json`を生成します。既存出力がある場合は失敗し、
pathを確認したうえでのみ`--force`を使います。両fileは`--workspace-root`（既定は
current directory）内に限定され、OpenAPI inputや参照source fileを置換できません。

active Policyへ設定をコピーする前にCandidateとsidecarをレビューしてください。特に
`omittedRecommendations`と`capabilityFindings`を確認します。その後、Candidateを
明示指定して検証・buildします。

```bash
npm run lint:policy -- policy/openapi.candidate.yml
npx cdn-security build --policy policy/openapi.candidate.yml --out-dir dist/candidate
```

Candidateのbuildはlocal artifactを生成するだけで、Policyのapplyやdeployは行いません。

## 決定性とmetadata

YAMLとJSON sidecarには時刻やabsolute pathを含めません。同じinput byteと同じoptionで
再実行するとbyte-identicalな出力になり、正規化対象fieldの順序はCandidate Policyへ
影響しません。sidecarにはraw source digest、Security IR digest、Candidate digest、
generator version、採用・省略Recommendation、target capability findingを記録します。
raw credential、request body、推測したsecret値は記録しません。
