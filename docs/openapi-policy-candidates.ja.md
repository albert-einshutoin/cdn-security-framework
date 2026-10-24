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

## Next.jsのバージョンに応じた仮想パッチ

applicationのmanifestとnpm lockfileを両方指定すると、同じCandidateへ確認済みの
バージョン別controlを追加できます。

```bash
npx cdn-security openapi generate-policy \
  --input openapi.yaml --profile balanced \
  --package-json package.json --package-lock package-lock.json \
  --deployment self-hosted --out policy/next.candidate.yml
npx cdn-security build --policy policy/next.candidate.yml --target aws --out-dir dist/next-aws
```

初期catalog `nextjs-middleware-v1`は**CVE-2025-29927だけ**を扱います。依存全体の
脆弱性監査や最新advisory feedではありません。直接の本番用`next`宣言をnpm
lockfile v2/v3と照合し、root identityと依存宣言の一致を確認します。public npmの
`next` tarballに解決された安定版の確定バージョンだけを扱い、alias、local/workspace
link、private registry、prerelease、解決元の欠落、dev専用Nextはunknownにします。
inputはworkspace内の通常のUTF-8 fileで各8 MiB以下に限定します。package scripts、
install、network照会、module探索は行いません。

`--deployment`はEdgeのproviderとは独立した**originの実行方式**です。

| origin | 影響を受けるNext.js版の場合 |
| --- | --- |
| `self-hosted`（`next start`またはstandalone） | `request.block.header_present: [x-middleware-subrequest]`を生成。 |
| `static-export` | middleware runtimeが存在しないため、このCVEは対象外と報告。 |
| `unknown`（既定） | `APPLICATION_ANALYSIS_UNKNOWN`で生成停止。fileを書きません。 |

[公式advisory](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)の
対象範囲は`>=11.1.4 <12.3.5`、`>=13.0.0 <13.5.9`、`>=14.0.0 <14.2.25`、
`>=15.0.0 <15.2.3`です。範囲外は**このCVE**のpatchを出さないだけで、一般的な
安全性を保証しません。managed hostingを自動判定せず、未対応の実行方式は
安全だと推測せず`unknown`を使います。

AWS CloudFront FunctionsとCloudflare Workersの両方で、空値も含む対象headerの
存在をCORS preflightやorigin転送より先に拒否します。OpenAPIにないframework
routeも含めて全pathへ適用します。application inputがある場合、API仕様だけでは
画面・asset・内部routeの全体を表せないため、OpenAPI由来のglobal method・必須
header・数値limitは省略し、選択profileのbaselineを保持します。他のRecommendationは
review用metadataへ残します。採用前に画面・asset・認証に対するprofileのlimitと
CSPを確認してください。

sidecarの`application`には両inputのraw digest、指定deployment、catalogの対象範囲、
解決版、判断、公式sourceを記録します。不正inputやmanifest/lock不一致は
`APPLICATION_INPUT_INVALID`、解析未確定は生成停止です。digestが結び付けるのは
指定fileで、実際のinstall内容や稼働deploymentの証明ではありません。恒久対応は
Next.jsの更新です。仮想patchの効果には全external routeへのenforce適用とoriginへの
直接アクセス防止が必要で、monitor modeは記録だけを行います。

自己host originの前にCloudflareを置く場合は`capabilityFindings`も確認してください。
balanced profileにはCloudflareで完全に表せないAWS managed-WAF mappingがあり、
`build --target cloudflare`が拒否する場合があります。provider用にCandidateのWAF
設定を確認・修正してからbuildします。このheader controlはWAF全体の同等性や
account entitlementを証明しません。

programmatic APIの`generatePolicyCandidate`も、optionへ
`application: { packageJson: manifestText, packageLock: lockText, deployment: 'self-hosted' }`
を渡せます。`application`を省略すると従来のOpenAPI専用mappingを保持します。
解析未確定はcode `APPLICATION_ANALYSIS_UNKNOWN`、不正inputは
`APPLICATION_INPUT_INVALID`のErrorになります。APIは渡された文字列だけを解析し、
fileを読みません。

## 継続advisory確認

`cdn-security advisory check --package-json package.json --package-lock
package-lock.json --deployment self-hosted`は、確定した直接の本番用Next.js版を
GitHubの公開・審査済みnpm advisoryで照会します。結果はJSONで、GHSA/CVE IDと
`mitigation-candidate-available`（このcatalogで生成可能）、`unassessed`
（このcatalogに緩和策なし）、`not-applicable`（このCVEと実行方式の組合せのみ対象外）を
区別します。候補は有効Policy・CDNへの配備や実際の防御を証明しません。

照会先は固定のGitHub APIです。最大100件・4 MiB・10秒で、続きのページ、取得失敗、
不正応答、版または実行方式の不明を成功扱いしません。終了コードは対象なし`0`、
対応が必要`2`、判断不能または不正入力`1`です。対象範囲は直接の本番用`next`と
GitHub審査済みの公開advisoryに限られます。結果の時刻・入力digestは実際の稼働版や
CDN適用状態の証拠ではありません。恒久対応はadvisoryに沿ったNext.jsの更新です。

## 決定性とmetadata

YAMLとJSON sidecarには時刻やabsolute pathを含めません。同じinput byteと同じoptionで
再実行するとbyte-identicalな出力になり、正規化対象fieldの順序はCandidate Policyへ
影響しません。sidecarにはraw source digest、Security IR digest、Candidate digest、
generator version、採用・省略Recommendation、target capability findingを記録します。
raw credential、request body、推測したsecret値は記録しません。
