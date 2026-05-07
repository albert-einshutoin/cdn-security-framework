# IaC 連携（Terraform / CloudFormation / CDK / WAF）

このドキュメントでは、生成された **`dist/edge/`** と **`dist/infra/`** を Terraform、AWS CloudFormation、AWS CDK でどう使うかを説明します。

---

## 概要

`npx cdn-security build` のあと:

| 出力 | 用途 |
|------|------|
| **dist/edge/viewer-request.js** | CloudFront Function (Viewer Request) |
| **dist/edge/viewer-response.js** | CloudFront Function (Viewer Response) |
| **dist/edge/cloudflare/index.ts** | Cloudflare Worker（`--target cloudflare` でビルドした場合）。出力は TypeScript。Wrangler がデプロイ時にコンパイルする。Wrangler を使わない場合は TypeScript ビルド環境が必要。 |
| **dist/infra/waf-rules.tf.json** | Terraform JSON: WAFv2 rule group / Web ACL resources。ポリシーに `firewall.waf` がある場合に生成。 |
| **dist/infra/waf-cloudformation.json** | AWS CloudFormation: `AWS::WAFv2::*` リソース。`emit-waf --format cloudformation` で生成。 |

---

## Terraform: CloudFront Functions（Edge）

生成された JS を `file()` で参照し、`cdn-security build` をやり直したときに Terraform が変更を検知できるようにします。

### Viewer Request / Viewer Response

```hcl
# パスは Terraform 設定からの相対（または path.root を使用）
locals {
  edge_dir = "${path.module}/dist/edge"
}

resource "aws_cloudfront_function" "viewer_request" {
  name    = "viewer-request"
  runtime = "cloudfront-js-1.0"
  comment = "Generated from security.yml"
  publish = true
  code    = file("${local.edge_dir}/viewer-request.js")
}

resource "aws_cloudfront_function" "viewer_response" {
  name    = "viewer-response"
  runtime = "cloudfront-js-1.0"
  comment = "Generated from security.yml"
  publish = true
  code    = file("${local.edge_dir}/viewer-response.js")
}

# ディストリビューションのデフォルトキャッシュビヘイビアにアタッチ
resource "aws_cloudfront_distribution" "main" {
  # ...
  default_cache_behavior {
    # ...
    viewer_protocol_policy = "redirect-to-https"
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.viewer_request.arn
    }
    function_association {
      event_type   = "viewer-response"
      function_arn = aws_cloudfront_function.viewer_response.arn
    }
  }
}
```

### Lambda@Edge (Origin Request)

`dist/edge/origin-request.js` を生成している場合は、zip にして `aws_lambda_function` の `filename` または `s3_*` で指定し、CloudFront の origin request にアタッチします。

---

## Terraform: WAF（Infra）

ポリシーに **`firewall.waf`** セクションがあると、ビルドで **`dist/infra/waf-rules.tf.json`**（Terraform JSON）が出力されます。最も単純な production path は、このファイルを CloudFront distribution を管理している Terraform root にコピーまたは生成し、生成された Web ACL ARN を distribution から参照する形です。

### 推奨レイアウト

```text
infra/
  main.tf
  cdn-security.auto.tf.json   # dist/infra/waf-rules.tf.json からコピー
```

ビルドしてコピー:

```bash
EDGE_ADMIN_TOKEN=replace-with-a-deploy-secret npx cdn-security build
cp dist/infra/waf-rules.tf.json infra/cdn-security.auto.tf.json
```

その後、生成された Web ACL を CloudFront distribution にアタッチします。生成リソース名には policy の `project` を sanitize した値が入ります。`project: example-cdn-security` の場合、Web ACL resource name は `aws_wafv2_web_acl.example_cdn_security` です。

```hcl
resource "aws_cloudfront_distribution" "main" {
  # ...

  web_acl_id = aws_wafv2_web_acl.example_cdn_security.arn

  default_cache_behavior {
    # ...
  }
}
```

既存 Web ACL を別で管理している場合は、`npx cdn-security build --rule-group-only` を実行し、手書きの `aws_wafv2_web_acl` から生成 rule group を参照してください。生成 JSON は Web ACL と同じ Terraform state に置く必要があります。そうでないと Terraform から直接参照できません。

---

## CloudFormation: AWS WAFv2

エッジコードを再生成せず AWS CloudFormation テンプレートだけを生成できます。

```bash
npx cdn-security emit-waf --target aws --format cloudformation
```

このコマンドは `dist/infra/waf-cloudformation.json` を出力します。テンプレートには `AWS::WAFv2::RuleGroup`、full 出力時の `AWS::WAFv2::WebACL`、IP allow/block list を使う場合の IP set リソースが含まれます。

Web ACL を別スタックで管理している場合は `--rule-group-only` を使い、再利用可能な rule group のみを出力します。

---

## AWS CDK: CloudFront Functions

生成コードをインラインで渡します:

```typescript
import * as path from 'path';
import * as fs from 'fs';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';

// npx cdn-security build のあと
const edgeDir = path.join(__dirname, '..', 'dist', 'edge');
const viewerRequestCode = fs.readFileSync(path.join(edgeDir, 'viewer-request.js'), 'utf8');
const viewerResponseCode = fs.readFileSync(path.join(edgeDir, 'viewer-response.js'), 'utf8');

const viewerRequestFn = new cloudfront.Function(this, 'ViewerRequest', {
  code: cloudfront.FunctionCode.fromInline(viewerRequestCode),
  runtime: cloudfront.FunctionRuntime.JS_1_0,
});
const viewerResponseFn = new cloudfront.Function(this, 'ViewerResponse', {
  code: cloudfront.FunctionCode.fromInline(viewerResponseCode),
  runtime: cloudfront.FunctionRuntime.JS_1_0,
});

// ディストリビューションのデフォルトビヘイビアにアタッチ
distribution.addBehavior('*', origin, {
  viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
  functionAssociations: [
    { eventType: cloudfront.FunctionEventType.VIEWER_REQUEST, function: viewerRequestFn },
    { eventType: cloudfront.FunctionEventType.VIEWER_RESPONSE, function: viewerResponseFn },
  ],
});
```

---

## まとめ

| 目的 | 操作 |
|------|------|
| **Edge (CloudFront)** | Terraform では `file("dist/edge/viewer-request.js")`、CDK では `FunctionCode.fromInline(...)` で生成ファイルを参照。 |
| **Edge (Cloudflare)** | `dist/edge/cloudflare/index.ts` を Worker プロジェクトにコピーまたは参照し、Wrangler でデプロイ。 |
| **WAF (Terraform)** | `dist/infra/waf-rules.tf.json` を Terraform の設定に含め、Web ACL でルールグループを参照。 |
| **WAF (CloudFormation)** | `npx cdn-security emit-waf --format cloudformation` を実行し、`dist/infra/waf-cloudformation.json` をデプロイ。 |

`policy/security.yml` を変更したら `npx cdn-security build` を再実行し、続けて Terraform または CDK を実行すると、デプロイされる Edge と WAF がポリシーと一致します。

---

## Origin Auth（custom_header）

<a id="origin-auth"></a>

`origin.auth.type: custom_header` を設定すると、エッジが共有シークレットを `X-Origin-Verify`（既定）などのヘッダとして付与し、オリジンはそれを検証して「エッジ経由のトラフィックのみ信頼」できます。値は環境変数から読み込みます。

```yaml
origin:
  auth:
    type: custom_header
    header: X-Origin-Verify
    secret_env: ORIGIN_AUTH_SECRET   # ^[A-Z][A-Z0-9_]*$ に一致
```

- **`header`**: 必須（空文字不可）。
- **`secret_env`**: 必須。`^[A-Z][A-Z0-9_]*$` にマッチしない名前は schema lint で弾かれる（存在しない env を参照するミスを防止）。
- **ビルド時チェック**: `node scripts/compile.js --strict-origin-auth` を指定すると、指定 env が未設定 / 空のときビルドをハードフェイルします。フラグ無しでは `[origin-auth]` 警告のみ。**CI では必ず `--strict-origin-auth` を付ける** ことを推奨。
- **ランタイム挙動**: ランタイムで env が空のとき、エッジは **ヘッダを付与しません**。オリジン側は既定で拒否する構成にしてください（そうでないと、空の `X-Origin-Verify` を「エッジから」と誤認する可能性）。エッジは `event:"error", block_reason:"origin_auth_secret_missing"` の JSON ログを出すので観測性で拾えます。

### Terraform 例（env 経由で Lambda@Edge に渡す）

```hcl
variable "origin_auth_secret" {
  type      = string
  sensitive = true
}

resource "aws_lambda_function" "origin_request" {
  function_name = "edge-origin-request"
  environment {
    variables = {
      ORIGIN_AUTH_SECRET = var.origin_auth_secret
    }
  }
}
```

`TF_VAR_origin_auth_secret` はシークレットストア（AWS Secrets Manager, Vault, CI Secrets）から供給してください。`policy/security.yml` は git で管理されるので **絶対に値を書かないこと**。
