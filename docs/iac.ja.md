# IaC 連携（Terraform / CDK / WAF）

このドキュメントでは、生成された **`dist/edge/`** と **`dist/infra/`** を Terraform および AWS CDK でどう使うかを説明します。

---

## 概要

`npx cdn-security build`（および Infra 用に `npx cdn-security build --target aws`）のあと:

| 出力 | 用途 |
|------|------|
| **dist/edge/viewer-request.js** | CloudFront Function (Viewer Request) |
| **dist/edge/viewer-response.js** | CloudFront Function (Viewer Response) |
| **dist/edge/cloudflare/index.ts** | Cloudflare Worker（`--target cloudflare` でビルドした場合） |
| **dist/infra/waf-rules.tf.json** | Terraform JSON: `aws_wafv2_rule_group`（レートベースルール）。ポリシーに `firewall.waf` がある場合に生成。 |

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

ポリシーに **`firewall.waf`** セクションがあると、ビルドで **`dist/infra/waf-rules.tf.json`**（Terraform JSON）が出力されます。利用方法:

- **方法 A**: この JSON ファイルを Terraform のディレクトリに含め、`terraform plan` / `apply` でルールグループを管理する。
- **方法 B**: 生成されたルールグループを Web ACL から参照する。

### 生成 waf-rules.tf.json の利用

ファイルはそのまま Terraform JSON として有効です。

1. **Terraform モジュールにコピー**: `waf-rules.tf.json` を Terraform のディレクトリに置き、そのディレクトリで `terraform plan` / `apply` を実行する。
2. **別モジュールから参照**: このルールグループを Web ACL の `rule_group_reference_statement` で参照する。

例: ビルド実行後、Terraform の設定ディレクトリで:

```hcl
# 同一リポジトリ、または dist/infra/waf-rules.tf.json をこのディレクトリにコピー
# Web ACL でルールグループを参照:
resource "aws_wafv2_web_acl" "main" {
  name  = "main"
  scope = "REGIONAL"
  default_action { allow {} }
  rule {
    name     = "rate-limit"
    priority = 1
    override_action { none {} }
    statement {
      rule_group_reference_statement {
        arn = aws_wafv2_rule_group.example_cdn_security_rate_limit[0].arn
      }
    }
    visibility_config { ... }
  }
  visibility_config { ... }
}
```

`dist/infra/` をそのまま使う場合は、リポジトリルートや `dist/infra/` を含むディレクトリで Terraform を実行すると、ルールグループが同じ state で定義されます。

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

`policy/security.yml` を変更したら `npx cdn-security build` を再実行し、続けて Terraform または CDK を実行すると、デプロイされる Edge と WAF がポリシーと一致します。
