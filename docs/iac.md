# IaC Integration (Terraform / CloudFormation / CDK / WAF)

This document describes how to use the generated **`dist/edge/`** and **`dist/infra/`** outputs with Terraform, AWS CloudFormation, and AWS CDK.

---

## Overview

After `npx cdn-security build`:

| Output | Use |
|--------|-----|
| **dist/edge/viewer-request.js** | CloudFront Function (Viewer Request) |
| **dist/edge/viewer-response.js** | CloudFront Function (Viewer Response) |
| **dist/edge/cloudflare/index.ts** | Cloudflare Worker (when built with `--target cloudflare`). Output is TypeScript; Wrangler compiles it on deploy. Without Wrangler, a TypeScript build step is required. |
| **dist/infra/waf-rules.tf.json** | Terraform JSON: WAFv2 rule group / Web ACL resources. Use when policy has `firewall.waf`. |
| **dist/infra/waf-cloudformation.json** | AWS CloudFormation: `AWS::WAFv2::*` resources. Generate with `emit-waf --format cloudformation`. |

---

## Terraform: CloudFront Functions (Edge)

Reference the generated JS files with `file()` so Terraform picks up changes when you re-run `cdn-security build`.

### Viewer Request / Viewer Response

```hcl
# Path is relative to the Terraform config (or use path.root)
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

# Attach to your distribution's default cache behavior
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

If you generate `dist/edge/origin-request.js`, zip it and use `aws_lambda_function` with `filename` or `s3_*`, then attach to CloudFront origin request.

---

## Terraform: WAF (Infra)

When your policy includes a **`firewall.waf`** section, the build outputs **`dist/infra/waf-rules.tf.json`** (Terraform JSON). The simplest production path is to copy or generate that file into the same Terraform root that owns your CloudFront distribution, then reference the generated Web ACL ARN from your distribution.

### Recommended layout

```text
infra/
  main.tf
  cdn-security.auto.tf.json   # copied from dist/infra/waf-rules.tf.json
```

Build and copy:

```bash
EDGE_ADMIN_TOKEN=replace-with-a-deploy-secret npx cdn-security build
cp dist/infra/waf-rules.tf.json infra/cdn-security.auto.tf.json
```

Then attach the generated Web ACL. The generated resource names include the sanitized `project` value from your policy; if your policy uses `project: example-cdn-security`, the Web ACL resource name is `aws_wafv2_web_acl.example_cdn_security`.

```hcl
resource "aws_cloudfront_distribution" "main" {
  # ...

  web_acl_id = aws_wafv2_web_acl.example_cdn_security.arn

  default_cache_behavior {
    # ...
  }
}
```

For existing Web ACL ownership, run `npx cdn-security build --rule-group-only` and attach the generated rule group from your hand-written `aws_wafv2_web_acl`. Keep the generated JSON in the same Terraform state as the Web ACL, otherwise Terraform cannot reference the generated resources directly.

---

## CloudFormation: AWS WAFv2

Generate an AWS CloudFormation template without rebuilding edge code:

```bash
npx cdn-security emit-waf --target aws --format cloudformation
```

The command writes `dist/infra/waf-cloudformation.json`. The template contains `AWS::WAFv2::RuleGroup`, `AWS::WAFv2::WebACL` when full output is requested, plus related IP set resources when the policy uses IP allow/block lists.

Use `--rule-group-only` when another stack owns the Web ACL and you only want reusable rule groups.

---

## AWS CDK: CloudFront Functions

Use the generated code as inline function code:

```typescript
import * as cdk from 'aws-cdk-lib';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as path from 'path';
import * as fs from 'fs';

// After npx cdn-security build
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

// Attach to your distribution's default behavior
distribution.addBehavior('*', origin, {
  viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
  functionAssociations: [
    { eventType: cloudfront.FunctionEventType.VIEWER_REQUEST, function: viewerRequestFn },
    { eventType: cloudfront.FunctionEventType.VIEWER_RESPONSE, function: viewerResponseFn },
  ],
});
```

---

## Summary

| Goal | Action |
|------|--------|
| **Edge (CloudFront)** | Use `file("dist/edge/viewer-request.js")` (Terraform) or `FunctionCode.fromInline(...)` (CDK) with the generated files. |
| **Edge (Cloudflare)** | Copy or reference `dist/edge/cloudflare/index.ts` in your Worker project and deploy with Wrangler. |
| **WAF (Terraform)** | Use `dist/infra/waf-rules.tf.json` in your Terraform config (same directory or module) and attach the rule group to your Web ACL. |
| **WAF (CloudFormation)** | Use `npx cdn-security emit-waf --format cloudformation` and deploy `dist/infra/waf-cloudformation.json`. |

Re-run `npx cdn-security build` whenever you change `policy/security.yml`; then re-run Terraform or CDK so the deployed Edge and WAF match the policy.

---

## Origin Auth

<a id="origin-auth"></a>

When `origin.auth.type: custom_header` is configured, the edge injects a shared secret header (default `X-Origin-Verify`) read from an environment variable at build/runtime:

```yaml
origin:
  auth:
    type: custom_header
    header: X-Origin-Verify
    secret_env: ORIGIN_AUTH_SECRET   # must match ^[A-Z][A-Z0-9_]*$
```

- **`header`** is required (non-empty string).
- **`secret_env`** is required and must match `^[A-Z][A-Z0-9_]*$`. The schema rejects lowercase / spaced names so you cannot accidentally reference a non-existent env var.
- **Build-time check**: pass `--strict-origin-auth` to `node scripts/compile.js` to hard-fail when `secret_env` is unset or empty in the build environment. Without the flag the build emits a non-fatal `[origin-auth]` warning — useful for local development but **you should wire `--strict-origin-auth` into CI** so a misconfigured env never ships.
- **Runtime behavior**: if the env resolves to empty at runtime, the edge **refuses** to forward the header (origin should deny by default; otherwise the miswire silently falls back to trusting anything reaching origin). The edge emits a JSON error log (`event:"error", block_reason:"origin_auth_secret_missing"`) so the miswire is visible in observability.

### Terraform example (env-backed Lambda@Edge)

```hcl
variable "origin_auth_secret" {
  type      = string
  sensitive = true
}

resource "aws_lambda_function" "origin_request" {
  function_name = "edge-origin-request"
  # ... filename / role ...
  environment {
    variables = {
      ORIGIN_AUTH_SECRET = var.origin_auth_secret
    }
  }
}
```

Supply `TF_VAR_origin_auth_secret` via your secret store (AWS Secrets Manager, Vault, CI secret). Do **not** put the value in `policy/security.yml` — the policy file is checked into git.
