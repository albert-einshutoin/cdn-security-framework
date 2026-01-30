# IaC Integration (Terraform / CDK / WAF)

This document describes how to use the generated **`dist/edge/`** and **`dist/infra/`** outputs with Terraform and AWS CDK.

---

## Overview

After `npx cdn-security build` (and `npx cdn-security build --target aws` for Infra):

| Output | Use |
|--------|-----|
| **dist/edge/viewer-request.js** | CloudFront Function (Viewer Request) |
| **dist/edge/viewer-response.js** | CloudFront Function (Viewer Response) |
| **dist/edge/cloudflare/index.ts** | Cloudflare Worker (when built with `--target cloudflare`) |
| **dist/infra/waf-rules.tf.json** | Terraform JSON: `aws_wafv2_rule_group` (rate-based rule). Use when policy has `firewall.waf`. |

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

When your policy includes a **`firewall.waf`** section, the build outputs **`dist/infra/waf-rules.tf.json`** (Terraform JSON). You can:

- **Option A**: Import the rule group by referencing the JSON file (e.g. `terraform plan` in a directory that includes this file, or use `terraform import` if the resource is created elsewhere).
- **Option B**: Use the generated rule group in your Terraform by **inlining** or **reading** the JSON and creating an `aws_wafv2_rule_group` resource that matches.

### Using the generated waf-rules.tf.json

The file is valid Terraform JSON. You can:

1. **Copy into your Terraform module**: Place `waf-rules.tf.json` in a Terraform directory and run `terraform plan` / `apply` in that directory; Terraform will manage the rule group.
2. **Reference from another module**: Use a module that reads the JSON or use `terraform import` to attach the rule group to your Web ACL.

Example: ensure the build has run, then in a Terraform config directory:

```hcl
# In the same repo, or copy dist/infra/waf-rules.tf.json into this directory
# Then reference the rule group in your Web ACL:
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

If you keep the generated file in `dist/infra/`, run Terraform from the repo root or from a subdirectory that includes `dist/infra/waf-rules.tf.json` so the rule group is defined in the same state.

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

Re-run `npx cdn-security build` whenever you change `policy/security.yml`; then re-run Terraform or CDK so the deployed Edge and WAF match the policy.
