# Example: AWS CloudFront

This example shows how to deploy the Edge Security runtime with **AWS CloudFront** and **CloudFront Functions**.

---

## Prerequisites

- AWS account with CloudFront and CloudFront Functions available
- Origin (S3 bucket or custom origin) already set up

---

## Steps

### 1. Use the runtime

Copy or link the runtime from the framework:

- **Viewer Request**: `../../runtimes/aws-cloudfront-functions/viewer-request.js`
- **Viewer Response**: `../../runtimes/aws-cloudfront-functions/viewer-response.js`

Or deploy the framework's `runtimes/aws-cloudfront-functions/` directory as your Functions source.

### 2. Set the admin token

In `viewer-request.js`, replace:

```js
token: "REPLACE_ME_WITH_EDGE_ADMIN_TOKEN",
```

with your secret token (or use a build step to inject it from an env var).

### 3. Create CloudFront Functions in the console

1. CloudFront → Functions → Create function.
2. Create a function for **Viewer Request**: paste the contents of `viewer-request.js`, publish.
3. Create a function for **Viewer Response**: paste the contents of `viewer-response.js`, publish.

### 4. Associate with your distribution

1. Open your distribution → Behaviors → Edit default (or the behavior you use).
2. **Viewer request**: Function type = CloudFront Functions, select the Viewer Request function.
3. **Viewer response**: Function type = CloudFront Functions, select the Viewer Response function.
4. Save and wait for deployment.

### 5. Verify

```bash
# Without token: 401
curl -i https://YOUR_DISTRIBUTION_DOMAIN/admin

# With token: allowed
curl -i -H "x-edge-token: YOUR_TOKEN" https://YOUR_DISTRIBUTION_DOMAIN/admin

# Traversal / bad UA / too many query params: blocked
curl -i "https://YOUR_DISTRIBUTION_DOMAIN/foo/../bar"
```

---

## Policy alignment

Runtime behavior is aligned with `policy/base.yml` (or `policy/profiles/balanced.yml`). When the policy compiler is added, Functions can be generated from the policy.

---

## See also

- [CloudFront Functions Runtime](../../runtimes/aws-cloudfront-functions/README.md)
- [Quick Start](../../docs/quickstart.md)
- [Architecture](../../docs/architecture.md)
