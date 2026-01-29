# AWS Lambda@Edge Runtime

This directory is a template for Lambda@Edge (**Origin Request**).

## When to Use It (Where CloudFront Functions Fall Short)

- RS256 JWT validation (e.g., Cognito / OIDC)
- More complex signature verification (e.g., HMAC with multiple keys or `kid` support)
- A final gate immediately before the request reaches Origin

## Where to Attach

- `origin-request.js` → **Origin Request**

## Notes

- Lambda@Edge is heavier than Functions (cold start, execution time, deployment steps).
- Prefer Functions for entry blocking and lightweight normalization; use Lambda@Edge only when needed.

## Verification

- Associate the Lambda@Edge function with the CloudFront Behavior, then access the target path and check logs.
