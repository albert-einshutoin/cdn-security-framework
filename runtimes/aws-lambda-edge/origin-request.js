/**
 * Lambda@Edge - Origin Request
 *
 * Purpose:
 * - Heavier logic than CloudFront Functions: JWT validation, signature verification, dynamic rules
 * - Final gate before traffic reaches Origin
 *
 * You can also:
 * - Verify Cognito/OIDC JWT (RS256)
 * - Add internal headers visible only to origin
 */

exports.handler = async (event) => {
    const cf = event.Records[0].cf;
    const req = cf.request;

    // TODO: verify JWT (RS256) / validate signature / advanced checks
    // NOTE: This is a template. If you implement, design key handling and cold-start behavior.

    return req;
  };
