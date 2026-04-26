#!/usr/bin/env node
/**
 * Cloudflare Worker integration harness.
 *
 * Compiles a policy → TypeScript Worker, transpiles to JS via esbuild, and
 * invokes `fetch()` with real `Request` / `Response` globals (Node ≥ 18).
 * This is deliberately Node-native instead of miniflare: our runtime needs
 * are small (no KV, no Durable Objects), and avoiding the extra dep keeps
 * CI fast and deterministic.
 *
 * Coverage goal: ≥ 6 distinct request/response shapes per issue #27
 *   1. allowed GET on non-protected path
 *   2. blocked path-traversal payload → 400
 *   3. blocked disallowed method → 405
 *   4. blocked URI length → 414
 *   5. blocked UA on deny list → 403
 *   6. admin without token → 401
 *   7. admin with correct static_token → passes gate
 *   8. structured JSON log shape on a block
 */
export {};
