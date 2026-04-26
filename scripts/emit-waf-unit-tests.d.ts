#!/usr/bin/env node
/**
 * emit-waf subcommand integration: spawn `bin/cli.js emit-waf` in a fresh tmp
 * repo and assert it drops only infra/*.tf.json (no edge/*.js), supports each
 * --target + --rule-group-only + stubbed --format rejections.
 *
 * We use ci-build-token-not-for-deploy for ORIGIN_SECRET so archetypes /
 * policies that reference env vars through schema still lint cleanly (policy
 * lint reads env at build time for origin.auth). The cli-doctor env check is
 * NOT exercised here — that's covered by doctor-unit-tests.js.
 */
export {};
