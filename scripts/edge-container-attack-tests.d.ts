#!/usr/bin/env node
/**
 * Pseudo Edge container attack tests.
 *
 * These tests start short-lived local HTTP servers that wrap generated edge
 * artifacts. Incoming HTTP requests are translated into the platform event
 * contracts, executed through the generated runtime, and converted back to an
 * HTTP response. This gives CI a black-box layer above direct handler tests.
 */
export {};
