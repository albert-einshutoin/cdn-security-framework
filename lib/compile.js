"use strict";
/**
 * Programmatic API: compile
 *
 * Build edge runtime + infra config from a policy file. Stable public
 * contract; emission is delegated to the compiler emitter phase so the API no
 * longer owns script orchestration details directly.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const { compileArtifacts } = require('../emitter');
function compile(opts = {}) {
    return compileArtifacts(opts);
}
module.exports = { compile };
