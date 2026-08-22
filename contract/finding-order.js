"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sortFindings = sortFindings;
const SEVERITY_ORDER = { error: 0, warning: 1, info: 2 };
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function sortFindings(findings) {
    return [...findings].sort((left, right) => (SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]
        || compareText(left.ruleId, right.ruleId)
        || compareText(left.route?.path ?? '', right.route?.path ?? '')
        || compareText(left.route?.method ?? '', right.route?.method ?? '')
        || compareText(left.instanceId, right.instanceId)));
}
