import type { SecurityFindingV1 } from './finding';

const SEVERITY_ORDER = { error: 0, warning: 1, info: 2 } as const;

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function sortFindings(findings: readonly SecurityFindingV1[]): SecurityFindingV1[] {
  return [...findings].sort((left, right) => (
    SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]
    || compareText(left.ruleId, right.ruleId)
    || compareText(left.route?.path ?? '', right.route?.path ?? '')
    || compareText(left.route?.method ?? '', right.route?.method ?? '')
    || compareText(left.instanceId, right.instanceId)
  ));
}
