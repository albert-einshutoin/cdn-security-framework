import {
  contractDiffExitCode,
  type ContractDiffFailOn,
  type ContractDiffReportV1,
} from '../contract/contract-diff';
import type { SecurityFindingV1 } from '../contract/finding';
import { sortFindings } from '../contract/finding-order';

const TOP_FINDING_LIMIT = 10;

function cell(value: string): string {
  const normalized = value.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}|`]/gu, ' ').replace(/\s+/g, ' ').trim();
  return normalized.length > 120 ? `${normalized.slice(0, 117)}...` : normalized;
}

function route(finding: SecurityFindingV1): string {
  const method = cell(finding.route?.method ?? '');
  const path = cell((finding.route?.path ?? '').split(/[?#]/, 1)[0]);
  return method || path ? `\`${[method, path].filter(Boolean).join(' ')}\`` : '-';
}

export function renderContractDiffGitHubSummary(
  report: ContractDiffReportV1,
  options: { failOn?: ContractDiffFailOn } = {},
): string {
  const findings = sortFindings([...report.findings, ...report.exceptionDiagnostics]);
  const expired = report.exceptionDiagnostics.filter(({ ruleId }) => ruleId === 'SC-GOV-001').length;
  const categories = report.summary.byCategory;
  const top = findings.slice(0, TOP_FINDING_LIMIT);
  const remaining = findings.length - top.length;
  const lines = [
    '# CDN Security Contract Diff',
    '',
    contractDiffExitCode(report, options.failOn ?? 'error') === 1
      ? `**Gate: failing** (findings crossed the ${options.failOn ?? 'error'} threshold)`
      : '**Gate: passing**',
    ...(report.omittedComparisons.length > 0
      ? [`**Coverage warning:** ${report.omittedComparisons.length} comparison(s) omitted or unknown.`]
      : []),
    '',
    '| Error | Warning | Info | Suppressed | Expired exceptions |',
    '| ---: | ---: | ---: | ---: | ---: |',
    `| ${report.summary.error} | ${report.summary.warning} | ${report.summary.info} | ${report.summary.suppressed} | ${expired} |`,
    '',
    '## Change overview',
    '',
    '| Area | Findings |',
    '| --- | ---: |',
    `| New / removed routes | ${categories.inventory} |`,
    `| Extra / blocked methods | ${categories.exposure} |`,
    `| Authentication / authorization drift | ${categories.authentication + categories.authorization} |`,
    `| Limit / header / content-type drift | ${categories['resource-limit'] + categories.misconfiguration} |`,
    '',
    '## Top findings',
    '',
    '| Severity | Rule | Route | Finding |',
    '| --- | --- | --- | --- |',
    ...top.map((finding) => (
      `| ${finding.severity} | ${cell(finding.ruleId)} | ${route(finding)} | ${cell(finding.title)} |`
    )),
    '',
    ...(remaining > 0 ? [`${remaining} additional findings are available in the JSON and SARIF artifacts.`, ''] : []),
    'Full details: `contract-diff.json` and `cdn-security.sarif` artifacts.',
    '',
  ];
  return lines.join('\n');
}
