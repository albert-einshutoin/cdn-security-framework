import { previewFinding, SOURCE_AWARE_COMPARISONS } from '../contract/source-aware-finalizer';
import type { SourceAwareOutputBundle } from '../contract/source-aware-output';
import { sortFindings } from '../contract/finding-order';
import { redactSensitiveText } from '../contract/sensitive-text';

const DEFAULT_TOP = 10;
const DEFAULT_BYTES = 32_768;

export class SourceAwareSummaryError extends Error {
  readonly code = 'SOURCE_SUMMARY_OUTPUT_LIMIT_EXCEEDED';
  constructor() {
    super('Source-aware Summary exceeds the output limit.');
    this.name = 'SourceAwareSummaryError';
  }
}

function cell(value: string, max = 120): string {
  const redacted = redactSensitiveText(value);
  const cleaned = redacted.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, ' ').replace(/\s+/gu, ' ').trim();
  const bounded = [...cleaned].slice(0, max).join('');
  return `${bounded}${[...cleaned].length > max ? '…' : ''}`
    .replace(/&/gu, '&amp;').replace(/</gu, '&lt;').replace(/>/gu, '&gt;')
    .replace(/[\\`*_[\]{}()#+.!|~:]/gu, '\\$&');
}

function linesFor(bundle: SourceAwareOutputBundle, top: number): string[] {
  const final = bundle.finalized;
  const error = bundle.finalizationError;
  const lines = [
    '# Source-aware Contract Diff (internal pre-Entry)', '',
    final?.analysis.outcome !== 'ok' ? '**Result: tool error**'
      : final.analysis.status === 'partial' ? '**Result: partial analysis**'
        : '**Result: analysis complete**',
    final ? `**Finding threshold:** ${final.threshold.reached ? 'reached' : 'not reached'} (${final.threshold.failOn})`
      : '**Finding threshold:** not evaluated',
    final ? `**Exit verdict:** ${final.exitCode}`
      : `**Exit verdict:** ${error?.exitCode ?? 3} (finalization failed)`,
    '', '## Stage status', '', '| Stage | Status | Reason |', '| --- | --- | --- |',
  ];
  if (bundle.metadata.routingAssumption) {
    const routing = bundle.metadata.routingAssumption;
    if (routing.globalPrefix) lines.splice(2, 0,
      `**Routing assumption:** explicit global prefix ${cell(routing.globalPrefix)} (not bootstrap-verified).`);
    if (routing.sourceVersioning) lines.splice(2, 0,
      '**Routing assumption:** explicit URI versioning with default v prefix (not bootstrap-verified).');
  }
  if (bundle.metadata.sourceVersionMetadata) {
    const versions = bundle.metadata.sourceVersionMetadata;
    lines.splice(3, 0, `**Source AST versions:** ${versions.total} route candidates; SHA-256 ${versions.digest}.`);
  }
  for (const name of ['declared', 'implemented', 'allowed'] as const) {
    const stage = final?.stages[name];
    lines.push(`| ${name} | ${stage?.status ?? error?.stages[name] ?? 'unknown'} | ${stage?.code ?? '-'} |`);
  }
  lines.push('', '## Comparison status', '', '| Comparison | Status | Unique in comparison | Active | Suppressed | Reason |',
    '| --- | --- | ---: | ---: | ---: | --- |');
  for (const name of SOURCE_AWARE_COMPARISONS) {
    const comparison = final?.comparisons[name];
    lines.push(comparison && (comparison.status === 'complete' || comparison.status === 'partial')
      ? `| ${name} | ${comparison.status} | ${comparison.count} | ${comparison.active} | ${comparison.suppressed} | - |`
      : `| ${name} | ${comparison?.status ?? error?.comparisons[name] ?? 'not evaluated'} | - | - | - | ${comparison && 'code' in comparison ? comparison.code : error?.code ?? '-'} |`);
  }
  const passport = bundle.metadata.passportFactoryObservation;
  const strategy = bundle.metadata.passportStrategyObservation;
  lines.push('', '## Passport direct factory observation', '');
  if (!passport) lines.push('Source factory observation not available.');
  else {
    const authUnknown = final?.passportFactoryObservation?.operations.filter(({ authMode }) => (
      authMode === 'unknown'
    )).length;
    lines.push(`Call sites: ${passport.totalCallSites}; operation associations: ${passport.totalAssociations}; inspected operations: ${passport.totalOperations}; Source auth unknown: ${authUnknown ?? 'not evaluated'}.`,
      'Strategy names are static syntax only; strategy registration, auth kind, and runtime enforcement are unverified.');
    for (const site of passport.callSites.slice(0, top)) {
      lines.push(`- ${site.scope} ${cell(site.strategy ?? `unsupported: ${site.reason ?? 'unknown'}`)} at ${cell(site.sourceUri)}:${site.line}`);
    }
    for (const item of passport.associations.slice(0, top)) {
      lines.push(`- operation ${cell(item.method)} ${cell(item.comparisonPath)}: ${cell(item.callSiteId)}; auth ${item.authMode}`);
    }
    lines.push(`Call sites omitted: ${passport.totalCallSites - Math.min(passport.callSites.length, top)}; associations omitted: ${passport.totalAssociations - Math.min(passport.associations.length, top)}.`);
  }
  lines.push('', '## Passport static strategy links', '');
  if (!strategy) lines.push('Source strategy linkage not available.');
  else {
    lines.push(`Definitions: ${strategy.totalDefinitions}; direct provider entries: ${strategy.totalProviders}; call-site matches: ${strategy.totalMatches}; definitions with unverified names: ${strategy.incompleteDefinitionNames}; SHA-256 ${strategy.digest}.`,
      'Extractor and provider entries describe static syntax. Runtime registration, reachability, authentication kind, and enforcement are unverified.');
    for (const match of strategy.matches.slice(0, top)) {
      lines.push(`- ${cell(match.strategy ?? 'unmatchable')}: ${match.status}${match.reason ? ` (${match.reason})` : ''}; candidates ${match.totalCandidates}; call ${cell(match.callSiteId)}`);
    }
    for (const definition of strategy.definitions.slice(0, top)) {
      lines.push(`- ${cell(definition.strategy)}: ${cell(definition.className)} at ${cell(definition.sourceUri)}:${definition.line}; base ${definition.baseStatus}; extractor ${definition.extractor.status}`);
    }
    for (const provider of strategy.providers.slice(0, top)) {
      lines.push(`- provider ${cell(provider.moduleClass)} at ${cell(provider.sourceUri)}:${provider.line} for ${cell(provider.definitionId)}`);
    }
    lines.push(`Definitions omitted: ${strategy.totalDefinitions - Math.min(strategy.definitions.length, top)}; providers omitted: ${strategy.totalProviders - Math.min(strategy.providers.length, top)}; matches omitted: ${strategy.totalMatches - Math.min(strategy.matches.length, top)}.`);
  }
  lines.push('', '## Overall findings', '', '| Kind | Count |', '| --- | ---: |',
    `| Unique | ${final?.summary.unique ?? 'not evaluated'} |`,
    `| Active | ${final?.summary.active ?? 'not evaluated'} |`,
    `| Suppressed | ${final?.summary.suppressed ?? 'not evaluated'} |`,
    `| Governance | ${final?.summary.governance ?? 'not evaluated'} |`,
    '', 'Comparison counts may overlap: one canonical Finding can belong to multiple comparisons.',
    '', '## Top findings', '', '| State | Severity | Rule | Instance | Route | Title | Comparisons |',
    '| --- | --- | --- | --- | --- | --- | --- |');
  const groups = final ? [
    ...final.findings.map((finding) => ({ finding, disposition: 'active' })),
    ...final.suppressedFindings.map((finding) => ({ finding, disposition: 'suppressed' })),
    ...final.exceptionDiagnostics.map((finding) => ({ finding, disposition: 'governance' })),
  ] : [];
  const ordered = sortFindings(groups.map(({ finding }) => finding));
  const state = new Map(groups.map(({ finding, disposition }) => [finding.instanceId, disposition]));
  const memberships = new Map(final?.memberships.map(({ instanceId, comparisons }) => [instanceId, comparisons]) ?? []);
  for (const finding of ordered.slice(0, top)) {
    const projected = previewFinding(finding, memberships.get(finding.instanceId) ?? []);
    const route = [projected.route?.method, projected.route?.path].filter(Boolean).join(' ') || '-';
    lines.push(`| ${state.get(finding.instanceId) ?? 'governance'} | ${finding.severity} | ${cell(finding.ruleId)} | ${cell(finding.instanceId)} | ${cell(route)} | ${cell(finding.title)} | ${projected.comparisons.join(', ') || '-'} |`);
  }
  lines.push('', `Top findings omitted: ${ordered.length - Math.min(ordered.length, top)}.`,
    '', '## Coverage and capabilities', '',
    `Analysis: ${final?.analysis.status ?? 'failed'}; outcome: ${final?.analysis.outcome ?? 'internal-error'}.`,
    `Diagnostic codes: ${final?.analysis.codes.join(', ') || error?.code || 'none'}.`);
  const limited = bundle.metadata.targetCapabilities.filter(({ status }) => status !== 'supported');
  lines.push(`Provider target: ${bundle.target}; limited capabilities: ${limited.length}.`);
  for (const capability of limited) lines.push(`- ${cell(capability.id)}: ${capability.status}`);
  lines.push('', '## Exceptions and detail', '',
    `Applied exceptions: ${final?.appliedExceptionIds.length ?? 'not evaluated'}; governance diagnostics: ${final?.summary.governance ?? 'not evaluated'}.`,
    'This bounded Summary is not a full Finding report. No full report artifact is attached by this renderer.');
  return lines;
}

/** Pure internal Markdown renderer. A small display never changes the finalizer verdict. */
export function renderSourceAwareSummary(
  bundle: SourceAwareOutputBundle,
  options: { top?: number; maxOutputBytes?: number } = {},
): string {
  const top = options.top ?? DEFAULT_TOP;
  const maxBytes = options.maxOutputBytes ?? DEFAULT_BYTES;
  if (!bundle || (!bundle.finalized && !bundle.finalizationError)
    || !Number.isSafeInteger(top) || top < 0 || top > 100
    || !Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new SourceAwareSummaryError();
  }
  for (let visible = top; visible >= 0; visible -= 1) {
    const output = `${linesFor(bundle, visible).join('\n')}\n`;
    if (Buffer.byteLength(output, 'utf8') <= maxBytes) return output;
  }
  throw new SourceAwareSummaryError();
}
