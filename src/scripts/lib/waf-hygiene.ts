/**
 * Shared WAF hygiene warnings used by policy-lint and the programmatic validator.
 * AWS-scoped checks are skipped when `firewall.waf.scope` is absent (Cloudflare).
 */

function collectWafHygieneWarnings(policy: any): string[] {
  const warnings: string[] = [];
  const mode = (policy && policy.defaults && policy.defaults.mode) || null;
  const isEnforce = mode === 'enforce';
  const waf = (policy && policy.firewall && policy.firewall.waf) || null;
  if (!isEnforce || !waf) return warnings;

  const scope = waf.scope;
  const isAwsScope = scope === 'CLOUDFRONT' || scope === 'REGIONAL';
  if (!isAwsScope) return warnings;

  const managed = Array.isArray(waf.managed_rules) ? waf.managed_rules : [];
  const hasCoreSignal = managed.some((r: string) =>
    r === 'AWSManagedRulesBotControlRuleSet' ||
    r === 'AWSManagedRulesATPRuleSet' ||
    r === 'AWSManagedRulesIPReputationList' ||
    r === 'AWSManagedRulesAnonymousIpList'
  );
  if (!hasCoreSignal) {
    warnings.push(
      'firewall.waf.managed_rules does not include any of BotControl / ATP / IPReputation / AnonymousIp. Consider adding at least IPReputation + AnonymousIp for production enforce mode.',
    );
  }
  const loggingEnabled = waf.logging && waf.logging.enabled === true;
  if (scope === 'CLOUDFRONT' && !loggingEnabled) {
    warnings.push(
      'firewall.waf.logging is not enabled while scope=CLOUDFRONT. PCI-DSS / SOC2 require WAF log retention — set logging.enabled: true and supply destination_arn_env.',
    );
  }
  return warnings;
}

module.exports = {
  collectWafHygieneWarnings,
};
