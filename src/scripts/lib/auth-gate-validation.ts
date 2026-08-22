import { normalizeStringList } from './value-normalize';

const JWKS_DISALLOWED_HOSTNAMES = new Set([
  'localhost',
  'ip6-localhost',
  'ip6-loopback',
  'broadcasthost',
]);

function isPrivateIPv4Literal(hostname: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (!match) return false;
  const octets = match.slice(1, 5).map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255)) return false;
  const [a, b] = octets;
  return a === 10 || a === 127 || a === 0 || a >= 224
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 169 && b === 254)
    || (a === 100 && b >= 64 && b <= 127);
}

function isPrivateIPv6Literal(hostname: string): boolean {
  const value = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1).toLowerCase()
    : hostname.toLowerCase();
  if (!value.includes(':')) return false;
  return value === '::' || value === '::1' || value.startsWith('fe80:')
    || value.startsWith('fc') || value.startsWith('fd') || value.startsWith('::ffff:');
}

export function validateJwksUrl(rawUrl: string, allowedHosts: unknown): { ok: boolean; reason?: string; hostname?: string } {
  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') return { ok: false, reason: 'jwks_url is empty' };
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, reason: `jwks_url is not a valid URL: ${rawUrl}` };
  }
  if (parsed.protocol !== 'https:') {
    return { ok: false, reason: `jwks_url must use https:// (got ${parsed.protocol})` };
  }
  if (parsed.username || parsed.password) return { ok: false, reason: 'jwks_url must not contain userinfo (user:pass@host)' };
  const hostname = (parsed.hostname || '').toLowerCase();
  if (!hostname) return { ok: false, reason: 'jwks_url has empty hostname' };
  if (JWKS_DISALLOWED_HOSTNAMES.has(hostname)) {
    return { ok: false, reason: `jwks_url hostname "${hostname}" is a loopback alias` };
  }
  if (isPrivateIPv4Literal(hostname) || isPrivateIPv6Literal(parsed.hostname)) {
    return { ok: false, reason: `jwks_url hostname "${hostname}" resolves to a private/loopback/link-local range` };
  }
  const normalizedHosts = normalizeStringList(allowedHosts, 'lower');
  if (normalizedHosts.length > 0 && !normalizedHosts.includes(hostname)) {
    return {
      ok: false,
      reason: `jwks_url hostname "${hostname}" is not in firewall.jwks.allowed_hosts (${normalizedHosts.join(', ')})`,
    };
  }
  return { ok: true, hostname };
}

export function validateAuthGateStructure(
  policy: any,
  route: any,
  options: { requireJwksAllowedHosts?: boolean } = {},
): string[] {
  const gate = route.auth_gate;
  if (!gate) return [];
  const errors: string[] = [];
  const authType = gate.type || 'static_token';
  const allowedHosts = ((policy.firewall || {}).jwks || {}).allowed_hosts;
  const normalizedAllowedHosts = normalizeStringList(allowedHosts, 'lower');

  if (authType === 'jwt') {
    const algorithm = gate.algorithm || 'RS256';
    if (algorithm === 'RS256' && !gate.jwks_url) errors.push('JWT+RS256 requires "jwks_url"');
    if (algorithm === 'RS256' && options.requireJwksAllowedHosts && normalizedAllowedHosts.length === 0) {
      errors.push('JWT+RS256 requires firewall.jwks.allowed_hosts for this target');
    }
    if (gate.jwks_url) {
      const validation = validateJwksUrl(gate.jwks_url, allowedHosts);
      if (!validation.ok) errors.push(validation.reason || 'invalid jwks_url');
    }
    if (algorithm === 'HS256' && !gate.secret_env) errors.push('JWT+HS256 requires "secret_env"');
    if (Array.isArray(gate.allowed_algorithms) && gate.allowed_algorithms.length > 0) {
      const extras = gate.allowed_algorithms.filter(
        (candidate: unknown) => typeof candidate === 'string' && candidate !== 'none' && candidate !== algorithm,
      );
      if (extras.length > 0) {
        errors.push(
          `auth_gate.allowed_algorithms contains ${JSON.stringify(extras)} but the gate only runs the `
          + `"${algorithm}" verifier. Remove the extra algorithm(s) or switch the gate's "algorithm" field.`,
        );
      }
    }
  } else if (authType === 'signed_url' && !gate.secret_env) {
    errors.push('signed_url requires "secret_env"');
  }
  return errors;
}
