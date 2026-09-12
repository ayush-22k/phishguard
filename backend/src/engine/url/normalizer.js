/**
 * PhishGuard URL Normalizer
 * Safe, deterministic parsing and canonicalization of raw URLs.
 */

const SUPPORTED_PROTOCOLS = new Set(['http:', 'https:']);

// Common Multi-part Public Suffixes (lightweight heuristic list to accurately separate subdomains)
const MULTIPART_TLDS = new Set([
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk',
  'com.au', 'net.au', 'org.au', 'edu.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.jp', 'ne.jp', 'or.jp',
  'co.kr', 'ne.kr', 're.kr',
  'com.br', 'net.br', 'org.br',
  'co.in', 'net.in', 'org.in', 'gen.in',
  'com.cn', 'net.cn', 'org.cn',
  'com.tw', 'idv.tw',
  'com.sg', 'edu.sg',
  'com.hk', 'edu.hk',
]);

/**
 * Parses the domain into subdomains, registered domain, and TLD.
 */
function parseDomainHierarchy(hostname) {
  if (!hostname || typeof hostname !== 'string') {
    return { subdomains: [], registeredDomain: '', tld: '' };
  }

  // If it's an IP address, domain hierarchy doesn't apply
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const isIpv6 = hostname.startsWith('[') && hostname.endsWith(']');
  if (isIpv4 || isIpv6) {
    return { subdomains: [], registeredDomain: hostname, tld: '' };
  }

  const parts = hostname.toLowerCase().split('.').filter(Boolean);
  if (parts.length === 0) {
    return { subdomains: [], registeredDomain: '', tld: '' };
  }
  if (parts.length === 1) {
    return { subdomains: [], registeredDomain: parts[0], tld: parts[0] };
  }

  // Check 2-part TLDs (e.g. co.uk)
  const lastTwo = parts.slice(-2).join('.');
  let tld = '';
  let registeredDomain = '';
  let subdomains = [];

  if (MULTIPART_TLDS.has(lastTwo) && parts.length >= 3) {
    tld = lastTwo;
    registeredDomain = parts.slice(-3).join('.');
    subdomains = parts.slice(0, -3);
  } else {
    tld = parts[parts.length - 1];
    registeredDomain = parts.slice(-2).join('.');
    subdomains = parts.slice(0, -2);
  }

  return { subdomains, registeredDomain, tld };
}

/**
 * Normalizes a raw URL string safely.
 * Never throws uncaught errors on malformed input.
 */
export function normalizeUrl(rawInput) {
  if (typeof rawInput !== 'string' || !rawInput.trim()) {
    return {
      isValid: false,
      error: 'URL input must be a non-empty string.',
      raw: typeof rawInput === 'string' ? rawInput : '',
      normalized: '',
    };
  }

  let raw = rawInput.trim();

  // Basic length sanity check (prevent regex DoS or memory issues on absurdly giant input)
  if (raw.length > 8192) {
    return {
      isValid: false,
      error: 'URL exceeds maximum allowable length of 8192 characters.',
      raw,
      normalized: '',
    };
  }

  // Check if raw URL contains the @ symbol before URL parsing (can be stripped or masked in standard parser)
  const hasAtSymbol = raw.includes('@');

  // Check for explicit URI scheme (e.g., javascript:, data:, file:, ftp:, etc.)
  const schemeMatch = raw.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (!['http', 'https'].includes(scheme)) {
      return {
        isValid: false,
        error: `Unsupported or dangerous URL protocol: "${scheme}:". Only HTTP and HTTPS are permitted.`,
        raw,
        normalized: '',
        protocol: `${scheme}:`,
        hasAtSymbol,
      };
    }
  }

  // If input lacks a protocol scheme, prepend https:// for heuristic normalization attempt
  let urlToParse = raw;
  let protocolImplicit = false;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(urlToParse)) {
    urlToParse = `https://${urlToParse}`;
    protocolImplicit = true;
  }

  let parsed;
  try {
    parsed = new URL(urlToParse);
  } catch (err) {
    return {
      isValid: false,
      error: `Malformed URL structure: ${err.message}`,
      raw,
      normalized: '',
      hasAtSymbol,
    };
  }

  // Ensure protocol is valid HTTP or HTTPS
  const protocol = parsed.protocol.toLowerCase();
  if (!SUPPORTED_PROTOCOLS.has(protocol)) {
    return {
      isValid: false,
      error: `Unsupported or dangerous URL protocol: "${parsed.protocol}". Only HTTP and HTTPS are permitted.`,
      raw,
      normalized: parsed.href,
      protocol: parsed.protocol,
      hasAtSymbol,
    };
  }

  // Normalize hostname: lowercase, remove trailing dots
  let hostname = parsed.hostname.toLowerCase();
  if (hostname.endsWith('.')) {
    hostname = hostname.slice(0, -1);
  }

  if (!hostname) {
    return {
      isValid: false,
      error: 'URL is missing a valid hostname.',
      raw,
      normalized: '',
      hasAtSymbol,
    };
  }

  // Normalize port
  let port = parsed.port;
  if ((protocol === 'http:' && port === '80') || (protocol === 'https:' && port === '443')) {
    port = '';
  }

  // Normalize pathname: collapse consecutive slashes
  let pathname = parsed.pathname || '/';
  pathname = pathname.replace(/\/+/g, '/');

  const search = parsed.search || '';
  const hash = parsed.hash || '';

  // Construct canonical normalized URL
  const portSuffix = port ? `:${port}` : '';
  const normalized = `${protocol}//${hostname}${portSuffix}${pathname}${search}${hash}`;

  const { subdomains, registeredDomain, tld } = parseDomainHierarchy(hostname);

  return {
    isValid: true,
    error: null,
    raw,
    normalized,
    protocol,
    protocolImplicit,
    hostname,
    port,
    pathname,
    search,
    hash,
    subdomains,
    registeredDomain,
    tld,
    hasAtSymbol,
    userinfo: parsed.username || parsed.password ? `${parsed.username}:${parsed.password}` : null,
  };
}
