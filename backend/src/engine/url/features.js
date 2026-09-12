/**
 * PhishGuard Feature Extractor
 * Extracts deterministic structural, lexical, and semantic heuristics from a normalized URL.
 */

// Suspicious security, credential, and banking terms often exploited in phishing
const CREDENTIAL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in',
  'verify', 'verification', 'update', 'upgrade',
  'secure', 'security', 'account', 'banking',
  'wallet', 'confirm', 'password', 'credential',
  'authenticate', 'recover', 'billing', 'invoice',
  'support', 'helpdesk', 'webmail', 'portal',
];

// Open redirect parameter keys frequently used in phishing campaigns
const REDIRECT_PARAM_KEYS = new Set([
  'redirect', 'redirect_uri', 'redirect_url', 'return', 'return_url',
  'url', 'dest', 'destination', 'target', 'next', 'r', 'out', 'link',
  'goto', 'forward', 'relay', 'checkout_url',
]);

// Non-standard or high-risk web ports
const HIGH_RISK_PORTS = new Set([
  '21',   // FTP
  '22',   // SSH
  '23',   // Telnet
  '25',   // SMTP
  '53',   // DNS
  '110',  // POP3
  '143',  // IMAP
  '3389', // RDP
  '6667', // IRC
  '1337', // Hacker trope / unassigned
]);

const SUSPICIOUS_WEB_PORTS = new Set([
  '8080', '8000', '8888', '8443', '3000', '5000', '9000', '9090',
]);

/**
 * Detects whether the hostname is an IPv4 or IPv6 address.
 * Covers standard dotted decimal, octal, hex, and IPv6 brackets.
 */
function isIpAddress(hostname) {
  if (!hostname) return false;

  // Standard IPv4 dotted-decimal
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Pattern.test(hostname)) {
    const octets = hostname.split('.').map(Number);
    return octets.every((octet) => octet >= 0 && octet <= 255);
  }

  // IPv6 bracketed format
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    return true;
  }

  // Hexadecimal (e.g. 0x7f000001) or Decimal IP integer representations (e.g. 2130706433)
  if (/^0x[0-9a-fA-F]{8}$/.test(hostname) || /^\d{8,11}$/.test(hostname)) {
    return true;
  }

  return false;
}

/**
 * Identifies suspicious encoded sequences that indicate obfuscation attempts.
 */
function detectSuspiciousEncoding(rawUrl) {
  const encodings = [];
  const lower = rawUrl.toLowerCase();

  if (lower.includes('%00')) encodings.push('NULL_BYTE');
  if (lower.includes('%2f') || lower.includes('%5c')) encodings.push('ENCODED_SLASH');
  if (lower.includes('%2e')) encodings.push('ENCODED_DOT');
  if (lower.includes('%40')) encodings.push('ENCODED_AT');
  if (lower.includes('%25')) encodings.push('DOUBLE_PERCENT');
  if (lower.includes('%20')) encodings.push('ENCODED_SPACE');

  return encodings;
}

/**
 * Checks for Base64 formatted parameter values (often used to pass stolen credentials or destination URLs).
 */
function detectBase64InQuery(searchParams) {
  const base64Regex = /^[A-Za-z0-9+/]{24,}={0,2}$/;
  for (const [, value] of searchParams.entries()) {
    if (value.length >= 24 && base64Regex.test(value)) {
      return true;
    }
  }
  return false;
}

/**
 * Extracts all features from a normalized URL descriptor.
 */
export function extractFeatures(normalized) {
  if (!normalized || !normalized.isValid) {
    return {
      isValid: false,
      urlLength: normalized?.raw?.length || 0,
      hostnameLength: 0,
      pathLength: 0,
      queryLength: 0,
      subdomainCount: 0,
      pathDepth: 0,
      isIpHost: false,
      isHttp: false,
      isHttps: false,
      port: '',
      hasPort: false,
      isHighRiskPort: false,
      isSuspiciousWebPort: false,
      hasAtSymbol: normalized?.hasAtSymbol || false,
      excessiveDots: false,
      excessiveHyphens: false,
      percentEncodingCount: 0,
      suspiciousEncodedChars: [],
      isPunycode: false,
      subdomainKeywords: [],
      domainKeywords: [],
      pathKeywords: [],
      queryKeywords: [],
      redirectParams: [],
      hasBase64InQuery: false,
      queryParamCount: 0,
    };
  }

  const { raw, protocol, hostname, port, pathname, search, subdomains, registeredDomain } = normalized;

  // Length measurements
  const urlLength = raw.length;
  const hostnameLength = hostname.length;
  const pathLength = pathname.length;
  const queryLength = search.length;

  // Structural counts
  const subdomainCount = subdomains.length;
  const pathSegments = pathname.split('/').filter(Boolean);
  const pathDepth = pathSegments.length;

  // Host & Protocol
  const isIpHost = isIpAddress(hostname);
  const isHttp = protocol === 'http:';
  const isHttps = protocol === 'https:';

  // Port checks
  const hasPort = Boolean(port);
  const isHighRiskPort = hasPort && HIGH_RISK_PORTS.has(port);
  const isSuspiciousWebPort = hasPort && SUSPICIOUS_WEB_PORTS.has(port);

  // Character frequency checks
  const dotCountInHost = (hostname.match(/\./g) || []).length;
  const totalDotCount = (raw.match(/\./g) || []).length;
  const excessiveDots = (!isIpHost && dotCountInHost >= 3) || totalDotCount >= 5;

  const hyphenCountInHost = (hostname.match(/-/g) || []).length;
  const excessiveHyphens = hyphenCountInHost >= 2;

  // Obfuscation and Encoding
  const percentMatches = raw.match(/%[0-9a-fA-F]{2}/g) || [];
  const percentEncodingCount = percentMatches.length;
  const suspiciousEncodedChars = detectSuspiciousEncoding(raw);

  // Punycode (IDN homograph attack)
  const isPunycode = hostname.includes('xn--');

  // Lexical & Credential Keyword Analysis
  const lowerSubdomains = subdomains.join('.').toLowerCase();
  const lowerDomain = (registeredDomain || '').toLowerCase();
  const lowerPath = pathname.toLowerCase();
  const lowerQuery = search.toLowerCase();

  const subdomainKeywords = CREDENTIAL_KEYWORDS.filter((kw) => lowerSubdomains.includes(kw));
  const domainKeywords = CREDENTIAL_KEYWORDS.filter((kw) => lowerDomain.includes(kw));
  const pathKeywords = CREDENTIAL_KEYWORDS.filter((kw) => lowerPath.includes(kw));
  const queryKeywords = CREDENTIAL_KEYWORDS.filter((kw) => lowerQuery.includes(kw));

  // Query Parameter analysis
  let redirectParams = [];
  let hasBase64InQuery = false;
  let queryParamCount = 0;

  if (search && search.length > 1) {
    try {
      const searchParams = new URLSearchParams(search);
      queryParamCount = Array.from(searchParams.keys()).length;

      for (const [key, value] of searchParams.entries()) {
        const lowerKey = key.toLowerCase();
        if (REDIRECT_PARAM_KEYS.has(lowerKey)) {
          redirectParams.push({ key, value });
        }
      }

      hasBase64InQuery = detectBase64InQuery(searchParams);
    } catch {
      // If query cannot be parsed by URLSearchParams, fallback safely
    }
  }

  return {
    isValid: true,
    urlLength,
    hostnameLength,
    pathLength,
    queryLength,
    subdomainCount,
    pathDepth,
    isIpHost,
    isHttp,
    isHttps,
    port,
    hasPort,
    isHighRiskPort,
    isSuspiciousWebPort,
    hasAtSymbol: normalized.hasAtSymbol,
    excessiveDots,
    excessiveHyphens,
    percentEncodingCount,
    suspiciousEncodedChars,
    isPunycode,
    subdomainKeywords,
    domainKeywords,
    pathKeywords,
    queryKeywords,
    redirectParams,
    hasBase64InQuery,
    queryParamCount,
  };
}

