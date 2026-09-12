/**
 * PhishGuard URL Scoring Weights & Thresholds
 * Centralized, configurable heuristic risk weights and classification criteria.
 */

export const RISK_THRESHOLDS = Object.freeze({
  SAFE_MAX: 29,
  SUSPICIOUS_MAX: 59,
  // 60 and above is classified as MALICIOUS
});

export const CLASSIFICATIONS = Object.freeze({
  SAFE: 'SAFE',
  SUSPICIOUS: 'SUSPICIOUS',
  MALICIOUS: 'MALICIOUS',
});

export const SEVERITIES = Object.freeze({
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
});

export const FEATURE_WEIGHTS = Object.freeze({
  // Host and Network Protocol
  IP_HOST: {
    weight: 35,
    severity: SEVERITIES.HIGH,
    type: 'IP_HOST',
    message: 'The URL uses an IP address instead of a standard registered domain name.',
  },
  INSECURE_HTTP: {
    weight: 12,
    severity: SEVERITIES.LOW,
    type: 'INSECURE_HTTP',
    message: 'The URL uses unencrypted HTTP instead of secure HTTPS.',
  },
  HIGH_RISK_PORT: {
    weight: 35,
    severity: SEVERITIES.HIGH,
    type: 'HIGH_RISK_PORT',
    message: 'The URL specifies a high-risk or non-standard administrative port.',
  },
  SUSPICIOUS_WEB_PORT: {
    weight: 15,
    severity: SEVERITIES.LOW,
    type: 'SUSPICIOUS_WEB_PORT',
    message: 'The URL specifies an alternative development or proxy port.',
  },

  // Obfuscation and Deception
  AT_SYMBOL: {
    weight: 40,
    severity: SEVERITIES.HIGH,
    type: 'AT_SYMBOL',
    message: 'The URL contains an "@" symbol used to obscure the true target destination.',
  },
  PUNYCODE_DOMAIN: {
    weight: 25,
    severity: SEVERITIES.MEDIUM,
    type: 'PUNYCODE_DOMAIN',
    message: 'The domain uses Punycode (xn--), which can be exploited for IDN homograph impersonation attacks.',
  },
  SUSPICIOUS_ENCODING_NULL_BYTE: {
    weight: 45,
    severity: SEVERITIES.CRITICAL,
    type: 'SUSPICIOUS_ENCODING',
    message: 'The URL contains an encoded null byte (%00) often used to bypass validation filters.',
  },
  SUSPICIOUS_ENCODING_CHARS: {
    weight: 20,
    severity: SEVERITIES.MEDIUM,
    type: 'SUSPICIOUS_ENCODING',
    message: 'The URL contains suspicious percent-encoded control characters or double encoding.',
  },
  HIGH_PERCENT_ENCODING: {
    weight: 15,
    severity: SEVERITIES.LOW,
    type: 'HIGH_PERCENT_ENCODING',
    message: 'The URL contains an unusually high frequency of percent-encoded characters.',
  },

  // Structural & Lexical Anomalies
  EXCESSIVE_HYPHENS: {
    weight: 20,
    severity: SEVERITIES.MEDIUM,
    type: 'EXCESSIVE_HYPHENS',
    message: 'The domain contains multiple hyphens, a common pattern in typosquatting and brand spoofing.',
  },
  EXCESSIVE_DOTS: {
    weight: 15,
    severity: SEVERITIES.LOW,
    type: 'EXCESSIVE_DOTS',
    message: 'The URL structure contains an excessive number of dot delimiters.',
  },
  EXCESSIVE_SUBDOMAINS: {
    weight: 15,
    severity: SEVERITIES.LOW,
    type: 'EXCESSIVE_SUBDOMAINS',
    message: 'The domain hierarchy contains an unusually deep chain of subdomains.',
  },
  EXCESSIVE_URL_LENGTH: {
    weight: 12,
    severity: SEVERITIES.LOW,
    type: 'EXCESSIVE_URL_LENGTH',
    message: 'The overall URL exceeds 150 characters, often used to conceal target parameters in mobile browsers.',
  },
  EXCESSIVE_HOST_LENGTH: {
    weight: 15,
    severity: SEVERITIES.LOW,
    type: 'EXCESSIVE_HOST_LENGTH',
    message: 'The hostname length is unusually long (>45 characters).',
  },
  EXCESSIVE_PATH_DEPTH: {
    weight: 10,
    severity: SEVERITIES.LOW,
    type: 'EXCESSIVE_PATH_DEPTH',
    message: 'The URL contains an abnormally deep directory path hierarchy.',
  },

  // Semantic Credential & Target Signals
  DOMAIN_CREDENTIAL_KEYWORD: {
    weight: 20,
    severity: SEVERITIES.MEDIUM,
    type: 'DOMAIN_CREDENTIAL_KEYWORD',
    message: 'The registered domain includes sensitive account, security, or banking terms.',
  },
  SUBDOMAIN_CREDENTIAL_KEYWORD: {
    weight: 18,
    severity: SEVERITIES.MEDIUM,
    type: 'SUBDOMAIN_CREDENTIAL_KEYWORD',
    message: 'A subdomain includes sensitive authentication, security, or account terms.',
  },
  PATH_CREDENTIAL_KEYWORD: {
    weight: 5,
    severity: SEVERITIES.LOW,
    type: 'PATH_CREDENTIAL_KEYWORD',
    message: 'The path contains authentication-related terms.',
  },
  CREDENTIAL_KEYWORD_ON_UNTRUSTED_HOST: {
    weight: 20,
    severity: SEVERITIES.HIGH,
    type: 'CREDENTIAL_KEYWORD_ON_UNTRUSTED_HOST',
    message: 'Authentication or security keywords were detected on an IP address or unencrypted host.',
  },

  // Query & Redirection Signals
  OPEN_REDIRECT_PARAM: {
    weight: 15,
    severity: SEVERITIES.LOW,
    type: 'OPEN_REDIRECT_PARAM',
    message: 'The query string contains parameters commonly used for open redirect exploitation.',
  },
  BASE64_IN_QUERY: {
    weight: 15,
    severity: SEVERITIES.MEDIUM,
    type: 'BASE64_IN_QUERY',
    message: 'The query string contains long Base64-encoded strings, commonly used to pass exfiltrated data or hidden targets.',
  },
});

