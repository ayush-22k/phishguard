/**
 * PhishGuard URL Analysis Engine
 * Deterministic, explainable heuristic analyzer for detecting phishing and malicious URLs.
 */

import { normalizeUrl } from './normalizer.js';
import { extractFeatures } from './features.js';
import { FEATURE_WEIGHTS, RISK_THRESHOLDS, CLASSIFICATIONS, SEVERITIES } from './weights.js';
import { calculateConfidence } from './confidence.js';

/**
 * Classifies a numerical risk score into SAFE, SUSPICIOUS, or MALICIOUS.
 */
function classifyScore(score) {
  if (score <= RISK_THRESHOLDS.SAFE_MAX) {
    return CLASSIFICATIONS.SAFE;
  }
  if (score <= RISK_THRESHOLDS.SUSPICIOUS_MAX) {
    return CLASSIFICATIONS.SUSPICIOUS;
  }
  return CLASSIFICATIONS.MALICIOUS;
}

/**
 * Generates an explainable summary text based on classification and indicators.
 */
function generateSummary(classification, riskScore, indicators) {
  if (indicators.length === 0) {
    return 'No suspicious structural or lexical indicators detected. The URL conforms to standard benign web conventions.';
  }

  const highSeverityCount = indicators.filter((i) => i.severity === SEVERITIES.HIGH || i.severity === SEVERITIES.CRITICAL).length;

  if (classification === CLASSIFICATIONS.MALICIOUS) {
    return `Identified high-risk indicators (${highSeverityCount} critical/high severity) indicating strong potential for phishing, impersonation, or deceptive intent.`;
  }

  if (classification === CLASSIFICATIONS.SUSPICIOUS) {
    return `Detected ${indicators.length} structural or lexical anomalies that warrant caution before interacting with this destination.`;
  }

  return `URL exhibits standard benign characteristics with minor non-threatening indicators. Low risk.`;
}

/**
 * Evaluates features against heuristic rules to produce risk score and indicators.
 */
function evaluateRules(normalized, features) {
  const indicators = [];
  let score = 0;

  function addIndicator(weightConfig, dynamicMessage) {
    indicators.push({
      type: weightConfig.type,
      severity: weightConfig.severity,
      message: dynamicMessage || weightConfig.message,
    });
    score += weightConfig.weight;
  }

  // 1. IP Host
  if (features.isIpHost) {
    addIndicator(FEATURE_WEIGHTS.IP_HOST);
  }

  // 2. Insecure HTTP
  if (features.isHttp) {
    addIndicator(FEATURE_WEIGHTS.INSECURE_HTTP);
  }

  // 3. High-risk or Suspicious Ports
  if (features.isHighRiskPort) {
    addIndicator(
      FEATURE_WEIGHTS.HIGH_RISK_PORT,
      `The URL specifies a high-risk administrative port (${features.port}).`
    );
  } else if (features.isSuspiciousWebPort) {
    addIndicator(
      FEATURE_WEIGHTS.SUSPICIOUS_WEB_PORT,
      `The URL specifies a non-standard web port (${features.port}).`
    );
  }

  // 4. @ Symbol Impersonation
  if (features.hasAtSymbol) {
    addIndicator(FEATURE_WEIGHTS.AT_SYMBOL);
  }

  // 5. Punycode (IDN homograph attack)
  if (features.isPunycode) {
    addIndicator(FEATURE_WEIGHTS.PUNYCODE_DOMAIN);
  }

  // 6. Obfuscation & Encoded Characters
  if (features.suspiciousEncodedChars.includes('NULL_BYTE')) {
    addIndicator(FEATURE_WEIGHTS.SUSPICIOUS_ENCODING_NULL_BYTE);
  }

  const controlChars = features.suspiciousEncodedChars.filter((c) => c !== 'NULL_BYTE');
  if (controlChars.length > 0) {
    addIndicator(
      FEATURE_WEIGHTS.SUSPICIOUS_ENCODING_CHARS,
      `The URL contains suspicious encoded control sequences: ${controlChars.join(', ')}.`
    );
  }

  if (features.percentEncodingCount >= 5) {
    addIndicator(FEATURE_WEIGHTS.HIGH_PERCENT_ENCODING);
  }

  // 7. Structural Anomalies
  if (features.excessiveHyphens) {
    addIndicator(FEATURE_WEIGHTS.EXCESSIVE_HYPHENS);
  }

  if (features.excessiveDots) {
    addIndicator(FEATURE_WEIGHTS.EXCESSIVE_DOTS);
  }

  if (features.subdomainCount >= 3) {
    addIndicator(
      FEATURE_WEIGHTS.EXCESSIVE_SUBDOMAINS,
      `The domain contains ${features.subdomainCount} subdomains, suggesting potential host obfuscation.`
    );
  }

  if (features.urlLength > 150) {
    addIndicator(FEATURE_WEIGHTS.EXCESSIVE_URL_LENGTH);
  }

  if (features.hostnameLength > 45) {
    addIndicator(FEATURE_WEIGHTS.EXCESSIVE_HOST_LENGTH);
  }

  if (features.pathDepth >= 6) {
    addIndicator(FEATURE_WEIGHTS.EXCESSIVE_PATH_DEPTH);
  }

  // 8. Semantic Credential Keywords (Contextualized to prevent false positives)
  if (features.domainKeywords.length > 0) {
    addIndicator(
      FEATURE_WEIGHTS.DOMAIN_CREDENTIAL_KEYWORD,
      `The domain name incorporates sensitive keyword(s): ${features.domainKeywords.join(', ')}.`
    );
  }

  if (features.subdomainKeywords.length > 0) {
    addIndicator(
      FEATURE_WEIGHTS.SUBDOMAIN_CREDENTIAL_KEYWORD,
      `Subdomain hierarchy incorporates sensitive keyword(s): ${features.subdomainKeywords.join(', ')}.`
    );
  }

  // Credential keyword in path
  if (features.pathKeywords.length > 0) {
    // If the host is an untrusted IP or plain HTTP or uses excessive hyphens, escalate risk!
    if (features.isIpHost || features.isHttp || features.excessiveHyphens) {
      addIndicator(
        FEATURE_WEIGHTS.CREDENTIAL_KEYWORD_ON_UNTRUSTED_HOST,
        `Authentication keyword (${features.pathKeywords.join(', ')}) found on an unencrypted or untrusted host.`
      );
    } else {
      // Standard HTTPS domain with /login or /accounts: minor low-weight indicator (5 pts)
      addIndicator(
        FEATURE_WEIGHTS.PATH_CREDENTIAL_KEYWORD,
        `Path includes standard authentication keyword: ${features.pathKeywords.join(', ')}.`
      );
    }
  }

  // 9. Query & Redirection
  if (features.redirectParams.length > 0) {
    const keys = features.redirectParams.map((p) => p.key).join(', ');
    addIndicator(
      FEATURE_WEIGHTS.OPEN_REDIRECT_PARAM,
      `URL query contains redirect target parameter(s): ${keys}.`
    );
  }

  if (features.hasBase64InQuery) {
    addIndicator(FEATURE_WEIGHTS.BASE64_IN_QUERY);
  }

  return { score, indicators };
}

/**
 * Main URL analysis entry point.
 * Never throws an unhandled error; safely handles all malformed inputs.
 *
 * @param {string} rawUrl - Untrusted URL input from user
 * @returns {Object} Structured analysis result
 */
export function analyzeUrl(rawUrl) {
  // Step 1: Normalization & Validation
  const normalized = normalizeUrl(rawUrl);

  // Handle malformed or unsupported URLs safely
  if (!normalized.isValid) {
    const isDangerousScheme = normalized.protocol && !['http:', 'https:'].includes(normalized.protocol.toLowerCase());
    const score = isDangerousScheme ? 70 : 40;
    const classification = classifyScore(score);

    return {
      url: {
        raw: typeof rawUrl === 'string' ? rawUrl : '',
        normalized: '',
      },
      isValid: false,
      riskScore: score,
      classification,
      confidence: 95,
      indicators: [
        {
          type: isDangerousScheme ? 'DANGEROUS_PROTOCOL' : 'MALFORMED_URL',
          severity: isDangerousScheme ? SEVERITIES.CRITICAL : SEVERITIES.HIGH,
          message: normalized.error || 'The supplied URL could not be parsed into a valid web destination.',
        },
      ],
      features: null,
      explanation: normalized.error || 'Invalid URL structure.',
    };
  }

  // Step 2: Feature Extraction
  const features = extractFeatures(normalized);

  // Step 3 & 4: Heuristic Scoring & Indicator Generation
  const { score: rawScore, indicators } = evaluateRules(normalized, features);

  // Step 5: Risk Aggregation (Bounded strictly between 0 and 100)
  const riskScore = Math.min(100, Math.max(0, Math.round(rawScore)));

  // Step 6: Classification
  const classification = classifyScore(riskScore);

  // Step 7: Confidence Calculation
  const confidence = calculateConfidence(normalized, features, indicators, riskScore);

  // Step 8: Explanation Generation
  const explanation = generateSummary(classification, riskScore, indicators);

  return {
    url: {
      raw: normalized.raw,
      normalized: normalized.normalized,
      protocol: normalized.protocol,
      hostname: normalized.hostname,
      port: normalized.port,
      pathname: normalized.pathname,
      search: normalized.search,
    },
    isValid: true,
    riskScore,
    classification,
    confidence,
    indicators,
    features,
    explanation,
  };
}

export { normalizeUrl } from './normalizer.js';
export { extractFeatures } from './features.js';
export { FEATURE_WEIGHTS, RISK_THRESHOLDS, CLASSIFICATIONS, SEVERITIES } from './weights.js';
export { calculateConfidence } from './confidence.js';

