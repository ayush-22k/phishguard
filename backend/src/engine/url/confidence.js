/**
 * PhishGuard Confidence Calculator
 * Deterministic calculation of assessment confidence, independent of the risk score.
 * 
 * Confidence reflects the certainty of the heuristic classification based on:
 * 1. Structural parseability and available analytical depth
 * 2. Indicator density and corroboration across independent feature categories
 * 3. Presence of definitive high-certainty signals (e.g. IP host, null bytes, @ trick)
 * 4. Distinctness from ambiguous edge cases (e.g. single generic keyword on standard HTTPS)
 */

/**
 * Calculates deterministic confidence score (0 - 100).
 *
 * @param {Object} normalized - Output of URL normalizer
 * @param {Object} features - Extracted features
 * @param {Array} indicators - Generated threat indicators
 * @param {number} rawRiskScore - Calculated risk score
 * @returns {number} Integer between 0 and 100
 */
export function calculateConfidence(normalized, features, indicators, rawRiskScore) {
  // If URL is completely malformed, we are highly confident that it is invalid input
  if (!normalized || !normalized.isValid) {
    return 95;
  }

  // Base confidence starts at 60 for any well-formed, successfully parsed URL
  let confidence = 60;

  // Factor 1: Structural completeness (+10)
  // Well-formed standard web protocol with registered domain
  if (normalized.registeredDomain && (normalized.protocol === 'https:' || normalized.protocol === 'http:')) {
    confidence += 10;
  }

  // Factor 2: Definitive high-certainty indicators (+15)
  // Certain features are unambiguous architectural anomalies
  const hasDefinitiveSignal = indicators.some((ind) =>
    ind.type === 'IP_HOST' ||
    ind.type === 'AT_SYMBOL' ||
    ind.type === 'SUSPICIOUS_ENCODING' ||
    ind.type === 'HIGH_RISK_PORT' ||
    ind.type === 'PUNYCODE_DOMAIN'
  );

  if (hasDefinitiveSignal) {
    confidence += 15;
  }

  // Factor 3: Multi-signal corroboration (+10)
  // Multiple independent indicators reinforcing each other
  if (indicators.length >= 3) {
    confidence += 10;
  } else if (indicators.length === 2) {
    confidence += 5;
  }

  // Factor 4: Clear benign certainty (+15)
  // If a URL is HTTPS, has no indicators, standard port, and simple domain
  if (indicators.length === 0 && features.isHttps && !features.hasPort) {
    confidence += 15;
  }

  // Factor 5: Ambiguity penalty (-15)
  // If the only indicator is a low-severity path keyword (e.g. /login on HTTPS)
  // or a single low-severity redirect parameter, reduce confidence slightly
  if (indicators.length === 1 && indicators[0].severity === 'LOW') {
    confidence -= 15;
  }

  // Clamp confidence strictly between 0 and 100
  return Math.min(100, Math.max(0, Math.round(confidence)));
}

