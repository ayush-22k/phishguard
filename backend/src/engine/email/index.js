/**
 * PhishGuard Email Analysis Engine
 * Deterministic, explainable heuristic analyzer for phishing emails.
 */

import { extractUrlsFromText } from './extractor.js';
import { extractEmailFeatures } from './features.js';
import { EMAIL_FEATURE_WEIGHTS, RISK_THRESHOLDS, CLASSIFICATIONS } from './weights.js';
import { analyzeUrl } from '../url/index.js';

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
 * Evaluates semantic email features against heuristic weights.
 */
function evaluateEmailRules(features) {
  const indicators = [];
  let score = 0;

  function addIndicator(weightConfig) {
    indicators.push({
      type: weightConfig.type,
      severity: weightConfig.severity,
      message: weightConfig.message,
    });
    score += weightConfig.weight;
  }

  if (features.hasUrgency) addIndicator(EMAIL_FEATURE_WEIGHTS.URGENCY);
  if (features.hasCredentialRequest) addIndicator(EMAIL_FEATURE_WEIGHTS.CREDENTIAL_REQUEST);
  if (features.hasAccountSuspension) addIndicator(EMAIL_FEATURE_WEIGHTS.ACCOUNT_SUSPENSION);
  if (features.hasPaymentRequest) addIndicator(EMAIL_FEATURE_WEIGHTS.PAYMENT_REQUEST);
  if (features.hasIdentityVerification) addIndicator(EMAIL_FEATURE_WEIGHTS.IDENTITY_VERIFICATION);
  if (features.hasSuspiciousCta) addIndicator(EMAIL_FEATURE_WEIGHTS.SUSPICIOUS_CTA);
  if (features.hasBrandImpersonation) addIndicator(EMAIL_FEATURE_WEIGHTS.BRAND_IMPERSONATION);

  return { score, indicators };
}

/**
 * Generates an explainable summary text.
 */
function generateSummary(classification, emailIndicators, parsedUrls) {
  const maliciousUrls = parsedUrls.filter(u => u.classification === CLASSIFICATIONS.MALICIOUS);
  const suspiciousUrls = parsedUrls.filter(u => u.classification === CLASSIFICATIONS.SUSPICIOUS);

  if (classification === CLASSIFICATIONS.MALICIOUS) {
    if (maliciousUrls.length > 0) {
      return `CRITICAL: Email contains ${maliciousUrls.length} malicious URL(s) alongside ${emailIndicators.length} social-engineering indicator(s).`;
    }
    return `CRITICAL: Strong social-engineering and credential-theft patterns detected, escalating risk to malicious levels.`;
  }

  if (classification === CLASSIFICATIONS.SUSPICIOUS) {
    if (suspiciousUrls.length > 0) {
      return `WARNING: Email contains suspicious links and phishing-related language. Proceed with caution.`;
    }
    return `WARNING: Email contains suspicious language patterns often used in phishing, such as urgency or identity verification.`;
  }

  return 'Email appears safe. No malicious URLs or strong phishing semantics detected.';
}

/**
 * Calculates email confidence deterministically.
 */
function calculateEmailConfidence(emailScore, emailIndicators, parsedUrls, finalRiskScore) {
  let confidence = 60; // Base confidence

  // Corroboration: If email semantics AND a URL both flag as suspicious/malicious, confidence is very high.
  const hasSuspiciousEmail = emailScore > 0;
  const maxUrlScore = parsedUrls.length > 0 ? Math.max(...parsedUrls.map(u => u.riskScore)) : 0;

  if (hasSuspiciousEmail && maxUrlScore >= 30) {
    confidence += 25; // Strong corroboration
  } else if (parsedUrls.length > 0) {
    // Average out URL confidences
    const urlConf = parsedUrls.reduce((acc, u) => acc + u.confidence, 0) / parsedUrls.length;
    confidence = (confidence + urlConf) / 2;
  }

  // Clear benign certainty
  if (emailIndicators.length === 0 && maxUrlScore === 0) {
    confidence += 20;
  }

  // Extremely high scores are generally highly confident detections
  if (finalRiskScore >= 80) {
    confidence += 15;
  }

  return Math.min(100, Math.max(0, Math.round(confidence)));
}

/**
 * Main Email Analysis Entry Point
 * 
 * @param {Object} input - { subject: string, body: string }
 * @returns {Object} Structured analysis result
 */
export function analyzeEmail(input) {
  if (!input || (typeof input.subject !== 'string' && typeof input.body !== 'string')) {
    return {
      isValid: false,
      riskScore: 0,
      classification: CLASSIFICATIONS.SAFE,
      confidence: 95,
      emailIndicators: [],
      urlIndicators: [],
      explanation: 'Invalid or empty email input provided.',
    };
  }

  const subject = input.subject || '';
  const body = input.body || '';

  // 1. Extract Email Features & Score Semantic Content
  const features = extractEmailFeatures(subject, body);
  const { score: emailScore, indicators: emailIndicators } = evaluateEmailRules(features);

  // 2. Extract and Analyze URLs
  const rawUrls = extractUrlsFromText(`${subject}\n${body}`);
  const parsedUrls = rawUrls.map(url => analyzeUrl(url));

  // 3. Aggregate URL Indicators & Max URL Score
  let maxUrlScore = 0;
  let allUrlIndicators = [];

  for (const result of parsedUrls) {
    if (result.riskScore > maxUrlScore) {
      maxUrlScore = result.riskScore;
    }
    // Attach the offending URL to the indicator for context
    const contextualizedIndicators = result.indicators.map(ind => ({
      ...ind,
      url: result.url.raw
    }));
    allUrlIndicators.push(...contextualizedIndicators);
  }

  // 4. Combined Risk Calculation
  // Transparent aggregation: Base semantic risk + Max embedded URL risk
  // This ensures a malicious URL instantly spikes the score, while semantic clues corroborate neutral URLs.
  const combinedRisk = Math.min(100, emailScore + maxUrlScore);

  // 5. Classification
  const classification = classifyScore(combinedRisk);

  // 6. Confidence Calculation
  const confidence = calculateEmailConfidence(emailScore, emailIndicators, parsedUrls, combinedRisk);

  // 7. Explanation
  const explanation = generateSummary(classification, emailIndicators, parsedUrls);

  return {
    isValid: true,
    classification,
    riskScore: combinedRisk,
    confidence,
    emailIndicators,
    urlIndicators: allUrlIndicators,
    explanation,
    metrics: {
      urlsFound: parsedUrls.length,
      semanticScore: emailScore,
      highestUrlScore: maxUrlScore,
    }
  };
}

