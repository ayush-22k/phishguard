/**
 * PhishGuard Email Scoring Weights & Thresholds
 * Centralized, configurable heuristic risk weights for email text analysis.
 */

export const SEVERITIES = Object.freeze({
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
});

// Reuse the same classification thresholds for consistency
export const RISK_THRESHOLDS = Object.freeze({
  SAFE_MAX: 29,
  SUSPICIOUS_MAX: 59,
});

export const CLASSIFICATIONS = Object.freeze({
  SAFE: 'SAFE',
  SUSPICIOUS: 'SUSPICIOUS',
  MALICIOUS: 'MALICIOUS',
});

export const EMAIL_FEATURE_WEIGHTS = Object.freeze({
  URGENCY: {
    weight: 15,
    severity: SEVERITIES.MEDIUM,
    type: 'URGENCY',
    message: 'The email uses urgent or time-sensitive language designed to provoke immediate action.',
  },
  CREDENTIAL_REQUEST: {
    weight: 25,
    severity: SEVERITIES.HIGH,
    type: 'CREDENTIAL_REQUEST',
    message: 'The email directly requests passwords, PINs, or login credentials.',
  },
  ACCOUNT_SUSPENSION: {
    weight: 20,
    severity: SEVERITIES.MEDIUM,
    type: 'ACCOUNT_SUSPENSION',
    message: 'The email threatens account suspension, restriction, or termination.',
  },
  PAYMENT_REQUEST: {
    weight: 15,
    severity: SEVERITIES.MEDIUM,
    type: 'PAYMENT_REQUEST',
    message: 'The email requests payment, wire transfers, or references overdue invoices.',
  },
  IDENTITY_VERIFICATION: {
    weight: 20,
    severity: SEVERITIES.MEDIUM,
    type: 'IDENTITY_VERIFICATION',
    message: 'The email asks the recipient to verify their identity or update account information.',
  },
  SUSPICIOUS_CTA: {
    weight: 10,
    severity: SEVERITIES.LOW,
    type: 'SUSPICIOUS_CTA',
    message: 'The email contains suspicious calls to action commonly used in phishing.',
  },
  BRAND_IMPERSONATION: {
    weight: 15,
    severity: SEVERITIES.MEDIUM,
    type: 'BRAND_IMPERSONATION',
    message: 'The email references highly targeted brands commonly spoofed in phishing attacks.',
  },
});

