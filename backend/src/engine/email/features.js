/**
 * PhishGuard Email Feature Extractor
 * Detects semantic social-engineering patterns in email text.
 */

const PATTERNS = {
  URGENCY: [
    /urgent/i, /immediate action/i, /within \d+ hours/i, /final notice/i,
    /action required/i, /immediately/i, /act now/i, /before it's too late/i
  ],
  CREDENTIAL_REQUEST: [
    /password/i, /login details/i, /credentials/i, /security phrase/i,
    /passcode/i, /one-time code/i, /recovery phrase/i
  ],
  ACCOUNT_SUSPENSION: [
    /suspend/i, /suspension/i, /lock/i, /terminate/i, /restrict/i, /unauthorized access/i,
    /account closed/i, /account disabled/i, /temporarily suspended/i
  ],
  PAYMENT_REQUEST: [
    /invoice/i, /payment overdue/i, /wire transfer/i, /gift card/i,
    /remittance/i, /outstanding balance/i, /unpaid/i, /crypto/i, /bitcoin/i
  ],
  IDENTITY_VERIFICATION: [
    /verify your identity/i, /confirm your account/i, /update your information/i,
    /verify account/i, /validate your/i, /confirm identity/i
  ],
  SUSPICIOUS_CTA: [
    /click here/i, /login below/i, /download attached/i, /secure link/i,
    /view document/i, /open attachment/i
  ],
  BRAND_IMPERSONATION: [
    /paypal/i, /apple/i, /microsoft/i, /amazon/i, /netflix/i,
    /bank of america/i, /chase/i, /wells fargo/i, /dhl/i, /fedex/i, /ups/i
  ]
};

/**
 * Helper to check if any regex in an array matches the text.
 */
function matchesAny(text, regexArray) {
  return regexArray.some((regex) => regex.test(text));
}

/**
 * Extracts semantic features from the combined email subject and body.
 * 
 * @param {string} subject - Email subject
 * @param {string} body - Email body
 * @returns {Object} Detected features
 */
export function extractEmailFeatures(subject, body) {
  const safeSubject = typeof subject === 'string' ? subject : '';
  const safeBody = typeof body === 'string' ? body : '';
  
  // Combine for global context searches
  const fullText = `${safeSubject}\n\n${safeBody}`;
  
  return {
    hasUrgency: matchesAny(fullText, PATTERNS.URGENCY),
    hasCredentialRequest: matchesAny(fullText, PATTERNS.CREDENTIAL_REQUEST),
    hasAccountSuspension: matchesAny(fullText, PATTERNS.ACCOUNT_SUSPENSION),
    hasPaymentRequest: matchesAny(fullText, PATTERNS.PAYMENT_REQUEST),
    hasIdentityVerification: matchesAny(fullText, PATTERNS.IDENTITY_VERIFICATION),
    hasSuspiciousCta: matchesAny(fullText, PATTERNS.SUSPICIOUS_CTA),
    hasBrandImpersonation: matchesAny(safeSubject, PATTERNS.BRAND_IMPERSONATION) || matchesAny(safeBody, PATTERNS.BRAND_IMPERSONATION),
  };
}
