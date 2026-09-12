import assert from 'node:assert/strict';
import test from 'node:test';
import { analyzeEmail } from '../src/engine/email/index.js';
import { CLASSIFICATIONS, RISK_THRESHOLDS } from '../src/engine/email/weights.js';

test('Email Analysis Engine - Benign email', () => {
  const result = analyzeEmail({
    subject: 'Meeting notes',
    body: 'Hi team, just wanted to share the notes from our meeting today. Let me know if you have questions.',
  });
  
  assert.equal(result.isValid, true);
  assert.equal(result.classification, CLASSIFICATIONS.SAFE);
  assert.ok(result.riskScore <= RISK_THRESHOLDS.SAFE_MAX);
  assert.equal(result.emailIndicators.length, 0);
  assert.equal(result.urlIndicators.length, 0);
});

test('Email Analysis Engine - Suspicious email (keywords only, no URLs)', () => {
  const result = analyzeEmail({
    subject: 'Action Required: Update Your Information',
    body: 'Please verify your identity immediately to prevent account suspension.',
  });
  
  assert.equal(result.isValid, true);
  // Contains URGENCY, ACCOUNT_SUSPENSION, IDENTITY_VERIFICATION
  assert.equal(result.classification, CLASSIFICATIONS.SUSPICIOUS);
  assert.ok(result.riskScore > RISK_THRESHOLDS.SAFE_MAX);
  assert.ok(result.emailIndicators.length >= 3);
  assert.equal(result.urlIndicators.length, 0);
  assert.equal(result.metrics.urlsFound, 0);
});

test('Email Analysis Engine - Phishing email (keywords + malicious URL)', () => {
  const result = analyzeEmail({
    subject: 'PayPal Security Alert',
    body: 'Your account is suspended. Click here to verify your credentials: http://192.168.1.1/paypal/login',
  });
  
  assert.equal(result.isValid, true);
  assert.equal(result.classification, CLASSIFICATIONS.MALICIOUS);
  assert.ok(result.riskScore >= 60);
  
  assert.ok(result.emailIndicators.some(i => i.type === 'BRAND_IMPERSONATION'));
  assert.ok(result.emailIndicators.some(i => i.type === 'ACCOUNT_SUSPENSION'));
  
  // URL Indicators from Phase 2.4 should pass through
  assert.ok(result.urlIndicators.some(i => i.type === 'IP_HOST'));
  assert.ok(result.urlIndicators.some(i => i.type === 'INSECURE_HTTP'));
});

test('Email Analysis Engine - Email containing one benign URL', () => {
  const result = analyzeEmail({
    subject: 'Check this out',
    body: 'Read the new documentation at https://developer.mozilla.org/en-US/',
  });
  
  assert.equal(result.isValid, true);
  assert.equal(result.classification, CLASSIFICATIONS.SAFE);
  assert.equal(result.metrics.urlsFound, 1);
  assert.equal(result.urlIndicators.length, 0); // No high-risk URL indicators
});

test('Email Analysis Engine - Email containing multiple URLs (takes highest risk)', () => {
  const result = analyzeEmail({
    subject: 'Resources',
    body: 'Google: https://google.com\nEvil: http://google.com@phishing.com/secure',
  });
  
  assert.equal(result.isValid, true);
  assert.equal(result.metrics.urlsFound, 2);
  
  // The benign URL should be ignored in the final max URL score, the malicious one triggers it
  assert.ok(result.metrics.highestUrlScore >= 60);
  assert.equal(result.classification, CLASSIFICATIONS.MALICIOUS);
  assert.ok(result.urlIndicators.some(i => i.type === 'AT_SYMBOL'));
});

test('Email Analysis Engine - Malformed URLs in text fail safely', () => {
  const result = analyzeEmail({
    subject: 'Look',
    body: 'Go to javascript:alert(1) for free money',
  });
  
  assert.equal(result.isValid, true); // Email is valid even if URL inside is malformed
  assert.equal(result.metrics.urlsFound, 0); // Our extractor strictly targets http/https/www
});

test('Email Analysis Engine - Empty input', () => {
  const result = analyzeEmail({});
  assert.equal(result.isValid, false);
  assert.equal(result.classification, CLASSIFICATIONS.SAFE);
  assert.equal(result.riskScore, 0);
  
  const result2 = analyzeEmail({ subject: '', body: '   ' });
  assert.equal(result2.classification, CLASSIFICATIONS.SAFE);
});

test('Email Analysis Engine - Suspicious keywords without malicious URLs (e.g. valid support email)', () => {
  const result = analyzeEmail({
    subject: 'Reset your password',
    body: 'You requested a password reset. Click here: https://github.com/login/reset',
  });
  
  assert.equal(result.isValid, true);
  // Email has CREDENTIAL_REQUEST (25) + SUSPICIOUS_CTA (10) = 35 (SUSPICIOUS). 
  // URL is safe (5 pts for path keyword on HTTPS).
  // Total = 40 (SUSPICIOUS). It should NOT hit MALICIOUS because the URL is fully trusted.
  assert.equal(result.classification, CLASSIFICATIONS.SUSPICIOUS);
  assert.ok(result.riskScore < 60);
  assert.equal(result.metrics.highestUrlScore, 5); // 5 points for 'login' in path
});

test('Email Analysis Engine - Malicious URL with otherwise neutral email content', () => {
  const result = analyzeEmail({
    subject: 'Hello',
    body: 'Check this picture: http://192.168.1.1:8080/image.jpg%00.exe',
  });
  
  assert.equal(result.isValid, true);
  assert.equal(result.metrics.semanticScore, 0); // No email phishing keywords
  
  // URL has IP_HOST (35), INSECURE_HTTP (12), SUSPICIOUS_WEB_PORT (15), SUSPICIOUS_ENCODING_NULL_BYTE (45)
  // Total URL score > 100
  assert.ok(result.metrics.highestUrlScore >= 60);
  assert.equal(result.classification, CLASSIFICATIONS.MALICIOUS);
  assert.equal(result.riskScore, 100); // Clamped to 100
});

