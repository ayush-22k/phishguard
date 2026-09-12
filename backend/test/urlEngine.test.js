import assert from 'node:assert/strict';
import test from 'node:test';
import {
  analyzeUrl,
  normalizeUrl,
  extractFeatures,
  FEATURE_WEIGHTS,
  RISK_THRESHOLDS,
  CLASSIFICATIONS,
} from '../src/engine/url/index.js';

test('URL Analysis Engine - Normal benign HTTPS URLs', () => {
  const result = analyzeUrl('https://www.example.com');
  assert.equal(result.isValid, true);
  assert.equal(result.classification, CLASSIFICATIONS.SAFE);
  assert.ok(result.riskScore <= RISK_THRESHOLDS.SAFE_MAX);
  assert.equal(result.indicators.length, 0);
  assert.ok(result.confidence >= 80);
});

test('URL Analysis Engine - Benign URLs containing sensitive/suspicious words remain SAFE', () => {
  // Test case 1: GitHub login
  const githubResult = analyzeUrl('https://github.com/login');
  assert.equal(githubResult.isValid, true);
  assert.equal(githubResult.classification, CLASSIFICATIONS.SAFE);
  assert.ok(githubResult.riskScore <= RISK_THRESHOLDS.SAFE_MAX);
  // Verify it did not flag high severity
  const hasHighSeverity = githubResult.indicators.some((i) => i.severity === 'HIGH' || i.severity === 'CRITICAL');
  assert.equal(hasHighSeverity, false);

  // Test case 2: Google Accounts support page
  const googleResult = analyzeUrl('https://support.google.com/accounts/answer/12345');
  assert.equal(googleResult.isValid, true);
  assert.equal(googleResult.classification, CLASSIFICATIONS.SAFE);
  assert.ok(googleResult.riskScore <= RISK_THRESHOLDS.SAFE_MAX);

  // Test case 3: Standard portal on reputable HTTPS
  const portalResult = analyzeUrl('https://developer.mozilla.org/en-US/docs/Web/Security');
  assert.equal(portalResult.isValid, true);
  assert.equal(portalResult.classification, CLASSIFICATIONS.SAFE);
  assert.ok(portalResult.riskScore <= RISK_THRESHOLDS.SAFE_MAX);
});

test('URL Analysis Engine - Insecure HTTP URL detection', () => {
  const result = analyzeUrl('http://www.insecure-site.org/about');
  assert.equal(result.isValid, true);
  const httpIndicator = result.indicators.find((i) => i.type === 'INSECURE_HTTP');
  assert.ok(httpIndicator);
  assert.equal(httpIndicator.severity, 'LOW');
  // Plain HTTP alone should not make a normal site malicious
  assert.ok(result.riskScore < RISK_THRESHOLDS.SUSPICIOUS_MAX);
});

test('URL Analysis Engine - IP address hostname with authentication target', () => {
  const result = analyzeUrl('http://192.168.1.100/admin/login');
  assert.equal(result.isValid, true);
  assert.equal(result.classification, CLASSIFICATIONS.MALICIOUS);
  assert.ok(result.riskScore >= 60);

  const ipIndicator = result.indicators.find((i) => i.type === 'IP_HOST');
  assert.ok(ipIndicator);
  assert.equal(ipIndicator.severity, 'HIGH');

  const untrustedAuth = result.indicators.find((i) => i.type === 'CREDENTIAL_KEYWORD_ON_UNTRUSTED_HOST');
  assert.ok(untrustedAuth);
});

test('URL Analysis Engine - Non-standard and high-risk ports', () => {
  // Telnet port
  const telnetResult = analyzeUrl('http://attacker.com:23/exploit');
  assert.equal(telnetResult.isValid, true);
  const highRiskPort = telnetResult.indicators.find((i) => i.type === 'HIGH_RISK_PORT');
  assert.ok(highRiskPort);
  assert.equal(highRiskPort.severity, 'HIGH');

  // Alternative web port
  const webPortResult = analyzeUrl('http://internal-test.local:8080/dashboard');
  assert.equal(webPortResult.isValid, true);
  const webPort = webPortResult.indicators.find((i) => i.type === 'SUSPICIOUS_WEB_PORT');
  assert.ok(webPort);
});

test('URL Analysis Engine - Obfuscation via @ symbol userinfo disguise', () => {
  const result = analyzeUrl('http://google.com@phishing-target.com/secure');
  assert.equal(result.isValid, true);
  assert.ok(result.riskScore >= RISK_THRESHOLDS.SUSPICIOUS_MAX);

  const atIndicator = result.indicators.find((i) => i.type === 'AT_SYMBOL');
  assert.ok(atIndicator);
  assert.equal(atIndicator.severity, 'HIGH');
});

test('URL Analysis Engine - Punycode (IDN homograph attack indicator)', () => {
  // xn--pple-43d.com (apple.com with Cyrillic characters)
  const result = analyzeUrl('https://xn--pple-43d.com/verification');
  assert.equal(result.isValid, true);

  const punyIndicator = result.indicators.find((i) => i.type === 'PUNYCODE_DOMAIN');
  assert.ok(punyIndicator);
  assert.equal(punyIndicator.severity, 'MEDIUM');
  assert.ok(result.riskScore >= 30);
});

test('URL Analysis Engine - Suspicious encoded characters and null bytes', () => {
  // Null byte evasion
  const nullByteResult = analyzeUrl('http://phish.com/invoice.pdf%00.exe');
  assert.equal(nullByteResult.isValid, true);
  const nullByteIndicator = nullByteResult.indicators.find((i) => i.type === 'SUSPICIOUS_ENCODING');
  assert.ok(nullByteIndicator);
  assert.equal(nullByteIndicator.severity, 'CRITICAL');

  // Double percent encoding and encoded slashes
  const encodedResult = analyzeUrl('http://example.com/%252e%252e/%2fadmin');
  assert.equal(encodedResult.isValid, true);
  const encodingIndicator = encodedResult.indicators.find((i) => i.type === 'SUSPICIOUS_ENCODING');
  assert.ok(encodingIndicator);
});

test('URL Analysis Engine - Excessive hyphens, dots, and subdomains', () => {
  const result = analyzeUrl('https://login.secure.update.paypal-security-verification.com/account');
  assert.equal(result.isValid, true);
  assert.ok(result.riskScore >= 30);

  const hyphens = result.indicators.find((i) => i.type === 'EXCESSIVE_HYPHENS');
  assert.ok(hyphens);

  const subdomains = result.indicators.find((i) => i.type === 'EXCESSIVE_SUBDOMAINS');
  assert.ok(subdomains);

  const subdomainKeywords = result.indicators.find((i) => i.type === 'SUBDOMAIN_CREDENTIAL_KEYWORD');
  assert.ok(subdomainKeywords);
});

test('URL Analysis Engine - Open redirect parameters and Base64 in query', () => {
  const b64 = Buffer.from('https://evil-site.com/steal-creds').toString('base64');
  const result = analyzeUrl(`https://vulnerable.com/out?redirect=https://target.com&data=${b64}`);
  assert.equal(result.isValid, true);

  const redirectIndicator = result.indicators.find((i) => i.type === 'OPEN_REDIRECT_PARAM');
  assert.ok(redirectIndicator);

  const b64Indicator = result.indicators.find((i) => i.type === 'BASE64_IN_QUERY');
  assert.ok(b64Indicator);
});

test('URL Analysis Engine - Abnormally long URLs and deep paths', () => {
  const longPath = '/segment'.repeat(10);
  const longQuery = '?param=' + 'A'.repeat(160);
  const result = analyzeUrl(`https://legit-service.com${longPath}${longQuery}`);
  assert.equal(result.isValid, true);

  const lenIndicator = result.indicators.find((i) => i.type === 'EXCESSIVE_URL_LENGTH');
  assert.ok(lenIndicator);

  const depthIndicator = result.indicators.find((i) => i.type === 'EXCESSIVE_PATH_DEPTH');
  assert.ok(depthIndicator);
});

test('URL Analysis Engine - Malformed and unsupported URLs fail safely', () => {
  // Empty or invalid types
  const emptyResult = analyzeUrl('');
  assert.equal(emptyResult.isValid, false);
  assert.ok(emptyResult.indicators.length > 0);

  // Unparseable garbage
  const garbageResult = analyzeUrl('http://///');
  assert.equal(garbageResult.isValid, false);
  assert.equal(garbageResult.indicators[0].type, 'MALFORMED_URL');

  // Dangerous protocol scheme
  const jsResult = analyzeUrl('javascript:alert("XSS")');
  assert.equal(jsResult.isValid, false);
  assert.equal(jsResult.classification, CLASSIFICATIONS.MALICIOUS);
  assert.equal(jsResult.indicators[0].type, 'DANGEROUS_PROTOCOL');

  // Data URI scheme
  const dataResult = analyzeUrl('data:text/html,<script>alert(1)</script>');
  assert.equal(dataResult.isValid, false);
  assert.equal(dataResult.classification, CLASSIFICATIONS.MALICIOUS);
});

test('URL Analysis Engine - Confidence calculation is deterministic and distinct from risk score', () => {
  const result1 = analyzeUrl('https://example.com');
  const result2 = analyzeUrl('http://192.168.1.1/login');

  // Low risk URL has high confidence of being safe
  assert.equal(result1.riskScore, 0);
  assert.ok(result1.confidence >= 80);

  // High risk URL has high confidence of being malicious
  assert.ok(result2.riskScore >= 60);
  assert.ok(result2.confidence >= 85);

  // Confidence is an integer bounded strictly between 0 and 100
  assert.ok(result1.confidence >= 0 && result1.confidence <= 100);
  assert.ok(result2.confidence >= 0 && result2.confidence <= 100);
});

