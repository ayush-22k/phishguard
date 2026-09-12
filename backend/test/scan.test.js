import assert from 'node:assert/strict';
import test from 'node:test';
import request from 'supertest';
import app from '../src/app.js';
import { query } from '../src/database/index.js';

let tokenA, tokenB;
let userIdA, userIdB;

test.before(async () => {
  await query('DELETE FROM users');
  await query('DELETE FROM scans');

  const resA = await request(app).post('/api/auth/register').send({
    name: 'Alice',
    email: 'alice@example.com',
    password: 'Password1234!',
  });
  userIdA = resA.body.data.user.id;

  const loginA = await request(app).post('/api/auth/login').send({
    email: 'alice@example.com',
    password: 'Password1234!',
  });
  tokenA = loginA.body.data.accessToken;

  const resB = await request(app).post('/api/auth/register').send({
    name: 'Bob',
    email: 'bob@example.com',
    password: 'Password1234!',
  });
  userIdB = resB.body.data.user.id;

  const loginB = await request(app).post('/api/auth/login').send({
    email: 'bob@example.com',
    password: 'Password1234!',
  });
  tokenB = loginB.body.data.accessToken;
});

test('Scan API - Unauthenticated requests fail (401)', async () => {
  const res = await request(app).post('/api/scans/url').send({ url: 'https://example.com' });
  assert.equal(res.status, 401);
});

test('Scan API - Invalid URL requests fail (400)', async () => {
  const res = await request(app)
    .post('/api/scans/url')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ url: '' });
  assert.equal(res.status, 400);

  const res2 = await request(app)
    .post('/api/scans/url')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ url: 'javascript:alert(1)' });
  assert.equal(res2.status, 400);
});

test('Scan API - Invalid Email requests fail (400)', async () => {
  const res = await request(app)
    .post('/api/scans/email')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({});
  assert.equal(res.status, 400);
});

let scanIdA;

test('Scan API - Authenticated URL scan succeeds and persists', async () => {
  const res = await request(app)
    .post('/api/scans/url')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ url: 'http://192.168.1.1/login' });

  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.data.type, 'url');
  assert.equal(res.body.data.classification, 'phishing');
  assert.ok(res.body.data.riskScore >= 60);

  scanIdA = res.body.data.id;
});

let scanIdEmail;

test('Scan API - Authenticated Email scan succeeds and persists securely', async () => {
  const res = await request(app)
    .post('/api/scans/email')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({
      subject: 'Urgent Action Required',
      body: 'Verify your account here: https://example.com',
    });

  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.data.type, 'email');
  
  assert.ok(res.body.data.metadata.subjectPreview);
  assert.equal(res.body.data.metadata.body, undefined);

  scanIdEmail = res.body.data.id;
});

test('Scan API - History pagination and filtering', async () => {
  const res = await request(app)
    .get('/api/scans?type=url&limit=10&page=1&classification=phishing')
    .set('Authorization', `Bearer ${tokenA}`);

  assert.equal(res.status, 200);
  assert.ok(res.body.data.scans.length >= 1);
  assert.equal(res.body.data.pagination.total >= 1, true);

  const resB = await request(app)
    .get('/api/scans')
    .set('Authorization', `Bearer ${tokenB}`);
  assert.equal(resB.body.data.scans.length, 0);
});

test('Scan API - Own-scan access (Single scan)', async () => {
  const res = await request(app)
    .get(`/api/scans/${scanIdA}`)
    .set('Authorization', `Bearer ${tokenA}`);

  assert.equal(res.status, 200);
  assert.equal(res.body.data.id, scanIdA);
  assert.ok(res.body.data.analysis);
});

test('Scan API - IDOR Prevention: Cannot access another user\'s scan', async () => {
  const res = await request(app)
    .get(`/api/scans/${scanIdA}`)
    .set('Authorization', `Bearer ${tokenB}`);

  assert.equal(res.status, 404);
});

test('Scan API - IDOR Prevention: Cannot delete another user\'s scan', async () => {
  const res = await request(app)
    .delete(`/api/scans/${scanIdA}`)
    .set('Authorization', `Bearer ${tokenB}`);

  assert.equal(res.status, 404);
});

test('Scan API - Admin Authorization: Admin can view and manage other users\' scans', async () => {
  // Create an admin user
  await request(app).post('/api/auth/register').send({
    name: 'Admin User',
    email: 'admin@example.com',
    password: 'Password1234!',
  });
  await query("UPDATE users SET role = 'admin' WHERE email = 'admin@example.com'");

  const adminLogin = await request(app).post('/api/auth/login').send({
    email: 'admin@example.com',
    password: 'Password1234!',
  });
  const adminToken = adminLogin.body.data.accessToken;

  // Regular user B cannot access Alice's email scan
  const nonOwnerRes = await request(app)
    .get(`/api/scans/${scanIdEmail}`)
    .set('Authorization', `Bearer ${tokenB}`);
  assert.equal(nonOwnerRes.status, 404);

  // Admin CAN access Alice's email scan
  const adminGetRes = await request(app)
    .get(`/api/scans/${scanIdEmail}`)
    .set('Authorization', `Bearer ${adminToken}`);
  assert.equal(adminGetRes.status, 200);
  assert.equal(adminGetRes.body.data.id, scanIdEmail);

  // Admin CAN delete Alice's email scan
  const adminDelRes = await request(app)
    .delete(`/api/scans/${scanIdEmail}`)
    .set('Authorization', `Bearer ${adminToken}`);
  assert.equal(adminDelRes.status, 200);

  // Verified deleted
  const verifyRes = await request(app)
    .get(`/api/scans/${scanIdEmail}`)
    .set('Authorization', `Bearer ${adminToken}`);
  assert.equal(verifyRes.status, 404);
});

test('Scan API Phase 3.2 - Search and Filters (Tests 5, 7, 9, 10, 11, 12)', async () => {
  // We need some data to test against, let's create a few specific scans for Alice
  await request(app).post('/api/scans/url').set('Authorization', `Bearer ${tokenA}`).send({ url: 'http://test-safe-domain.com' });
  await request(app).post('/api/scans/url').set('Authorization', `Bearer ${tokenA}`).send({ url: 'http://evil-phishing-site.com/login' });
  await request(app).post('/api/scans/email').set('Authorization', `Bearer ${tokenA}`).send({ subject: 'Invoice 12345', body: 'Please pay.' });

  // Test 7: Verdict Filter (SAFE)
  const safeRes = await request(app).get('/api/scans?verdict=SAFE').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(safeRes.status, 200);
  assert.equal(safeRes.body.data.scans[0].verdict, 'BENIGN');

  // Test 9: Scan type filter (EMAIL)
  const emailRes = await request(app).get('/api/scans?scanType=EMAIL').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(emailRes.status, 200);
  assert.ok(emailRes.body.data.scans.every(s => s.scanType === 'EMAIL'));

  // Test 10: Search and SQL Injection protection
  const searchRes = await request(app).get('/api/scans?search=Invoice').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(searchRes.status, 200);
  assert.ok(searchRes.body.data.scans.some(s => s.input.includes('Invoice')));

  const sqliRes = await request(app).get('/api/scans?search=evil-phishing\'; DROP TABLE scans;--').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(sqliRes.status, 200); // Should safely execute as a literal search string returning 0 results or safely ignoring the SQL syntax
  assert.equal(sqliRes.body.data.pagination.total, 0);

  // Test 11: Date filtering
  const fromDate = new Date();
  fromDate.setHours(fromDate.getHours() - 1);
  const toDate = new Date();
  toDate.setHours(toDate.getHours() + 1);
  
  const dateRes = await request(app)
    .get(`/api/scans?from=${fromDate.toISOString()}&to=${toDate.toISOString()}`)
    .set('Authorization', `Bearer ${tokenA}`);
  assert.equal(dateRes.status, 200);
  assert.ok(dateRes.body.data.scans.length >= 3);

  // Test 12: Combined filters
  const combinedRes = await request(app)
    .get(`/api/scans?scanType=URL&verdict=SUSPICIOUS&search=evil-phishing-site&limit=5&page=1`)
    .set('Authorization', `Bearer ${tokenA}`);
  assert.equal(combinedRes.status, 200);
  assert.ok(combinedRes.body.data.scans.length >= 1);
  assert.equal(combinedRes.body.data.scans[0].scanType, 'URL');
});

test('Scan API Phase 3.2 - Invalid parameters and Limits (Tests 6, 8, 13)', async () => {
  // Test 6: Maximum limit
  const maxLimit = await request(app).get('/api/scans?limit=10000').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(maxLimit.status, 400);

  // Test 8: Invalid verdict
  const invalidVerdict = await request(app).get('/api/scans?verdict=INVALID').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(invalidVerdict.status, 400);

  // Test 13: Invalid parameters
  const resPageString = await request(app).get('/api/scans?page=abc').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(resPageString.status, 400);

  const resPageNeg = await request(app).get('/api/scans?page=-1').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(resPageNeg.status, 400);

  const resInvalidDate = await request(app).get('/api/scans?from=not-a-date').set('Authorization', `Bearer ${tokenA}`);
  assert.equal(resInvalidDate.status, 400);
});

test('Scan API - Own-scan deletion', async () => {
  const res = await request(app)
    .delete(`/api/scans/${scanIdA}`)
    .set('Authorization', `Bearer ${tokenA}`);

  assert.equal(res.status, 200);

  const fetchRes = await request(app)
    .get(`/api/scans/${scanIdA}`)
    .set('Authorization', `Bearer ${tokenA}`);
  assert.equal(fetchRes.status, 404);
});

test('Scan API - Clear History', async () => {
  // Alice scans another URL
  await request(app)
    .post('/api/scans/url')
    .set('Authorization', `Bearer ${tokenA}`)
    .send({ url: 'http://test.com' });

  // Bob scans a URL so he has history
  await request(app)
    .post('/api/scans/url')
    .set('Authorization', `Bearer ${tokenB}`)
    .send({ url: 'http://bobs-scan.com' });

  // Clear Alice's history
  const res = await request(app)
    .delete('/api/scans')
    .set('Authorization', `Bearer ${tokenA}`);
  assert.equal(res.status, 200);
  assert.ok(res.body.data.success);
  assert.equal(typeof res.body.data.deletedCount, 'number');

  // Verify history is empty
  const getRes = await request(app)
    .get('/api/scans')
    .set('Authorization', `Bearer ${tokenA}`);
  assert.equal(getRes.status, 200);
  assert.equal(getRes.body.data.scans.length, 0);
  assert.equal(getRes.body.data.pagination.total, 0);

  // Bob's history should remain unaffected
  const bobRes = await request(app)
    .get('/api/scans')
    .set('Authorization', `Bearer ${tokenB}`);
  assert.ok(bobRes.body.data.scans.length > 0);
});

test('Scan API - Analytics (Empty State)', async () => {
  // Wait, tokenA cleared history, so Alice has 0 scans currently! Let's check her analytics
  const res = await request(app)
    .get('/api/scans/analytics')
    .set('Authorization', `Bearer ${tokenA}`);
  
  assert.equal(res.status, 200);
  assert.equal(res.body.data.summary.totalScans, 0);
  assert.equal(res.body.data.summary.phishingRate, 0);
});

test('Scan API - Analytics (Populated)', async () => {
  // Bob has 1 scan from the previous test ('http://bobs-scan.com')
  const res = await request(app)
    .get('/api/scans/analytics')
    .set('Authorization', `Bearer ${tokenB}`);
  
  assert.equal(res.status, 200);
  assert.ok(res.body.data.summary.totalScans > 0);
  assert.equal(typeof res.body.data.summary.urlScans, 'number');
  assert.ok(res.body.data.summary.averageRiskScore >= 0);
});

test('Scan API - Analytics (Date Filtering)', async () => {
  const from = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const to = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  
  const res = await request(app)
    .get(`/api/scans/analytics?from=${from}&to=${to}`)
    .set('Authorization', `Bearer ${tokenB}`);
    
  assert.equal(res.status, 200);
  assert.ok(res.body.data.summary.totalScans > 0);

  const resInvalid = await request(app)
    .get('/api/scans/analytics?from=invalid-date')
    .set('Authorization', `Bearer ${tokenB}`);
  
  assert.equal(resInvalid.status, 200); // Invalid dates are ignored as per implementation
});

test('Scan API - Rate limiting prevents abuse', async () => {
  // Batch requests to trigger the 50 req/15min rate limit efficiently
  let hitRateLimit = false;
  for (let batch = 0; batch < 6; batch++) {
    const promises = Array.from({ length: 10 }, () =>
      request(app)
        .get('/api/scans')
        .set('Authorization', `Bearer ${tokenA}`)
    );
    const responses = await Promise.all(promises);
    if (responses.some((r) => r.status === 429)) {
      hitRateLimit = true;
      break;
    }
  }
  
  assert.ok(hitRateLimit, 'Rate limit should kick in after too many requests');
});
