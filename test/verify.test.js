import { test } from 'node:test';
import assert from 'node:assert/strict';

import { signPayload, signHeader, verifySignature } from '../src/verify.js';

const SECRET = 'whsec_fixture';
const BODY = JSON.stringify({ id: 'evt_001', type: 'invoice.paid' });
const TIMESTAMP = 1614556800;

// Golden vectors. These pin the signing scheme itself: `${timestamp}.${rawBody}` when a
// timestamp is present, the raw body alone when it is not. A refactor that changes the
// separator or the ordering breaks every deployed sender, so it should break here first.
const GOLDEN_TIMESTAMPED = '15b7d59d564ed01a44d1e8588099329e67bdee7bfc252212f9a2b3a6363739e1';
const GOLDEN_PLAIN = 'e2ca6c5df240a63577da392e7d5a128e244d2a902a65f82db4335fdf125b9dcf';

test('signPayload matches its golden vector for the timestamped scheme', () => {
  assert.equal(signPayload({ rawBody: BODY, secret: SECRET, timestamp: TIMESTAMP }), GOLDEN_TIMESTAMPED);
});

test('signPayload matches its golden vector when there is no timestamp to bind', () => {
  assert.equal(signPayload({ rawBody: BODY, secret: SECRET }), GOLDEN_PLAIN);
});

test('a genuine signature verifies', () => {
  const header = signHeader({ rawBody: BODY, secret: SECRET, timestamp: TIMESTAMP });
  const result = verifySignature({ rawBody: BODY, header, secret: SECRET, now: TIMESTAMP * 1000 });
  assert.equal(result.valid, true);
  assert.equal(result.timestamp, TIMESTAMP);
  assert.equal(result.keyIndex, 0);
});

test('the wrong secret does not verify', () => {
  const header = signHeader({ rawBody: BODY, secret: 'whsec_somebody_elses', timestamp: TIMESTAMP });
  const result = verifySignature({ rawBody: BODY, header, secret: SECRET, now: TIMESTAMP * 1000 });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'no_matching_signature');
});

test('a body changed by one byte after signing does not verify', () => {
  const header = signHeader({ rawBody: BODY, secret: SECRET, timestamp: TIMESTAMP });
  const tampered = BODY.replace('invoice.paid', 'invoice.paiD');
  const result = verifySignature({ rawBody: tampered, header, secret: SECRET, now: TIMESTAMP * 1000 });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'no_matching_signature');
});

test('a missing or malformed header is a rejection with a distinguishable reason', () => {
  for (const header of [undefined, '', 'not a signature header']) {
    const result = verifySignature({ rawBody: BODY, header, secret: SECRET, now: TIMESTAMP * 1000 });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'malformed_header');
  }
});

test('an absent secret throws instead of letting the endpoint fall open', () => {
  // The common receiver wraps its check in `if (secret) { ... }`, so an unset
  // environment variable turns authentication off and the endpoint keeps returning
  // 200. Nothing about that failure is visible from the outside. Refusing to
  // construct is the only version of this that cannot be deployed by accident.
  const header = signHeader({ rawBody: BODY, secret: SECRET, timestamp: TIMESTAMP });
  for (const secret of [undefined, '', null, [], ['']]) {
    assert.throws(
      () => verifySignature({ rawBody: BODY, header, secret }),
      /secret/i,
      `expected a throw for ${JSON.stringify(secret)}`,
    );
  }
});

test('any secret in the list verifies, which is what makes a rotation survivable', () => {
  const header = signHeader({ rawBody: BODY, secret: 'whsec_retiring', timestamp: TIMESTAMP });
  const result = verifySignature({
    rawBody: BODY,
    header,
    secret: ['whsec_incoming', 'whsec_retiring'],
    now: TIMESTAMP * 1000,
  });
  assert.equal(result.valid, true);
  assert.equal(result.keyIndex, 1, 'reports which key matched, so rotation progress is observable');
});

test('several signatures in one header verify if any of them matches', () => {
  const good = signPayload({ rawBody: BODY, secret: SECRET, timestamp: TIMESTAMP });
  const header = `t=${TIMESTAMP},v1=${'0'.repeat(64)},v1=${good}`;
  const result = verifySignature({ rawBody: BODY, header, secret: SECRET, now: TIMESTAMP * 1000 });
  assert.equal(result.valid, true);
});

test('a Buffer body and the equivalent string body produce the same signature', () => {
  const fromString = signPayload({ rawBody: BODY, secret: SECRET, timestamp: TIMESTAMP });
  const fromBuffer = signPayload({ rawBody: Buffer.from(BODY, 'utf8'), secret: SECRET, timestamp: TIMESTAMP });
  assert.equal(fromString, fromBuffer);

  const header = signHeader({ rawBody: BODY, secret: SECRET, timestamp: TIMESTAMP });
  const result = verifySignature({
    rawBody: Buffer.from(BODY, 'utf8'),
    header,
    secret: SECRET,
    now: TIMESTAMP * 1000,
  });
  assert.equal(result.valid, true);
});

test('a body with non-ASCII bytes verifies, because the signature is over bytes', () => {
  const body = JSON.stringify({ id: 'evt_002', note: 'café — naïve — 東京' });
  const header = signHeader({ rawBody: body, secret: SECRET, timestamp: TIMESTAMP });
  const result = verifySignature({ rawBody: body, header, secret: SECRET, now: TIMESTAMP * 1000 });
  assert.equal(result.valid, true);
});

test('a body that is neither a string nor a Buffer is a rejection, not a crash', () => {
  const header = signHeader({ rawBody: BODY, secret: SECRET, timestamp: TIMESTAMP });
  for (const rawBody of [undefined, null, 42, { id: 'evt_001' }]) {
    const result = verifySignature({ rawBody, header, secret: SECRET, now: TIMESTAMP * 1000 });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'no_raw_body');
  }
});

test('an empty body is signable and verifiable, because some events carry none', () => {
  const header = signHeader({ rawBody: '', secret: SECRET, timestamp: TIMESTAMP });
  const result = verifySignature({ rawBody: '', header, secret: SECRET, now: TIMESTAMP * 1000 });
  assert.equal(result.valid, true);
});

test('base64 signatures verify when the caller asks for base64', () => {
  const header = signHeader({ rawBody: BODY, secret: SECRET, timestamp: TIMESTAMP, encoding: 'base64' });
  assert.ok(header.includes('+') || header.includes('/') || header.includes('='), 'looks like base64');
  const result = verifySignature({
    rawBody: BODY,
    header,
    secret: SECRET,
    encoding: 'base64',
    now: TIMESTAMP * 1000,
  });
  assert.equal(result.valid, true);
});

test('a hex signature does not verify against a receiver expecting base64', () => {
  const header = signHeader({ rawBody: BODY, secret: SECRET, timestamp: TIMESTAMP });
  const result = verifySignature({
    rawBody: BODY,
    header,
    secret: SECRET,
    encoding: 'base64',
    now: TIMESTAMP * 1000,
  });
  assert.equal(result.valid, false);
});

test('a signed id is bound into the payload, so an edited id fails verification', async () => {
  const rawBody = '{"id":"rec_1"}';
  const timestamp = 1614556800;
  const header = signHeader({ rawBody, secret: 'whsec_bind', timestamp, signedId: 'msg_1' });
  const base = { rawBody, header, secret: 'whsec_bind', now: timestamp * 1000 };
  assert.equal(verifySignature({ ...base, signedId: 'msg_1' }).valid, true);
  assert.equal(verifySignature({ ...base, signedId: 'msg_2' }).reason, 'no_matching_signature');
  assert.equal(verifySignature(base).valid, false, 'a signature over an id does not verify as a body-only signature');
});
