import { test } from 'node:test';
import assert from 'node:assert/strict';

import { signHeader, signPayload, verifySignature, DEFAULT_TOLERANCE_SECONDS } from '../src/verify.js';

const SECRET = 'whsec_fixture';
const BODY = JSON.stringify({ id: 'evt_003', type: 'shipment.delivered' });
const SIGNED_AT = 1614556800;

/** Verify the same captured request as though `secondsLater` had passed since it was signed. */
function verifyAfter(secondsLater, options = {}) {
  const header = signHeader({ rawBody: BODY, secret: SECRET, timestamp: SIGNED_AT });
  return verifySignature({
    rawBody: BODY,
    header,
    secret: SECRET,
    now: (SIGNED_AT + secondsLater) * 1000,
    ...options,
  });
}

test('the default tolerance is the five minutes every major provider uses', () => {
  assert.equal(DEFAULT_TOLERANCE_SECONDS, 300);
});

test('a request captured and replayed inside the window still verifies', () => {
  assert.equal(verifyAfter(299).valid, true);
});

test('a request replayed exactly on the boundary still verifies', () => {
  assert.equal(verifyAfter(300).valid, true);
});

test('the same request, one second past the window, does not', () => {
  // Identical bytes, identical signature, identical secret. The only difference between
  // this assertion and the one above is one second of wall clock, which is the whole
  // point of binding a timestamp into the signed payload.
  const result = verifyAfter(301);
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'timestamp_out_of_tolerance');
  assert.equal(result.timestamp, SIGNED_AT);
});

test('a timestamp far enough in the future is rejected too', () => {
  assert.equal(verifyAfter(-301).valid, false);
  assert.equal(verifyAfter(-301).reason, 'timestamp_out_of_tolerance');
});

test('a timestamp slightly in the future is accepted, because sender clocks drift', () => {
  assert.equal(verifyAfter(-299).valid, true);
});

test('the tolerance is configurable in both directions', () => {
  assert.equal(verifyAfter(400, { toleranceSeconds: 600 }).valid, true);
  assert.equal(verifyAfter(60, { toleranceSeconds: 30 }).valid, false);
});

test('a header carrying no timestamp is rejected unless the caller opts out', () => {
  // A provider that sends no timestamp cannot have a replay window, so opting out is a
  // real decision with a real cost. Making it the default would mean every caller who
  // never read this file silently has no replay protection.
  const header = signHeader({ rawBody: BODY, secret: SECRET });
  const strict = verifySignature({ rawBody: BODY, header, secret: SECRET, now: SIGNED_AT * 1000 });
  assert.equal(strict.valid, false);
  assert.equal(strict.reason, 'no_timestamp');

  const relaxed = verifySignature({
    rawBody: BODY,
    header,
    secret: SECRET,
    requireTimestamp: false,
    now: SIGNED_AT * 1000,
  });
  assert.equal(relaxed.valid, true);
});

test('a timestamp delivered in its own header is bound into the signature, not trusted beside it', () => {
  // Providers that put the timestamp in a separate header still sign it. If it were
  // merely read alongside the body, an attacker replaying a captured request would edit
  // the header, move the window, and the signature would not notice.
  const signature = signPayload({ rawBody: BODY, secret: SECRET, timestamp: SIGNED_AT });
  const header = `sha256=${signature}`;

  const honest = verifySignature({
    rawBody: BODY,
    header,
    secret: SECRET,
    timestamp: SIGNED_AT,
    now: SIGNED_AT * 1000,
  });
  assert.equal(honest.valid, true);

  const forged = verifySignature({
    rawBody: BODY,
    header,
    secret: SECRET,
    timestamp: SIGNED_AT + 10_000, // moved forward to escape the window
    now: (SIGNED_AT + 10_000) * 1000,
  });
  assert.equal(forged.valid, false, 'moving the timestamp invalidates the signature');
  assert.equal(forged.reason, 'no_matching_signature');
});

test('a timestamp in the header and a different one beside it is a conflict, not a preference', () => {
  const header = signHeader({ rawBody: BODY, secret: SECRET, timestamp: SIGNED_AT });
  const result = verifySignature({
    rawBody: BODY,
    header,
    secret: SECRET,
    timestamp: SIGNED_AT + 1,
    now: SIGNED_AT * 1000,
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'timestamp_conflict');
});

test('an out-of-window request is rejected before the HMAC is computed', () => {
  // Reason precedence documents the ordering: a stale request costs a comparison of two
  // integers, not a hash over an attacker-chosen body.
  const header = `t=${SIGNED_AT},v1=${'0'.repeat(64)}`;
  const result = verifySignature({
    rawBody: BODY,
    header,
    secret: SECRET,
    now: (SIGNED_AT + 10_000) * 1000,
  });
  assert.equal(result.reason, 'timestamp_out_of_tolerance', 'not no_matching_signature');
});

test('a non-numeric or negative tolerance is refused rather than quietly disabling the window', () => {
  for (const toleranceSeconds of [-1, NaN, '300', null, Infinity]) {
    assert.throws(
      () => verifyAfter(0, { toleranceSeconds }),
      /tolerance/i,
      `expected a throw for ${String(toleranceSeconds)}`,
    );
  }
});
