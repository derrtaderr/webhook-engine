import { test } from 'node:test';
import assert from 'node:assert/strict';
import { timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { signPayload, signHeader, verifySignature, constantTimeEqual } from '../src/verify.js';

const SECRET = 'whsec_fixture';
const BODY = JSON.stringify({ id: 'evt_101', type: 'payment.succeeded', amount: 4200 });
const SIGNED_AT = 1614556800;
const NOW = SIGNED_AT * 1000;

/**
 * The comparator most webhook receivers actually ship. Reproduced here so each case
 * below can assert that it accepts the forgery before asserting that this library does
 * not. A test that only checks our own rejection cannot tell you whether the rejection
 * was hard to get right.
 */
const lenientCompare = (presented, expected) =>
  (presented ?? '').trim().toLowerCase() === (expected ?? '').trim().toLowerCase();

test('a signature with a trailing newline is accepted by a trimming comparator and rejected here', () => {
  const good = signPayload({ rawBody: BODY, secret: SECRET, timestamp: SIGNED_AT });
  const padded = `${good}\n`;

  assert.equal(lenientCompare(padded, good), true, 'the common receiver accepts this');
  assert.equal(constantTimeEqual(padded, good), false);

  const result = verifySignature({
    rawBody: BODY,
    header: `t=${SIGNED_AT},v1=${padded}`,
    secret: SECRET,
    now: NOW,
  });
  assert.equal(result.valid, false);
});

test('a signature in the wrong case is accepted by a folding comparator and rejected here', () => {
  const good = signPayload({ rawBody: BODY, secret: SECRET, timestamp: SIGNED_AT });
  const shouted = good.toUpperCase();

  assert.equal(lenientCompare(shouted, good), true, 'the common receiver accepts this');
  assert.equal(constantTimeEqual(shouted, good), false);

  const result = verifySignature({
    rawBody: BODY,
    header: `t=${SIGNED_AT},v1=${shouted}`,
    secret: SECRET,
    now: NOW,
  });
  assert.equal(result.valid, false, 'strictness here is deliberate; see the README limits');
});

test('a signature of hostile length is rejected instead of throwing out of timingSafeEqual', () => {
  // The unguarded call, for comparison. A receiver that forwards this exception returns
  // 500, which at most providers schedules an automatic redelivery, which throws again.
  assert.throws(
    () => timingSafeEqual(Buffer.from('abc'), Buffer.from('a'.repeat(64))),
    /length/i,
    'the raw primitive throws, which is the failure being guarded',
  );

  for (const forged of ['a', 'abc', 'a'.repeat(63), 'a'.repeat(65), 'a'.repeat(512)]) {
    const result = verifySignature({
      rawBody: BODY,
      header: `t=${SIGNED_AT},v1=${forged}`,
      secret: SECRET,
      now: NOW,
    });
    assert.equal(result.valid, false, `length ${forged.length} should be a rejection`);
    assert.equal(result.reason, 'no_matching_signature', `length ${forged.length}`);
  }
});

test('a signature too long to be a header is rejected before any comparison at all', () => {
  // The outer bound catches this one first, and the reason differs from the case above
  // for that reason. Both are rejections; neither is an exception.
  const result = verifySignature({
    rawBody: BODY,
    header: `t=${SIGNED_AT},v1=${'a'.repeat(4096)}`,
    secret: SECRET,
    now: NOW,
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'malformed_header');
});

test('a signature valid over the raw bytes fails over the reserialised body', () => {
  // This is the case that makes "just verify req.body" wrong. The sender transmitted
  // these exact bytes, with this spacing and this key order. A parse and a restringify
  // returns different bytes and therefore a different digest.
  const raw = '{ "type" : "payment.succeeded",  "id": "evt_102" }';
  const reserialised = JSON.stringify(JSON.parse(raw));
  assert.notEqual(raw, reserialised, 'the roundtrip really did change the bytes');

  const header = signHeader({ rawBody: raw, secret: SECRET, timestamp: SIGNED_AT });

  assert.equal(verifySignature({ rawBody: raw, header, secret: SECRET, now: NOW }).valid, true);
  assert.equal(
    verifySignature({ rawBody: reserialised, header, secret: SECRET, now: NOW }).valid,
    false,
    'a receiver verifying the parsed body rejects its own genuine traffic',
  );
});

test('the reserialisation trap fires on numbers and escapes, not just whitespace', () => {
  // Anyone who has "fixed" this by stripping whitespace has these two left.
  for (const raw of ['{"amount":1.0}', '{"note":"caf\\u00e9"}', '{"id":1e3}']) {
    const reserialised = JSON.stringify(JSON.parse(raw));
    assert.notEqual(raw, reserialised, `${raw} should survive parse differently`);

    const header = signHeader({ rawBody: raw, secret: SECRET, timestamp: SIGNED_AT });
    assert.equal(verifySignature({ rawBody: raw, header, secret: SECRET, now: NOW }).valid, true);
    assert.equal(
      verifySignature({ rawBody: reserialised, header, secret: SECRET, now: NOW }).valid,
      false,
    );
  }
});

test('a genuine signature cut from one event and pasted onto another does not verify', () => {
  const other = JSON.stringify({ id: 'evt_103', type: 'refund.created', amount: 4200 });
  const header = signHeader({ rawBody: other, secret: SECRET, timestamp: SIGNED_AT });

  assert.equal(verifySignature({ rawBody: other, header, secret: SECRET, now: NOW }).valid, true);
  assert.equal(verifySignature({ rawBody: BODY, header, secret: SECRET, now: NOW }).valid, false);
});

test('a genuine signature re-presented under a fresher timestamp does not verify', () => {
  // The obvious way to defeat a replay window: keep the signature, move the clock.
  const signature = signPayload({ rawBody: BODY, secret: SECRET, timestamp: SIGNED_AT });
  const stale = SIGNED_AT + 100_000;

  const result = verifySignature({
    rawBody: BODY,
    header: `t=${stale},v1=${signature}`,
    secret: SECRET,
    now: stale * 1000,
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'no_matching_signature');
});

test('the timestamp and the body cannot be slid past the delimiter into each other', () => {
  // `${t}.${body}` is only unambiguous because the timestamp is constrained to digits.
  // If a caller could move a digit across the dot, two different requests would share a
  // signed payload and therefore a signature.
  const shifted = signPayload({ rawBody: `0.${BODY}`, secret: SECRET, timestamp: 161455680 });
  const honest = signPayload({ rawBody: BODY, secret: SECRET, timestamp: SIGNED_AT });
  assert.notEqual(shifted, honest);
});

test('a valid signature presented under a key from another scheme is not accepted', () => {
  const signature = signPayload({ rawBody: BODY, secret: SECRET, timestamp: SIGNED_AT });
  const result = verifySignature({
    rawBody: BODY,
    header: `t=${SIGNED_AT},v0=${signature}`,
    secret: SECRET,
    now: NOW,
  });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'malformed_header', 'v0 is not a candidate, so nothing was offered');
});

test('an all-zero signature of exactly the right length is rejected', () => {
  const result = verifySignature({
    rawBody: BODY,
    header: `t=${SIGNED_AT},v1=${'0'.repeat(64)}`,
    secret: SECRET,
    now: NOW,
  });
  assert.equal(result.valid, false);
});

test('two empty strings do not compare equal, so an empty signature never matches', () => {
  // A digest is never empty, so the only way to reach this is a bug upstream. It should
  // not be the one comparison in the file that returns true for free.
  assert.equal(constantTimeEqual('', ''), false);
});

test('the comparison is built on timingSafeEqual, which is the one claim behaviour cannot make', () => {
  // HONEST ABOUT WHAT THIS IS. Constant-time comparison and `===` return the same
  // boolean for every input; the only difference between them is how long they take,
  // and that is not observable from inside this process with any stability worth a CI
  // job. The mutation check found exactly that: replacing the body of constantTimeEqual
  // with `a === b` turned nothing red.
  //
  // So this is a source canary, not a behavioural test. It fails if someone swaps the
  // primitive out. It does NOT prove the process is constant time — a JIT, a compiler,
  // or the surrounding code can still leak. The README says so in its limits.
  const source = readFileSync(fileURLToPath(new URL('../src/verify.js', import.meta.url)), 'utf8');

  assert.match(source, /import \{[^}]*timingSafeEqual[^}]*\} from 'node:crypto'/);
  assert.match(source, /return timingSafeEqual\(left, right\);/);
  assert.doesNotMatch(
    source,
    /return\s+(candidate|presented)\s*===/,
    'no string equality shortcut on the comparison path',
  );
});

test('the same forgery is rejected the same way whether it is early or late in the digest', () => {
  const good = signPayload({ rawBody: BODY, secret: SECRET, timestamp: SIGNED_AT });
  const firstByteWrong = (good[0] === 'a' ? 'b' : 'a') + good.slice(1);
  const lastByteWrong = good.slice(0, -1) + (good.at(-1) === 'a' ? 'b' : 'a');

  assert.equal(constantTimeEqual(firstByteWrong, good), false);
  assert.equal(constantTimeEqual(lastByteWrong, good), false);
});
