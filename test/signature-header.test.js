import { test } from 'node:test';
import assert from 'node:assert/strict';

import { parseSignatureHeader, MAX_HEADER_LENGTH, MAX_HEADER_ELEMENTS } from '../src/signature-header.js';

test('parses the Stripe shape: a timestamp and one signature', () => {
  const parsed = parseSignatureHeader('t=1614556800,v1=abc123');
  assert.deepEqual(parsed, { timestamp: 1614556800, signatures: ['abc123'] });
});

test('parses several signatures under one timestamp, which is how key rotation works', () => {
  // During rotation the sender signs with the old key and the new one, and the
  // receiver accepts either. Without this, rotation needs a window of rejected traffic.
  const parsed = parseSignatureHeader('t=1614556800,v1=oldkeysig,v1=newkeysig');
  assert.deepEqual(parsed.signatures, ['oldkeysig', 'newkeysig']);
});

test('parses the GitHub shape: an algorithm-prefixed signature and no timestamp', () => {
  const parsed = parseSignatureHeader('sha256=abc123');
  assert.deepEqual(parsed, { timestamp: null, signatures: ['abc123'] });
});

test('parses a bare signature with no key at all', () => {
  const parsed = parseSignatureHeader('abc123');
  assert.deepEqual(parsed, { timestamp: null, signatures: ['abc123'] });
});

test('ignores key names it does not recognise rather than treating them as signatures', () => {
  // Stripe's v0 belongs to a different scheme. Collecting it as a candidate
  // signature would mean checking a value that was never meant to match.
  const parsed = parseSignatureHeader('t=1614556800,v0=somethingelse,v1=real');
  assert.deepEqual(parsed.signatures, ['real']);
});

test('returns null for an empty, missing or non-string header', () => {
  for (const value of ['', undefined, null, 42, {}, []]) {
    assert.equal(parseSignatureHeader(value), null, `expected null for ${JSON.stringify(value)}`);
  }
});

test('returns null when a timestamp arrives with no signature beside it', () => {
  assert.equal(parseSignatureHeader('t=1614556800'), null);
});

test('returns null for a non-numeric or negative timestamp', () => {
  assert.equal(parseSignatureHeader('t=notanumber,v1=abc'), null);
  assert.equal(parseSignatureHeader('t=-5,v1=abc'), null);
  assert.equal(parseSignatureHeader('t=1.5,v1=abc'), null);
});

test('returns null when the timestamp is given twice, because which one signed is ambiguous', () => {
  assert.equal(parseSignatureHeader('t=1614556800,t=1614556801,v1=abc'), null);
});

test('refuses whitespace inside a signature value instead of trimming it away', () => {
  // This is the whole posture in one assertion. A comparator that trims is a
  // comparator that accepts a value which is not the signature.
  assert.equal(parseSignatureHeader('t=1614556800,v1=abc123\n'), null);
  assert.equal(parseSignatureHeader('t=1614556800,v1= abc123'), null);
  assert.equal(parseSignatureHeader('sha256=abc123 '), null);
});

test('refuses characters outside the encodings a signature can actually be in', () => {
  assert.equal(parseSignatureHeader('v1=abc;drop'), null);
  assert.equal(parseSignatureHeader('v1=<script>'), null);
});

test('accepts base64 padding and the url-safe alphabet, because some providers send base64', () => {
  assert.deepEqual(parseSignatureHeader('sha256=aGVsbG8=').signatures, ['aGVsbG8=']);
  assert.deepEqual(parseSignatureHeader('sha256=a-b_c').signatures, ['a-b_c']);
});

test('refuses a header longer than the bound rather than parsing it', () => {
  const huge = 't=1614556800,' + 'v1=' + 'a'.repeat(MAX_HEADER_LENGTH);
  assert.equal(parseSignatureHeader(huge), null);
});

test('refuses a header with more elements than the bound', () => {
  const many = ['t=1614556800', ...Array(MAX_HEADER_ELEMENTS).fill('v1=abc')].join(',');
  assert.equal(parseSignatureHeader(many), null);
});

test('refuses an element with no value and an element with no key', () => {
  assert.equal(parseSignatureHeader('t=1614556800,v1='), null);
  assert.equal(parseSignatureHeader('t=1614556800,,v1=abc'), null);
});
