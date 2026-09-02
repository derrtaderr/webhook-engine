/**
 * HMAC signature verification over the raw request bytes.
 *
 * Three decisions live in this file, and each one is the opposite of what the common
 * receiver does.
 *
 * 1. The signature is computed over the RAW BYTES, never a reparsed body. `JSON.parse`
 *    then `JSON.stringify` does not reproduce the transmitted bytes: it renormalises
 *    whitespace, re-encodes escapes, and turns `1.0` into `1`. Any of those changes the
 *    digest. A receiver that verifies a reserialised body either rejects genuine traffic
 *    or was loosened until it stopped rejecting anything.
 *
 * 2. The comparison is CONSTANT TIME. `===` on strings returns at the first differing
 *    byte, so response latency reveals the length of the matching prefix and a valid
 *    signature can be recovered byte by byte. `timingSafeEqual` reads every byte.
 *    It also throws on a length mismatch, so the length check has to come first and
 *    has to return rather than let the exception escape — a receiver that 500s on a
 *    three-character signature has handed out a denial of service plus, at most
 *    providers, an automatic redelivery storm.
 *
 * 3. An absent secret THROWS. The usual `if (secret) { check }` turns an unset
 *    environment variable into an endpoint with authentication silently disabled, and
 *    nothing about that is visible from the outside.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { parseSignatureHeader } from './signature-header.js';

export const DEFAULT_ALGORITHM = 'sha256';
export const DEFAULT_ENCODING = 'hex';

/**
 * Five minutes, which is what the major providers use and the number people get wrong in
 * both directions. Too tight and ordinary clock skew on the sender rejects genuine
 * traffic. Too loose and the window stops meaning anything.
 */
export const DEFAULT_TOLERANCE_SECONDS = 300;

/**
 * Compare two signature strings without leaking a byte-by-byte match through timing.
 *
 * The length comparison is not constant time, and does not need to be: the length of a
 * digest is public. What must not leak is WHERE two equal-length values diverge.
 */
export function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  if (left.length === 0) return false;
  return timingSafeEqual(left, right);
}

/**
 * The bytes that get signed. A timestamp, when present, is bound into the payload so it
 * cannot be edited in flight — a replay window over an unsigned timestamp is decoration.
 */
function signedPayload(bodyBytes, timestamp) {
  if (timestamp === null || timestamp === undefined) return bodyBytes;
  return Buffer.concat([Buffer.from(`${timestamp}.`, 'utf8'), bodyBytes]);
}

function toBytes(rawBody) {
  if (typeof rawBody === 'string') return Buffer.from(rawBody, 'utf8');
  if (Buffer.isBuffer(rawBody)) return rawBody;
  if (rawBody instanceof Uint8Array) return Buffer.from(rawBody);
  return null;
}

/**
 * Accepts a string or an array of strings, so a rotation can present both keys.
 * @throws {TypeError} when no usable secret is present. Never returns an empty list.
 */
function normaliseSecrets(secret) {
  const list = Array.isArray(secret) ? secret : [secret];
  const usable = list.filter((s) => typeof s === 'string' && s.length > 0);
  if (usable.length === 0) {
    throw new TypeError(
      'webhook-engine: a signing secret is required. An endpoint with no secret is an ' +
        'endpoint with no authentication, and this library will not fall open for one.',
    );
  }
  return usable;
}

/**
 * Produce a signature. Exists so tests, examples and a stranger reproducing a failure
 * locally can generate valid input. This is not an outbound webhook sender.
 *
 * @param {object} options
 * @param {string|Buffer} options.rawBody
 * @param {string|string[]} options.secret signing key, or a list whose first entry is used
 * @param {number|null} [options.timestamp] unix seconds, bound into the signed payload
 * @param {string} [options.algorithm]
 * @param {'hex'|'base64'} [options.encoding]
 * @returns {string}
 */
export function signPayload({
  rawBody,
  secret,
  timestamp = null,
  algorithm = DEFAULT_ALGORITHM,
  encoding = DEFAULT_ENCODING,
}) {
  const [key] = normaliseSecrets(secret);
  const bytes = toBytes(rawBody);
  if (bytes === null) throw new TypeError('webhook-engine: rawBody must be a string or a Buffer.');
  return createHmac(algorithm, key).update(signedPayload(bytes, timestamp)).digest(encoding);
}

/**
 * Produce a full header value in the shape this library parses, so an example can send
 * a realistic request. Emits the timestamped form when given a timestamp.
 */
export function signHeader({ rawBody, secret, timestamp = null, algorithm, encoding }) {
  const signature = signPayload({ rawBody, secret, timestamp, algorithm, encoding });
  if (timestamp === null || timestamp === undefined) return `${algorithm ?? DEFAULT_ALGORITHM}=${signature}`;
  return `t=${timestamp},v1=${signature}`;
}

/**
 * @param {object} options
 * @param {string|Buffer} options.rawBody the exact received bytes, before any parsing
 * @param {unknown} options.header the signature header value
 * @param {string|string[]} options.secret one key, or several during a rotation
 * @param {string} [options.algorithm]
 * @param {'hex'|'base64'} [options.encoding]
 * @param {number} [options.timestamp] unix seconds, for providers that deliver the
 *   timestamp in its own header. It is bound into the signed payload, never merely read.
 * @param {number} [options.toleranceSeconds] replay window, in both directions
 * @param {boolean} [options.requireTimestamp] default true
 * @param {number} [options.now] milliseconds, injectable so the window is testable
 * @returns {{valid: true, timestamp: number|null, keyIndex: number}
 *          |{valid: false, reason: string, timestamp?: number|null}}
 * @throws {TypeError} when no secret is configured, or the tolerance is not a whole
 *   number of seconds
 */
export function verifySignature({
  rawBody,
  header,
  secret,
  timestamp: externalTimestamp,
  toleranceSeconds = DEFAULT_TOLERANCE_SECONDS,
  requireTimestamp = true,
  algorithm = DEFAULT_ALGORITHM,
  encoding = DEFAULT_ENCODING,
  now = Date.now(),
}) {
  const secrets = normaliseSecrets(secret);

  // A tolerance that is not a number would compare as NaN and let every timestamp
  // through, which is the failure mode of quietly disabling the window.
  if (!Number.isInteger(toleranceSeconds) || toleranceSeconds < 0) {
    throw new TypeError(
      'webhook-engine: toleranceSeconds must be a non-negative whole number of seconds.',
    );
  }

  const bytes = toBytes(rawBody);
  if (bytes === null) return { valid: false, reason: 'no_raw_body' };

  const parsed = parseSignatureHeader(header);
  if (parsed === null) return { valid: false, reason: 'malformed_header' };

  const timestamp = resolveTimestamp(parsed.timestamp, externalTimestamp);
  if (timestamp === CONFLICT) return { valid: false, reason: 'timestamp_conflict' };

  if (timestamp === null) {
    if (requireTimestamp) return { valid: false, reason: 'no_timestamp' };
  } else if (Math.abs(Math.floor(now / 1000) - timestamp) > toleranceSeconds) {
    // Checked before the HMAC, so a stale request costs two integers rather than a hash
    // over a body an unauthenticated caller chose the size of.
    return { valid: false, reason: 'timestamp_out_of_tolerance', timestamp };
  }

  const payload = signedPayload(bytes, timestamp);

  for (let keyIndex = 0; keyIndex < secrets.length; keyIndex += 1) {
    const expected = createHmac(algorithm, secrets[keyIndex]).update(payload).digest(encoding);
    for (const candidate of parsed.signatures) {
      if (constantTimeEqual(candidate, expected)) {
        return { valid: true, timestamp, keyIndex };
      }
    }
  }

  return { valid: false, reason: 'no_matching_signature', timestamp };
}

/** Sentinel for a header timestamp and an out-of-band one that disagree. */
const CONFLICT = Symbol('timestamp_conflict');

/**
 * A timestamp may arrive inside the signature header or in its own header. Both are
 * bound into the signed payload. Two that disagree is a conflict rather than a
 * preference, because silently picking one means the other was attacker-editable.
 */
function resolveTimestamp(headerTimestamp, externalTimestamp) {
  if (externalTimestamp === undefined || externalTimestamp === null) return headerTimestamp;
  if (!Number.isSafeInteger(externalTimestamp) || externalTimestamp < 0) return CONFLICT;
  if (headerTimestamp !== null && headerTimestamp !== externalTimestamp) return CONFLICT;
  return externalTimestamp;
}
