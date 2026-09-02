/**
 * Signature header parsing.
 *
 * Providers do not agree on a shape, and the three that exist in the wild are all
 * handled here:
 *
 *   t=1614556800,v1=abc,v1=def   a signed timestamp and one or more signatures
 *   sha256=abc                   an algorithm-prefixed signature, no timestamp
 *   abc                          a bare signature
 *
 * The multi-signature form is the one that earns its place. During a key rotation the
 * sender signs with both keys and the receiver accepts either, so the rotation needs no
 * window of rejected traffic.
 *
 * Nothing here is trimmed, normalised or case-folded. Every leniency in a signature
 * comparator is a value that is not the signature being treated as the signature, and
 * the whole reason this library exists is that the common receiver does exactly that.
 * A signature carrying a trailing newline is malformed, and malformed is a rejection.
 */

/** Longer than any real signature header. Bounds the work an unauthenticated caller can ask for. */
export const MAX_HEADER_LENGTH = 1024;

/** More signatures than any rotation needs. Same reason. */
export const MAX_HEADER_ELEMENTS = 16;

/**
 * Keys that may appear in a structured header. A key outside this set makes the whole
 * header malformed rather than being skipped, so a typo fails loudly instead of
 * silently dropping the only signature present.
 */
const KNOWN_KEYS = new Set(['t', 'v0', 'v1', 'sha1', 'sha256', 'sha512', 'signature']);

/** Of those, the ones whose value is a candidate signature. `v0` belongs to another scheme. */
const SIGNATURE_KEYS = new Set(['v1', 'sha1', 'sha256', 'sha512', 'signature']);

/** Hex, standard base64 and url-safe base64. No whitespace, deliberately. */
const SIGNATURE_CHARS = /^[A-Za-z0-9+/_=-]+$/;

const UNSIGNED_INTEGER = /^[0-9]+$/;

/**
 * @param {unknown} header raw header value
 * @returns {{ timestamp: number|null, signatures: string[] }|null} null when the header
 *   is absent or malformed. The caller treats null as "unauthenticated", never as
 *   "no signature required".
 */
export function parseSignatureHeader(header) {
  if (typeof header !== 'string' || header.length === 0) return null;
  if (header.length > MAX_HEADER_LENGTH) return null;

  const elements = header.split(',');
  if (elements.length > MAX_HEADER_ELEMENTS) return null;

  // The bare form has no commas, so it is only reachable with a single element.
  if (elements.length === 1 && !isKeyedElement(elements[0])) {
    return SIGNATURE_CHARS.test(elements[0]) ? { timestamp: null, signatures: [elements[0]] } : null;
  }

  let timestamp = null;
  const signatures = [];

  for (const element of elements) {
    const eq = element.indexOf('=');
    if (eq <= 0) return null;

    const key = element.slice(0, eq);
    const value = element.slice(eq + 1);
    if (!KNOWN_KEYS.has(key)) return null;
    if (value.length === 0) return null;

    if (key === 't') {
      // Two timestamps means it is unknowable which one was signed.
      if (timestamp !== null) return null;
      if (!UNSIGNED_INTEGER.test(value)) return null;
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed)) return null;
      timestamp = parsed;
      continue;
    }

    if (!SIGNATURE_KEYS.has(key)) continue; // recognised, but not a signature. v0.
    if (!SIGNATURE_CHARS.test(value)) return null;
    signatures.push(value);
  }

  if (signatures.length === 0) return null;
  return { timestamp, signatures };
}

/** True when the element opens with a key this parser knows, so `aGVsbG8=` stays a bare signature. */
function isKeyedElement(element) {
  const eq = element.indexOf('=');
  if (eq <= 0) return false;
  return KNOWN_KEYS.has(element.slice(0, eq));
}
