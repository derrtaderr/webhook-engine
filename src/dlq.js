/**
 * The dead letter queue.
 *
 * After the last attempt the event is either recorded somewhere actionable or it is
 * lost. `console.error` is not a dead letter queue; it is a place events go to be found
 * during a postmortem, if the retention window has not already rolled.
 *
 * WHAT "ENOUGH CONTEXT TO REPLAY" MEANS, CONCRETELY. A record you cannot replay from is
 * a log line with extra steps. So the record carries the RAW BYTES, unparsed, the header
 * set including the signature, the event id, the attempt count, every error in order,
 * and both timestamps. That set is sufficient to hand the record back to the engine and
 * have it verify — the same verification it passed on the way in.
 *
 * Storing the parsed body instead is the convenient choice: smaller, readable in a
 * dashboard, and it silently destroys replayability, because a JSON roundtrip does not
 * reproduce the bytes the signature covers. `buildDeadLetterRecord` refuses a non-string
 * body for that reason, and the refusal is tested.
 *
 * The store contract, which any backend must satisfy:
 *
 *   push(record)  → record
 *   list()        → record[]
 *   get(id)       → record | null
 *   remove(id)    → boolean
 */

import { randomBytes } from 'node:crypto';

/** Credentials that would otherwise outlive the request inside a durable record. */
export const DEFAULT_REDACTED_HEADERS = Object.freeze([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
]);

export const DEFAULT_MAX_RECORDS = 10_000;

export class DeadLetterQueueFullError extends Error {
  constructor(maxRecords) {
    super(
      `webhook-engine: the dead letter queue is full at ${maxRecords} records. ` +
        'Nothing was evicted. Drain it, or configure a durable backend.',
    );
    this.name = 'DeadLetterQueueFullError';
    this.retryable = false;
  }
}

/**
 * Validate the parts of a record that the replay guarantee depends on. Called both by
 * the builder and by the in-memory store, because a caller assembling a record by hand
 * for a custom backend is not a reason for the guarantee to lapse.
 */
export function assertReplayable(record) {
  if (record === null || typeof record !== 'object') {
    throw new TypeError('webhook-engine: a dead letter record must be an object.');
  }
  if (typeof record.eventId !== 'string' || record.eventId.length === 0) {
    throw new TypeError('webhook-engine: a dead letter record needs a non-empty eventId.');
  }
  if (typeof record.rawBody !== 'string') {
    throw new TypeError(
      'webhook-engine: a dead letter record needs rawBody as the exact received string. ' +
        'A parsed body cannot be replayed, because its signature no longer covers it.',
    );
  }
  if (record.headers === null || typeof record.headers !== 'object') {
    throw new TypeError('webhook-engine: a dead letter record needs the request headers.');
  }
  if (!Number.isInteger(record.attempts) || record.attempts < 1) {
    throw new TypeError('webhook-engine: a dead letter record needs a positive attempts count.');
  }
  return record;
}

function redactHeaders(headers, redacted) {
  const lower = new Set(redacted.map((name) => name.toLowerCase()));
  const copy = {};
  for (const [name, value] of Object.entries(headers)) {
    copy[name] = lower.has(name.toLowerCase()) ? '[redacted]' : value;
  }
  return copy;
}

/**
 * Assemble a record. Copies the headers so a later mutation of the request object cannot
 * rewrite what was recorded, and redacts credential headers while leaving the signature
 * header alone — without it the record cannot be replayed through verification.
 */
export function buildDeadLetterRecord({
  eventId,
  rawBody,
  rawBodyBase64,
  headers,
  attempts,
  errors = [],
  firstFailedAt = null,
  redacted = DEFAULT_REDACTED_HEADERS,
  now = () => new Date(),
}) {
  const record = {
    id: `dlq_${randomBytes(8).toString('hex')}`,
    eventId,
    rawBody,
    // The bytes as received. `rawBody` stays because a record a human reads is worth more
    // than one they cannot, but a body that is not valid UTF-8 does not survive
    // Buffer -> string -> Buffer, and replay re-verifies against the bytes that were
    // signed. This field is what makes the replay guarantee literally true.
    rawBodyBase64:
      rawBodyBase64 ?? (typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8').toString('base64') : undefined),
    headers: headers && typeof headers === 'object' ? redactHeaders(headers, redacted) : headers,
    attempts,
    errors: [...errors],
    firstFailedAt,
    deadLetteredAt: now().toISOString(),
  };
  return assertReplayable(record);
}

/**
 * The default queue. In memory, so it survives exactly as long as the process, which is
 * said plainly in the README rather than left to be discovered.
 */
export class MemoryDeadLetterQueue {
  #records = new Map();
  #maxRecords;

  constructor({ maxRecords = DEFAULT_MAX_RECORDS } = {}) {
    if (!Number.isInteger(maxRecords) || maxRecords <= 0) {
      throw new TypeError('webhook-engine: maxRecords must be a positive whole number.');
    }
    this.#maxRecords = maxRecords;
  }

  get size() {
    return this.#records.size;
  }

  /**
   * @throws {DeadLetterQueueFullError} rather than evicting. Every other buffer in this
   *   library drops its oldest entry when full; this one holds the events that already
   *   failed everywhere else, and a queue that quietly forgets them is a log file.
   */
  async push(record) {
    assertReplayable(record);
    if (this.#records.size >= this.#maxRecords) throw new DeadLetterQueueFullError(this.#maxRecords);
    this.#records.set(record.id, record);
    return record;
  }

  async list() {
    return [...this.#records.values()];
  }

  async get(id) {
    return this.#records.get(id) ?? null;
  }

  async remove(id) {
    return this.#records.delete(id);
  }
}
