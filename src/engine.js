/**
 * The engine. The four mechanics in the order that makes them work together.
 *
 *   raw bytes + headers
 *     → verify signature          reject: 401, nothing is stored
 *     → parse + extract event id  reject: 400, nothing is stored
 *     → reserve idempotency key   duplicate: 200, in flight: 409, handler never runs
 *     → retry(handler)            success: 200, key completed
 *     → dead letter               exhausted: 200, key released, record stored
 *
 * Three of those orderings are decisions rather than accidents.
 *
 * VERIFICATION COMES BEFORE PARSING. Parsing attacker-controlled bytes is attack
 * surface, and an unverified sender should not get to exercise the JSON parser or
 * anything downstream of it. It also means a rejected sender can fill neither the
 * idempotency store nor the dead letter queue.
 *
 * THE KEY IS RESERVED BEFORE THE HANDLER RUNS. Reserving afterwards leaves the
 * check-then-set window open for the whole duration of the handler, which is exactly
 * when duplicates arrive.
 *
 * A DEAD LETTERED EVENT RETURNS 200. This is the counterintuitive one. A 5xx tells the
 * provider to redeliver; the redelivery fails identically, burns the provider's retry
 * budget, and eventually gets the endpoint disabled, while a perfectly good copy of the
 * event is already sitting in the DLQ. The 200 means responsibility has been taken, and
 * it is only honest because the record exists — so when the DLQ refuses the record, the
 * status inverts to 500 and the provider is asked to redeliver after all.
 */

import { verifySignature } from './verify.js';
import { MemoryIdempotencyStore } from './idempotency.js';
import { MemoryDeadLetterQueue, buildDeadLetterRecord } from './dlq.js';
import { retry as retryFn, DEFAULT_RETRY } from './retry.js';

export const DEFAULT_SIGNATURE_HEADER = 'webhook-signature';
export const DEFAULT_ID_HEADER = 'webhook-id';

function lowercaseHeaders(headers) {
  const map = new Map();
  if (headers && typeof headers === 'object') {
    for (const [name, value] of Object.entries(headers)) map.set(name.toLowerCase(), value);
  }
  return map;
}

function assertStore(store) {
  for (const method of ['reserve', 'complete', 'release']) {
    if (typeof store?.[method] !== 'function') {
      throw new TypeError(`webhook-engine: store must implement ${method}(). See SPEC.md section 5.`);
    }
  }
}

function assertDlq(dlq) {
  for (const method of ['push', 'list', 'get', 'remove']) {
    if (typeof dlq?.[method] !== 'function') {
      throw new TypeError(`webhook-engine: dlq must implement ${method}(). See SPEC.md section 5.`);
    }
  }
}

/**
 * @param {object} options
 * @param {string|string[]} options.secret signing key, or several during a rotation
 * @param {(event: {id: string, body: unknown, rawBody: string, headers: object}) => Promise<unknown>} options.handler
 * @param {object} [options.store] idempotency store, default in-memory
 * @param {object} [options.dlq] dead letter queue, default in-memory
 * @param {object} [options.retry] retry options, see DEFAULT_RETRY
 * @param {string} [options.signatureHeader]
 * @param {string} [options.idHeader]
 * @param {string} [options.timestampHeader] for providers that deliver it separately
 * @param {(body: unknown, headers: Map<string,string>, rawBody: string) => string|null} [options.eventId]
 * @param {(rawBody: string) => unknown} [options.parse] pass null to skip parsing
 * @param {(info: object) => void} [options.onEvent]
 * @returns {{receive: Function, replay: Function, store: object, dlq: object}}
 */
export function createEngine({
  secret,
  handler,
  store = new MemoryIdempotencyStore(),
  dlq = new MemoryDeadLetterQueue(),
  retry: retryOptions = {},
  signatureHeader = DEFAULT_SIGNATURE_HEADER,
  idHeader = DEFAULT_ID_HEADER,
  timestampHeader = null,
  eventId,
  parse = JSON.parse,
  toleranceSeconds,
  requireTimestamp,
  algorithm,
  encoding,
  now = Date.now,
  sleep,
  onEvent,
} = {}) {
  // Configuration is checked at construction, so a misconfigured deployment fails at
  // boot rather than at the first delivery.
  if (typeof handler !== 'function') {
    throw new TypeError('webhook-engine: handler must be a function.');
  }
  const secrets = Array.isArray(secret) ? secret : [secret];
  if (!secrets.some((s) => typeof s === 'string' && s.length > 0)) {
    throw new TypeError(
      'webhook-engine: a signing secret is required. An endpoint with no secret has no ' +
        'authentication, and this library will not fall open for one.',
    );
  }
  assertStore(store);
  assertDlq(dlq);

  const retryConfig = { ...DEFAULT_RETRY, ...retryOptions, ...(sleep ? { sleep } : {}) };

  // THE SIGNED BODY DECIDES, AND THE HEADER IS ONLY A FALLBACK.
  //
  // The HMAC covers the body and the timestamp. It does not cover any other header, so
  // an id read out of `webhook-id` is attacker-editable by anyone who can rewrite
  // headers in flight — a proxy, a sidecar, a compromised load balancer. Preferring the
  // header would let the same signed event be presented under a fresh id and processed a
  // second time, which defeats deduplication without ever touching the signature.
  //
  // Where a provider does bind the id into the signature (the Standard Webhooks scheme
  // signs `${id}.${timestamp}.${body}`), the header is as trustworthy as the body and
  // this ordering costs nothing, because the two values agree.
  const defaultEventId = (body, headers) => {
    const fromBody = body?.id ?? body?.event_id ?? body?.eventId;
    if (typeof fromBody === 'string' && fromBody.length > 0) return fromBody;
    const fromHeader = headers.get(idHeader);
    return typeof fromHeader === 'string' && fromHeader.length > 0 ? fromHeader : null;
  };
  const resolveEventId = eventId ?? defaultEventId;

  function report(info) {
    onEvent?.(info);
    return info;
  }

  /**
   * @param {{rawBody: string|Buffer, headers: object}} request
   * @param {{skipVerification?: boolean}} [options]
   */
  async function receive({ rawBody, headers } = {}, { skipVerification = false } = {}) {
    const lower = lowercaseHeaders(headers);

    if (!skipVerification) {
      const timestamp = timestampHeader ? Number(lower.get(timestampHeader)) : undefined;
      const verified = verifySignature({
        rawBody,
        header: lower.get(signatureHeader),
        secret,
        timestamp: Number.isFinite(timestamp) ? timestamp : undefined,
        toleranceSeconds,
        requireTimestamp,
        algorithm,
        encoding,
        now: now(),
      });
      if (!verified.valid) {
        return report({ status: 401, outcome: 'rejected', reason: verified.reason });
      }
    } else if (typeof rawBody !== 'string' && !Buffer.isBuffer(rawBody)) {
      return report({ status: 401, outcome: 'rejected', reason: 'no_raw_body' });
    }

    const rawText = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;

    let body = rawText;
    if (parse) {
      try {
        body = parse(rawText);
      } catch (error) {
        return report({ status: 400, outcome: 'unparsable', reason: error.message });
      }
    }

    const id = resolveEventId(body, lower, rawText);
    if (typeof id !== 'string' || id.length === 0) {
      return report({ status: 400, outcome: 'no_event_id' });
    }

    const claim = await store.reserve(id);
    if (claim.state === 'done') {
      return report({ status: 200, outcome: 'duplicate', eventId: id, result: claim.result });
    }
    if (claim.state === 'in_flight') {
      // Not 200. The first delivery may still fail, and telling the provider "already
      // done" while the work is unfinished is how an event disappears.
      return report({ status: 409, outcome: 'in_flight', eventId: id });
    }

    const event = { id, body, rawBody: rawText, headers: Object.fromEntries(lower) };
    const outcome = await retryFn(() => handler(event), retryConfig);

    if (outcome.ok) {
      await store.complete(id, outcome.result);
      return report({
        status: 200,
        outcome: 'processed',
        eventId: id,
        result: outcome.result,
        attempts: outcome.attempts,
      });
    }

    // THE RECORD BECOMES DURABLE BEFORE THE RESERVATION IS RELEASED.
    //
    // Releasing first leaves a window in which the event is covered by neither the
    // reservation nor a record, and a duplicate delivery landing inside it reserves
    // cleanly and runs the handler a second time while the first copy is still on its way
    // to the queue. Pushing first means the cover is continuous: the reservation holds
    // until a durable record replaces it.
    //
    // The release still happens, so the original reason for the old order survives — a
    // manual redelivery of a dead lettered event is allowed to run rather than being
    // refused as a duplicate.
    let record;
    try {
      record = await dlq.push(
        buildDeadLetterRecord({
          eventId: id,
          rawBody: rawText,
          headers: Object.fromEntries(lower),
          attempts: outcome.attempts,
          errors: outcome.errors,
          firstFailedAt: new Date(now()).toISOString(),
          now: () => new Date(now()),
        }),
      );
    } catch (error) {
      // Nothing was stored, so a 200 would have been a lie. Release the key so the
      // provider's redelivery is allowed to run, and ask for one.
      await store.release(id);
      return report({
        status: 500,
        outcome: 'dead_letter_failed',
        eventId: id,
        reason: error.message,
      });
    }

    await store.release(id);
    return report({
      status: 200,
      outcome: 'dead_lettered',
      eventId: id,
      attempts: outcome.attempts,
      dlqId: record.id,
      errors: outcome.errors,
    });
  }

  /**
   * Put a dead lettered event back through the pipeline. Verification runs again by
   * default, which means an old record fails its replay window — correct, and
   * deliberately inconvenient. `skipVerification` is an explicit argument so the
   * operator's decision to bypass it is visible in the code they wrote, rather than a
   * replay path that quietly accepts anything.
   *
   * @param {string|object} recordOrId
   * @param {{skipVerification?: boolean}} [options]
   */
  async function replay(recordOrId, { skipVerification = false } = {}) {
    const record = typeof recordOrId === 'string' ? await dlq.get(recordOrId) : recordOrId;
    if (!record) return report({ status: 404, outcome: 'not_found' });

    const response = await receive(
      { rawBody: record.rawBody, headers: record.headers },
      { skipVerification },
    );

    // Drained only on a real success. A refused replay leaves the record where it was.
    if (response.outcome === 'processed') await dlq.remove(record.id);
    return { ...response, replayedFrom: record.id };
  }

  return { receive, replay, store, dlq };
}
