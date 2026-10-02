/**
 * Idempotency.
 *
 * Duplicate delivery is documented behaviour at every major provider, not an edge case.
 * It happens when the receiver's 200 is lost on the way back, when a load balancer times
 * out a slow handler, when a provider fails over, and every time an operator presses
 * "resend" in a dashboard. If the handler charges a card or sends an email, a duplicate
 * is a customer-visible incident.
 *
 * The interface has three calls rather than one because the one-call version has two
 * holes, and both of them are quiet.
 *
 *   if (seen.has(id)) return;      // (a) two deliveries in the same tick both pass here
 *   seen.add(id);                  // (b) marked done before the work succeeded
 *   await handle(event);           //     so a throw here loses the event forever
 *
 * `reserve` closes (a) by claiming and reporting in one operation. `complete` closes (b)
 * by being the only thing that marks a key done. `release` is what a permanent failure
 * calls so the key can be claimed again.
 *
 * The store contract, which any backend must satisfy:
 *
 *   reserve(key)           → { state: 'reserved' } | { state: 'in_flight' } | { state: 'done', result }
 *   complete(key, result)  → void
 *   release(key)           → void
 *
 * `reserve` must be atomic. In Redis that is `SET key <state> NX PX ttl`. In Postgres it
 * is `INSERT ... ON CONFLICT DO NOTHING` against a unique index, then a read. The
 * in-memory implementation below is atomic for free, because its reserve does all of its
 * reading and writing inside one synchronous body and JavaScript will not preempt it.
 */

/** A day. Long enough to outlive every provider's retry schedule, which is the point. */
export const DEFAULT_IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;

/** A ceiling, because an unbounded Map behind an HTTP endpoint is a memory leak with a schedule. */
export const DEFAULT_MAX_ENTRIES = 100_000;

function assertKey(key) {
  if (typeof key !== 'string' || key.length === 0) {
    throw new TypeError('webhook-engine: an idempotency key must be a non-empty string.');
  }
}

/**
 * The default store. Correct for one process and worthless across two, which is stated
 * plainly in the README rather than left for a reader to discover in production.
 */
export class MemoryIdempotencyStore {
  #entries = new Map();
  #ttlMs;
  #maxEntries;
  #now;

  constructor({ ttlMs = DEFAULT_IDEMPOTENCY_TTL_MS, maxEntries = DEFAULT_MAX_ENTRIES, now = Date.now } = {}) {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new TypeError('webhook-engine: ttlMs must be a positive number of milliseconds.');
    }
    if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
      throw new TypeError('webhook-engine: maxEntries must be a positive whole number.');
    }
    this.#ttlMs = ttlMs;
    this.#maxEntries = maxEntries;
    this.#now = now;
  }

  get size() {
    return this.#entries.size;
  }

  /**
   * Claim the key, or report who already holds it. Atomic by construction.
   * @returns {Promise<{state:'reserved'}|{state:'in_flight'}|{state:'done', result:unknown}>}
   */
  async reserve(key) {
    assertKey(key);
    const entry = this.#entries.get(key);

    // An expired reservation is an abandoned one. Without this, a process that dies
    // mid-handler blocks that event id permanently, and the redelivery that would have
    // fixed it comes back as a duplicate.
    if (entry && this.#now() - entry.at <= this.#ttlMs) {
      return entry.state === 'done' ? { state: 'done', result: entry.result } : { state: 'in_flight' };
    }

    this.#write(key, { state: 'in_flight', at: this.#now() });
    return { state: 'reserved' };
  }

  /** Mark the key done and record what the handler returned, for the next redelivery. */
  async complete(key, result) {
    assertKey(key);
    // Deliberately an upsert. A handler slow enough to outlive the TTL, or a process
    // restarted mid-flow, must not turn a success into a throw here.
    this.#write(key, { state: 'done', result, at: this.#now() });
  }

  /** Give the key back, so a permanently failed event can be redelivered and retried. */
  async release(key) {
    assertKey(key);
    this.#entries.delete(key);
  }

  #write(key, entry) {
    // Re-insert so Map iteration order stays oldest-first for eviction.
    this.#entries.delete(key);
    this.#entries.set(key, entry);
    while (this.#entries.size > this.#maxEntries) {
      const victim = this.#evictable();
      if (victim === undefined) break;
      this.#entries.delete(victim);
    }
  }

  /**
   * The oldest entry that is safe to forget: a completed key, or a reservation past its
   * TTL (abandoned). NEVER A LIVE RESERVATION. Dropping one lets a duplicate arriving
   * next reserve cleanly and run the handler a second time. When every entry is a live
   * reservation the store goes over its cap instead, which is bounded by how much work
   * is genuinely in flight rather than by how many events have ever arrived.
   */
  #evictable() {
    const now = this.#now();
    for (const [key, entry] of this.#entries) {
      if (entry.state === 'done' || now - entry.at > this.#ttlMs) return key;
    }
    return undefined;
  }
}
