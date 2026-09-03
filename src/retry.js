/**
 * Retry with exponential backoff and full jitter.
 *
 * Most handler failures are transient: a connection reset, a lock timeout, a rate limit,
 * a four-second restart. Returning a 500 and leaning on the provider's own retry works
 * until you notice that the provider's retry is a fresh delivery, on a schedule you do
 * not control, up to a limit you cannot change, going back through verification and
 * idempotency each time. An in-process retry turns a four-second outage into a
 * four-second delay.
 *
 * WHY JITTER IS NOT OPTIONAL, since it is the part that gets left out.
 *
 * When a shared dependency fails, every in-flight handler fails at the same moment. On a
 * deterministic schedule all of them wait 250ms, all of them retry in the same
 * millisecond, all of them wait 500ms, and retry together again. The backoff has
 * synchronised the callers into a thundering herd that hits the recovering dependency in
 * tight, growing waves, which is the load pattern that stops it recovering. Randomising
 * the delay spreads the same number of retries across the interval.
 *
 * Full jitter (`random() * backoff`) is used rather than the half-jitter variants
 * because it spreads hardest. The worst it costs is a retry that happens sooner than the
 * nominal schedule suggested.
 *
 * WHY THE TWO BOUNDS. Uncapped doubling reaches an hour by attempt 16 and a day by
 * attempt 21, holding a request handler and its memory the whole time. Unbounded
 * attempts mean a permanently poisoned event retries forever and never reaches the dead
 * letter queue, so the queue stays reassuringly empty while the backlog grows.
 */

export const DEFAULT_RETRY = Object.freeze({
  attempts: 4,
  baseMs: 250,
  maxMs: 30_000,
  factor: 2,
  jitter: true,
});

function validate({ attempts, baseMs, maxMs, factor }) {
  if (!Number.isInteger(attempts) || attempts < 1) {
    throw new TypeError('webhook-engine: retry attempts must be a whole number of at least 1.');
  }
  if (!Number.isFinite(baseMs) || baseMs <= 0) {
    throw new TypeError('webhook-engine: retry baseMs must be a positive number of milliseconds.');
  }
  if (!Number.isFinite(maxMs) || maxMs < baseMs) {
    throw new TypeError('webhook-engine: retry maxMs must be a finite number no smaller than baseMs.');
  }
  if (!Number.isFinite(factor) || factor < 1) {
    throw new TypeError('webhook-engine: retry factor must be at least 1, or the backoff shrinks.');
  }
}

/**
 * The wait before the given attempt's retry. `attempt` is 1-based, so `computeDelay(1)`
 * is the pause after the first failure.
 *
 * `factor ** attempt` overflows to Infinity somewhere past attempt 1024, and an infinite
 * delay is a handler that never returns. The cap is applied before the jitter for that
 * reason as well as the obvious one.
 */
export function computeDelay(attempt, options = {}) {
  const { baseMs, maxMs, factor, jitter, random } = { ...DEFAULT_RETRY, random: Math.random, ...options };
  const exponential = baseMs * factor ** (attempt - 1);
  const capped = Math.min(maxMs, exponential);
  return jitter ? Math.floor(random() * capped) : capped;
}

/** An error thrown as a string or an object still has to end up in the DLQ record. */
function toErrorRecord(thrown, attempt) {
  const isError = thrown instanceof Error;
  return {
    attempt,
    name: isError ? thrown.name : typeof thrown,
    message: isError ? thrown.message : `non-Error thrown: ${String(thrown)}`,
    retryable: thrown?.retryable,
  };
}

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Run `fn` until it succeeds or the attempt bound is reached. Returns an outcome rather
 * than throwing, because the caller's next move on failure is to write a dead letter
 * record and it needs every error to do that.
 *
 * @param {(attempt: number) => Promise<unknown>} fn
 * @param {object} [options]
 * @param {number} [options.attempts] hard bound on invocations of fn
 * @param {number} [options.baseMs]
 * @param {number} [options.maxMs] cap on any single wait
 * @param {number} [options.factor]
 * @param {boolean} [options.jitter]
 * @param {() => number} [options.random] injectable, so the schedule is testable
 * @param {(ms: number) => Promise<void>} [options.sleep] injectable, so tests do not wait
 * @param {(error: unknown) => boolean} [options.shouldRetry] caller's classifier
 * @param {(info: {attempt: number, error: object, delayMs: number|null}) => void} [options.onAttempt]
 * @returns {Promise<{ok: true, result: unknown, attempts: number, errors: object[]}
 *                  |{ok: false, attempts: number, errors: object[]}>}
 */
export async function retry(fn, options = {}) {
  const config = { ...DEFAULT_RETRY, random: Math.random, ...options };
  validate(config);

  const { attempts, sleep = defaultSleep, shouldRetry, onAttempt } = config;
  const errors = [];

  // The attempt bound is expressed twice: here, and in the `last` check below. The
  // mutation check found that widening this condition alone changes nothing, because
  // `last` still returns at the bound. That redundancy is deliberate — a loop over an
  // attacker-influenced count wants a hard ceiling that does not depend on the logic
  // inside it staying correct — but it means this line is not the one under test.
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const result = await fn(attempt);
      return { ok: true, result, attempts: attempt, errors };
    } catch (thrown) {
      const record = toErrorRecord(thrown, attempt);
      errors.push(record);

      // An error the caller has classified as permanent, or one that says so itself.
      // Retrying a validation failure four times is four times the load for one answer.
      const retryable = shouldRetry ? shouldRetry(thrown, attempt) : thrown?.retryable !== false;
      const last = attempt === attempts || !retryable;
      const delayMs = last ? null : computeDelay(attempt, config);

      onAttempt?.({ attempt, error: record, delayMs });

      if (last) return { ok: false, attempts: attempt, errors };
      await sleep(delayMs);
    }
  }

  /* c8 ignore next */
  return { ok: false, attempts, errors };
}
