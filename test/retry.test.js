import { test } from 'node:test';
import assert from 'node:assert/strict';

import { retry, computeDelay, DEFAULT_RETRY } from '../src/retry.js';

/** A sleep that records what it was asked to wait for instead of waiting. */
function recordingSleep() {
  const waits = [];
  const sleep = async (ms) => void waits.push(ms);
  return { sleep, waits };
}

const noJitter = { random: () => 1 };

test('a handler that succeeds first time is called once and never sleeps', async () => {
  const { sleep, waits } = recordingSleep();
  let calls = 0;

  const outcome = await retry(async () => { calls += 1; return 'ok'; }, { sleep });

  assert.equal(outcome.ok, true);
  assert.equal(outcome.result, 'ok');
  assert.equal(outcome.attempts, 1);
  assert.equal(calls, 1);
  assert.deepEqual(waits, [], 'no delay before an attempt that has not failed yet');
});

test('a handler that succeeds on the third attempt reports three attempts and two waits', async () => {
  const { sleep, waits } = recordingSleep();
  let calls = 0;

  const outcome = await retry(
    async () => {
      calls += 1;
      if (calls < 3) throw new Error(`transient ${calls}`);
      return 'recovered';
    },
    { attempts: 5, baseMs: 100, sleep, ...noJitter },
  );

  assert.equal(outcome.ok, true);
  assert.equal(outcome.result, 'recovered');
  assert.equal(outcome.attempts, 3);
  assert.equal(waits.length, 2);
  assert.equal(outcome.errors.length, 2, 'the failures are kept, because the DLQ needs them');
});

test('a handler that always fails is called exactly the bounded number of times', async () => {
  const { sleep } = recordingSleep();
  let calls = 0;

  const outcome = await retry(async () => { calls += 1; throw new Error('down'); }, {
    attempts: 4,
    sleep,
    ...noJitter,
  });

  assert.equal(outcome.ok, false);
  assert.equal(calls, 4, 'not 5, not until it works');
  assert.equal(outcome.attempts, 4);
  assert.equal(outcome.errors.length, 4);
  assert.equal(outcome.errors[0].attempt, 1);
  assert.equal(outcome.errors.at(-1).message, 'down');
});

test('a retry storm across many callers never exceeds its cap', async () => {
  // Fifty concurrent deliveries of a permanently broken handler. The number that matters
  // is the total load placed on the failing dependency, and it has to be bounded by the
  // configuration rather than by how long the outage lasts.
  const { sleep, waits } = recordingSleep();
  let calls = 0;
  const attempts = 3;
  const maxMs = 5_000;

  const outcomes = await Promise.all(
    Array.from({ length: 50 }, () =>
      retry(async () => { calls += 1; throw new Error('dependency down'); }, {
        attempts,
        baseMs: 100,
        maxMs,
        sleep,
      }),
    ),
  );

  assert.equal(calls, 50 * attempts, 'exactly attempts per caller, no more');
  assert.equal(outcomes.every((o) => o.ok === false), true);
  assert.equal(waits.length, 50 * (attempts - 1));
  assert.equal(waits.every((w) => w <= maxMs), true, 'no single wait exceeds the cap');
  assert.ok(
    waits.reduce((a, b) => a + b, 0) <= 50 * (attempts - 1) * maxMs,
    'total waiting is bounded by configuration, not by the outage',
  );
});

test('the backoff doubles, and stops doubling at the cap', () => {
  const options = { baseMs: 100, maxMs: 1_000, ...noJitter };
  assert.equal(computeDelay(1, options), 100);
  assert.equal(computeDelay(2, options), 200);
  assert.equal(computeDelay(3, options), 400);
  assert.equal(computeDelay(4, options), 800);
  assert.equal(computeDelay(5, options), 1_000, 'capped, not 1600');
  assert.equal(computeDelay(6, options), 1_000);
});

test('the cap holds at an attempt number where the exponential has overflowed', () => {
  // 2 ** 1023 is finite, 2 ** 1024 is Infinity. Math.min against a cap survives both,
  // and a delay of Infinity is a handler that never returns.
  const options = { baseMs: 100, maxMs: 30_000, ...noJitter };
  for (const attempt of [30, 100, 2_000]) {
    const delay = computeDelay(attempt, options);
    assert.equal(delay, 30_000, `attempt ${attempt}`);
    assert.equal(Number.isFinite(delay), true);
  }
});

test('full jitter spreads the delay across the whole interval', () => {
  const options = { baseMs: 100, maxMs: 10_000 };
  assert.equal(computeDelay(3, { ...options, random: () => 0 }), 0);
  assert.equal(computeDelay(3, { ...options, random: () => 0.5 }), 200);
  assert.equal(computeDelay(3, { ...options, random: () => 1 }), 400);
});

test('a hundred callers backing off together do not line up on the same instant', () => {
  // This is why jitter is not optional. Without it every caller that failed against the
  // same dependency waits exactly the same interval and retries in one synchronised
  // wave, which is the load pattern that stops the dependency recovering.
  const options = { baseMs: 100, maxMs: 10_000 };

  const jittered = new Set(Array.from({ length: 100 }, () => computeDelay(4, options)));
  const lockstep = new Set(Array.from({ length: 100 }, () => computeDelay(4, { ...options, jitter: false })));

  assert.equal(lockstep.size, 1, 'without jitter, one hundred callers pick one instant');
  assert.ok(jittered.size > 50, `with jitter they spread out, saw ${jittered.size} distinct delays`);
});

test('jitter can be switched off, and then the schedule is the bare exponential', () => {
  const options = { baseMs: 100, maxMs: 10_000, jitter: false };
  assert.equal(computeDelay(1, options), 100);
  assert.equal(computeDelay(3, options), 400);
});

test('an error marked not retryable stops immediately', async () => {
  const { sleep, waits } = recordingSleep();
  let calls = 0;

  const outcome = await retry(
    async () => {
      calls += 1;
      throw Object.assign(new Error('malformed payload'), { retryable: false });
    },
    { attempts: 5, sleep, ...noJitter },
  );

  assert.equal(outcome.ok, false);
  assert.equal(calls, 1, 'retrying a validation failure is four times the load for one answer');
  assert.equal(outcome.attempts, 1);
  assert.deepEqual(waits, []);
  assert.equal(outcome.errors[0].retryable, false);
});

test('shouldRetry lets the caller classify errors the library cannot', async () => {
  const { sleep } = recordingSleep();
  let calls = 0;

  const outcome = await retry(
    async () => { calls += 1; throw Object.assign(new Error('nope'), { status: 422 }); },
    { attempts: 5, sleep, shouldRetry: (error) => error.status >= 500, ...noJitter },
  );

  assert.equal(calls, 1);
  assert.equal(outcome.ok, false);
});

test('a thrown non-Error is captured rather than crashing the retry loop', async () => {
  const { sleep } = recordingSleep();
  const outcome = await retry(async () => { throw 'a bare string'; }, { attempts: 2, sleep, ...noJitter });

  assert.equal(outcome.ok, false);
  assert.equal(outcome.errors.length, 2);
  assert.match(outcome.errors[0].message, /a bare string/);
});

test('onAttempt observes every failure with its attempt number and the wait that follows', async () => {
  const { sleep } = recordingSleep();
  const seen = [];

  await retry(async () => { throw new Error('down'); }, {
    attempts: 3,
    baseMs: 100,
    sleep,
    ...noJitter,
    onAttempt: (info) => seen.push(info),
  });

  assert.deepEqual(seen.map((s) => s.attempt), [1, 2, 3]);
  assert.deepEqual(seen.map((s) => s.delayMs), [100, 200, null], 'the last failure has nothing after it');
});

test('the defaults are stated once and are the ones documented', () => {
  assert.deepEqual(DEFAULT_RETRY, {
    attempts: 4,
    baseMs: 250,
    maxMs: 30_000,
    factor: 2,
    jitter: true,
    timeoutMs: 10_000,
  });
});

test('nonsense configuration is refused instead of quietly becoming a single attempt', async () => {
  const cases = [
    { attempts: 0 },
    { attempts: -1 },
    { attempts: 1.5 },
    { attempts: '3' },
    { baseMs: 0 },
    { baseMs: -1 },
    { maxMs: 10, baseMs: 100 },
    { factor: 0.5 },
  ];
  for (const bad of cases) {
    await assert.rejects(
      () => retry(async () => 'ok', { sleep: async () => {}, ...bad }),
      /webhook-engine/,
      JSON.stringify(bad),
    );
  }
});

test('a handler that never settles is abandoned at the timeout and counts as a failed attempt', { timeout: 2000 }, async () => {
  // The failure retry could not previously see. A rejection is handled; a promise that
  // never settles held the loop open forever, so the retry never fired, the dead letter
  // was never written, and the connection stayed open with the key reserved.
  const { sleep } = recordingSleep();

  const outcome = await retry(() => new Promise(() => {}), { attempts: 2, timeoutMs: 10, sleep });

  assert.equal(outcome.ok, false);
  assert.equal(outcome.attempts, 2, 'a timeout is a failed attempt, so the bound still applies');
  assert.equal(outcome.errors.length, 2);
  assert.match(outcome.errors[0].message, /timed out after 10ms/);
});

test('the handler is given a signal that aborts when its attempt times out', { timeout: 2000 }, async () => {
  // Abandoning the promise is not enough on its own. Without a signal the work carries on
  // in the background against a dependency the engine has already given up on.
  const seen = [];

  await retry(
    (attempt, { signal }) =>
      // Records the abort and never settles. Resolving here would make the attempt a
      // success, the loop would return after the first one, and the test would be
      // asserting the opposite of what it claims.
      new Promise(() => {
        signal.addEventListener('abort', () => void seen.push(attempt));
      }),
    { attempts: 2, timeoutMs: 10, sleep: async () => {} },
  );

  assert.deepEqual(seen, [1, 2], 'every timed-out attempt aborts its own signal');
});

test('a handler that settles in time is never aborted', { timeout: 2000 }, async () => {
  let aborted = false;

  const outcome = await retry(
    async (attempt, { signal }) => {
      signal.addEventListener('abort', () => {
        aborted = true;
      });
      return 'ok';
    },
    { attempts: 2, timeoutMs: 50, sleep: async () => {} },
  );

  assert.equal(outcome.ok, true);
  assert.equal(aborted, false, 'a successful attempt must not leave an aborted signal behind');
});
