import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createEngine } from '../src/engine.js';
import { signHeader, verifySignature } from '../src/verify.js';
import { MemoryDeadLetterQueue, MemoryIdempotencyStore, buildDeadLetterRecord } from '../src/index.js';

const SECRET = 'whsec_fixture';
const SIGNED_AT = 1614556800;
const NOW = SIGNED_AT * 1000;

function delivery(body, { secret = SECRET, timestamp = SIGNED_AT, headers = {} } = {}) {
  const rawBody = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    rawBody,
    headers: {
      'content-type': 'application/json',
      'webhook-signature': signHeader({ rawBody, secret, timestamp }),
      ...headers,
    },
  };
}

function engineWith(handler, options = {}) {
  return createEngine({
    secret: SECRET,
    handler,
    now: () => NOW,
    sleep: async () => {},
    retry: { attempts: 3, baseMs: 1, maxMs: 5 },
    ...options,
  });
}

test('a dead lettered record still verifies on replay, which a parsed body could not', async () => {
  // The whole reason the DLQ stores bytes. The body below is deliberately not what
  // JSON.stringify would have produced, so a record that had "helpfully" stored the
  // parsed object is provably unreplayable, and that counterfactual is asserted rather
  // than described.
  const raw = '{ "id" : "evt_201",  "type":"payout.failed" }';
  const request = delivery(raw);

  let failing = true;
  const engine = engineWith(async () => {
    if (failing) throw new Error('downstream down');
    return 'replayed';
  });

  assert.equal((await engine.receive(request)).outcome, 'dead_lettered');
  const [record] = await engine.dlq.list();

  assert.equal(record.rawBody, raw);
  assert.ok(record.headers['webhook-signature'], 'the signature survives, or there is nothing to replay');

  // The record as stored verifies.
  assert.equal(
    verifySignature({
      rawBody: record.rawBody,
      header: record.headers['webhook-signature'],
      secret: SECRET,
      now: NOW,
    }).valid,
    true,
  );

  // The same record with the convenient body does not.
  const convenient = JSON.stringify(JSON.parse(record.rawBody));
  assert.equal(
    verifySignature({
      rawBody: convenient,
      header: record.headers['webhook-signature'],
      secret: SECRET,
      now: NOW,
    }).valid,
    false,
    'storing the parsed body would have made this record dead weight',
  );

  failing = false;
  const replayed = await engine.replay(record.id);
  assert.equal(replayed.outcome, 'processed');
});

test('the same signed request delivered twice inside the window is caught by idempotency, not the window', async () => {
  // Both deliveries are inside the replay window, so verification passes both times.
  // This is the pairing the SPEC insists on: the window bounds how long a captured
  // request stays usable, and idempotency is what stops it being used twice.
  let calls = 0;
  const engine = engineWith(async () => { calls += 1; return 'charged'; });
  const request = delivery({ id: 'evt_202', amount: 4200 });

  const first = await engine.receive(request);
  const replayedInsideWindow = await engine.receive(request);

  assert.equal(first.outcome, 'processed');
  assert.equal(replayedInsideWindow.outcome, 'duplicate');
  assert.equal(calls, 1, 'the card is charged once');
});

test('the same signed request delivered outside the window never reaches idempotency at all', async () => {
  let calls = 0;
  const store = new MemoryIdempotencyStore();
  const engine = createEngine({
    secret: SECRET,
    handler: async () => { calls += 1; },
    store,
    now: () => NOW + 301_000,
    sleep: async () => {},
  });

  const response = await engine.receive(delivery({ id: 'evt_203' }));
  assert.equal(response.status, 401);
  assert.equal(response.reason, 'timestamp_out_of_tolerance');
  assert.equal(calls, 0);
  assert.equal(store.size, 0, 'a stale request cannot even claim a key');
});

test('a slow handler and a redelivery in the same tick still charge the card once', async () => {
  // The concurrency hole, driven through the whole engine rather than the store alone.
  let calls = 0;
  const engine = engineWith(async () => {
    calls += 1;
    await new Promise((resolve) => setTimeout(resolve, 5));
    return 'charged';
  });
  const request = delivery({ id: 'evt_204' });

  const responses = await Promise.all(Array.from({ length: 6 }, () => engine.receive(request)));

  assert.equal(calls, 1);
  assert.equal(responses.filter((r) => r.outcome === 'processed').length, 1);
  assert.equal(responses.filter((r) => r.outcome === 'in_flight').length, 5);
});

test('a retry storm through the engine stays inside its cap and lands every event in the DLQ', async () => {
  let calls = 0;
  const store = new MemoryIdempotencyStore();
  const engine = engineWith(async () => { calls += 1; throw new Error('dependency down'); }, { store });

  const responses = await Promise.all(
    Array.from({ length: 20 }, (_, i) => engine.receive(delivery({ id: `evt_3${i}` }))),
  );

  assert.equal(calls, 20 * 3, 'twenty events, three attempts each, and not one more');
  assert.equal(responses.every((r) => r.outcome === 'dead_lettered'), true);
  assert.equal((await engine.dlq.list()).length, 20);
  assert.equal(store.size, 0, 'every key was released, so every event is redeliverable');
});

test('a forged sender can fill neither the idempotency store nor the dead letter queue', async () => {
  let calls = 0;
  const store = new MemoryIdempotencyStore();
  const dlq = new MemoryDeadLetterQueue();
  const engine = engineWith(async () => { calls += 1; }, { store, dlq });

  for (let i = 0; i < 100; i += 1) {
    const response = await engine.receive(delivery({ id: `evt_4${i}` }, { secret: 'whsec_wrong' }));
    assert.equal(response.status, 401);
  }

  assert.equal(calls, 0);
  assert.equal(store.size, 0);
  assert.equal(dlq.size, 0);
});

test('an unsigned header cannot be used to slip a duplicate past deduplication', async () => {
  // The event id is read from the body first, precisely because the body is covered by
  // the signature and a transport header is not. Anyone able to rewrite headers in
  // flight could otherwise present the same signed event under a fresh id and have it
  // processed a second time.
  let calls = 0;
  const engine = engineWith(async () => { calls += 1; return 'charged'; });
  const body = { id: 'evt_205', amount: 4200 };

  await engine.receive(delivery(body, { headers: { 'webhook-id': 'evt_205' } }));
  const rewritten = await engine.receive(delivery(body, { headers: { 'webhook-id': 'evt_this_is_new' } }));

  assert.equal(rewritten.outcome, 'duplicate');
  assert.equal(rewritten.eventId, 'evt_205', 'the signed body decided, not the header');
  assert.equal(calls, 1);
});

test('a handler that mutates the event it was given cannot corrupt the dead letter record', async () => {
  const raw = '{"id":"evt_206","type":"order.created"}';
  const engine = engineWith(async (event) => {
    event.rawBody = '{"id":"evt_206","type":"order.cancelled"}';
    event.headers['webhook-signature'] = 'tampered';
    throw new Error('down');
  });

  await engine.receive(delivery(raw));
  const [record] = await engine.dlq.list();

  assert.equal(record.rawBody, raw);
  assert.notEqual(record.headers['webhook-signature'], 'tampered');
});

test('a replay that fails again is dead lettered afresh rather than vanishing', async () => {
  const engine = engineWith(async () => { throw new Error('still down'); });
  await engine.receive(delivery({ id: 'evt_207' }));

  const [record] = await engine.dlq.list();
  const response = await engine.replay(record.id);

  assert.equal(response.outcome, 'dead_lettered');
  const records = await engine.dlq.list();
  assert.equal(records.length, 2, 'the original stays and the replay attempt is recorded');
  assert.equal(records.every((r) => r.eventId === 'evt_207'), true);
});

test('a dead letter record assembled by hand from a parsed body is refused by the queue', async () => {
  // A caller writing their own backend, or reconstructing a record from a dashboard,
  // does not get to opt out of the property that makes the record worth keeping.
  const dlq = new MemoryDeadLetterQueue();

  // Assembled without the builder, which is the only way this reaches the queue at all.
  const handRolled = {
    id: 'dlq_handrolled',
    eventId: 'evt_208',
    rawBody: { id: 'evt_208' },
    headers: {},
    attempts: 1,
    errors: [],
  };

  await assert.rejects(() => dlq.push(handRolled), /rawBody/);
  assert.equal(dlq.size, 0);

  // And the builder refuses it one layer earlier, so neither route gets there.
  assert.throws(() => buildDeadLetterRecord(handRolled), /rawBody/);
});

test('a redelivery arriving while the dead letter is being written cannot start the handler again', async () => {
  // The window between releasing the reservation and the record becoming durable. If the
  // key is released first, the event is briefly covered by neither the reservation nor a
  // record, and a duplicate that lands in that gap reserves cleanly and runs the handler a
  // second time. The DLQ's push is the seam, so the redelivery is fired from inside it.
  let handlerRuns = 0;
  let secondOutcome = null;

  const dlq = new MemoryDeadLetterQueue();
  const push = dlq.push.bind(dlq);
  let engine;
  let fired = false;
  dlq.push = async (record) => {
    // The guard is set BEFORE the await. Setting it after lets the nested delivery's own
    // dead letter re-enter this hook, and the test deadlocks instead of asserting.
    if (!fired) {
      fired = true;
      secondOutcome = (await engine.receive(delivery(RAW))).outcome;
    }
    return push(record);
  };

  const RAW = JSON.stringify({ id: 'evt_race', type: 'payout.failed' });
  engine = engineWith(
    async () => {
      handlerRuns += 1;
      throw new Error('downstream down');
    },
    { dlq },
  );

  assert.equal((await engine.receive(delivery(RAW))).outcome, 'dead_lettered');
  assert.equal(secondOutcome, 'in_flight', 'the duplicate must still see a reservation');
  assert.equal(handlerRuns, 3, 'three attempts for the first delivery, and none for the second');
});

test('a release that fails after the record is durable does not turn a truthful 200 into an error', async () => {
  // Once the record exists the event is safe and responsibility has transferred, so the
  // 200 is honest. The cost of the failed release is a key stuck until its TTL, which the
  // operator needs told rather than discovering it when a replay is refused.
  const store = new MemoryIdempotencyStore();
  store.release = async () => {
    throw new Error('store unreachable');
  };

  const engine = engineWith(
    async () => {
      throw new Error('downstream down');
    },
    { store },
  );

  const response = await engine.receive(delivery({ id: 'evt_release_fail', type: 'payout.failed' }));

  assert.equal(response.status, 200);
  assert.equal(response.outcome, 'dead_lettered');
  assert.equal(response.releaseFailed, 'store unreachable');
  assert.equal((await engine.dlq.list()).length, 1, 'the record is what makes the 200 honest');
});

test('a handler that hangs is dead lettered rather than holding the connection open', { timeout: 2000 }, async () => {
  // End to end, the failure retry.js gained a bound for. Without it this delivery never
  // returns at all: no retry, no record, no response, and the key reserved the whole time.
  const signals = [];
  const engine = engineWith(
    (event, { signal }) =>
      new Promise(() => {
        signals.push(signal);
      }),
    { retry: { attempts: 2, baseMs: 1, maxMs: 5, timeoutMs: 10 } },
  );

  const response = await engine.receive(delivery({ id: 'evt_hang', type: 'payout.failed' }));

  assert.equal(response.outcome, 'dead_lettered');
  assert.equal(response.attempts, 2);
  assert.equal(signals.length, 2, 'the handler is reached on both attempts');
  assert.ok(
    signals.every((signal) => signal.aborted),
    'every abandoned attempt aborts its own signal',
  );
  assert.match((await engine.dlq.list())[0].errors[0].message, /timed out after 10ms/);
});

test('a dead lettered record replays byte for byte when the body is not valid UTF-8', { timeout: 2000 }, async () => {
  // The DLQ's whole purpose is replay, and replay re-verifies. Decoding the body to a
  // string on the way in makes `Buffer -> string -> Buffer` lossy for anything that is not
  // valid UTF-8: the bytes that come back out are not the bytes that were signed, so the
  // record fails verification at exactly the moment it exists to be used.
  //
  // The suite's existing replay counterfactual uses a string body, so it passes either
  // way. This is the input shape that separates them.
  const rawBody = Buffer.concat([
    Buffer.from('{"id":"evt_bytes","note":"'),
    Buffer.from([0xff, 0xfe]),
    Buffer.from('"}'),
  ]);
  assert.notDeepEqual(
    Buffer.from(rawBody.toString('utf8'), 'utf8'),
    rawBody,
    'the fixture has to actually survive the round trip badly, or it proves nothing',
  );

  const request = {
    rawBody,
    headers: {
      'content-type': 'application/json',
      'webhook-signature': signHeader({ rawBody, secret: SECRET, timestamp: SIGNED_AT }),
    },
  };

  let failing = true;
  const engine = engineWith(async () => {
    if (failing) throw new Error('downstream down');
    return 'replayed';
  });

  assert.equal((await engine.receive(request)).outcome, 'dead_lettered');
  const [record] = await engine.dlq.list();

  failing = false;
  const response = await engine.replay(record.id);
  assert.equal(response.outcome, 'processed', 'the stored record must still verify');
});
