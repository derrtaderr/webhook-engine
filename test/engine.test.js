import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createEngine } from '../src/engine.js';
import { signHeader } from '../src/verify.js';
import { MemoryDeadLetterQueue } from '../src/dlq.js';

const SECRET = 'whsec_fixture';
const SIGNED_AT = 1614556800;
const NOW = SIGNED_AT * 1000;

/** A signed delivery, in the shape a server hands to the engine. */
function delivery(body, { secret = SECRET, timestamp = SIGNED_AT, id } = {}) {
  const rawBody = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    rawBody,
    headers: {
      'content-type': 'application/json',
      'webhook-id': id ?? (typeof body === 'object' ? body.id : undefined),
      'webhook-signature': signHeader({ rawBody, secret, timestamp }),
    },
  };
}

function engineWith(handler, options = {}) {
  return createEngine({
    secret: SECRET,
    handler,
    now: () => NOW,
    sleep: async () => {},
    retry: { attempts: 3, baseMs: 1, maxMs: 10, ...(options.retry ?? {}) },
    ...options,
  });
}

test('a signed delivery is verified, deduplicated and handled', async () => {
  const seen = [];
  const engine = engineWith(async (event) => { seen.push(event); return 'stored'; });

  const response = await engine.receive(delivery({ id: 'evt_1', type: 'order.created' }));

  assert.equal(response.status, 200);
  assert.equal(response.outcome, 'processed');
  assert.equal(response.eventId, 'evt_1');
  assert.equal(response.result, 'stored');
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0].body, { id: 'evt_1', type: 'order.created' });
  assert.equal(seen[0].rawBody, '{"id":"evt_1","type":"order.created"}');
});

test('an unsigned or wrongly signed delivery is a 401 and the handler never runs', async () => {
  let calls = 0;
  const engine = engineWith(async () => { calls += 1; });

  const forged = delivery({ id: 'evt_2' }, { secret: 'whsec_wrong' });
  const response = await engine.receive(forged);

  assert.equal(response.status, 401);
  assert.equal(response.outcome, 'rejected');
  assert.equal(response.reason, 'no_matching_signature');
  assert.equal(calls, 0);
  assert.equal((await engine.dlq.list()).length, 0, 'a rejected sender cannot fill the DLQ');
});

test('a body that is not parsable is a 400, and the handler never runs', async () => {
  let calls = 0;
  const engine = engineWith(async () => { calls += 1; });

  const response = await engine.receive(delivery('{not json', { id: 'evt_3' }));

  assert.equal(response.status, 400);
  assert.equal(response.outcome, 'unparsable');
  assert.equal(calls, 0);
});

test('a verified delivery with no event id anywhere is a 400', async () => {
  const engine = engineWith(async () => 'ok');
  const response = await engine.receive(delivery({ type: 'order.created' }));

  assert.equal(response.status, 400);
  assert.equal(response.outcome, 'no_event_id');
});

test('the event id falls back to the body when the header does not carry one', async () => {
  const engine = engineWith(async () => 'ok');
  const request = delivery({ id: 'evt_4', type: 'order.created' });
  delete request.headers['webhook-id'];

  const response = await engine.receive(request);
  assert.equal(response.eventId, 'evt_4');
});

test('a redelivery is recognised and the handler is not run twice', async () => {
  let calls = 0;
  const engine = engineWith(async () => { calls += 1; return `run ${calls}`; });
  const request = delivery({ id: 'evt_5', type: 'invoice.paid' });

  const first = await engine.receive(request);
  const second = await engine.receive(request);

  assert.equal(first.outcome, 'processed');
  assert.equal(second.outcome, 'duplicate');
  assert.equal(second.status, 200);
  assert.equal(second.result, 'run 1', 'the original result is returned, not a fresh one');
  assert.equal(calls, 1);
});

test('a redelivery arriving while the first is still working gets a 409', async () => {
  // 409 rather than 200, because the first delivery may still fail. Telling the provider
  // "already done" while the work is unfinished is how an event disappears.
  // The handler releases itself on a timer rather than waiting for the second response.
  // An earlier version had the second response release it, which meant a store that
  // handed out the key twice deadlocked instead of failing, and a deadlocked test
  // reports nothing at all.
  let concurrent = 0;
  let peak = 0;
  const engine = engineWith(async () => {
    concurrent += 1;
    peak = Math.max(peak, concurrent);
    await new Promise((resolve) => setTimeout(resolve, 20));
    concurrent -= 1;
    return 'done';
  });
  const request = delivery({ id: 'evt_6' });

  const first = engine.receive(request);
  const second = await engine.receive(request);
  assert.equal(second.status, 409);
  assert.equal(second.outcome, 'in_flight');

  assert.equal((await first).outcome, 'processed');
  assert.equal(peak, 1, 'the handler was never running twice at once');
});

test('a transient failure is retried inside the request and then succeeds', async () => {
  let calls = 0;
  const engine = engineWith(async () => {
    calls += 1;
    if (calls < 3) throw new Error('database restarting');
    return 'eventually';
  });

  const response = await engine.receive(delivery({ id: 'evt_7' }));

  assert.equal(response.outcome, 'processed');
  assert.equal(response.attempts, 3);
  assert.equal(calls, 3);
});

test('a permanent failure is dead lettered, and the response is 200', async () => {
  // The counterintuitive one. A 5xx tells the provider to redeliver, the redelivery
  // fails identically, and the endpoint eventually gets disabled while a perfectly good
  // copy of the event sits in the DLQ. The 200 means responsibility has been taken, and
  // it is true because the record exists.
  const engine = engineWith(async () => { throw new Error('schema mismatch'); });
  const request = delivery({ id: 'evt_8', type: 'payout.failed' });

  const response = await engine.receive(request);

  assert.equal(response.status, 200);
  assert.equal(response.outcome, 'dead_lettered');
  assert.equal(response.attempts, 3);

  const [record] = await engine.dlq.list();
  assert.equal(record.eventId, 'evt_8');
  assert.equal(record.rawBody, request.rawBody, 'the exact bytes, not a reserialisation');
  assert.equal(record.attempts, 3);
  assert.equal(record.errors.length, 3);
  assert.equal(response.dlqId, record.id);
});

test('a dead lettered event releases its key, so a manual redelivery is allowed to run', async () => {
  let calls = 0;
  const engine = engineWith(async () => {
    calls += 1;
    if (calls <= 3) throw new Error('down');
    return 'recovered';
  });
  const request = delivery({ id: 'evt_9' });

  assert.equal((await engine.receive(request)).outcome, 'dead_lettered');
  const second = await engine.receive(request);

  assert.equal(second.outcome, 'processed', 'not reported as a duplicate');
  assert.equal(second.result, 'recovered');
});

test('a dead letter queue that refuses the push returns 500, so the provider does redeliver', async () => {
  // The inverse of the case above, and it has to be, because the 200 was only honest
  // while the record existed.
  const dlq = new MemoryDeadLetterQueue({ maxRecords: 1 });
  const engine = engineWith(async () => { throw new Error('down'); }, { dlq });

  assert.equal((await engine.receive(delivery({ id: 'evt_10' }))).status, 200);

  const response = await engine.receive(delivery({ id: 'evt_11' }));
  assert.equal(response.status, 500);
  assert.equal(response.outcome, 'dead_letter_failed');
  assert.match(response.reason, /full/i);
});

test('headers are matched without regard to case, because casing is not stable in transit', async () => {
  const engine = engineWith(async () => 'ok');
  const request = delivery({ id: 'evt_12' });

  const response = await engine.receive({
    rawBody: request.rawBody,
    headers: {
      'Webhook-Id': request.headers['webhook-id'],
      'WEBHOOK-SIGNATURE': request.headers['webhook-signature'],
    },
  });
  assert.equal(response.outcome, 'processed');
});

test('a dead lettered record replays through the engine and leaves the queue', async () => {
  let failing = true;
  const engine = engineWith(async () => {
    if (failing) throw new Error('down');
    return 'replayed';
  });

  await engine.receive(delivery({ id: 'evt_13' }));
  const [record] = await engine.dlq.list();

  failing = false;
  const response = await engine.replay(record.id);

  assert.equal(response.outcome, 'processed');
  assert.equal(response.result, 'replayed');
  assert.equal((await engine.dlq.list()).length, 0, 'a replayed record is drained');
});

test('replaying an old record fails its replay window unless the operator says otherwise', async () => {
  // Correct, and deliberately inconvenient. The alternative is a replay path that
  // accepts any signature, which is an unsigned back door into a signed endpoint.
  let failing = true;
  const engine = engineWith(async () => {
    if (failing) throw new Error('down');
    return 'replayed';
  });

  await engine.receive(delivery({ id: 'evt_14' }));
  const [record] = await engine.dlq.list();
  failing = false;

  const aWeekLater = createEngine({
    secret: SECRET,
    handler: async () => 'replayed',
    now: () => NOW + 7 * 24 * 60 * 60 * 1000,
    sleep: async () => {},
    dlq: engine.dlq,
  });

  const refused = await aWeekLater.replay(record.id);
  assert.equal(refused.status, 401);
  assert.equal(refused.reason, 'timestamp_out_of_tolerance');
  assert.equal((await engine.dlq.list()).length, 1, 'a refused replay does not drain the record');

  const forced = await aWeekLater.replay(record.id, { skipVerification: true });
  assert.equal(forced.outcome, 'processed');
  assert.equal((await engine.dlq.list()).length, 0);
});

test('replaying an id that is not in the queue says so instead of throwing', async () => {
  const engine = engineWith(async () => 'ok');
  const response = await engine.replay('dlq_absent');
  assert.equal(response.status, 404);
  assert.equal(response.outcome, 'not_found');
});

test('onEvent sees every outcome, so a receiver can emit metrics without wrapping calls', async () => {
  const observed = [];
  const engine = engineWith(async () => 'ok', { onEvent: (info) => observed.push(info) });

  await engine.receive(delivery({ id: 'evt_15' }));
  await engine.receive(delivery({ id: 'evt_15' }));
  await engine.receive(delivery({ id: 'evt_16' }, { secret: 'whsec_wrong' }));

  assert.deepEqual(observed.map((o) => o.outcome), ['processed', 'duplicate', 'rejected']);
  assert.equal(observed[0].eventId, 'evt_15');
});

test('a misconfigured engine refuses to be constructed', async () => {
  assert.throws(() => createEngine({ handler: async () => {} }), /secret/i);
  assert.throws(() => createEngine({ secret: SECRET }), /handler/i);
  assert.throws(() => createEngine({ secret: SECRET, handler: 'not a function' }), /handler/i);
  assert.throws(() => createEngine({ secret: SECRET, handler: async () => {}, store: {} }), /store/i);
  assert.throws(() => createEngine({ secret: SECRET, handler: async () => {}, dlq: {} }), /dlq/i);
});

test('a request with no rawBody is a 400 rather than an exception', async () => {
  const engine = engineWith(async () => 'ok');
  const response = await engine.receive({ headers: {} });
  assert.equal(response.status, 401);
  assert.equal(response.reason, 'no_raw_body');
});
