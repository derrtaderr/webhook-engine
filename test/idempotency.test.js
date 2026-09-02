import { test } from 'node:test';
import assert from 'node:assert/strict';

import { MemoryIdempotencyStore, DEFAULT_IDEMPOTENCY_TTL_MS } from '../src/idempotency.js';

test('a key nobody has claimed is reserved by the first caller', async () => {
  const store = new MemoryIdempotencyStore();
  assert.deepEqual(await store.reserve('evt_001'), { state: 'reserved' });
});

test('a second caller finds the key in flight while the first is still working', async () => {
  const store = new MemoryIdempotencyStore();
  await store.reserve('evt_001');
  assert.deepEqual(await store.reserve('evt_001'), { state: 'in_flight' });
});

test('once completed, the key reports done and hands back the recorded result', async () => {
  const store = new MemoryIdempotencyStore();
  await store.reserve('evt_001');
  await store.complete('evt_001', { charged: true, receipt: 'rcpt_9' });

  const seen = await store.reserve('evt_001');
  assert.equal(seen.state, 'done');
  assert.deepEqual(seen.result, { charged: true, receipt: 'rcpt_9' });
});

test('a released key is claimable again, so a failure is not swallowed forever', async () => {
  // The naive store marks the key seen before the handler runs. When the handler throws,
  // the event can never be retried and never be redelivered: it is silently gone.
  const store = new MemoryIdempotencyStore();
  await store.reserve('evt_001');
  await store.release('evt_001');
  assert.deepEqual(await store.reserve('evt_001'), { state: 'reserved' });
});

test('two concurrent reservations of one key produce exactly one winner', async () => {
  // Check-then-set is not atomic. `if (!seen.has(k)) { seen.add(k) }` lets both callers
  // through when they arrive in the same tick, which is exactly when duplicates arrive.
  const store = new MemoryIdempotencyStore();
  const results = await Promise.all(Array.from({ length: 8 }, () => store.reserve('evt_001')));

  const reserved = results.filter((r) => r.state === 'reserved');
  assert.equal(reserved.length, 1, 'exactly one caller may hold the key');
  assert.equal(results.filter((r) => r.state === 'in_flight').length, 7);
});

test('a reservation abandoned by a crashed process becomes claimable after the TTL', async () => {
  // Without this, one process dying mid-handler blocks that event id permanently and the
  // redelivery that would have fixed it is reported as a duplicate.
  let now = 1_000_000;
  const store = new MemoryIdempotencyStore({ ttlMs: 60_000, now: () => now });

  await store.reserve('evt_001');
  now += 59_999;
  assert.equal((await store.reserve('evt_001')).state, 'in_flight');

  now += 2;
  assert.equal((await store.reserve('evt_001')).state, 'reserved');
});

test('a completed key also expires, so the store does not grow without bound', async () => {
  let now = 1_000_000;
  const store = new MemoryIdempotencyStore({ ttlMs: 60_000, now: () => now });

  await store.reserve('evt_001');
  await store.complete('evt_001', 'ok');
  assert.equal((await store.reserve('evt_001')).state, 'done');

  now += 60_001;
  assert.equal((await store.reserve('evt_001')).state, 'reserved');
});

test('the default TTL is long enough to outlive a provider retry schedule', () => {
  assert.equal(DEFAULT_IDEMPOTENCY_TTL_MS, 24 * 60 * 60 * 1000);
});

test('the store is bounded, and the oldest entry is the one evicted', async () => {
  // The key is attacker-influenced even though the sender is authenticated, and an
  // unbounded Map behind an HTTP endpoint is a memory leak with a schedule.
  const store = new MemoryIdempotencyStore({ maxEntries: 3 });
  for (const id of ['evt_1', 'evt_2', 'evt_3']) {
    await store.reserve(id);
    await store.complete(id, id);
  }
  assert.equal(store.size, 3);

  await store.reserve('evt_4');
  assert.equal(store.size, 3);
  assert.equal((await store.reserve('evt_1')).state, 'reserved', 'the oldest was evicted');
  assert.equal((await store.reserve('evt_3')).state, 'done', 'the newest survived');
});

test('completing a key whose reservation expired mid-flight still records the result', async () => {
  // A slow handler outliving the TTL is a real case. Throwing here would turn a slow
  // success into a hard failure and then into a duplicate on redelivery.
  let now = 1_000_000;
  const store = new MemoryIdempotencyStore({ ttlMs: 10, now: () => now });

  await store.reserve('evt_001');
  now += 1000;
  await store.complete('evt_001', 'finished late');
  assert.deepEqual(await store.reserve('evt_001'), { state: 'done', result: 'finished late' });
});

test('a key that is not a non-empty string is refused by every call', async () => {
  const store = new MemoryIdempotencyStore();
  for (const key of ['', undefined, null, 42, {}]) {
    await assert.rejects(() => store.reserve(key), /key/i, `reserve ${JSON.stringify(key)}`);
    await assert.rejects(() => store.complete(key, 'x'), /key/i, `complete ${JSON.stringify(key)}`);
    await assert.rejects(() => store.release(key), /key/i, `release ${JSON.stringify(key)}`);
  }
});

test('releasing or completing a key nobody reserved is not an error', async () => {
  // After a restart the store is empty and the engine is mid-flow. Neither call should
  // be the thing that takes the process down.
  const store = new MemoryIdempotencyStore();
  await store.release('evt_never_seen');
  await store.complete('evt_never_seen', 'ok');
  assert.deepEqual(await store.reserve('evt_never_seen'), { state: 'done', result: 'ok' });
});
