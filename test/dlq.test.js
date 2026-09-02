import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  MemoryDeadLetterQueue,
  buildDeadLetterRecord,
  DeadLetterQueueFullError,
  DEFAULT_REDACTED_HEADERS,
} from '../src/dlq.js';

const BASE = {
  eventId: 'evt_501',
  rawBody: '{"id":"evt_501","type":"payout.failed"}',
  headers: { 'webhook-signature': 't=1614556800,v1=abc', 'content-type': 'application/json' },
  attempts: 4,
  errors: [{ attempt: 1, message: 'ECONNRESET' }],
  firstFailedAt: '2026-09-02T10:00:00.000Z',
};

test('a record carries the raw bytes, the headers, the attempts and every error', () => {
  const record = buildDeadLetterRecord({ ...BASE, now: () => new Date('2026-09-02T10:00:10Z') });

  assert.equal(record.eventId, 'evt_501');
  assert.equal(record.rawBody, BASE.rawBody);
  assert.equal(record.attempts, 4);
  assert.deepEqual(record.errors, BASE.errors);
  assert.equal(record.firstFailedAt, BASE.firstFailedAt);
  assert.equal(record.deadLetteredAt, '2026-09-02T10:00:10.000Z');
  assert.match(record.id, /^dlq_[0-9a-f]{16}$/);
});

test('the raw body must be a string, because a parsed body cannot be replayed', () => {
  // The convenient thing to store is the parsed object. It is smaller, it reads well in a
  // dashboard, and it silently destroys the only property that makes a DLQ worth having.
  assert.throws(
    () => buildDeadLetterRecord({ ...BASE, rawBody: JSON.parse(BASE.rawBody) }),
    /rawBody/,
  );
  assert.throws(() => buildDeadLetterRecord({ ...BASE, rawBody: undefined }), /rawBody/);
});

test('a record with no event id or no headers is refused', () => {
  assert.throws(() => buildDeadLetterRecord({ ...BASE, eventId: '' }), /eventId/);
  assert.throws(() => buildDeadLetterRecord({ ...BASE, headers: null }), /headers/);
  assert.throws(() => buildDeadLetterRecord({ ...BASE, attempts: 0 }), /attempts/);
});

test('credential headers are redacted, and the signature header is not', () => {
  // The record is durable and it is read by whoever operates the replay. A bearer token
  // sitting in it outlives the request that carried it. The signature has to survive,
  // because without it the record cannot be replayed through verification.
  const record = buildDeadLetterRecord({
    ...BASE,
    headers: {
      authorization: 'Bearer sk_live_notreal',
      cookie: 'session=abc',
      'x-api-key': 'key_notreal',
      'webhook-signature': 't=1614556800,v1=abc',
    },
  });

  assert.equal(record.headers.authorization, '[redacted]');
  assert.equal(record.headers.cookie, '[redacted]');
  assert.equal(record.headers['x-api-key'], '[redacted]');
  assert.equal(record.headers['webhook-signature'], 't=1614556800,v1=abc');
  assert.ok(DEFAULT_REDACTED_HEADERS.includes('authorization'));
});

test('header redaction is case-insensitive, because header casing is not stable', () => {
  const record = buildDeadLetterRecord({ ...BASE, headers: { Authorization: 'Bearer x', COOKIE: 'a=b' } });
  assert.equal(record.headers.Authorization, '[redacted]');
  assert.equal(record.headers.COOKIE, '[redacted]');
});

test('the record is a copy, so a later mutation of the request headers cannot rewrite history', () => {
  const headers = { ...BASE.headers };
  const record = buildDeadLetterRecord({ ...BASE, headers });
  headers['content-type'] = 'text/plain';
  assert.equal(record.headers['content-type'], 'application/json');
});

test('pushed records come back in order and can be fetched by id', async () => {
  const dlq = new MemoryDeadLetterQueue();
  const first = await dlq.push(buildDeadLetterRecord({ ...BASE, eventId: 'evt_1' }));
  const second = await dlq.push(buildDeadLetterRecord({ ...BASE, eventId: 'evt_2' }));

  assert.equal(dlq.size, 2);
  assert.deepEqual((await dlq.list()).map((r) => r.eventId), ['evt_1', 'evt_2']);
  assert.equal((await dlq.get(second.id)).eventId, 'evt_2');
  assert.equal(await dlq.get('dlq_nothing'), null);
  assert.notEqual(first.id, second.id);
});

test('removing a record returns whether there was one to remove', async () => {
  const dlq = new MemoryDeadLetterQueue();
  const record = await dlq.push(buildDeadLetterRecord(BASE));

  assert.equal(await dlq.remove(record.id), true);
  assert.equal(await dlq.remove(record.id), false);
  assert.equal(dlq.size, 0);
});

test('a full queue refuses the push instead of evicting the oldest dead letter', async () => {
  // Eviction is the obvious bound and it is wrong here. Every other buffer in this
  // library can drop its oldest entry; this one holds the events that already failed
  // everywhere else. A DLQ that quietly forgets is a log file with extra steps, so a
  // full queue is loud and the caller has to decide.
  const dlq = new MemoryDeadLetterQueue({ maxRecords: 2 });
  await dlq.push(buildDeadLetterRecord({ ...BASE, eventId: 'evt_1' }));
  await dlq.push(buildDeadLetterRecord({ ...BASE, eventId: 'evt_2' }));

  await assert.rejects(
    () => dlq.push(buildDeadLetterRecord({ ...BASE, eventId: 'evt_3' })),
    DeadLetterQueueFullError,
  );
  assert.deepEqual((await dlq.list()).map((r) => r.eventId), ['evt_1', 'evt_2'], 'nothing was lost');
});

test('a record that did not come from buildDeadLetterRecord is validated on the way in', async () => {
  // A custom DLQ backend is expected. A caller assembling the record by hand is not a
  // reason for the replay guarantee to lapse.
  const dlq = new MemoryDeadLetterQueue();
  await assert.rejects(() => dlq.push({ eventId: 'evt_1', rawBody: { parsed: true } }), /rawBody/);
  await assert.rejects(() => dlq.push(null), /record/);
});

test('the list is a copy, so an operator iterating it cannot corrupt the queue', async () => {
  const dlq = new MemoryDeadLetterQueue();
  await dlq.push(buildDeadLetterRecord(BASE));

  const listed = await dlq.list();
  listed.pop();
  assert.equal(dlq.size, 1);
});
