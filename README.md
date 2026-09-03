# webhook-engine

Webhook ingestion that survives a hostile sender and a flaky handler.

Zero dependencies. Node 20 or newer. A library plus a runnable example receiver.

## Why this exists

Writing a webhook receiver takes ten minutes.

```js
app.post('/hook', async (req, res) => {
  await handle(req.body);
  res.sendStatus(200);
});
```

That receiver is in production at most companies right now, and it is wrong in four
specific ways that only show up under load, under attack, or during an outage.

**It trusts the sender.** Either there is no authentication, or there is a shared secret
compared like this, which is the single most common webhook auth check in the wild:

```js
return (headerValue ?? '').trim() === expected.trim();
```

Three defects in one line. The secret travels on every request, so it leaks the way bearer
tokens leak — a log, a proxy, a screenshot. The `trim()` makes the comparison lenient, so
a value that is not the secret is accepted as the secret. And `===` returns at the first
differing byte, so response time tells an attacker how much of their guess was right.

**It trusts the network.** Duplicate delivery is documented behaviour at Stripe, GitHub,
Shopify and Twilio, not an edge case. Without idempotency, a duplicate double-charges.

**It gives up on the first error.** The database was restarting for four seconds. The
event is gone.

**It has nowhere to put a failure.** `console.error` is not a dead letter queue.

This library is those four, together, with the interfaces a real deployment needs.

## Install

```bash
npm install webhook-engine
```

Or clone it. There is nothing to install and nothing to build.

```bash
git clone https://github.com/derrtaderr/webhook-engine.git
cd webhook-engine
npm test
node example/receiver.js
```

## Thirty seconds

```bash
node example/receiver.js
```

```
1. a genuine delivery
   → {"status":200,"body":{"outcome":"processed","eventId":"evt_1001","result":{"ledgerSize":1},"attempts":1}}

2. the same delivery again, which is what every provider eventually does
   → {"status":200,"body":{"outcome":"duplicate","eventId":"evt_1001","result":{"ledgerSize":1}}}
   the handler ran once. the ledger holds 1 entry.

3. a forgery, signed with a key we do not hold
   → {"status":401,"body":{"outcome":"rejected","reason":"no_matching_signature"}}

4. a genuine delivery captured six minutes ago and replayed
   → {"status":401,"body":{"outcome":"rejected","reason":"timestamp_out_of_tolerance"}}

5. a delivery whose handler keeps failing
   → {"status":200,"body":{"outcome":"dead_lettered","eventId":"evt_1004","attempts":3,"dlqId":"dlq_9c2f80af...","errors":[...]}}
   the record kept the exact bytes: {"id":"evt_1004","type":"payout.failed"}
   and 3 attempts worth of errors: ledger service refused the write, ...

6. the dependency recovers, and an operator replays the record
   → {"outcome":"processed","result":{"ledgerSize":2}}
   replayed from the dead letter queue. remaining records: 0
```

The walkthrough is run by the test suite and by CI, so the instruction above cannot rot.

## Worked example

A complete receiver. Copy it into a file and run it.

```js
import { createServer } from 'node:http';
import { createEngine } from 'webhook-engine';

const engine = createEngine({
  secret: process.env.WEBHOOK_SECRET,
  retry: { attempts: 4, baseMs: 250, maxMs: 30_000 },

  async handler(event) {
    // event.id       the deduplication key, taken from the signed body
    // event.body     parsed, only after the signature verified
    // event.rawBody  the exact bytes, if you need them
    await recordPayment(event.body);
    return { recorded: true };
  },

  onEvent: ({ outcome, eventId }) => metrics.increment(`webhook.${outcome}`),
});

createServer(async (request, response) => {
  // THE RAW BODY IS READ BEFORE ANYTHING PARSES IT. See the next section.
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);

  const { status, ...body } = await engine.receive({
    rawBody: Buffer.concat(chunks),
    headers: request.headers,
  });

  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}).listen(3000);
```

Every outcome `receive` can return:

| status | outcome | what happened |
|---|---|---|
| 200 | `processed` | verified, deduplicated, handled |
| 200 | `duplicate` | seen before, the original result is returned, the handler did not run |
| 200 | `dead_lettered` | retries exhausted, the event is in the DLQ, do not redeliver |
| 401 | `rejected` | signature, replay window, or missing body. `reason` says which |
| 400 | `unparsable` | verified, but the body is not what `parse` expected |
| 400 | `no_event_id` | verified and parsed, but there is nothing to deduplicate on |
| 409 | `in_flight` | another delivery of this event is being handled right now |
| 500 | `dead_letter_failed` | the DLQ refused the record, so please do redeliver |

## The raw body, and why your framework is in the way

The signature covers the exact bytes the sender transmitted. `JSON.parse` followed by
`JSON.stringify` does not reproduce those bytes:

```js
JSON.parse('{ "amount" : 1.0 }');  // → { amount: 1 }
JSON.stringify({ amount: 1 });     // → '{"amount":1}'
```

Whitespace, number formatting, `\uXXXX` escapes and key ordering all change, and any one
of them changes the HMAC. A receiver that verifies against a reparsed body is either
rejecting its own genuine traffic or was loosened until it stopped rejecting anything.

So the raw bytes must be captured before the body parser runs.

```js
// Express
app.post('/hook', express.raw({ type: 'application/json' }), (req, res) => {
  engine.receive({ rawBody: req.body, headers: req.headers });
});

// Express, keeping express.json() elsewhere
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));

// Fastify
fastify.addContentTypeParser('application/json', { parseAs: 'buffer' }, (_req, body, done) => done(null, body));

// Next.js app router
export async function POST(request) {
  const rawBody = await request.text();
}
```

## The four mechanics

### Signature verification

HMAC over the raw bytes, compared with `crypto.timingSafeEqual`, with a replay window on
a timestamp that is bound into the signed payload. Three header shapes parse:

```
t=1614556800,v1=abc,v1=def   Stripe-style, several signatures for key rotation
sha256=abc                   GitHub-style
abc                          bare
```

The multi-signature form is the one that earns its place. During a rotation the sender
signs with both keys, the receiver accepts either, and nobody schedules downtime:

```js
createEngine({ secret: [process.env.WEBHOOK_SECRET_NEW, process.env.WEBHOOK_SECRET_OLD] });
```

Nothing is trimmed or case-folded on the way in. A signature with a trailing newline is
malformed, not a signature that needs tidying, because every leniency in a comparator is
a value that is not the signature being accepted as one.

An absent secret **throws at construction**. The usual `if (secret) { check }` turns an
unset environment variable into an endpoint with authentication switched off, and nothing
about that is visible from outside.

### Idempotency

The store has three calls, not one, because the one-call version has two quiet holes.

```js
if (seen.has(id)) return;   // two deliveries in the same tick both pass here
seen.add(id);               // marked done before the work succeeded, so a throw
await handle(event);        // below loses the event permanently
```

`reserve` claims and reports in a single operation. `complete` is the only call that
marks a key done. `release` hands the key back so a permanent failure stays redeliverable.

Plug in your own backend by passing anything with those three methods:

```js
// Redis. reserve must be atomic; SET NX is what makes it so.
const store = {
  async reserve(key) {
    const claimed = await redis.set(`wh:${key}`, 'in_flight', { NX: true, PX: 86_400_000 });
    if (claimed) return { state: 'reserved' };
    const current = await redis.get(`wh:${key}`);
    if (current === 'in_flight') return { state: 'in_flight' };
    return { state: 'done', result: JSON.parse(current) };
  },
  complete: (key, result) => redis.set(`wh:${key}`, JSON.stringify(result), { PX: 86_400_000 }),
  release: (key) => redis.del(`wh:${key}`),
};

createEngine({ secret, handler, store });
```

In Postgres the same atomicity comes from `INSERT ... ON CONFLICT DO NOTHING` against a
unique index on the key, followed by a read.

### Retry with backoff

Exponential, with **full jitter**, an absolute cap, and a bounded attempt count.

Jitter is the part that gets left out, and leaving it out is worse than having no backoff
at all. When a shared dependency fails, every in-flight handler fails in the same moment.
On a deterministic schedule all of them wait 250ms and retry in the same millisecond,
then wait 500ms and retry together again. The backoff has synchronised the callers into a
herd that hits the recovering dependency in tight, growing waves, which is the load
pattern that stops it recovering.

An error carrying `retryable: false` stops immediately, and `shouldRetry` lets you
classify by status code or anything else.

### Dead letter queue

The record holds the raw bytes unparsed, the headers including the signature, the event
id, the attempt count and every error in order. That is what makes it replayable through
the same verification it passed on the way in.

```js
for (const record of await engine.dlq.list()) {
  console.log(record.eventId, record.attempts, record.errors.at(-1).message);
}

await engine.replay(recordId);                            // verifies again
await engine.replay(recordId, { skipVerification: true }); // for a record older than the window
```

Storing the parsed body is the convenient choice and it silently destroys replayability,
so a non-string `rawBody` is refused at the boundary and refused again in the store.

A full queue **throws** rather than evicting. Every other buffer here drops its oldest
entry; this one holds the events that already failed everywhere else.

Credential headers (`authorization`, `cookie`, `x-api-key` and friends) are redacted in
the record. The signature header is not, because without it there is nothing to replay.

## Configuration

```js
createEngine({
  secret,                     // string | string[] — required, throws if absent
  handler,                    // async (event) => result — required

  store,                      // default: MemoryIdempotencyStore
  dlq,                        // default: MemoryDeadLetterQueue
  retry: { attempts: 4, baseMs: 250, maxMs: 30_000, factor: 2, jitter: true },

  signatureHeader: 'webhook-signature',
  idHeader: 'webhook-id',     // fallback only; the signed body decides first
  timestampHeader: null,      // for providers that deliver it separately
  toleranceSeconds: 300,
  requireTimestamp: true,
  algorithm: 'sha256',
  encoding: 'hex',            // or 'base64'

  eventId,                    // (body, headers: Map<lowercase, value>, rawBody) => string | null
  parse: JSON.parse,          // pass null to leave the body as a string
  onEvent,                    // (info) => void, for metrics
  now, sleep,                 // injectable clocks, for tests
});
```

## Limits, stated plainly

**The in-memory store and queue are for one process.** A `Map` is correct for one process
and worthless across two, and every real deployment has more than one. They exist so
`npm test` and the example run with no infrastructure. Use the Redis or Postgres shape
above in production, and remember that the dead letter queue is the one that must be
durable — it holds the events that already failed.

**Constant-time comparison is asserted structurally, not behaviourally.** A constant-time
comparison and `===` return the same boolean for every input and differ only in timing,
which is not observable from inside the process with any stability worth a CI job. The
mutation check confirmed this: swapping in `===` turned no behavioural test red. So one
test reads the source and fails if the primitive is swapped out. It does not prove the
compiled behaviour is constant time — a JIT can undo what the source intends.

**Signatures are compared byte for byte in the encoding you configure.** An uppercase hex
signature is rejected rather than normalised. Every provider this was written against
sends lowercase hex or base64. If yours does not, normalise it before handing it over,
deliberately, in your own code.

**Retries happen inside the request.** With the defaults, four attempts can hold a
connection for around a minute and a half of wall clock. If your handler is slow, the
right design is to verify, enqueue, return 200, and let this library's job end at the
enqueue.

**The event id is only as trustworthy as its source.** It is read from the signed body
first for that reason. If your provider puts the id only in a header and does not bind
that header into the signature, anything on the request path can rewrite it and defeat
deduplication. That is a property of the provider, not something this library can fix.

**No nonce cache.** The replay window bounds how long a captured request stays usable, and
idempotency stops it being processed twice. There is no record of every signature ever
seen, because a cache large enough to be honest is a durable store this library has
decided not to own.

**Not a queue, not a framework, not a provider SDK.** No Express adapter, no payload
schemas, no `constructEvent` equivalent. Bytes and headers in, a status out.

## Tests

```bash
npm test          # 129 tests, no network, no install step
```

Two files carry the weight. `test/adversarial-signature.test.js` reproduces the lenient
comparator most receivers ship and asserts that it accepts each forgery before asserting
that this library rejects it. `test/adversarial-engine.test.js` does the same at the
system level, including the counterfactual that a dead letter record holding a parsed
body provably fails the verification the stored bytes pass.

The suite is mutation checked. Thirty-two guards were deleted one at a time and the
number of failing tests recorded; the survivors are described in the commit history and,
where they cannot be closed, in the limits above.

## License

MIT.
