# webhook-engine spec

Webhook ingestion that survives a hostile sender and a flaky handler.

Status: v0.1.0. Node >= 20. Zero runtime dependencies.

## 1. The problem this exists for

Writing a webhook receiver takes ten minutes. `app.post('/hook', ...)`, read the body, do the
work, return 200. That receiver is in production at most companies right now, and it is wrong in
four specific ways that only show up under load, under attack, or during an outage.

1. **It trusts the sender.** Either there is no authentication at all, or there is a shared
   secret compared with `===`. A shared secret in a header is a bearer token: whoever sees it in
   a log, a proxy, a browser devtools panel or a screenshot can forge every future event. And a
   `===` comparison over a secret leaks its own answer through timing.
2. **It trusts the network.** A duplicate delivery is not an edge case, it is the documented
   behaviour of every major provider. Stripe, GitHub, Shopify and Twilio all say, in their own
   docs, that they may deliver the same event more than once. A receiver with no idempotency
   double-charges, double-emails, double-creates.
3. **It gives up on the first error.** The downstream database was restarting for four seconds.
   The event is gone.
4. **It has nowhere to put a failure.** When something does fail permanently, the event goes to
   `console.error` and the record of what was supposed to happen dies with the log rotation.

Each of those has a well understood fix. None of the four ships in the ten-minute receiver, and
they are annoying enough to build correctly that they usually never get built at all. This
library is the four of them, together, with the interfaces a real deployment needs.

## 2. What this is, precisely

A library and an example server. Not a framework, not a hosted service, not a queue.

- `verifySignature` — HMAC over the **raw request bytes**, constant-time comparison, a replay
  window on the signed timestamp, multiple accepted signatures for key rotation.
- `IdempotencyStore` — an interface with a reserve/complete/release lifecycle and an in-memory
  default. A caller swaps in Redis or Postgres without editing a line of this source.
- `retry` — exponential backoff with full jitter, an absolute delay cap, and a bounded attempt
  count.
- `DeadLetterQueue` — an interface with an in-memory default, and a record shaped so the event
  can be replayed later through the same verification it originally passed.
- `createEngine` — the four wired in the correct order, returning an HTTP status and a named
  outcome.

## 3. The four mechanics, and why each is required

### 3.1 Signature verification over the raw body

**Why HMAC and not a shared secret.** A shared secret proves the sender knew a string. An HMAC
signature proves the sender knew a key *and* commits the sender to this exact payload. With a
shared secret, an attacker who has ever seen the secret can send any body they like forever.
With an HMAC, an attacker who has not got the key cannot produce a valid signature for a body
they chose, and the secret never travels on the wire at all.

This matters more than it sounds, because the shared-secret receiver is the common case in the
wild, not the exception. The usual implementation is one line:

```js
// The receiver most teams actually have.
return (headerValue ?? '').trim() === expected.trim();
```

Three defects in one line. The secret is transmitted on every request, so it leaks the way
bearer tokens leak. The `trim()` makes the comparison lenient, so a value that is not the secret
is accepted as the secret. And `===` on strings short-circuits at the first differing byte, so
response time is a function of how many leading bytes the guess got right.

Two of those three are tested here as adversarial cases, because a signature check that would
also accept a near-miss is not a signature check.

**Why constant-time comparison.** String `===` returns as soon as two bytes differ. An attacker
who can time responses learns the length of the matching prefix, and can therefore recover a
valid signature byte by byte in a few thousand requests instead of 2^256. `timingSafeEqual`
compares every byte regardless. This is not theoretical paranoia; it is the reason every provider
SDK ships its own comparison helper.

`timingSafeEqual` **throws** when the two buffers differ in length. So a length check has to come
first, and the length check has to return a value rather than let the exception escape. A
receiver that throws a 500 on a three-character signature has handed an attacker a denial of
service and, at most providers, an automatic redelivery storm on top.

**Why the raw body, and why parsed-body verification is broken.** The signature is computed over
the exact bytes the sender transmitted. `JSON.parse` followed by `JSON.stringify` does not return
those bytes. It normalizes whitespace, re-encodes non-ASCII, drops key ordering guarantees, and
turns `1.0` into `1`. Any of those changes the HMAC. So a receiver that verifies against a
reserialized body is either rejecting every genuine event (if it is lucky) or — worse, and more
common — was written to "work" by loosening something else until it passed.

The practical consequence for the caller is a constraint on their HTTP framework: the raw body
must be captured *before* the JSON body parser runs. Express needs `express.raw()` or the
`verify` hook; Next.js needs the body parser disabled on the route. The README says this in the
one place a stranger will look.

**Why a replay window.** A signature is valid forever. Without a timestamp bound, an attacker who
captures one valid signed request — from a log, a proxy, a mirrored port — can resend it in six
months and it will verify. Binding a timestamp into the signed payload and rejecting anything
outside a tolerance turns a permanent forgery into a five-minute one. The default is 300 seconds,
which is what the major providers use, and it is the number people get wrong in both directions:
too tight and clock skew on the sender rejects genuine traffic, too loose and the window stops
meaning anything.

The replay window is a bound, not a defence on its own. Inside the window, the same signed
request can still be sent twice. That is idempotency's job, and the two mechanics are documented
together for exactly that reason.

**The header shape.** Real providers do not send a bare hex string. Stripe sends
`t=1614556800,v1=abc...,v1=def...` — a timestamp, and one or more signatures so that a key can
be rotated without a window of rejected traffic. GitHub sends `sha256=abc...`. Some send bare
hex. All three parse here, and the multi-signature case is the one that matters: during rotation
the sender signs with both keys, the receiver accepts either, and nobody schedules downtime.

### 3.2 Idempotency

**Why it is required.** Duplicate delivery is documented behaviour, not a bug. It happens when
the receiver's 200 is lost on the way back, when a load balancer times out a slow handler, when
a provider fails over, and every time an operator hits "resend" in a dashboard. If the handler
charges a card or sends an email, a duplicate is a customer-visible incident.

**Why the interface has three calls and not one.** The naive implementation is
`if (seen.has(id)) return; seen.add(id); await handle(event)`. It has two holes, and both are
tested here.

- **The concurrency hole.** Two deliveries of the same event arriving at the same moment both
  pass `seen.has(id)` before either reaches `seen.add(id)`, and the handler runs twice. Check-then-set
  is not atomic. So the store's first call is `reserve(key)`, which claims the key and reports
  what it found in a single operation — the same shape as `SET NX` in Redis or an insert against
  a unique index in Postgres.
- **The failure hole.** If the key is marked done before the handler succeeds, a handler that
  throws leaves an event that can never be retried and never be redelivered. It is silently
  swallowed. So `complete(key, result)` is what marks it done, and `release(key)` is what a
  permanent failure calls to make the key claimable again.

**Why in-memory is the default and not the recommendation.** A `Map` is correct for one process
and worthless across two, and every real deployment has more than one. The default exists so
`npm test` and the example run with no infrastructure. The README's limits section says this
without hedging.

### 3.3 Retry with backoff

**Why retry.** Most handler failures are transient — a connection reset, a lock timeout, a
rate limit, a four-second restart. Returning a 500 and leaning on the provider's own retry works
until you notice that the provider's retry is a fresh delivery, which means it goes through
verification and idempotency again, on a schedule you do not control, up to a limit you cannot
change. An in-process retry turns a four-second outage into a four-second delay.

**Why exponential.** A fixed delay against a struggling dependency is a constant-rate attack on
the thing you want to recover. Doubling gives the dependency room.

**Why jitter is not optional.** This is the part that gets left out, and leaving it out is worse
than having no backoff at all. When a shared dependency fails, every in-flight handler fails at
the same moment. With a deterministic schedule, all of them wait exactly 100ms, then all of them
retry at the same instant, then all of them wait exactly 200ms, and retry at the same instant
again. The backoff has synchronized the callers into a thundering herd that hits the recovering
dependency in tight, ever-larger waves — which is precisely the load pattern that stops it
recovering. Randomizing the delay spreads the same number of retries across the interval. Full
jitter (`random() * backoff`) is used here rather than the half-jitter variants because it
spreads hardest, and the worst case it costs is a retry that happens sooner than the schedule
suggested.

**Why a cap and a bounded count.** Uncapped doubling reaches an hour by attempt 16 and a day by
attempt 21, holding a request handler and its memory the whole time. Unbounded attempts mean a
permanently poisoned event retries forever and never reaches the DLQ, so the DLQ stays
reassuringly empty while the queue backs up. Both bounds are load-bearing and both are tested
against a storm.

**Non-retryable errors.** An error carrying `retryable: false` stops immediately. Retrying a
validation failure four times is four times the load for the same answer.

### 3.4 Dead letter queue

**Why it is required.** After the last attempt, the event is either recorded somewhere
actionable or it is lost. `console.error` is not a dead letter queue; it is a place events go to
be found during a postmortem, if the retention window has not rolled.

**What "enough context to replay" means, concretely.** A DLQ record you cannot replay from is a
log line with extra steps. So the record carries the **raw body as bytes, unparsed**, the full
header set including the signature, the event id, the number of attempts, the error messages in
order, and the timestamps. That set is sufficient to hand the record back to
`engine.receive()` and have it verify — the same verification it passed on the way in.

This is a design constraint that falls out of the raw-body decision in 3.1 and it is the
adversarial test for this mechanic: **store a parsed body and replay verification fails.** The
convenient thing to store is the parsed object. It is smaller, it is readable in a dashboard, and
it silently destroys replayability. The test exists so that convenience cannot be taken later
without a red suite.

Replay does not bypass the replay window. A record dead-lettered a week ago will fail its
timestamp tolerance on replay, and that is correct — the operator replaying it is deciding to
reprocess, so they pass `skipVerification` explicitly and that decision is visible in the code
they wrote. The alternative, a replay path that quietly accepts any signature, is a signed
endpoint with an unsigned back door.

## 4. Order of operations, and why this order

```
raw bytes + headers
  → verify signature          reject: 401, nothing is stored
  → parse + extract event id  reject: 400, nothing is stored
  → reserve idempotency key   already done: 200 duplicate, handler never runs
                              still running: 409 in flight, handler never runs
  → retry(handler)            success: 200, key completed
  → dead letter               exhausted: 200, key released, record stored
                              queue refused: 500, so the provider does redeliver
```

**A duplicate that is still in flight gets 409, not 200.** The first delivery may still fail.
Telling the provider "already done" while the work is unfinished is how an event disappears:
the provider stops, the first attempt dies, and nothing is left holding the event.

**The event id comes from the signed body before the header.** The HMAC covers the body and
the timestamp and no other header, so an id read out of `webhook-id` is editable by anything on
the request path. See section 7 for how this was found.

Three of those orderings are decisions rather than accidents.

**Verification comes before parsing.** Parsing attacker-controlled bytes is attack surface, and
an unverified sender should not get to exercise the JSON parser, the schema validator or
anything downstream of them. Reject first, parse second.

**The idempotency key is reserved before the handler runs, not after.** Reserving after means
the concurrency hole from 3.2 is wide open for the whole duration of the handler, which is
exactly when duplicates arrive.

**A dead-lettered event returns 200, not 500.** This is the counterintuitive one. The event
failed, so a 500 feels honest. But a 5xx tells the provider to redeliver, and the redelivery
will fail the same way, burn the provider's retry budget, and eventually get the endpoint
disabled — while a perfectly good copy of the event is already sitting in the DLQ. The 200 means
"I have taken responsibility for this event," which is true, because the DLQ record exists.
Getting this backwards produces an outage where the provider's own retry logic amplifies a
handler bug into a delivery storm.

The idempotency key is **released** on dead-lettering, so a manual redelivery of the same event
is allowed to run rather than being reported as a duplicate.

## 5. The storage interfaces

Both are duck-typed. No base class to extend, no registration, no factory.

```js
// IdempotencyStore
await store.reserve(key)          // → { state: 'reserved' }
                                  // | { state: 'in_flight' }
                                  // | { state: 'done', result }
await store.complete(key, result) // → void
await store.release(key)          // → void
```

`reserve` must be atomic. In Redis that is `SET key <state> NX PX ttl`. In Postgres it is
`INSERT ... ON CONFLICT DO NOTHING` against a unique index on the key, then a read. The in-memory
default is atomic for free because JavaScript has no preemption inside a synchronous function,
and its `reserve` is deliberately synchronous internally for that reason.

```js
// DeadLetterQueue
await dlq.push(record)   // → record
await dlq.list()         // → record[]
await dlq.remove(id)     // → boolean
```

A record:

```js
{
  id, eventId, rawBody, headers, attempts,
  errors: [{ attempt, message, at }],
  firstFailedAt, deadLetteredAt
}
```

`rawBody` is a string of the exact received bytes. Never an object. Section 3.4 says why.

## 6. What this deliberately does not do

- **No transport.** No Express, no Fastify, no framework adapters. The engine takes bytes and
  headers and returns a status; wiring that to a server is six lines, and the example shows them
  over `node:http`.
- **No durable storage.** In-memory defaults only. Redis and Postgres implementations are
  sketched in the README as the interface they must satisfy, not shipped, because shipping them
  means shipping their drivers and this library has no dependencies on purpose.
- **No provider-specific parsing.** No `stripe.events.constructEvent` equivalent, no payload
  schemas. The header parser covers the three shapes providers actually use; what is inside the
  body is the caller's business.
- **No queue.** Retries happen in-process, inside the request. If a handler needs minutes, the
  correct design is to verify, enqueue, and return 200 immediately — and then this library's job
  ends at the enqueue.
- **No replay protection beyond the window and idempotency.** There is no nonce cache of every
  signature ever seen. Idempotency on the event id covers the case that matters, and a nonce
  cache large enough to be honest is a durable store this library has decided not to own.
- **No key management.** Secrets come in as strings. Rotation is supported by accepting an array
  of them; where they are stored is not this library's problem.
- **No signing service.** `signPayload` exists so tests, examples and a stranger's local
  reproduction can produce a valid signature. It is not an outbound webhook sender.

## 7. Verification posture

Every mechanic here is a guard, and a guard that cannot fail is decoration. The failure mode
being avoided is a check that shares a matcher with the thing it checks, so it passes on
everything and reads as a green suite.

So each of the four ships with at least one test where the naive implementation passes and the
correct one fails:

| Mechanic | The test that the naive version fails |
|---|---|
| Signature | A signature accepted by a trimming, case-lenient comparator is rejected here |
| Signature | A three-byte signature returns invalid instead of throwing out of `timingSafeEqual` |
| Signature | A signature valid over the raw bytes fails over the `JSON.parse`/`stringify` roundtrip |
| Replay window | Same signature, one second inside the window and one second outside |
| Idempotency | Two concurrent deliveries of one event run the handler exactly once |
| Idempotency | A failed event is claimable again; a naive `seen.add` before the handler swallows it |
| Retry | A permanently failing handler is called exactly `attempts` times under a storm |
| Retry | Delay never exceeds the cap, at attempt 3 and at attempt 30 |
| DLQ | A dead-lettered record still verifies on replay, which a parsed body cannot |

### The mutation check, and what it found

The suite is mutation-checked: thirty-two guards were deleted one at a time and the number of
failing tests recorded. A guard whose deletion turns nothing red is not guarded.

The first pass caught twenty-eight and missed four. After the fixes below the same pass catches
thirty-one, and the one remaining survivor is a redundancy rather than a hole. Each of the four
is worth stating rather than tidying away.

1. **Replacing the constant-time comparison with `===` turned nothing red.** This is not
   fixable by a better behavioural test. The two return the same boolean for every input and
   differ only in how long they take, and that difference is not observable from inside the
   process with any stability worth a CI job. The suite now carries a **source canary** that
   fails if the primitive is swapped out, labelled in the test as what it is. It asserts the
   intent of the code, not the behaviour of the compiled program.
2. **Two mutations survived by hanging rather than failing.** A test had the second delivery's
   response releasing the handler's gate, so a store that handed out the same key twice
   deadlocked instead of asserting. A deadlocked run reports nothing at all, which is worse
   than a missed guard because the suite looks like it is still working. The handler now
   releases itself on a timer and the test asserts peak concurrency; both mutations then
   produced clean failures.
3. **Widening the retry loop's bound changed nothing**, because the `last` check inside the
   loop still returns at the bound. Mutating that instead goes red. The duplication is
   deliberate on a loop whose count is influenced by an authenticated but external party, and
   it stays, with a comment saying which of the two lines is the one under test.

### A defect this process found

The default event id originally preferred the `webhook-id` header over the body. The HMAC
covers the body and the timestamp and no other header, so that id is editable by anything on
the request path. The same signed event could be re-presented under a fresh id and processed a
second time, defeating deduplication without ever touching the signature. The signed body now
decides and the header is the fallback. Where a provider binds the id into the signature — the
Standard Webhooks scheme signs `${id}.${timestamp}.${body}` — the two agree and the ordering
costs nothing.

It was found by writing the adversarial test, not by reading the code.

---

## 8. Hardening pass 01 (2026-09-05)

Four defects found by external review of the shipped 0.1.0 and confirmed against the source
before any code was written. Each is real; the line references below were checked, not taken
on the reviewer's word.

**Prior art check.** The existing suite does not cover any of the four. `test/adversarial-engine.test.js:118`
covers a redelivery arriving *during* the handler, which is a different window from the one in
8.1. Buffer input is exercised only at the `verify.js` unit layer with valid UTF-8
(`test/verify.test.js:91`), never end to end through engine → DLQ → replay. There is no timeout
test because there is no timeout. So all four cycles start genuinely red.

### 8.1 The dead letter write must be durable before the key is released

`engine.js:206` releases the idempotency reservation, then `:209` pushes the record. Between
those two lines the event is neither reserved nor safely stored: a duplicate delivery arriving
in that window reserves successfully and starts the handler a second time, while the first
request is still on its way to the DLQ.

Corrected order: push the record, then release. The event is covered by the reservation right
up until the moment it is covered by a durable record instead, and there is no instant where it
is covered by neither.

**The trap in the naive swap, and the decision.** The current ordering exists for a stated
reason — the comment at `:205` wants a manual replay of a dead-lettered event to run rather
than be refused as a duplicate. Pushing first preserves that, because the release still
happens. But if `release()` itself throws after a successful push, the record is durable while
the key stays `in_flight` for the full 24h TTL, and `replay()` inside that window returns 409
instead of running. That is a regression to the very path the old ordering protected.

Decision: **once the record is durable, a failed release is not fatal to the response.** The
event is safe, responsibility has transferred, and the reply stays 200. The failure is reported
on the result object as `releaseFailed` so an operator can see the key will be stuck until TTL,
rather than discovering it at replay time. A push failure still inverts the status to 500, as
it does today.

### 8.2 The handler needs a timeout, not just a retry count

`retry.js:114` is a bare `await fn(attempt)`. It handles a handler that rejects. It cannot
handle a handler that never settles, and a hung handler hangs the whole `receive()` forever:
the key stays reserved, the retry never fires, the DLQ record is never written, and the
connection is held open indefinitely. The 24h reservation TTL eventually lets another delivery
claim the key, but that is recovery from an abandoned reservation, not handler-timeout
semantics.

`retry` gains `timeoutMs`. A handler that exceeds it is treated as a failed attempt — the error
record says so, backoff and the attempt bound apply as normal, and exhaustion dead-letters as
any other permanent failure. The handler receives an `AbortSignal` so cooperative work can stop
rather than continue in the background after the engine has moved on.

Default: `timeoutMs: 10_000`. A tagline that promises survival of a flaky handler has to include
the handler that hangs, which is the most common shape of a dependency outage.

### 8.3 The dead letter record must hold bytes, not a decoded string

`engine.js:164` decodes a Buffer body to a UTF-8 string and `dlq.js:105` stores that string.
HMAC verification itself is byte-correct (`verify.js` `toBytes` keeps the Buffer intact), so the
split is narrow but real: for a body that is not valid UTF-8, `Buffer → string → Buffer` does
not reconstruct the original bytes, and the record fails verification on replay. That failure
lands at the exact moment the DLQ exists to serve, during recovery.

Reachability is low, because JSON is required to be UTF-8 and no conforming provider sends
anything else. The reason to fix it now anyway is that the record is a persisted, user-visible
format. At 0.1.0 with an in-memory default queue, changing its shape costs nothing. After
anyone runs a durable DLQ in production it costs a migration.

The record gains `rawBodyBase64`, and replay reconstructs the exact bytes from it. `rawBody`
stays for readability and for records already in flight.

This is the same failure class the suite already tests in another form — §7's counterfactual,
that a signature valid over the raw bytes fails over a `JSON.parse`/`stringify` round trip. The
project knew this shape and shipped a second instance of it.

### 8.4 The README's retry-duration claim

README:323 says four attempts can hold a connection "for around a minute and a half of wall
clock." With the defaults (`attempts: 4, baseMs: 250, factor: 2`, full jitter) there are three
waits of at most 250, 500 and 1000ms, so the backoff totals at most 1.75s and averages nearer
875ms.

This is not an independent item. It is 8.2 seen from the documentation side: the sentence
asserts a wall-clock bound, and with no handler timeout the honest answer is *unbounded*, not
90 seconds and not 1.75s. Correcting the number alone would state a tight bound for a request
that can in fact hang forever. So 8.2 lands first and this sentence is then rewritten to a
number the code actually guarantees — `attempts × timeoutMs` plus backoff, 41.75s at the
defaults.

### Out of scope

The reviewer's positioning suggestion ("a fail-closed webhook ingestion engine") is a README
and package-description change with no code behind it. It is not part of this pass.
