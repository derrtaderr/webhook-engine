#!/usr/bin/env node
/**
 * A complete webhook receiver, wired to all four mechanics, over node:http.
 *
 * Run it:   node example/receiver.js
 *
 * It starts a server on an ephemeral port, sends itself six deliveries covering every
 * outcome the engine can produce, prints what happened, and exits. Nothing listens on a
 * fixed port and nothing is left running.
 *
 * The one line that matters most is the raw body read. The signature covers the exact
 * bytes the sender transmitted, so those bytes have to be captured BEFORE anything
 * parses them. In Express that means express.raw() or the verify hook; in Next.js it
 * means disabling the body parser on the route. Here it is a plain stream read.
 */

import { createServer } from 'node:http';
import { createEngine, signHeader } from '../src/index.js';

const SECRET = process.env.WEBHOOK_SECRET ?? 'whsec_example_only_not_a_real_key';
const PATH = '/webhooks/orbit';

/** Anything larger than this is not a webhook, and an unauthenticated caller chooses the size. */
const MAX_BODY_BYTES = 1_000_000;

// ---------------------------------------------------------------------------
// The handler. Everything above it is transport; this is the business.
// ---------------------------------------------------------------------------

const ledger = [];

/** Flipped in step 6 of the walkthrough, so the replay has something real to succeed against. */
let ledgerServiceIsDown = true;

async function handleEvent(event) {
  // A handler is expected to throw on failure. The engine retries it, and dead letters
  // it when the attempts run out.
  if (event.body.type === 'payout.failed' && ledgerServiceIsDown) {
    throw new Error('ledger service refused the write');
  }
  ledger.push({ id: event.id, type: event.body.type });
  return { ledgerSize: ledger.length };
}

const engine = createEngine({
  secret: SECRET,
  handler: handleEvent,
  retry: { attempts: 3, baseMs: 20, maxMs: 200 },
  onEvent: (info) => log(`  engine: ${info.outcome}${info.eventId ? ` ${info.eventId}` : ''}`),
});

// ---------------------------------------------------------------------------
// Transport.
// ---------------------------------------------------------------------------

function readRawBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('body too large'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

const server = createServer(async (request, response) => {
  if (request.method !== 'POST' || request.url !== PATH) {
    response.writeHead(404).end();
    return;
  }

  let rawBody;
  try {
    rawBody = await readRawBody(request);
  } catch {
    response.writeHead(413).end();
    return;
  }

  // Raw bytes in, status out. The engine does the rest.
  const { status, ...body } = await engine.receive({ rawBody, headers: request.headers });
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
});

// ---------------------------------------------------------------------------
// The walkthrough. Everything below here is the demonstration, not the receiver.
// ---------------------------------------------------------------------------

function log(line) {
  console.log(line);
}

/** Send a delivery the way the provider would: signed over the raw bytes it transmits. */
async function send(url, body, { secret = SECRET, timestamp = Math.floor(Date.now() / 1000) } = {}) {
  const rawBody = JSON.stringify(body);
  const httpResponse = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'webhook-signature': signHeader({ rawBody, secret, timestamp }),
    },
    body: rawBody,
  });
  return { status: httpResponse.status, body: await httpResponse.json() };
}

async function walkthrough(url) {
  log('1. a genuine delivery');
  log(`   → ${JSON.stringify(await send(url, { id: 'evt_1001', type: 'order.created' }))}`);

  log('\n2. the same delivery again, which is what every provider eventually does');
  log(`   → ${JSON.stringify(await send(url, { id: 'evt_1001', type: 'order.created' }))}`);
  log(`   the handler ran once. the ledger holds ${ledger.length} entry.`);

  log('\n3. a forgery, signed with a key we do not hold');
  log(`   → ${JSON.stringify(await send(url, { id: 'evt_1002', type: 'order.created' }, { secret: 'whsec_attacker' }))}`);

  log('\n4. a genuine delivery captured six minutes ago and replayed');
  const sixMinutesAgo = Math.floor(Date.now() / 1000) - 360;
  log(`   → ${JSON.stringify(await send(url, { id: 'evt_1003', type: 'order.created' }, { timestamp: sixMinutesAgo }))}`);

  log('\n5. a delivery whose handler keeps failing');
  log(`   → ${JSON.stringify(await send(url, { id: 'evt_1004', type: 'payout.failed' }))}`);

  const [record] = await engine.dlq.list();
  log(`   the record kept the exact bytes: ${record.rawBody}`);
  log(`   and ${record.attempts} attempts worth of errors: ${record.errors.map((e) => e.message).join(', ')}`);

  log('\n6. the dependency recovers, and an operator replays the record');
  ledgerServiceIsDown = false;
  // skipVerification because the record's own timestamp is now outside the replay
  // window. The operator is deciding to reprocess, and the argument makes that decision
  // visible in the line they wrote.
  const replayed = await engine.replay(record.id, { skipVerification: true });
  log(`   → ${JSON.stringify({ outcome: replayed.outcome, result: replayed.result })}`);
  log(`   replayed from the dead letter queue. remaining records: ${(await engine.dlq.list()).length}`);
}

server.listen(0, '127.0.0.1', async () => {
  const { port } = server.address();
  const url = `http://127.0.0.1:${port}${PATH}`;
  log(`webhook-engine example receiver listening on ${url}\n`);

  try {
    await walkthrough(url);
  } finally {
    server.close();
  }
});
