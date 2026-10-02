import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { createEngine } from '../src/engine.js';
import { signHeader } from '../src/verify.js';

// The README's Redis store is code people paste. This runs the block exactly as written,
// against a fake with node-redis v4 semantics, so the example cannot rot or mislead.
const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const block = README.match(/```js\n\/\/ Redis\. reserve must be atomic[\s\S]*?```/)[0];
const storeSource = block.slice(block.indexOf('const store = {'), block.indexOf('createEngine('));

function fakeRedis() {
  const data = new Map();
  return {
    async set(key, value, { NX } = {}) {
      if (typeof value !== 'string') throw new TypeError(`Invalid argument type: ${typeof value}`);
      if (NX && data.has(key)) return null;
      data.set(key, value);
      return 'OK';
    },
    async get(key) { return data.has(key) ? data.get(key) : null; },
    async del(key) { data.delete(key); return 1; },
  };
}

function storeFromReadme(redis) {
  return new Function('redis', `${storeSource}; return store;`)(redis);
}

const SECRET = 'whsec_fixture';
const SIGNED_AT = 1614556800;
function delivery(body) {
  const rawBody = JSON.stringify(body);
  return { rawBody, headers: { 'webhook-signature': signHeader({ rawBody, secret: SECRET, timestamp: SIGNED_AT }) } };
}

for (const [label, returned] of [['returns nothing', undefined], ['returns a string', 'ok'], ['returns an object', { n: 1 }]]) {
  test(`the README Redis store works when the handler ${label}`, async () => {
    const engine = createEngine({
      secret: SECRET, handler: async () => returned, store: storeFromReadme(fakeRedis()),
      now: () => SIGNED_AT * 1000, sleep: async () => {},
    });
    const first = await engine.receive(delivery({ id: `evt_${label}` }));
    assert.equal(first.outcome, 'processed');
    assert.equal(first.completeFailed, undefined, 'complete() must store any handler result');
    const duplicate = await engine.receive(delivery({ id: `evt_${label}` }));
    assert.equal(duplicate.outcome, 'duplicate');
    assert.deepEqual(duplicate.result, returned ?? null);
  });
}
