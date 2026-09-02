import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const run = promisify(execFile);
const RECEIVER = fileURLToPath(new URL('../example/receiver.js', import.meta.url));

test('the example receiver runs end to end and exits clean', async () => {
  // The README tells a stranger to run this file. Running it here is what stops that
  // instruction from rotting, and it is the only test in the suite that exercises a real
  // socket, a real request and a real raw-body read.
  const { stdout } = await run(process.execPath, [RECEIVER], { timeout: 30_000 });

  for (const expected of [
    'processed',
    'rejected',
    'duplicate',
    'dead_lettered',
    'replayed from the dead letter queue',
  ]) {
    assert.match(stdout, new RegExp(expected), `expected the walkthrough to reach: ${expected}`);
  }
});

test('the example refuses to start without a secret, the same as the library', async () => {
  await assert.rejects(
    () => run(process.execPath, [RECEIVER], { env: { ...process.env, WEBHOOK_SECRET: '' }, timeout: 30_000 }),
    (error) => {
      assert.match(error.stderr, /secret/i);
      return true;
    },
  );
});
