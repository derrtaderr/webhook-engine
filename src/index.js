/**
 * webhook-engine
 *
 * Reliable webhook ingestion: HMAC verification over the raw body, idempotency, retry
 * with jittered backoff, and a dead letter queue you can replay from.
 *
 * Zero runtime dependencies. Node 20 or newer.
 *
 * Start at `createEngine`. The individual pieces are exported too, because a receiver
 * that already has three of the four should be able to take only the one it is missing.
 */

export { createEngine, DEFAULT_SIGNATURE_HEADER, DEFAULT_ID_HEADER } from './engine.js';

export {
  verifySignature,
  signPayload,
  signHeader,
  constantTimeEqual,
  DEFAULT_ALGORITHM,
  DEFAULT_ENCODING,
  DEFAULT_TOLERANCE_SECONDS,
} from './verify.js';

export { parseSignatureHeader, MAX_HEADER_LENGTH, MAX_HEADER_ELEMENTS } from './signature-header.js';

export {
  MemoryIdempotencyStore,
  DEFAULT_IDEMPOTENCY_TTL_MS,
  DEFAULT_MAX_ENTRIES,
} from './idempotency.js';

export { retry, computeDelay, DEFAULT_RETRY } from './retry.js';

export {
  MemoryDeadLetterQueue,
  buildDeadLetterRecord,
  assertReplayable,
  DeadLetterQueueFullError,
  DEFAULT_REDACTED_HEADERS,
  DEFAULT_MAX_RECORDS,
} from './dlq.js';
