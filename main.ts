// Entrypoint: the bridge between this process and the trial env.
//
// The env owns port 8080 and drives the run. This process only has to:
// bind an ephemeral port, hand that port to the env, then wait until the
// env reports the trial is over. Nothing else happens here; the server in
// app.ts does the actual work, and the grading suite talks to it.
//
// Lifecycle, step by step:
//   1. MAKEFUN_ENV_URL is the env origin (http://store:8080 inside a trial
//      container). If it is unset there is no env to talk to, so exit 1.
//   2. Start the app server on port 0 and let the kernel pick a free port.
//      Never bind 8080: that port belongs to the env.
//   3. POST {port} to $MAKEFUN_ENV_URL/register. The env records the caller
//      address plus the port as this entry's base URL. The first register
//      wins; a 409 means some other entry registered first, and this process
//      simply waits like any other.
//   4. Poll GET $MAKEFUN_ENV_URL/done until it answers {"done": true}. The
//      env answers immediately ({"done": false} while the suite runs), so
//      this is a poll loop, not a long-held request. Transient failures are
//      retried with exponential backoff; the process never exits early.
//   5. Close the server and exit 0. The harness then stops the env, which
//      writes the export the scorer reads.
//
// main.ts imports its own server and nothing else: no third-party package,
// no Node built-in, no model call.

import { createApp } from './app.ts';

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
if (ENV_URL === '') {
  process.stderr.write('[entry] MAKEFUN_ENV_URL is not set: there is no env to register with\n');
  process.exit(1);
}

/** Cap on how long a single register or done request may run before it is dropped and retried. */
const REQUEST_TIMEOUT_MS = 30_000;
/** First backoff between retries, and the ceiling it grows to. */
const RETRY_INITIAL_MS = 250;
const RETRY_MAX_MS = 2_000;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Backoff after `attempt` failed requests: exponential from RETRY_INITIAL_MS, capped at RETRY_MAX_MS. */
function retryDelay(attempt: number): number {
  return Math.min(RETRY_MAX_MS, RETRY_INITIAL_MS * 2 ** Math.min(attempt, 8));
}

/**
 * POST the bound port until the env accepts it. 200 is the normal answer and
 * 409 means a first register already won, which is not ours to fix. 400 and
 * 405 are contract errors and end the program; a network error or any other
 * status is retried, because the env may still be starting up.
 */
async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) {
        throw new Error(`register answered HTTP ${res.status}: ${await res.text()}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(retryDelay(attempt));
  }
}

/** Poll GET /done until it answers {"done": true}; never return before that. */
async function waitForDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // The env is not answering yet, or the poll timed out: it is not done, so poll again.
    }
    await sleep(retryDelay(attempt));
  }
}

/** Bind the port, register it, then wait for the env: the whole life of this process. */
async function main(): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('the server did not bind an ephemeral TCP port');
  }
  process.stdout.write(`[entry] listening on port ${address.port}\n`);

  await register(address.port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');

  await waitForDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await main();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
