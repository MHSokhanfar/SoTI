import assert from 'node:assert/strict';
import test from 'node:test';
import {
  chunkLookupIndicators,
  clampThrottleIntervalMs,
  createThrottleConfig,
  describeThrottleConfig,
  formatMaxRps,
  GlobalApiRequestThrottle,
  loadGlobalThrottleConfig,
  saveGlobalThrottleConfig,
} from './requestThrottle';

test('GlobalApiRequestThrottle serializes overlapping concurrent callers without burst violations', async () => {
  let virtualClockMs = 1_000;
  const sleeps: number[] = [];
  const dispatchTimes: number[] = [];

  const throttle = new GlobalApiRequestThrottle({
    defaultIntervalMs: 250,
    nowFn: () => virtualClockMs,
    sleepFn: async (ms) => {
      sleeps.push(ms);
      virtualClockMs += ms;
    },
  });

  // Launch 5 concurrent callers inside Promise.all — scheduler must enforce strictly >= 250ms spacing
  const results = await Promise.all(
    Array.from({ length: 5 }, (_, idx) =>
      throttle.run(async () => {
        dispatchTimes.push(virtualClockMs);
        return idx;
      }),
    ),
  );

  assert.equal(results.length, 5);
  assert.deepEqual(dispatchTimes, [1000, 1250, 1500, 1750, 2000]);
  assert.deepEqual(sleeps, [250, 250, 250, 250]);

  const stats = throttle.getStats();
  assert.equal(stats.totalAcquired, 5);
  assert.equal(stats.pacedCount, 4);
  assert.equal(stats.totalWaitMs, 1000);
});

test('GlobalApiRequestThrottle supports 0ms unthrottled overrides and resets cleanly', async () => {
  let virtualClockMs = 5_000;
  const throttle = new GlobalApiRequestThrottle({
    defaultIntervalMs: 500,
    nowFn: () => virtualClockMs,
    sleepFn: async (ms) => {
      virtualClockMs += ms;
    },
  });

  const s1 = await throttle.acquire(0);
  const s2 = await throttle.acquire(0);
  assert.equal(s1.waitMs, 0);
  assert.equal(s2.waitMs, 0);
  assert.equal(throttle.getStats().pacedCount, 0);

  throttle.reset();
  assert.equal(throttle.getStats().totalAcquired, 0);
});

test('throttle config clamping, presets, RPS formatting, persistence, and chunking work cleanly', () => {
  assert.equal(clampThrottleIntervalMs(-50), 0);
  assert.equal(clampThrottleIntervalMs(99999), 5000);
  assert.equal(clampThrottleIntervalMs('abc', 200), 200);

  const balanced = createThrottleConfig(200);
  assert.equal(balanced.enabled, true);
  assert.equal(balanced.preset, 'balanced');
  assert.equal(formatMaxRps(200), '5.0 req/s');
  assert.match(describeThrottleConfig(balanced), /5\.0 req\/s/);

  const off = createThrottleConfig(0);
  assert.equal(off.enabled, false);
  assert.equal(off.preset, 'off');
  assert.match(describeThrottleConfig(off), /Throttling off/);

  const mem = new Map<string, string>();
  const storage = {
    getItem: (k: string) => mem.get(k) ?? null,
    setItem: (k: string, v: string) => void mem.set(k, v),
  };

  assert.equal(loadGlobalThrottleConfig(storage).minIntervalMs, 200);
  saveGlobalThrottleConfig(storage, createThrottleConfig(500));
  const reloaded = loadGlobalThrottleConfig(storage);
  assert.equal(reloaded.preset, 'conservative');
  assert.equal(reloaded.minIntervalMs, 500);

  assert.deepEqual(chunkLookupIndicators(['a', 'b', 'c', 'd', 'e'], 2), [
    ['a', 'b'],
    ['c', 'd'],
    ['e'],
  ]);
});
