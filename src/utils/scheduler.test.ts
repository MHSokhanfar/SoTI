import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildCliAddScheduleCommand,
  computeNextRunIso,
  formatIntervalLabel,
  formatRelativeScheduleTime,
  isScheduleDue,
  summarizeSchedules,
  validateAndNormalizeScheduleInput,
  type ScheduledJob,
} from './scheduler';

test('validateAndNormalizeScheduleInput cleans defanged IOCs and enforces constraints', () => {
  const valid = validateAndNormalizeScheduleInput({
    name: '  Edge Firewall Watch  ',
    indicators: '1[.]2[.]3[.]4, hxxp://evil[.]com/c2, invalid-token',
    source: 'all',
    sources: ['virustotal', 'alienvault'],
    intervalMinutes: 60,
    enabled: true,
    mode: 'live',
  });

  assert.equal(valid.ok, true);
  if (valid.ok) {
    assert.equal(valid.data.name, 'Edge Firewall Watch');
    assert.deepEqual(valid.data.indicators, ['1.2.3.4', 'evil.com']);
    assert.deepEqual(valid.data.sources, ['virustotal', 'alienvault']);
    assert.equal(valid.data.intervalMinutes, 60);
  }

  assert.equal(
    validateAndNormalizeScheduleInput({ name: '', indicators: '8.8.8.8', intervalMinutes: 60 }).ok,
    false,
  );
  assert.equal(
    validateAndNormalizeScheduleInput({ name: 'Bad IOC', indicators: 'not-an-ioc', intervalMinutes: 60 }).ok,
    false,
  );
  assert.equal(
    validateAndNormalizeScheduleInput({ name: 'Too Fast', indicators: '8.8.8.8', intervalMinutes: 1 }).ok,
    false,
  );
});

test('isScheduleDue and summarizeSchedules evaluate enabled/due states accurately', () => {
  const now = new Date('2026-11-14T12:00:00Z');
  const dueJob: ScheduledJob = {
    id: 'j1',
    name: 'Due Job',
    indicators: ['8.8.8.8'],
    source: 'all',
    sources: ['virustotal', 'abuseipdb', 'alienvault'],
    intervalMinutes: 60,
    enabled: true,
    mode: 'live',
    createdAt: '2026-11-14T10:00:00Z',
    updatedAt: '2026-11-14T10:00:00Z',
    lastRunAt: '2026-11-14T10:55:00Z',
    nextRunAt: '2026-11-14T11:55:00Z',
    lastStatus: 'success',
    lastReportFile: 'soti_20261114_105500.csv',
    lastSummary: '3 checks',
    runCount: 2,
  };
  const futureJob: ScheduledJob = {
    ...dueJob,
    id: 'j2',
    name: 'Future Job',
    nextRunAt: '2026-11-14T13:00:00Z',
    runCount: 1,
  };
  const pausedDueJob: ScheduledJob = {
    ...dueJob,
    id: 'j3',
    name: 'Paused Job',
    enabled: false,
    runCount: 4,
  };

  assert.equal(isScheduleDue(dueJob, now), true);
  assert.equal(isScheduleDue(futureJob, now), false);
  assert.equal(isScheduleDue(pausedDueJob, now), false);

  assert.deepEqual(summarizeSchedules([dueJob, futureJob, pausedDueJob], now), {
    total: 3,
    active: 2,
    paused: 1,
    dueNow: 1,
    totalRuns: 7,
  });
});

test('formatting helpers return clean labels and CLI commands', () => {
  assert.equal(formatIntervalLabel(15), 'Every 15 min');
  assert.equal(formatIntervalLabel(60), 'Hourly');
  assert.equal(formatIntervalLabel(360), 'Every 6h');
  assert.equal(formatIntervalLabel(1440), 'Daily');
  assert.equal(formatIntervalLabel(10080), 'Weekly');

  const now = new Date('2026-11-14T12:00:00Z');
  assert.equal(computeNextRunIso(now, 60), '2026-11-14T13:00:00Z');
  assert.equal(formatRelativeScheduleTime('2026-11-14T12:45:00Z', now), 'In 45m');
  assert.equal(formatRelativeScheduleTime('2026-11-14T11:30:00Z', now), '30m ago');

  const cmd = buildCliAddScheduleCommand({
    name: 'DNS Check',
    indicators: ['8.8.8.8', '1.1.1.1'],
    source: 'all',
    intervalMinutes: 60,
  });
  assert.match(cmd, /--add-schedule/);
  assert.match(cmd, /--interval 60/);
});
