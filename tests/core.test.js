import test from 'node:test'
import assert from 'node:assert/strict'
import { demoEvents, detectFindings, filterEvents, normalizeEvent, parseLogText, summarize, timelineBuckets } from '../core.js'

test('normalizes common log aliases without inventing a timestamp', () => {
  const event = normalizeEvent({ time: '2026-01-02T03:04:05Z', hostname: 'web-01', username: 'alex', action: 'LOGIN', status: 'FAILURE', src_ip: '192.0.2.4', details: 'Bad password' })
  assert.equal(event.source, 'web-01')
  assert.equal(event.actor, 'alex')
  assert.equal(event.eventType, 'login')
  assert.equal(event.outcome, 'failure')
  assert.equal(event.timestamp, '2026-01-02T03:04:05.000Z')
})

test('parses JSON, JSONL, and quoted CSV records', () => {
  assert.equal(parseLogText(JSON.stringify(demoEvents.slice(0, 2))).length, 2)
  assert.equal(parseLogText(demoEvents.slice(0, 2).map(JSON.stringify).join('\n')).length, 2)
  const csv = 'timestamp,source,actor,message\n2026-01-01T00:00:00Z,host-1,alex,"Hello, world"'
  assert.equal(parseLogText(csv)[0].message, 'Hello, world')
})

test('bounds imports and makes duplicate event identifiers stable', () => {
  const events = parseLogText(JSON.stringify([
    { id: 'same', timestamp: '2026-01-01T00:00:00Z' },
    { id: 'same', timestamp: '2026-01-01T00:01:00Z' },
  ]))
  assert.deepEqual(events.map((event) => event.id), ['same', 'same-2'])
  assert.throws(() => parseLogText(JSON.stringify(Array.from({ length: 5001 }, (_, index) => ({ timestamp: `2026-01-01T00:00:${String(index % 60).padStart(2, '0')}Z` })))), /5000 events/)
  assert.throws(() => parseLogText('timestamp,timestamp\n2026-01-01,2026-01-02'), /unique/)
  assert.throws(() => parseLogText('timestamp,message\n2026-01-01T00:00:00Z,"unfinished'), /unterminated/)
})

test('rejects files without usable timestamps', () => {
  assert.throws(() => parseLogText('[{"source":"host"}]'), /valid timestamps/)
})

test('correlates a failure burst and subsequent success', () => {
  const events = demoEvents.map(normalizeEvent)
  const findings = detectFindings(events)
  assert.ok(findings.some((finding) => finding.ruleId === 'auth-burst'))
  assert.ok(findings.some((finding) => finding.ruleId === 'failure-then-success' && finding.severity === 'critical'))
  assert.ok(findings.some((finding) => finding.ruleId === 'privilege-change'))
})

test('filters across source and free-text fields', () => {
  const events = demoEvents.map(normalizeEvent)
  assert.equal(filterEvents(events, { source: 'edr-console' }).length, 1)
  assert.equal(filterEvents(events, { query: '198.51.100.42' }).length, 6)
})

test('builds stable metrics and timeline buckets', () => {
  const events = demoEvents.map(normalizeEvent)
  const findings = detectFindings(events)
  const metrics = summarize(events, findings)
  assert.equal(metrics.events, demoEvents.length)
  assert.ok(metrics.critical >= 2)
  assert.equal(timelineBuckets(events, 6).length, 6)
  assert.equal(timelineBuckets(events, 6).reduce((sum, bucket) => sum + bucket.total, 0), events.length)
})
