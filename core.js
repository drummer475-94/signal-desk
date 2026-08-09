export const severityRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

const maxImportedEvents = 5000

function boundedText(value, maximum) {
  return String(value ?? '').trim().slice(0, maximum)
}

export const demoEvents = [
  { timestamp: '2026-08-08T13:02:11Z', source: 'vpn-gateway', actor: 'mrivera', eventType: 'authentication', outcome: 'failure', ip: '198.51.100.42', message: 'Invalid password' },
  { timestamp: '2026-08-08T13:03:08Z', source: 'vpn-gateway', actor: 'mrivera', eventType: 'authentication', outcome: 'failure', ip: '198.51.100.42', message: 'Invalid password' },
  { timestamp: '2026-08-08T13:04:19Z', source: 'vpn-gateway', actor: 'mrivera', eventType: 'authentication', outcome: 'failure', ip: '198.51.100.42', message: 'Invalid password' },
  { timestamp: '2026-08-08T13:05:31Z', source: 'vpn-gateway', actor: 'mrivera', eventType: 'authentication', outcome: 'failure', ip: '198.51.100.42', message: 'Invalid password' },
  { timestamp: '2026-08-08T13:06:44Z', source: 'vpn-gateway', actor: 'mrivera', eventType: 'authentication', outcome: 'failure', ip: '198.51.100.42', message: 'Invalid password' },
  { timestamp: '2026-08-08T13:07:02Z', source: 'vpn-gateway', actor: 'mrivera', eventType: 'authentication', outcome: 'success', ip: '198.51.100.42', message: 'MFA challenge accepted' },
  { timestamp: '2026-08-08T13:09:27Z', source: 'identity-admin', actor: 'svc-helpdesk', eventType: 'role-change', outcome: 'success', ip: '10.24.8.12', message: 'Assigned Global Administrator to mrivera' },
  { timestamp: '2026-08-08T13:11:03Z', source: 'endpoint-044', actor: 'mrivera', eventType: 'process', outcome: 'success', ip: '10.24.18.44', message: 'powershell.exe -NoP -enc SQBFAFgAIAAoAE4A' },
  { timestamp: '2026-08-08T13:14:51Z', source: 'edr-console', actor: 'mrivera', eventType: 'malware', outcome: 'blocked', ip: '10.24.18.44', severity: 'high', message: 'Credential dumper signature blocked in memory' },
  { timestamp: '2026-08-08T13:24:16Z', source: 'fileserver-02', actor: 'svc-backup', eventType: 'file-access', outcome: 'success', ip: '10.24.30.8', message: 'Nightly archive verification completed' },
  { timestamp: '2026-08-08T13:31:40Z', source: 'identity-provider', actor: 'former.contractor', eventType: 'authentication', outcome: 'success', ip: '203.0.113.91', severity: 'medium', message: 'Disabled account authenticated through legacy protocol' },
  { timestamp: '2026-08-08T13:39:04Z', source: 'patch-manager', actor: 'svc-patching', eventType: 'configuration', outcome: 'success', ip: '10.24.5.20', message: 'Approved browser update installed on 84 endpoints' },
]

const aliases = {
  timestamp: ['timestamp', 'time', 'date', '@timestamp', 'event_time'],
  source: ['source', 'host', 'device', 'hostname', 'system'],
  actor: ['actor', 'user', 'username', 'account', 'principal'],
  eventType: ['eventType', 'event_type', 'type', 'action', 'category'],
  outcome: ['outcome', 'status', 'result'],
  ip: ['ip', 'sourceIp', 'source_ip', 'src_ip', 'client_ip'],
  severity: ['severity', 'level', 'priority'],
  message: ['message', 'details', 'description', 'event'],
}

function firstValue(record, keys) {
  for (const key of keys) {
    if (record[key] !== undefined && record[key] !== null && String(record[key]).trim()) return record[key]
  }
  return ''
}

export function normalizeEvent(record, index = 0) {
  const input = record && typeof record === 'object' ? record : {}
  const rawTimestamp = String(firstValue(input, aliases.timestamp))
  const parsedTime = new Date(rawTimestamp)
  const validTime = Number.isFinite(parsedTime.getTime())
  const event = {
    id: boundedText(input.id || `event-${index + 1}`, 120),
    timestamp: validTime ? parsedTime.toISOString() : '',
    source: boundedText(firstValue(input, aliases.source) || 'unknown-source', 120),
    actor: boundedText(firstValue(input, aliases.actor) || 'unknown-actor', 120),
    eventType: boundedText(firstValue(input, aliases.eventType) || 'uncategorized', 80).toLowerCase(),
    outcome: boundedText(firstValue(input, aliases.outcome) || 'unknown', 40).toLowerCase(),
    ip: boundedText(firstValue(input, aliases.ip) || 'not-recorded', 128),
    severity: boundedText(firstValue(input, aliases.severity) || 'info', 20).toLowerCase(),
    message: boundedText(firstValue(input, aliases.message) || 'No event message', 2000),
    raw: input,
  }
  if (!(event.severity in severityRank)) event.severity = 'info'
  return event
}

function parseCsvLine(line) {
  const values = []
  let value = ''
  let quoted = false
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index]
    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        value += '"'
        index += 1
      } else {
        quoted = !quoted
      }
    } else if (character === ',' && !quoted) {
      values.push(value.trim())
      value = ''
    } else {
      value += character
    }
  }
  if (quoted) throw new Error('CSV contains an unterminated quoted field.')
  values.push(value.trim())
  return values
}

function parseCsv(text) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim())
  if (lines.length < 2) return []
  const headers = parseCsvLine(lines[0]).map((header, index) => boundedText(index ? header : header.replace(/^\uFEFF/, ''), 80))
  if (headers.some((header) => !header) || new Set(headers).size !== headers.length) throw new Error('CSV headers must be non-empty and unique.')
  return lines.slice(1).map((line) => {
    const values = parseCsvLine(line)
    return Object.fromEntries(headers.map((header, index) => [header, values[index] ?? '']))
  })
}

function uniqueEventIds(events) {
  const used = new Set()
  return events.map((event) => {
    let id = event.id
    let suffix = 2
    while (used.has(id)) { id = `${event.id}-${suffix}`; suffix += 1 }
    used.add(id)
    return id === event.id ? event : { ...event, id }
  })
}

export function parseLogText(text) {
  const source = String(text || '').trim()
  if (!source) throw new Error('The selected file is empty.')
  let records
  try {
    const parsed = JSON.parse(source)
    records = Array.isArray(parsed) ? parsed : Array.isArray(parsed.events) ? parsed.events : [parsed]
  } catch {
    const lines = source.split(/\r?\n/).filter((line) => line.trim())
    try {
      records = lines.map((line) => JSON.parse(line))
    } catch {
      records = parseCsv(source)
    }
  }
  if (!Array.isArray(records) || !records.length) throw new Error('No event records were found.')
  if (records.length > maxImportedEvents) throw new Error(`Imports are limited to ${maxImportedEvents} events.`)
  if (records.some((record) => !record || typeof record !== 'object' || Array.isArray(record))) {
    throw new Error('Every event must be a JSON object or CSV row.')
  }
  const events = uniqueEventIds(records.map(normalizeEvent).filter((event) => event.timestamp))
  if (!events.length) throw new Error('No events with valid timestamps were found. Use JSON, JSONL, or CSV with a timestamp field.')
  return events.sort((a, b) => a.timestamp.localeCompare(b.timestamp))
}

function finding(ruleId, severity, title, eventIds, rationale, recommendation) {
  return { id: `${ruleId}:${eventIds.join('|')}`, ruleId, severity, title, eventIds, rationale, recommendation }
}

export function detectFindings(events) {
  const findings = []
  const authenticationGroups = new Map()

  for (const event of events) {
    const key = `${event.actor}|${event.ip}`
    if (event.eventType.includes('auth')) {
      if (!authenticationGroups.has(key)) authenticationGroups.set(key, [])
      authenticationGroups.get(key).push(event)
    }
    const text = `${event.eventType} ${event.message}`.toLowerCase()
    if (/global administrator|domain admin|superuser|root role/.test(text)) {
      findings.push(finding('privilege-change', 'critical', 'High-impact privilege assignment', [event.id], `${event.actor} recorded a privileged role change on ${event.source}.`, 'Validate the approved request, target account, and administrator session.'))
    }
    if (/powershell/.test(text) && /(?:\s-enc(?:odedcommand)?\b|frombase64string)/.test(text)) {
      findings.push(finding('encoded-command', 'high', 'Encoded PowerShell execution', [event.id], `An encoded PowerShell command ran as ${event.actor}.`, 'Collect the full command line and process tree; isolate the endpoint if execution was not authorized.'))
    }
    if (event.eventType.includes('malware') || /malware|credential dumper|mimikatz/.test(text)) {
      findings.push(finding('malware-signal', 'high', 'Malware or credential-access signal', [event.id], event.message, 'Confirm containment, preserve endpoint evidence, and review adjacent identity activity.'))
    }
    if (/disabled account/.test(text) && event.outcome === 'success') {
      findings.push(finding('disabled-account', 'high', 'Disabled account authenticated', [event.id], `${event.actor} successfully used a path described as disabled.`, 'Disable the legacy path, revoke active sessions, and validate account lifecycle controls.'))
    }
  }

  for (const group of authenticationGroups.values()) {
    const failures = group.filter((event) => event.outcome === 'failure')
    for (let start = 0; start < failures.length; start += 1) {
      const windowStart = new Date(failures[start].timestamp).getTime()
      const burst = failures.filter((event) => {
        const delta = new Date(event.timestamp).getTime() - windowStart
        return delta >= 0 && delta <= 10 * 60 * 1000
      })
      if (burst.length >= 5) {
        findings.push(finding('auth-burst', 'high', 'Authentication failure burst', burst.map((event) => event.id), `${burst.length} failures for ${burst[0].actor} from ${burst[0].ip} occurred within 10 minutes.`, 'Validate the source, reset exposed credentials, and review MFA and conditional-access results.'))
        const lastFailure = new Date(burst.at(-1).timestamp).getTime()
        const success = group.find((event) => event.outcome === 'success' && new Date(event.timestamp).getTime() >= lastFailure && new Date(event.timestamp).getTime() - lastFailure <= 10 * 60 * 1000)
        if (success) {
          findings.push(finding('failure-then-success', 'critical', 'Successful sign-in after failure burst', [...burst.map((event) => event.id), success.id], `${success.actor} authenticated from ${success.ip} shortly after repeated failures.`, 'Treat as a possible account compromise and correlate the session with subsequent access.'))
        }
        break
      }
    }
  }

  return findings.sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || a.title.localeCompare(b.title))
}

export function filterEvents(events, filters = {}) {
  const query = String(filters.query || '').trim().toLowerCase()
  return events.filter((event) => {
    if (filters.source && event.source !== filters.source) return false
    if (filters.severity && event.severity !== filters.severity) return false
    if (!query) return true
    return [event.source, event.actor, event.eventType, event.outcome, event.ip, event.message]
      .some((value) => value.toLowerCase().includes(query))
  })
}

export function summarize(events, findings) {
  return {
    events: events.length,
    sources: new Set(events.map((event) => event.source)).size,
    critical: findings.filter((item) => item.severity === 'critical').length,
    suspiciousActors: new Set(findings.flatMap((item) => item.eventIds.map((id) => events.find((event) => event.id === id)?.actor).filter(Boolean))).size,
  }
}

export function timelineBuckets(events, count = 12) {
  if (!events.length) return []
  const times = events.map((event) => new Date(event.timestamp).getTime())
  const minimum = Math.min(...times)
  const maximum = Math.max(...times)
  const span = Math.max(maximum - minimum, 1)
  const buckets = Array.from({ length: count }, (_, index) => ({
    start: new Date(minimum + (span * index) / count),
    end: new Date(minimum + (span * (index + 1)) / count),
    total: 0,
    elevated: 0,
  }))
  events.forEach((event) => {
    const time = new Date(event.timestamp).getTime()
    const index = Math.min(count - 1, Math.floor(((time - minimum) / span) * count))
    buckets[index].total += 1
    if (severityRank[event.severity] >= severityRank.medium) buckets[index].elevated += 1
  })
  return buckets
}
