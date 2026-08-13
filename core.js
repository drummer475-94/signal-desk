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
  timestamp: ['timestamp', 'time', 'date', '@timestamp', 'event_time', 'TimeCreated', 'eventTime'],
  source: ['source', 'host', 'device', 'hostname', 'system', 'Computer', 'eventSource'],
  actor: ['actor', 'user', 'username', 'account', 'principal', 'TargetUserName', 'SubjectUserName', 'userName'],
  eventType: ['eventType', 'event_type', 'type', 'action', 'category', 'EventID', 'eventName'],
  outcome: ['outcome', 'status', 'result', 'Keywords', 'errorCode'],
  ip: ['ip', 'sourceIp', 'source_ip', 'src_ip', 'client_ip', 'IpAddress', 'sourceIPAddress'],
  severity: ['severity', 'level', 'priority', 'Level'],
  message: ['message', 'details', 'description', 'event', 'CommandLine', 'NewProcessName'],
}

function firstValue(record, keys) {
  for (const key of keys) {
    if (record[key] !== undefined && record[key] !== null && String(record[key]).trim()) return record[key]
  }
  return ''
}

export function normalizeEvent(record, index = 0) {
  const input = record && typeof record === 'object' ? record : {}
  let rawTimestamp = String(firstValue(input, aliases.timestamp))
  if (!rawTimestamp && input.System && input.System.TimeCreated) {
    rawTimestamp = String(input.System.TimeCreated.SystemTime || input.System.TimeCreated)
  }
  const parsedTime = new Date(rawTimestamp)
  const validTime = Number.isFinite(parsedTime.getTime())

  let source = boundedText(firstValue(input, aliases.source) || (input.System && input.System.Computer) || 'unknown-source', 120)
  let actor = boundedText(firstValue(input, aliases.actor) || 'unknown-actor', 120)
  if (input.EventData && typeof input.EventData === 'object') {
    if (!actor || actor === 'unknown-actor') {
      actor = boundedText(input.EventData.TargetUserName || input.EventData.SubjectUserName || input.EventData.NewProcessName || actor, 120)
    }
  }

  let eventType = boundedText(firstValue(input, aliases.eventType) || 'uncategorized', 80).toLowerCase()
  let outcome = boundedText(firstValue(input, aliases.outcome) || 'unknown', 40).toLowerCase()
  if (input.EventID) eventType = `windows-${input.EventID}`
  if (input.eventName) eventType = `cloudtrail-${input.eventName}`

  const event = {
    id: boundedText(input.id || `event-${index + 1}`, 120),
    timestamp: validTime ? parsedTime.toISOString() : '',
    source,
    actor,
    eventType,
    outcome,
    ip: boundedText(firstValue(input, aliases.ip) || (input.EventData && input.EventData.IpAddress) || 'not-recorded', 128),
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

// Windows Event Log (XML / EVTX) Parser
export function parseWindowsXmlEvents(xmlText) {
  const records = []
  const eventRegex = /<Event[\s\S]*?<\/Event>/g
  let match
  let index = 0

  while ((match = eventRegex.exec(xmlText)) !== null) {
    const xml = match[0]
    index += 1
    const eventIdMatch = xml.match(/<EventID>(.*?)<\/EventID>/)
    const timeCreatedPattern = /<TimeCreated[\s\S]*?SystemTime=['"]([^'"]+)['"]/
    const timeMatch = xml.match(timeCreatedPattern)
    const computerMatch = xml.match(/<Computer>(.*?)<\/Computer>/)

    const dataObj = {}
    const dataRegex = /<Data Name=['"]([^'"]+)['"]>([\s\S]*?)<\/Data>/g
    let dataMatch
    while ((dataMatch = dataRegex.exec(xml)) !== null) {
      dataObj[dataMatch[1]] = dataMatch[2].trim()
    }

    const eventId = eventIdMatch ? eventIdMatch[1].trim() : '4624'
    const timestamp = timeMatch ? timeMatch[1].trim() : new Date().toISOString()
    const computer = computerMatch ? computerMatch[1].trim() : 'WINDOWS-DC'

    let actor = dataObj.TargetUserName || dataObj.SubjectUserName || dataObj.NewProcessName || 'system'
    let outcome = eventId === '4625' ? 'failure' : 'success'
    let eventType = `windows-${eventId}`
    let severity = eventId === '4625' ? 'medium' : (eventId === '4672' || eventId === '4688' ? 'high' : 'info')
    let ip = dataObj.IpAddress || dataObj.WorkstationName || '127.0.0.1'
    let message = ''

    if (eventId === '4624') {
      message = `Windows Successful Logon (EventID 4624) for ${actor} from ${ip} (LogonType: ${dataObj.LogonType || '10'})`
    } else if (eventId === '4625') {
      message = `Windows Failed Logon (EventID 4625) for ${actor} from ${ip} - Status: ${dataObj.Status || dataObj.FailureReason || 'Bad Password'}`
    } else if (eventId === '4672') {
      message = `Windows Special Privileges Assigned (EventID 4672) to ${actor}. Privileges: ${dataObj.PrivilegeList || 'SeDebugPrivilege'}`
    } else if (eventId === '4688') {
      const cmd = dataObj.CommandLine || dataObj.NewProcessName || 'process.exe'
      message = `Windows Process Created (EventID 4688): ${cmd} by ${actor}`
    } else if (eventId === '4720') {
      message = `Windows User Account Created (EventID 4720): ${dataObj.TargetUserName || actor} by ${dataObj.SubjectUserName || 'Admin'}`
    } else {
      message = `Windows Security Event ${eventId} for ${actor}`
    }

    records.push({
      id: `win-event-${index}`,
      timestamp,
      source: computer,
      actor,
      eventType,
      outcome,
      ip,
      severity,
      message,
      raw: { eventId, dataObj, computer, timestamp }
    })
  }

  return records
}

// AWS CloudTrail JSON Parser
export function parseCloudTrailEvents(cloudTrailObj) {
  const rawRecords = Array.isArray(cloudTrailObj)
    ? cloudTrailObj
    : Array.isArray(cloudTrailObj.Records)
    ? cloudTrailObj.Records
    : [cloudTrailObj]

  return rawRecords.map((rec, idx) => {
    const timestamp = rec.eventTime || new Date().toISOString()
    const source = rec.eventSource || rec.awsRegion || 'aws-cloudtrail'
    const identity = rec.userIdentity || {}
    const actor = identity.userName || identity.arn || identity.principalId || 'aws-principal'
    const eventType = `cloudtrail:${rec.eventName || 'api'}`
    const outcome = rec.errorCode ? 'failure' : 'success'
    const severity = rec.errorCode ? 'medium' : 'info'
    const message = `AWS CloudTrail ${rec.eventName || 'API Call'} on ${source} by ${actor}${rec.errorCode ? ` (${rec.errorCode}: ${rec.errorMessage})` : ''}`

    return {
      id: `cloudtrail-${idx + 1}`,
      timestamp,
      source,
      actor,
      eventType,
      outcome,
      ip: rec.sourceIPAddress || 'aws-internal',
      severity,
      message,
      raw: rec
    }
  })
}

// Syslog RFC 5424 / 3164 Parser
export function parseSyslogText(syslogText) {
  const lines = syslogText.split(/\r?\n/).filter((l) => l.trim())
  const records = []

  lines.forEach((line, idx) => {
    const rfc5424Regex = /^<(\d{1,3})>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[.*?\]|-)\s+(.*)$/
    const rfc3164Regex = /^<(\d{1,3})>([A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+([^:\[]+)(?:\[\d+\])?:?\s+(.*)$/

    let match = line.match(rfc5424Regex)
    if (match) {
      const prival = parseInt(match[1], 10)
      const facility = Math.floor(prival / 8)
      const syslogSev = prival % 8
      const timestamp = match[2]
      const hostname = match[3]
      const appName = match[4]
      const msg = match[7]

      let severity = 'info'
      if (syslogSev <= 2) severity = 'critical'
      else if (syslogSev === 3) severity = 'high'
      else if (syslogSev === 4) severity = 'medium'

      records.push({
        id: `syslog-5424-${idx + 1}`,
        timestamp,
        source: hostname || 'syslog-host',
        actor: appName || 'syslog-app',
        eventType: `syslog-fac-${facility}`,
        outcome: /fail|deny|error|invalid/i.test(msg) ? 'failure' : 'success',
        ip: 'syslog-net',
        severity,
        message: msg,
        raw: { prival, facility, syslogSev, line }
      })
      return
    }

    match = line.match(rfc3164Regex)
    if (match) {
      const prival = parseInt(match[1], 10)
      const facility = Math.floor(prival / 8)
      const syslogSev = prival % 8
      const rawDateStr = match[2]
      const hostname = match[3]
      const tag = match[4]
      const msg = match[5]

      const year = new Date().getFullYear()
      const parsedDate = new Date(`${rawDateStr} ${year}`)
      const timestamp = Number.isFinite(parsedDate.getTime()) ? parsedDate.toISOString() : new Date().toISOString()

      let severity = 'info'
      if (syslogSev <= 2) severity = 'critical'
      else if (syslogSev === 3) severity = 'high'
      else if (syslogSev === 4) severity = 'medium'

      records.push({
        id: `syslog-3164-${idx + 1}`,
        timestamp,
        source: hostname || 'syslog-host',
        actor: tag || 'syslog-tag',
        eventType: `syslog-fac-${facility}`,
        outcome: /fail|deny|error|invalid/i.test(msg) ? 'failure' : 'success',
        ip: 'syslog-net',
        severity,
        message: msg,
        raw: { prival, facility, syslogSev, line }
      })
      return
    }

    if (line.includes('<')) {
      records.push({
        id: `syslog-raw-${idx + 1}`,
        timestamp: new Date().toISOString(),
        source: 'syslog-source',
        actor: 'syslog-actor',
        eventType: 'syslog-raw',
        outcome: 'info',
        ip: 'not-recorded',
        severity: 'info',
        message: line,
        raw: { line }
      })
    }
  })

  return records
}

export function parseLogText(text) {
  const source = String(text || '').trim()
  if (!source) throw new Error('The selected file is empty.')
  let records = []

  if (source.includes('<Event') && source.includes('</Event>')) {
    records = parseWindowsXmlEvents(source)
  } else if (source.startsWith('<') && (source.includes('>1 ') || /[A-Za-z]{3}\s+\d+/.test(source))) {
    records = parseSyslogText(source)
  } else {
    try {
      const parsed = JSON.parse(source)
      if (parsed && typeof parsed === 'object' && parsed.Records && Array.isArray(parsed.Records)) {
        records = parseCloudTrailEvents(parsed)
      } else if (parsed && typeof parsed === 'object' && parsed.eventSource) {
        records = parseCloudTrailEvents(parsed)
      } else {
        records = Array.isArray(parsed) ? parsed : Array.isArray(parsed.events) ? parsed.events : [parsed]
      }
    } catch {
      const lines = source.split(/\r?\n/).filter((line) => line.trim())
      let isJsonL = true
      const parsedLines = []
      for (const line of lines) {
        try {
          parsedLines.push(JSON.parse(line))
        } catch {
          isJsonL = false; break
        }
      }
      if (isJsonL && parsedLines.length > 0) {
        records = parsedLines
      } else if (lines.some(l => l.startsWith('<'))) {
        records = parseSyslogText(source)
      } else {
        records = parseCsv(source)
      }
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

function finding(ruleId, severity, title, eventIds, rationale, recommendation, mitreInfo = {}) {
  return {
    id: `${ruleId}:${eventIds.join('|')}`,
    ruleId,
    severity,
    title,
    eventIds,
    rationale,
    recommendation,
    mitreTechniqueId: mitreInfo.techniqueId || 'T1078',
    mitreTechniqueName: mitreInfo.techniqueName || 'Valid Accounts',
    mitreTactic: mitreInfo.tactic || 'Initial Access',
    mitreMapping: `${mitreInfo.techniqueId || 'T1078'} - ${mitreInfo.techniqueName || 'Valid Accounts'} (${mitreInfo.tactic || 'Initial Access'})`
  }
}

export function detectFindings(events) {
  const findings = []
  const authenticationGroups = new Map()

  for (const event of events) {
    const key = `${event.actor}|${event.ip}`
    if (event.eventType.includes('auth') || event.eventType.includes('4624') || event.eventType.includes('4625') || event.eventType.includes('login')) {
      if (!authenticationGroups.has(key)) authenticationGroups.set(key, [])
      authenticationGroups.get(key).push(event)
    }
    const text = `${event.eventType} ${event.message}`.toLowerCase()

    if (/global administrator|domain admin|superuser|root role|special privileges|4672|4720|user account created/.test(text)) {
      const isCreate = /4720|user account created/.test(text)
      findings.push(finding(
        isCreate ? 'account-creation' : 'privilege-change',
        isCreate ? 'medium' : 'critical',
        isCreate ? 'User Account Creation Detected (T1098)' : 'High-impact privilege assignment (T1098)',
        [event.id],
        `${event.actor} recorded a ${isCreate ? 'account creation' : 'privileged role change'} on ${event.source}.`,
        'Validate the approved request, target account, and administrator session.',
        { techniqueId: 'T1098', techniqueName: 'Account Manipulation', tactic: 'Persistence' }
      ))
    }

    if ((/powershell|pwsh/.test(text) && /(?:\s-enc(?:odedcommand)?\b|frombase64string|iex|downloadstring)/.test(text)) || /windows-4688/.test(text) && /powershell/.test(text)) {
      findings.push(finding(
        'encoded-command',
        'high',
        'Encoded or Suspicious PowerShell Execution (T1059.001)',
        [event.id],
        `An encoded or privileged PowerShell command ran as ${event.actor}.`,
        'Collect the full command line and process tree; isolate the endpoint if execution was not authorized.',
        { techniqueId: 'T1059.001', techniqueName: 'PowerShell', tactic: 'Execution' }
      ))
    }

    if (event.eventType.includes('malware') || /malware|credential dumper|mimikatz|lsass|sekurlsa|procdump/.test(text)) {
      findings.push(finding(
        'malware-signal',
        'high',
        'OS Credential Dumping or Malware Signal (T1003)',
        [event.id],
        event.message,
        'Confirm containment, preserve endpoint evidence, and review adjacent identity activity.',
        { techniqueId: 'T1003', techniqueName: 'OS Credential Dumping', tactic: 'Credential Access' }
      ))
    }

    if (/disabled account/.test(text) && event.outcome === 'success') {
      findings.push(finding(
        'disabled-account',
        'high',
        'Disabled Account Authenticated (T1078)',
        [event.id],
        `${event.actor} successfully used a path described as disabled.`,
        'Disable the legacy path, revoke active sessions, and validate account lifecycle controls.',
        { techniqueId: 'T1078', techniqueName: 'Valid Accounts', tactic: 'Initial Access' }
      ))
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
        findings.push(finding(
          'auth-burst',
          'high',
          'Authentication Failure Burst / Brute Force (T1110)',
          burst.map((event) => event.id),
          `${burst.length} failures for ${burst[0].actor} from ${burst[0].ip} occurred within 10 minutes.`,
          'Validate the source, reset exposed credentials, and review MFA and conditional-access results.',
          { techniqueId: 'T1110', techniqueName: 'Brute Force', tactic: 'Credential Access' }
        ))
        const lastFailure = new Date(burst.at(-1).timestamp).getTime()
        const success = group.find((event) => event.outcome === 'success' && new Date(event.timestamp).getTime() >= lastFailure && new Date(event.timestamp).getTime() - lastFailure <= 10 * 60 * 1000)
        if (success) {
          findings.push(finding(
            'failure-then-success',
            'critical',
            'Successful Sign-in After Brute Force Burst (T1110 + T1078)',
            [...burst.map((event) => event.id), success.id],
            `${success.actor} authenticated from ${success.ip} shortly after repeated failures.`,
            'Treat as a possible account compromise and correlate the session with subsequent access.',
            { techniqueId: 'T1110', techniqueName: 'Brute Force', tactic: 'Credential Access' }
          ))
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

export function generateNistReport(findings = [], events = []) {
  const reportTime = new Date().toISOString()
  const criticalCount = findings.filter(f => f.severity === 'critical').length
  const highCount = findings.filter(f => f.severity === 'high').length
  const mediumCount = findings.filter(f => f.severity === 'medium').length

  const mitreTechniques = [...new Set(findings.map(f => f.mitreMapping))]
  const techniqueIds = new Set(findings.map(f => f.mitreTechniqueId))
  const affectedActors = [...new Set(events.map(e => e.actor))].filter(a => a && a !== 'unknown-actor')
  const affectedSources = [...new Set(events.map(e => e.source))]
  let incidentCategory = 'No category assigned - No confirmed incident'
  if (techniqueIds.has('T1059.001') || techniqueIds.has('T1003')) {
    incidentCategory = 'CAT 3 - Malicious Code'
  } else if (techniqueIds.has('T1078') || techniqueIds.has('T1098') || findings.some(f => f.ruleId === 'failure-then-success')) {
    incidentCategory = 'CAT 1 - Unauthorized Access'
  } else if (techniqueIds.has('T1110')) {
    incidentCategory = 'CAT 5 - Scans, Probes, or Attempted Access'
  }

  return {
    title: 'NIST SP 800-61 Rev 2 Incident Handling & Analysis Report',
    generatedAt: reportTime,
    standard: 'NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide)',
    summary: {
      totalEventsAnalyzed: events.length,
      totalFindingsDetected: findings.length,
      severityCounts: { critical: criticalCount, high: highCount, medium: mediumCount },
      incidentCategory
    },
    phases: {
      preparation: {
        status: 'COMPLETE',
        logSourcesIngested: affectedSources,
        detectionRulesActive: ['T1078 (Valid Accounts)', 'T1110 (Brute Force)', 'T1059.001 (PowerShell)', 'T1098 (Account Manipulation)', 'T1003 (OS Credential Dumping)'],
        loggingHealth: affectedSources.length
          ? `${affectedSources.length} source(s) represented; collection completeness requires analyst validation.`
          : 'No log sources represented.'
      },
      detectionAndAnalysis: {
        status: findings.length > 0 ? 'INCIDENT_CONFIRMED' : 'NO_ANOMALIES',
        findings: findings.map(f => ({
          ruleId: f.ruleId,
          title: f.title,
          severity: f.severity,
          mitreMapping: f.mitreMapping,
          rationale: f.rationale,
          linkedEventsCount: f.eventIds.length
        })),
        mitreTechniquesCovered: mitreTechniques,
        affectedActors,
        affectedSources
      },
      containmentEradicationRecovery: {
        status: findings.length > 0 ? 'ACTION_REQUIRED' : 'MONITOR',
        containmentActions: [
          'Isolate endpoints exhibiting T1059.001 suspicious PowerShell or T1003 credential access.',
          'Revoke active tokens and force password reset for actors associated with T1110 brute force or T1078 valid account anomalies.',
          'Block offending IP addresses at network boundary firewalls and VPN gateways.'
        ],
        eradicationSteps: [
          'Remove unauthorized persistent access keys and newly created accounts (T1098).',
          'Perform full antivirus/EDR scan on affected hosts to ensure no web shells or persistence mechanisms remain.',
          'Audit Active Directory / Entra ID role assignments for unauthorized privileges.'
        ],
        recoverySteps: [
          'Re-enable user accounts after MFA credential reset.',
          'Restore host network connectivity after EDR verification.',
          'Monitor logs for 72 hours for recurrence.'
        ]
      },
      postIncidentActivity: {
        status: 'RECOMMENDED',
        lessonsLearned: [
          'Implement stricter Conditional Access policies requiring MFA for legacy protocol authentication.',
          'Enforce PowerShell Constrained Language Mode and Script Block Logging (Event ID 4104).',
          'Deploy automated account lockout upon 5 consecutive authentication failures.'
        ],
        indicatorSharing: {
          ips: [...new Set(events.map(e => e.ip).filter(i => i && i !== 'not-recorded' && i !== '127.0.0.1'))],
          actors: affectedActors
        }
      }
    }
  }
}

export function formatNistReportMarkdown(report) {
  return `# ${report.title}
**Generated At**: ${report.generatedAt}
**Standard**: ${report.standard}
**Category**: ${report.summary.incidentCategory}

## 1. Preparation Phase
- **Status**: ${report.phases.preparation.status}
- **Log Sources Ingested**: ${report.phases.preparation.logSourcesIngested.join(', ') || 'None'}
- **Active Detection Rules**: ${report.phases.preparation.detectionRulesActive.join(', ')}

## 2. Detection & Analysis Phase
- **Incident Status**: ${report.phases.detectionAndAnalysis.status}
- **Total Findings**: ${report.summary.totalFindingsDetected} (Critical: ${report.summary.severityCounts.critical}, High: ${report.summary.severityCounts.high}, Medium: ${report.summary.severityCounts.medium})
- **MITRE ATT&CK Mapping**:
${report.phases.detectionAndAnalysis.mitreTechniquesCovered.map(t => `  - ${t}`).join('\n') || '  - None'}
- **Impacted Actors**: ${report.phases.detectionAndAnalysis.affectedActors.join(', ') || 'None'}
- **Impacted Sources**: ${report.phases.detectionAndAnalysis.affectedSources.join(', ') || 'None'}

### Key Findings:
${report.phases.detectionAndAnalysis.findings.map(f => `#### [${f.severity.toUpperCase()}] ${f.title}\n- **MITRE**: ${f.mitreMapping}\n- **Rationale**: ${f.rationale}`).join('\n\n')}

## 3. Containment, Eradication & Recovery
### Containment:
${report.phases.containmentEradicationRecovery.containmentActions.map(a => `- ${a}`).join('\n')}

### Eradication:
${report.phases.containmentEradicationRecovery.eradicationSteps.map(a => `- ${a}`).join('\n')}

### Recovery:
${report.phases.containmentEradicationRecovery.recoverySteps.map(a => `- ${a}`).join('\n')}

## 4. Post-Incident Activity & Lessons Learned
${report.phases.postIncidentActivity.lessonsLearned.map(l => `- ${l}`).join('\n')}
`
}

export function buildCaseExport(events = [], findings = [], decisions = {}, exportedAt = new Date().toISOString()) {
  return {
    exportedAt,
    sourceNotice: 'Generated locally in Signal Desk. Validate heuristic findings before operational use.',
    summary: summarize(events, findings),
    nistIncidentReport: generateNistReport(findings, events),
    findings: findings.map((item) => ({
      ...item,
      triage: decisions[item.id] || { decision: 'new', note: '' },
    })),
    events: events.map(({ raw, ...event }) => event),
  }
}
