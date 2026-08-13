import test from 'node:test'
import assert from 'node:assert/strict'
import { buildCaseExport, demoEvents, detectFindings, formatNistReportMarkdown, generateNistReport, normalizeEvent } from '../core.js'

test('generates NIST SP 800-61 Rev 2 incident reports across all 4 phases', () => {
  const events = demoEvents.map(normalizeEvent)
  const findings = detectFindings(events)

  const report = generateNistReport(findings, events)
  assert.equal(report.title, 'NIST SP 800-61 Rev 2 Incident Handling & Analysis Report')
  assert.ok(report.generatedAt)
  assert.equal(report.standard, 'NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide)')
  assert.equal(report.summary.incidentCategory, 'CAT 3 - Malicious Code')

  // Check 4 Phases:
  assert.ok(report.phases.preparation, 'Phase 1: Preparation must exist')
  assert.equal(report.phases.preparation.status, 'COMPLETE')
  assert.ok(report.phases.preparation.detectionRulesActive.includes('T1078 (Valid Accounts)'))

  assert.ok(report.phases.detectionAndAnalysis, 'Phase 2: Detection & Analysis must exist')
  assert.equal(report.phases.detectionAndAnalysis.status, 'INCIDENT_CONFIRMED')
  assert.ok(report.phases.detectionAndAnalysis.findings.length > 0)
  assert.ok(report.phases.detectionAndAnalysis.mitreTechniquesCovered.length > 0)

  assert.ok(report.phases.containmentEradicationRecovery, 'Phase 3: Containment, Eradication & Recovery must exist')
  assert.ok(report.phases.containmentEradicationRecovery.containmentActions.length > 0)
  assert.ok(report.phases.containmentEradicationRecovery.eradicationSteps.length > 0)
  assert.ok(report.phases.containmentEradicationRecovery.recoverySteps.length > 0)

  assert.ok(report.phases.postIncidentActivity, 'Phase 4: Post-Incident Activity must exist')
  assert.ok(report.phases.postIncidentActivity.lessonsLearned.length > 0)

  // Markdown formatting
  const md = formatNistReportMarkdown(report)
  assert.ok(md.includes('# NIST SP 800-61 Rev 2 Incident Handling & Analysis Report'))
  assert.ok(md.includes('## 1. Preparation Phase'))
  assert.ok(md.includes('## 2. Detection & Analysis Phase'))
  assert.ok(md.includes('## 3. Containment, Eradication & Recovery'))
  assert.ok(md.includes('## 4. Post-Incident Activity & Lessons Learned'))
})

test('uses defensible incident categories and avoids claiming unverified logging completeness', () => {
  const bruteForceFinding = {
    ruleId: 'auth-burst', severity: 'high', mitreTechniqueId: 'T1110', mitreMapping: 'T1110 - Brute Force',
    title: 'Authentication failure burst', rationale: 'Five failures', eventIds: ['evt-1'],
  }
  const event = normalizeEvent({
    id: 'evt-1', timestamp: '2026-08-13T19:00:00Z', source: 'vpn', actor: 'user',
    eventType: 'auth', outcome: 'failure', ip: '192.0.2.1', severity: 'high', message: 'Invalid password',
  })
  const attemptedAccessReport = generateNistReport([bruteForceFinding], [event])
  assert.equal(attemptedAccessReport.summary.incidentCategory, 'CAT 5 - Scans, Probes, or Attempted Access')
  assert.match(attemptedAccessReport.phases.preparation.loggingHealth, /requires analyst validation/)

  const cleanReport = generateNistReport([], [])
  assert.equal(cleanReport.summary.incidentCategory, 'No category assigned - No confirmed incident')
  assert.equal(cleanReport.phases.containmentEradicationRecovery.status, 'MONITOR')
  assert.equal(cleanReport.phases.preparation.loggingHealth, 'No log sources represented.')
})

test('builds a case export with triage decisions and a structured NIST report', () => {
  const events = demoEvents.map(normalizeEvent)
  const findings = detectFindings(events)
  const reviewedFinding = findings[0]
  const exportedAt = '2026-08-13T20:00:00.000Z'
  const payload = buildCaseExport(events, findings, {
    [reviewedFinding.id]: { decision: 'escalate', note: 'Contain the affected account.' },
  }, exportedAt)

  assert.equal(payload.exportedAt, exportedAt)
  assert.equal(payload.nistIncidentReport.standard, 'NIST SP 800-61 Rev 2 (Computer Security Incident Handling Guide)')
  assert.equal(payload.findings[0].triage.decision, 'escalate')
  assert.equal(payload.findings[1].triage.decision, 'new')
  assert.ok(payload.events.every((event) => !Object.hasOwn(event, 'raw')))
})
