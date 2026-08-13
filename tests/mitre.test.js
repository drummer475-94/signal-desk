import test from 'node:test'
import assert from 'node:assert/strict'
import { detectFindings, normalizeEvent } from '../core.js'

test('detects and maps MITRE ATT&CK techniques: T1078, T1110, T1059.001, T1098, T1003', () => {
  const sampleEvents = [
    // T1078 Valid Accounts / Disabled Account
    { id: 'ev-1', timestamp: '2026-08-08T10:00:00Z', source: 'idp', actor: 'old_contractor', eventType: 'auth', outcome: 'success', ip: '1.2.3.4', message: 'Disabled account authenticated via legacy API' },
    
    // T1110 Brute Force (5 failures)
    { id: 'bf-1', timestamp: '2026-08-08T10:01:00Z', source: 'vpn', actor: 'attacker', eventType: 'auth', outcome: 'failure', ip: '5.6.7.8', message: 'Invalid password' },
    { id: 'bf-2', timestamp: '2026-08-08T10:02:00Z', source: 'vpn', actor: 'attacker', eventType: 'auth', outcome: 'failure', ip: '5.6.7.8', message: 'Invalid password' },
    { id: 'bf-3', timestamp: '2026-08-08T10:03:00Z', source: 'vpn', actor: 'attacker', eventType: 'auth', outcome: 'failure', ip: '5.6.7.8', message: 'Invalid password' },
    { id: 'bf-4', timestamp: '2026-08-08T10:04:00Z', source: 'vpn', actor: 'attacker', eventType: 'auth', outcome: 'failure', ip: '5.6.7.8', message: 'Invalid password' },
    { id: 'bf-5', timestamp: '2026-08-08T10:05:00Z', source: 'vpn', actor: 'attacker', eventType: 'auth', outcome: 'failure', ip: '5.6.7.8', message: 'Invalid password' },
    
    // T1059.001 PowerShell
    { id: 'ps-1', timestamp: '2026-08-08T10:06:00Z', source: 'host-01', actor: 'user1', eventType: 'windows-4688', outcome: 'success', ip: '10.0.0.5', message: 'powershell.exe -nop -enc SQBFAFgA' },
    
    // T1098 Account Manipulation / Privilege Change
    { id: 'ac-1', timestamp: '2026-08-08T10:07:00Z', source: 'dc-01', actor: 'admin1', eventType: 'windows-4720', outcome: 'success', ip: '10.0.0.1', message: 'User Account Created: temp_admin by admin1' },
    
    // T1003 OS Credential Dumping
    { id: 'cd-1', timestamp: '2026-08-08T10:08:00Z', source: 'host-01', actor: 'user1', eventType: 'edr', outcome: 'blocked', ip: '10.0.0.5', message: 'Mimikatz credential dumper execution blocked targeting lsass' },
  ].map((e) => normalizeEvent(e))

  const findings = detectFindings(sampleEvents)
  assert.ok(findings.length >= 5, `Expected at least 5 findings, got ${findings.length}`)

  const techniqueIds = findings.map(f => f.mitreTechniqueId)
  assert.ok(techniqueIds.includes('T1078'), 'Should map T1078 Valid Accounts')
  assert.ok(techniqueIds.includes('T1110'), 'Should map T1110 Brute Force')
  assert.ok(techniqueIds.includes('T1059.001'), 'Should map T1059.001 PowerShell')
  assert.ok(techniqueIds.includes('T1098'), 'Should map T1098 Account Manipulation')
  assert.ok(techniqueIds.includes('T1003'), 'Should map T1003 OS Credential Dumping')

  findings.forEach(f => {
    assert.ok(f.mitreTechniqueId, 'Finding should have mitreTechniqueId')
    assert.ok(f.mitreTechniqueName, 'Finding should have mitreTechniqueName')
    assert.ok(f.mitreTactic, 'Finding should have mitreTactic')
    assert.ok(f.mitreMapping.includes(f.mitreTechniqueId), 'mitreMapping string should contain technique ID')
  })
})
