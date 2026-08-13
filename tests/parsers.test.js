import test from 'node:test'
import assert from 'node:assert/strict'
import {
  parseWindowsXmlEvents,
  parseCloudTrailEvents,
  parseSyslogText,
  parseLogText
} from '../core.js'

test('parses Windows Security Event Logs XML (4624, 4625, 4672, 4688, 4720)', () => {
  const xml = `
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System>
        <EventID>4624</EventID>
        <TimeCreated SystemTime='2026-08-08T14:00:00.000Z'/>
        <Computer>DC-01.corp.local</Computer>
      </System>
      <EventData>
        <Data Name='TargetUserName'>jsmith</Data>
        <Data Name='IpAddress'>192.168.1.50</Data>
        <Data Name='LogonType'>10</Data>
      </EventData>
    </Event>
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System>
        <EventID>4625</EventID>
        <TimeCreated SystemTime='2026-08-08T14:01:00.000Z'/>
        <Computer>DC-01.corp.local</Computer>
      </System>
      <EventData>
        <Data Name='TargetUserName'>jsmith</Data>
        <Data Name='IpAddress'>192.168.1.50</Data>
        <Data Name='FailureReason'>0xc000006a</Data>
      </EventData>
    </Event>
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System>
        <EventID>4672</EventID>
        <TimeCreated SystemTime='2026-08-08T14:02:00.000Z'/>
        <Computer>DC-01.corp.local</Computer>
      </System>
      <EventData>
        <Data Name='SubjectUserName'>admin_user</Data>
        <Data Name='PrivilegeList'>SeDebugPrivilege SeTakeOwnershipPrivilege</Data>
      </EventData>
    </Event>
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System>
        <EventID>4688</EventID>
        <TimeCreated SystemTime='2026-08-08T14:03:00.000Z'/>
        <Computer>DC-01.corp.local</Computer>
      </System>
      <EventData>
        <Data Name='SubjectUserName'>jsmith</Data>
        <Data Name='CommandLine'>powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA</Data>
        <Data Name='NewProcessName'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      </EventData>
    </Event>
    <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
      <System>
        <EventID>4720</EventID>
        <TimeCreated SystemTime='2026-08-08T14:04:00.000Z'/>
        <Computer>DC-01.corp.local</Computer>
      </System>
      <EventData>
        <Data Name='SubjectUserName'>admin_user</Data>
        <Data Name='TargetUserName'>backdoor_account</Data>
      </EventData>
    </Event>
  `

  const xmlEvents = parseWindowsXmlEvents(xml)
  assert.equal(xmlEvents.length, 5)
  assert.equal(xmlEvents[0].eventType, 'windows-4624')
  assert.equal(xmlEvents[0].actor, 'jsmith')
  assert.equal(xmlEvents[1].eventType, 'windows-4625')
  assert.equal(xmlEvents[1].outcome, 'failure')
  assert.equal(xmlEvents[2].eventType, 'windows-4672')
  assert.equal(xmlEvents[2].severity, 'high')
  assert.equal(xmlEvents[3].eventType, 'windows-4688')
  assert.ok(xmlEvents[3].message.includes('powershell.exe'))
  assert.equal(xmlEvents[4].eventType, 'windows-4720')
  assert.ok(xmlEvents[4].message.includes('backdoor_account'))

  const events = parseLogText(xml)
  assert.equal(events.length, 5)
})

test('parses AWS CloudTrail JSON exports', () => {
  const cloudTrailJson = {
    Records: [
      {
        eventTime: '2026-08-08T15:00:00Z',
        eventSource: 'iam.amazonaws.com',
        eventName: 'CreateUser',
        awsRegion: 'us-east-1',
        sourceIPAddress: '203.0.113.10',
        userIdentity: { type: 'IAMUser', userName: 'admin_caller', arn: 'arn:aws:iam::123456789012:user/admin_caller' },
        responseElements: { user: { userName: 'new_temp_user' } }
      },
      {
        eventTime: '2026-08-08T15:05:00Z',
        eventSource: 'signin.amazonaws.com',
        eventName: 'ConsoleLogin',
        awsRegion: 'us-east-1',
        sourceIPAddress: '198.51.100.99',
        userIdentity: { type: 'IAMUser', userName: 'target_user' },
        errorCode: 'AuthFailure',
        errorMessage: 'Invalid password'
      }
    ]
  }

  const parsed = parseCloudTrailEvents(cloudTrailJson)
  assert.equal(parsed.length, 2)
  assert.equal(parsed[0].actor, 'admin_caller')
  assert.equal(parsed[0].eventType, 'cloudtrail:CreateUser')
  assert.equal(parsed[0].outcome, 'success')

  assert.equal(parsed[1].actor, 'target_user')
  assert.equal(parsed[1].outcome, 'failure')

  const textEvents = parseLogText(JSON.stringify(cloudTrailJson))
  assert.equal(textEvents.length, 2)
})

test('parses Syslog RFC 5424 and RFC 3164 lines', () => {
  const rfc5424 = '<165>1 2026-08-08T13:02:11.000Z mymachine.example.com appname 8710 id47 - Authentication failed for user admin'
  const rfc3164 = '<13>Aug  8 13:03:08 myhost sudo: pam_unix(sudo:auth): authentication failure; logname= uid=0 euid=0 tty=/dev/pts/1 user=root'
  const rawSyslog = '<14> Simple syslog message line'

  const syslogContent = `${rfc5424}\n${rfc3164}\n${rawSyslog}`
  const parsed = parseSyslogText(syslogContent)
  assert.equal(parsed.length, 3)

  assert.equal(parsed[0].source, 'mymachine.example.com')
  assert.equal(parsed[0].actor, 'appname')
  assert.equal(parsed[0].outcome, 'failure')

  assert.equal(parsed[1].source, 'myhost')
  assert.equal(parsed[1].actor, 'sudo')
  assert.equal(parsed[1].outcome, 'failure')

  assert.equal(parsed[2].source, 'syslog-source')

  const events = parseLogText(syslogContent)
  assert.equal(events.length, 3)
})
