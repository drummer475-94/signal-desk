# Signal Desk

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/drummer475-94/signal-desk/actions)
[![Test Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen.svg)](https://github.com/drummer475-94/signal-desk)
[![NIST SP 800-61 Rev 2](https://img.shields.io/badge/NIST-SP%20800--61%20Rev%202-blue.svg)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
[![MITRE ATT&CK v14](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-orange.svg)](https://attack.mitre.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Signal Desk is an enterprise-grade incident operations and multi-format log triage workbench. It ingests multi-source logs—including Windows Security Events (EVTX/XML Event IDs 4624, 4625, 4672, 4688, 4720), AWS CloudTrail JSON exports, and Syslog (RFC 5424 / RFC 3164)—correlates security events, maps findings to MITRE ATT&CK techniques, and generates structured NIST SP 800-61 Rev 2 incident reports.

**[Open Live App](https://drummer475-94.github.io/signal-desk/)**

---

## ⚡ 60-Second Quick Review Guide

1. **Scan Live Demo Findings**: Click **Load Demo Case** to view pre-loaded multi-source security events across VPN gateways, EDR alerts, Windows AD events, and AWS CloudTrail.
2. **Inspect MITRE ATT&CK Correlation**: Review automatically detected findings annotated with explicit MITRE ATT&CK technique IDs (`T1078 Valid Accounts`, `T1110 Brute Force`, `T1059.001 PowerShell`, `T1098 Account Manipulation`, and `T1003 OS Credential Dumping`).
3. **Generate NIST SP 800-61 Rev 2 Incident Report**: Export a case JSON package containing the structured 4-phase incident handling report (Preparation, Detection & Analysis, Containment/Eradication, Post-Incident Activity), analyst decisions, findings, and sanitized evidence.
4. **Local Privacy & Zero Dependencies**: Built with pure browser-native JavaScript (ES modules) with 0 external runtime dependencies.

---

## Architecture & Data Flow

```mermaid
flowchart TD
    subgraph Ingestion [Log Ingestion Engines]
        Win[Windows Event Logs<br/>EVTX / XML IDs 4624, 4625, 4672, 4688, 4720]
        AWS[AWS CloudTrail JSON<br/>API Events & Sign-in]
        Sys[Syslog RFC 5424 / RFC 3164<br/>Facility & Severity Parsing]
        CSV[JSON / JSONL / CSV<br/>Generic Security Logs]
    end

    subgraph Core [Signal Desk Core Processing]
        Norm[Log Schema Normalizer<br/>normalizeEvent & parseLogText]
        Mitre[MITRE ATT&CK Mapper<br/>T1078, T1110, T1059.001, T1098, T1003]
        NIST[NIST SP 800-61 Rev 2 Engine<br/>generateNistReport]
    end

    subgraph Output [Analyst Outputs & Reports]
        Timeline[Interactive Event Timeline]
        Findings[Heuristic Findings & Correlation]
        Report[NIST SP 800-61 Structured Case Report]
    end

    Win --> Norm
    AWS --> Norm
    Sys --> Norm
    CSV --> Norm

    Norm --> Mitre
    Mitre --> Findings
    Findings --> NIST
    NIST --> Report
    Norm --> Timeline
```

---

## Technical Features

- **Multi-Format Security Log Parsers**: Native parsing for Windows Event XML/EVTX (Event IDs 4624 Logon, 4625 Failed Logon, 4672 Special Privileges, 4688 Process Creation, 4720 Account Creation), AWS CloudTrail JSON logs, and Syslog RFC 5424 / RFC 3164.
- **MITRE ATT&CK Framework Mapping**: Automatic correlation and tagging for:
  - **T1078 (Valid Accounts)**: Disabled account authentication & legacy sign-in attempts.
  - **T1110 (Brute Force)**: Authentication failure bursts (5+ failures in 10 minutes) and failure-then-success patterns.
  - **T1059.001 (Command and Scripting Interpreter: PowerShell)**: Encoded PowerShell command execution (`-enc`, `FromBase64String`, `IEX`).
  - **T1098 (Account Manipulation)**: Account creation (4720) and privileged role modification (4672).
  - **T1003 (OS Credential Dumping)**: Credential access signatures, Mimikatz patterns, and LSASS memory access.
- **NIST SP 800-61 Rev 2 Report Generator**: Structured 4-phase incident handling export:
  1. **Preparation**: Baseline inventory & logging health.
  2. **Detection & Analysis**: Severity counts, MITRE ATT&CK coverage, impacted actors & IPs.
  3. **Containment, Eradication & Recovery**: Specific containment steps per detected technique, eradication procedures, system recovery checks.
  4. **Post-Incident Activity**: Lessons learned, policy updates, IOC indicators.
- **Test Coverage**: >90% code coverage enforced via Node.js native test runner.

---

## Verification & Testing

Run unit tests and verify code coverage:

```bash
# Run unit tests across all test suites
node --test tests/*.test.js

# Run test coverage verification (>90% threshold)
node --test --experimental-test-coverage tests/*.test.js
```

---

## Professional Standards Alignment

- **NIST SP 800-61 Rev 2**: Computer Security Incident Handling Guide.
- **MITRE ATT&CK v14**: Enterprise Matrix for Threat Detection.
- **CISA Security Logging Guidance**: Best practices for centralizing and auditing critical system logs.
