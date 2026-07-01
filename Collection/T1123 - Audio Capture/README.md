# T1123 - Audio Capture

## Overview

This project demonstrates a behavior-based detection for **MITRE ATT&CK T1123 - Audio Capture**. The objective is to identify suspicious attempts to capture audio from a Windows endpoint by analyzing endpoint telemetry rather than relying solely on specific tool names.

---

## MITRE ATT&CK

- **Technique:** T1123 - Audio Capture
- **Tactic:** Collection

---

## Objectives

- Research the attack technique
- Understand the underlying Windows functionality
- Generate the attack in a lab
- Collect and analyze telemetry
- Develop and validate an Elastic detection
- Document the investigation process

---

## Lab Environment

| Component | Version |
|-----------|---------|
| Windows 11 | Latest |
| Elastic Security | 9.x |
| Elastic Agent | Installed |
| Sysmon | SwiftOnSecurity Configuration |

---

## Detection Strategy

Rather than detecting a specific application, this detection focuses on identifying suspicious microphone access by unexpected processes and correlating that activity with surrounding endpoint telemetry.

---

## Validation

| Test | Status |
|------|--------|
| Attack Performed | ☐ |
| Telemetry Collected | ☐ |
| Detection Developed | ☐ |
| Detection Validated | ☐ |
| False Positives Reviewed | ☐ |

---

## Repository Contents

| File | Description |
|------|-------------|
| attack.md | Attack execution and methodology |
| detection.md | Detection logic and reasoning |
| investigation.md | SOC investigation guide |
| rules/ | Elastic detection rule(s) |
| screenshots/ | Lab screenshots and validation |

---

## References

- MITRE ATT&CK: https://attack.mitre.org/techniques/T1123/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
- Elastic Detection Rules: https://github.com/elastic/detection-rules
