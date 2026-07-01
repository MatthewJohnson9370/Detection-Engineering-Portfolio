# Attack Overview

## MITRE ATT&CK

- **Technique:** T1123 - Audio Capture
- **Tactic:** Collection

---

## Objective

The objective of Audio Capture is to collect sensitive information by recording audio from a victim's microphone. Adversaries may use this technique to capture conversations, meetings, verbal credentials, or other information that is not available through traditional file collection methods.

---

## Attack Description

Rather than stealing files or credentials directly, the attacker attempts to use the endpoint's microphone as an intelligence collection source. This activity may be performed by malware, commercially available remote access tools (RATs), or custom tooling after the attacker has established access to the system.

Because many legitimate applications also access microphones (Microsoft Teams, Zoom, Discord, etc.), detection should focus on identifying **unexpected or suspicious microphone access** rather than simply detecting audio recording software.

---

## Attack Prerequisites

- Initial access to the endpoint
- Ability to execute code on the victim system
- Access to an available audio input device

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Operating System | Windows 11 |
| Endpoint Protection | Elastic Agent |
| Logging | Sysmon |
| SIEM | Elastic Security |

---

## Attack Emulation

This attack was emulated in a controlled lab environment to generate endpoint telemetry for detection development.

### Tools

- Manual execution of audio recording software
- Atomic Red Team (validation)

---

## Expected Telemetry

During testing, the following telemetry is expected to be generated:

- Process creation events
- Parent-child process relationships
- Command-line arguments
- Endpoint security telemetry
- Application execution logs

---

## Detection Goal

Develop a behavior-based detection capable of identifying suspicious microphone access while minimizing false positives from legitimate collaboration software.

---

## References

- MITRE ATT&CK: https://attack.mitre.org/techniques/T1123/
- Atomic Red Team: https://github.com/redcanaryco/atomic-red-team
