# T1123 - Audio Capture

## Overview

This project documents two Windows lab tests mapped to **MITRE ATT&CK T1123 - Audio Capture**.

The goal was to understand what telemetry is available when a system interacts with microphone-related settings or recording devices, then build Elastic detections around that activity.

Neither test confirms that audio was recorded. I would treat both detections as low-severity signals that need context from the host, user, process, and surrounding activity.

## MITRE ATT&CK

| Technique             | Tactic     |
| --------------------- | ---------- |
| T1123 - Audio Capture | Collection |

## Detection Coverage

| Detection                                 | Telemetry                | What It Identifies                                                               |
| ----------------------------------------- | ------------------------ | -------------------------------------------------------------------------------- |
| Microphone ConsentStore Registry Activity | Sysmon Event ID 13       | Changes under the Windows microphone ConsentStore registry path                  |
| PowerShell Recording Device Selection     | PowerShell Event ID 4104 | PowerShell using `Get-AudioDevice`, `Set-AudioDevice`, and `-Recording` together |

## Lab Environment

* Windows 11
* Elastic Security
* Elastic Agent
* Sysmon
* PowerShell Script Block Logging

## Enterprise Considerations

I would deploy both detections as low-severity alerts or hunting signals first.

Microphone activity is expected on systems using Teams, Zoom, clinical dictation, accessibility tools, recording software, or other approved collaboration applications. The useful context is whether the activity is expected for the user, device, process path, parent process, and host role.

## Repository Contents

| File or Folder     | Purpose                                                                     |
| ------------------ | --------------------------------------------------------------------------- |
| `attack.md`        | Commands used in the lab and the telemetry each test was expected to create |
| `detection.md`     | Detection logic, rationale, limitations, and tuning notes                   |
| `investigation.md` | Notes for reviewing an alert                                                |
| `rules/`           | Copy-ready Elastic KQL detections                                           |
| `screenshots/`     | Evidence of the attack, telemetry, and alert                                |
| `logs/`            | Sanitized sample events collected during testing                            |

## References

* MITRE ATT&CK T1123 - Audio Capture
* Atomic Red Team T1123 - Audio Capture
* Elastic Detection Rules
