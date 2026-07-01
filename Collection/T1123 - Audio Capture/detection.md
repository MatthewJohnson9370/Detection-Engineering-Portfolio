# T1123 - Microphone Privacy Registry Modification

## Overview

Detects modifications to the Windows microphone privacy registry settings. Adversaries may alter these settings to facilitate or enable unauthorized audio capture.

- **MITRE ATT&CK:** T1123 - Audio Capture
- **Telemetry:** Sysmon Event ID 13 (Registry Value Set)
- **Platform:** Windows
- **Severity:** Medium
- **Risk Score:** 47

---

# Detection Logic

```
event.dataset:"windows.sysmon_operational" and
event.code:"13" and
registry.path:*CapabilityAccessManager* and
registry.path:*ConsentStore* and
registry.path:*microphone* and
(
  registry.path:*LastUsedTimeStart* or
  registry.path:*LastUsedTimeStop*
)
```

> **Note:** If `registry.path` is not populated in your environment, use the equivalent field (e.g., `winlog.event_data.TargetObject`) after validating your Sysmon ingestion pipeline.
> 

---

# Why This Detection Works

This rule detects modifications to the Windows microphone privacy registry path rather than a specific tool.

By focusing on the registry modification itself, it can detect changes made by:

- reg.exe
- PowerShell
- Win32 APIs
- .NET APIs
- Custom malware

Target Registry Path:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
CapabilityAccessManager\ConsentStore\microphone
```

---

# Required Telemetry

- Sysmon Event ID 13 – Registry Value Set

---

# Investigation Guide

1. Review the modified registry path and value.
2. Identify the process responsible for the modification.
3. Determine whether the process is trusted and expected.
4. Pivot on `host.name` and `user.name` to identify related activity.
5. Investigate for additional persistence, process execution, or network activity.
6. Escalate if the modification originated from an unexpected or unsigned process.

---

# Recommended Elastic Fields

- `@timestamp`
- `host.name`
- `user.name`
- `registry.path`
- `registry.value`
- `registry.data.strings`
- `process.name`
- `process.executable`
- `process.command_line`
- `event.code`

---

# Rule Configuration

| Setting | Value |
| --- | --- |
| Runs Every | 5 Minutes |
| Additional Look-back | 1 Minute |
| Alert Suppression | `host.id` + `user.name` |
| Suppression Duration | 10 Minutes |

---

# Exceptions

### Name

**Trusted Collaboration Applications**

### Description

Exclude trusted collaboration and conferencing applications that legitimately modify Windows microphone privacy settings.

Examples:

- Microsoft Teams
- Zoom
- Cisco Webex
- Slack

> Prefer trusted code signatures over process names whenever possible.
> 

---

# False Positives

- Collaboration software
- Enterprise conferencing tools
- Audio management software
- Endpoint management solutions

---

# MITRE ATT&CK Mapping

| Tactic | Technique |
| --- | --- |
| Collection | T1123 - Audio Capture |

---

# Detection Engineering Notes

- Detects **registry modifications**, not process execution.
- More resilient than Event ID 1 because it identifies the configuration change regardless of the tool used.
- If Event ID 13 is unavailable, consider a fallback detection using Sysmon Event ID 1 targeting the same registry path.

---

# Validation

**Tested With**

- Atomic Red Team
- Elastic Security
- Sysmon
- Windows 11 Enterprise

**Expected Result**

An alert is generated whenever a registry value under the following path is modified:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
CapabilityAccessManager\ConsentStore\microphone
```

---

# References

- MITRE ATT&CK: https://attack.mitre.org/techniques/T1123/
- Sysmon Documentation: https://learn.microsoft.com/sysinternals/downloads/sysmon
- Elastic Security Documentation: https://www.elastic.co/guide/en/security/current/index.html
