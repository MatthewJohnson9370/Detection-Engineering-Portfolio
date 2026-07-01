# Detection Logic — T1123 Audio Capture

## Objective

Detect suspicious Windows microphone-related activity associated with **MITRE ATT&CK T1123 — Audio Capture**.

This project uses two complementary analytics:

1. Microphone ConsentStore registry modifications.
2. PowerShell-based recording-device enumeration and selection.

Neither detection independently proves that audio was recorded. They are intended as detection signals that require investigation and correlation with surrounding activity.

---

## Required Telemetry

| Source                     | Requirement                                                 |
| -------------------------- | ----------------------------------------------------------- |
| Sysmon                     | Event ID 13 — Registry Value Set                            |
| PowerShell Operational Log | Event ID 4104 — Script Block Logging                        |
| Elastic Agent              | Windows integration collecting Sysmon and PowerShell events |

---

## Detection 1 — Microphone ConsentStore Registry Modification

### Purpose

Detect registry value modifications under the Windows microphone ConsentStore path. This can provide evidence of microphone consent or usage-related activity.

### Elastic KQL

```kql
event.dataset:"windows.sysmon_operational" and
event.code:"13" and
registry.path:*CapabilityAccessManager* and
registry.path:*ConsentStore* and
registry.path:*microphone*
```

### Why It Matters

An attacker or malicious application may interact with microphone-related consent or usage artifacts while preparing to capture audio. This rule detects the registry behavior rather than a specific recording application.

### Recommended Severity

**Low**

This activity can be legitimate on endpoints using conferencing, clinical dictation, accessibility, or approved recording software.

---

## Detection 2 — PowerShell Recording Device Enumeration and Selection

### Purpose

Detect PowerShell using `AudioDeviceCmdlets` to enumerate recording devices and set a recording device.

This covers the Atomic Red Team T1123 simulation:

```powershell
$mic = Get-AudioDevice -Recording
Set-AudioDevice -ID $mic.ID
Start-Sleep -Seconds 5
```

### Elastic KQL

```kql
event.dataset:"windows.powershell_operational" and
event.code:"4104" and
powershell.file.script_block_text:*Get-AudioDevice* and
powershell.file.script_block_text:*Set-AudioDevice* and
powershell.file.script_block_text:*Recording*
```

### Why It Matters

This combination is more specific than alerting on PowerShell or audio-related applications alone:

* `Get-AudioDevice -Recording` enumerates recording devices.
* `Set-AudioDevice` changes the selected device.
* Script Block Logging captures the executed PowerShell content.

This rule detects suspicious preparation for audio capture, but does not confirm that recording occurred.

### Recommended Severity

**Low during initial baselining.**

Promote to **Medium** only after confirming that approved IT automation, clinical dictation tooling, and endpoint configuration scripts do not use this cmdlet combination.

---

## Tuning Considerations

Avoid broad exclusions such as excluding all PowerShell or all microphone-related activity.

Instead, baseline and allowlist only verified business activity based on:

* Approved script path or script signer
* Known automation account
* Approved endpoint-management process
* Specific host groups, such as dictation or conferencing systems
* Consistent and documented IT workflows

---

## Investigation Guidance

When either alert fires:

1. Identify the host, user, process, and parent process.
2. Determine whether the host uses approved dictation, conferencing, or recording software.
3. Review related PowerShell Event ID 4104 logs for additional commands.
4. Check Sysmon Event ID 11 for nearby audio file creation, including `.wav`, `.mp3`, `.m4a`, `.aac`, or `.flac`.
5. Review Sysmon Event ID 3 for suspicious outbound connections from the related process.
6. Investigate unusual execution paths, unsigned scripts, temporary directories, Downloads, and network shares.
7. Escalate when microphone-related activity is paired with suspicious file creation, archive creation, or outbound data transfer.

---

## Detection Limitations

* Registry modifications do not prove that microphone audio was captured.
* The PowerShell rule detects a specific procedure and may miss custom tooling or direct Windows API usage.
* Legitimate conferencing and clinical applications can generate microphone-related activity.
* High-confidence detection requires correlation with audio-file creation and suspicious follow-on behavior.

---

## Future Improvement

Build a correlation detection that identifies:

```text
Microphone-related activity
        +
Audio file creation
        +
Suspicious process or outbound network activity
```

This would provide stronger evidence of potential audio capture and collection.
