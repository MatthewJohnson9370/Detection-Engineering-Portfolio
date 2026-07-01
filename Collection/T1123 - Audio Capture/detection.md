# Detection Notes — T1123 Audio Capture

## Summary

For this project, I tested two different ways to generate microphone-related activity on Windows.

The first detection looks for registry changes under the Windows microphone ConsentStore path. The second looks for PowerShell using `AudioDeviceCmdlets` to identify and select a recording device.

I would treat both as low-severity signals in an enterprise environment. Neither one proves that a user or attacker recorded audio, but they can be useful when paired with suspicious process activity, audio-file creation, or outbound network traffic.

---

## Detection 1 — Microphone ConsentStore Registry Activity

This was the original detection developed from Sysmon Event ID 13 telemetry.

```kql
event.dataset:"windows.sysmon_operational" and
event.code:"13" and
registry.path:*CapabilityAccessManager* and
registry.path:*ConsentStore* and
registry.path:*microphone*
```

This rule identifies registry value changes related to microphone consent or usage. In a lab, it provides useful evidence that an application interacted with Windows microphone-related settings or artifacts.

In a production environment, I would expect legitimate hits from conferencing, dictation, accessibility, and recording software. Because of that, I would start this as a low-severity rule and baseline which applications normally generate events in this path.

A future tuning option would be narrowing the rule to usage timestamp values such as `LastUsedTimeStart` and `LastUsedTimeStop` if those values appear consistently in the collected telemetry.

---

## Detection 2 — PowerShell Recording Device Selection

The Atomic Red Team test uses PowerShell to locate a recording device and set it as the active audio device:

```powershell
$mic = Get-AudioDevice -Recording
Set-AudioDevice -ID $mic.ID
Start-Sleep -Seconds 5
```

To identify this procedure, I would use PowerShell Script Block Logging and look for the combination of recording-device enumeration and selection:

```kql
event.code:"4104" and
powershell.file.script_block_text:*Get-AudioDevice* and
powershell.file.script_block_text:*Set-AudioDevice* and
powershell.file.script_block_text:*Recording*
```

This is more useful than alerting on PowerShell alone because it requires a specific sequence of audio-device actions. It still does not confirm that recording occurred; it only shows that PowerShell was used to identify and select a microphone or recording device.

I would keep this low severity unless the activity is unusual for the user, host, script path, or parent process.

---

## Tuning and Expected Benign Activity

I would not add broad exclusions before collecting baseline data.

In an enterprise environment, microphone-related registry activity may be expected from approved conferencing, clinical dictation, accessibility, recording, and collaboration software. PowerShell-based recording-device selection may also be legitimate when used by approved IT automation or endpoint configuration scripts.

For this lab project, I did not add production exclusions because the activity was only tested in an isolated environment.

If tuning is required, I would keep exclusions narrow and based on validated business activity, such as:

- A known approved executable path and publisher
- A specific signed PowerShell script or approved automation account
- A documented host group used for dictation or conferencing
- A known endpoint-management workflow

I would avoid broad exclusions such as excluding all PowerShell activity, all microphone ConsentStore changes, or all collaboration applications. Those exclusions could hide suspicious behavior occurring through otherwise legitimate software.

---

## Detection Gaps

Neither rule identifies every form of audio capture. An attacker could use a custom binary, a remote-access tool, a browser-based application, or direct Windows APIs without generating the same PowerShell or registry telemetry.

The stronger detection path would be correlating microphone-related activity with nearby creation of audio files such as `.wav`, `.mp3`, `.m4a`, `.aac`, or `.flac`, especially when the same process also makes unusual outbound network connections.

---

## Recommendation

I would use these detections as supporting collection signals rather than standalone high-confidence alerts. Their value increases when they occur alongside suspicious scripting, unexpected execution paths, archive creation, or potential exfiltration activity.
