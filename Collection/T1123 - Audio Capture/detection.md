# Detection Logic

## Objective

Detect suspicious audio capture activity by identifying processes commonly associated with microphone access and analyzing their execution context.

---

## Detection Rationale

Windows does not natively generate security events specifically for microphone access. Therefore, this detection relies on process creation telemetry combined with execution context to identify potentially suspicious audio recording activity.

---

## Elastic Detection (KQL)

```kql
event.dataset:"windows.sysmon_operational" and
event.code:"13" and
registry.path:*CapabilityAccessManager* and
registry.path:*ConsentStore* and
registry.path:*microphone*
```

---

## Why This Works

This detection identifies processes capable of recording audio. While process execution alone does not confirm malicious activity, it provides valuable telemetry when combined with:

- Parent process
- Command line
- User context
- Execution path
- Network activity

---

## Telemetry Used

| Source | Purpose |
|---------|---------|
| Sysmon Event ID 1 | Process Creation |
| Process Name | Identify recording applications |
| Parent Process | Execution context |
| Command Line | Suspicious arguments |
| Image Path | Detect renamed or relocated binaries |

---

## False Positives

- Microsoft Teams
- Zoom
- Discord
- OBS Studio
- Windows Sound Recorder

These applications should be baselined before deployment.

---

## Limitations

This detection does **not** confirm microphone access.

Higher confidence would require:

- Microsoft Defender for Endpoint DeviceEvents
- Endpoint sensor telemetry
- Microphone permission auditing

---

## Future Improvements

- Behavioral baselining
- Parent-child anomaly detection
- Correlation with outbound network traffic
- Correlation with file creation events
