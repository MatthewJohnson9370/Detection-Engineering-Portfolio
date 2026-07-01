# Attack Notes — T1123 Audio Capture

## Purpose

I used two Atomic Red Team tests to generate microphone-related activity in an isolated Windows lab.

These tests were used to validate telemetry and detection logic. They did not create or exfiltrate an audio recording.

---

## Test 1 — PowerShell Recording Device Selection

This test uses the `AudioDeviceCmdlets` PowerShell module to identify a recording device and set it as the active device.

### Prerequisite

```powershell
Install-Module -Name AudioDeviceCmdlets -Force
```

### Command Used

```powershell
$mic = Get-AudioDevice -Recording
Set-AudioDevice -ID $mic.ID
Start-Sleep -Seconds 5
```

### Expected Telemetry

* PowerShell Script Block Logging: Event ID 4104
* PowerShell process creation telemetry
* Script content containing:

  * `Get-AudioDevice`
  * `Set-AudioDevice`
  * `-Recording`

### Notes

This test does not record an audio file. It simulates activity associated with identifying and selecting a recording device.

---

## Test 2 — Microphone ConsentStore Registry Artifact

This test writes microphone-related usage values under the Windows ConsentStore registry path.

### Commands Used

```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged\C:#Windows#Temp#atomic.exe /v LastUsedTimeStart /t REG_BINARY /d a273b6f07104d601 /f

reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged\C:#Windows#Temp#atomic.exe /v LastUsedTimeStop /t REG_BINARY /d 96ef514b7204d601 /f
```

### Cleanup

```cmd
reg DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged\C:#Windows#Temp#atomic.exe /f
```

### Expected Telemetry

* Sysmon Event ID 13 — Registry Value Set
* Registry path containing:

  * `CapabilityAccessManager`
  * `ConsentStore`
  * `microphone`

### Notes

This test manually creates a microphone-related registry artifact. It is useful for validating the ConsentStore detection, but it does not prove that a microphone was accessed or that audio was recorded.
