# Detection Rules

This directory contains the Elastic KQL used for this project.

| File                                      | Description                                                                                               |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `elastic-microphone-consentstore.kql`     | Detects Sysmon Event ID 13 registry modifications under the Windows microphone ConsentStore path.         |
| `elastic-powershell-recording-device.kql` | Detects PowerShell script blocks that enumerate and select a recording device using `AudioDeviceCmdlets`. |

## Notes

Both detections should begin as low-severity alerts or hunting signals.

The ConsentStore rule requires Sysmon Event ID 13 collection. The PowerShell rule requires PowerShell Script Block Logging and Event ID 4104 ingestion.

I did not add exclusions directly into either query. Any production tuning should be narrow and based on validated business activity.
