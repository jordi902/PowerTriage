![PowerTriage - PowerShell Triage Tool](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiCzqxFE5Bl3MFLcJWDQkQ_5H92_0HY8g60rWbjziDPJ_AlWhDCKUE2soEAe2efjF0x4kqJxYJxdzM2WpfJ24ZTnS5EKd97opAskFQEp4wDG3MCLIIbQU8rDzks35AutMErCUH7kiR_nYU0bplBN_u6m5PoZtpubqRdAy0mCs0IrjOWWjmlbeb5RKn1eTk/s320/Logo.png)
# PowerTriage
Powertriage is a DFIR Powershell script to perform a live adquisition of artifacts on a Windows System without external software.

# PowerTriage Script - Extracted Artefacts

PowerTriage collects information from multiple sources, the output by default is in "C:\" folder but you can set an specific folder to perform the adquisition, the folder will be named as 'PowerTriage-hostname-yearmonthdate_hhmmss'. This folder will be zipped once the script finish (and the original folder will be delete), so that zip file could be remotely collected.
PowerTriage script collects the following artifacts:

**Functions**

- System Info
- Network Info:
	- Ip information (All interfaces)
	- TCP_Stablishe_Connections
- Activities Cache (All users)
- Event Logs (Application, Security, System, PowerShell Operational, TaskScheduler Operational, Sysmon Operational, WMI Activity Operational, NTLM Operational, etc.)
- PowerShell Command History (All users)
- Prefetch
- Process Information (Process List, Process Tree, Unique Process Hash)
- Recent Items (All users)
- Recycle Bin (All users)
- Schedule Task (Schedule Task List, Schedule Task Run Info)
- Active Users
- Autoruns
- DNS Cache
- Users:
	- Active Users
	- Local Users
- Services Running
- Shadow Copies List
- Browsers artifacts (Edge, Opera, Chrome, Firefox)
- RDP Connections
- Hashing artifacts
 
**More functions the next update :) ** 

# Windows Usage

PowerTriage script must be run with **admin** privileges for a best performance, if not, not all artifacts will be collect.

The PowerTriage **script is unsigned**, that could result in having to use the **_-ExecutionPolicy Bypass_** to run the script.

The script can be excuted by running the following command.
```.\Powertriage.ps1```
or
```Powershell.exe -ExecutionPolicy Bypass .\PowerTriage.ps1```


