# Sysmon

System Monitor. Provides process, network, and file telemetry that the default Windows audit policy does not.

## Deployment

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml
sysmon64.exe -c sysmonconfig.xml      # update config
sysmon64.exe -c                       # show current config
sysmon64.exe -u force                 # uninstall
```

Logs land in `Microsoft-Windows-Sysmon/Operational`.

## Event IDs

```text
1   process creation              2   file creation time changed
3   network connection            5   process terminated
6   driver loaded                 7   image (DLL) loaded
8   CreateRemoteThread            9   raw disk access
10  process access                11  file created
12  registry object created/deleted
13  registry value set            14  registry key renamed
15  file stream created           17  named pipe created
18  named pipe connected          22  DNS query
23  file delete (archived)        25  process tampering
```

The high-value four: **1** (what ran), **3** (where it talked), **10** (what touched what), **22** (what it resolved).

## Querying

```powershell
# process creation
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 100 |
  ForEach-Object {
      $x = [xml]$_.ToXml()
      [PSCustomObject]@{
          Time    = $_.TimeCreated
          Image   = ($x.Event.EventData.Data | Where-Object Name -eq 'Image').'#text'
          Cmd     = ($x.Event.EventData.Data | Where-Object Name -eq 'CommandLine').'#text'
          Parent  = ($x.Event.EventData.Data | Where-Object Name -eq 'ParentImage').'#text'
          User    = ($x.Event.EventData.Data | Where-Object Name -eq 'User').'#text'
          Hash    = ($x.Event.EventData.Data | Where-Object Name -eq 'Hashes').'#text'
      }
  }

# LSASS access: credential dumping indicator
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=10} |
  Where-Object { $_.Message -match "lsass.exe" }
```

## Parent-child relationships

The strongest signal Sysmon gives you. Normal parentage is predictable; deviation is not.

```text
Suspicious parent → child
  winword.exe    → powershell.exe, cmd.exe, wscript.exe
  excel.exe      → any shell
  outlook.exe    → any shell
  w3wp.exe       → cmd.exe                    (web shell)
  services.exe   → unsigned binary from temp
  wmiprvse.exe   → powershell.exe             (WMI lateral movement)
  explorer.exe   → rundll32.exe with odd args
```

## Configuration

Start from a maintained baseline, SwiftOnSecurity's config or Olaf Hartong's modular set, then tune for
your environment. Do not run the default config; it logs almost nothing useful.

Tuning principles:
- Exclude by full path and signature, never by filename alone. `svchost.exe` in `C:\Temp` is not `svchost.exe` in `System32`.
- Exclude noisy legitimate software explicitly, and record why in a comment.
- Keep Event ID 1 broad. Process creation is the backbone of everything else.
- Document every exclusion. An undocumented exclusion is a blind spot nobody remembers creating.

## Feeding a SIEM

Sysmon events surface in the `Event` table in Log Analytics:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| extend Cmd = extract("<Data Name='CommandLine'>(.*?)</Data>", 1, EventData)
| project TimeGenerated, Computer, Cmd
```

Defender for Endpoint provides equivalent data pre-parsed in `DeviceProcessEvents`, which is easier to query
where available.

## Notes

- Sysmon logs locally. Without forwarding, the evidence dies with the host.
- Hashes in Event 1 are configurable, enable at least SHA256.
- Event 10 is noisy without careful filtering; scope it to sensitive targets like `lsass.exe`.
- Version matters. Newer Sysmon adds event types and config schema changes; record the version used when documenting a case.
