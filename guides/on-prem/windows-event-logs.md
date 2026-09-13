# Windows Event Logs

The primary on-premises telemetry source for authentication, process, and service activity.

## Reading logs

```powershell
Get-WinEvent -ListLog * | Where-Object RecordCount -gt 0 |
  Sort-Object RecordCount -Descending | Select-Object -First 20

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-1)}
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100
```

`-FilterHashtable` filters server-side. Piping into `Where-Object` pulls every record into memory first and is
dramatically slower on a busy log.

## Extracting fields

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 200 |
  ForEach-Object {
      $x = [xml]$_.ToXml()
      [PSCustomObject]@{
          Time      = $_.TimeCreated
          Account   = ($x.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
          LogonType = ($x.Event.EventData.Data | Where-Object Name -eq 'LogonType').'#text'
          Source    = ($x.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
          Process   = ($x.Event.EventData.Data | Where-Object Name -eq 'ProcessName').'#text'
      }
  }
```

## Event IDs that matter

**Authentication**
```text
4624  logon succeeded          4625  logon failed
4634  logoff                   4648  explicit credential logon
4672  special privileges       4776  NTLM authentication
4768  Kerberos TGT             4769  Kerberos service ticket
4771  Kerberos pre-auth failed
```

**Logon types on 4624**
```text
2   interactive (console)        3   network (SMB, shares)
4   batch                        5   service
7   unlock                       8   network cleartext
9   new credentials (runas)      10  remote interactive (RDP)
11  cached interactive
```

Type 3 from a workstation to many hosts in a short window is a lateral movement pattern. Type 10 outside
business hours from an unusual source is worth checking.

**Account and group changes**
```text
4720  user created             4722  user enabled
4724  password reset attempt   4726  user deleted
4728  member added to global group
4732  member added to local group
4756  member added to universal group
```

**Process and service**
```text
4688  process created (include command line, off by default)
4697  service installed
7045  service installed (System log)
```

**Tampering**
```text
1102  audit log cleared
4719  audit policy changed
104   log cleared (System log)
```

## Failed logon substatus on 4625

```text
0xC0000064  user does not exist      0xC000006A  wrong password
0xC0000072  account disabled         0xC0000234  account locked out
0xC0000193  account expired          0xC000006F  logon outside allowed hours
```

Many `0xC0000064` from one source is enumeration. Many `0xC000006A` against one account is password guessing.
Few attempts across many accounts is password spraying.

## Auditing that must be enabled first

These are off by default. Without them the evidence does not exist.

| Setting | Gives you |
|---|---|
| Audit Process Creation + "Include command line" | 4688 with the full command line |
| PowerShell Script Block Logging | Event 4104 with decoded script content |
| PowerShell Module Logging | Event 4103 pipeline execution |
| Audit Logon / Account Logon | 4624, 4625, 4768, 4769 |
| Audit Directory Service Access | AD object modifications |

## Collection from multiple hosts

```powershell
$hosts = "DC01","SRV02","WKS10"
Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
} | Select-Object PSComputerName, TimeCreated, Id, Message
```

## Notes

- Default log sizes roll over fast on busy servers. Check retention before concluding an absence of evidence means absence of activity.
- Event 1102 with a gap afterwards is itself the finding.
- Timestamps are local to the host unless forwarded. Normalize to UTC when correlating across systems.
- Export as `.evtx` to preserve the original, not as text.
