# PowerShell: Log Collection and Analysis

Used for collecting, parsing, and correlating logs across hosts when no SIEM is available.

## Collection across hosts

```powershell
$hosts = Get-Content .\hosts.txt
$cred  = Get-Credential

$events = Invoke-Command -ComputerName $hosts -Credential $cred -ScriptBlock {
    Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        ID        = 4624, 4625, 4672
        StartTime = (Get-Date).AddDays(-7)
    } -ErrorAction SilentlyContinue
}

$events | Export-Csv .\collected.csv -NoTypeInformation
```

## Parsing event XML into objects

```powershell
function ConvertFrom-WinEvent {
    param([Parameter(ValueFromPipeline)]$Event)
    process {
        $x = [xml]$Event.ToXml()
        $o = [ordered]@{
            Time     = $Event.TimeCreated
            Computer = $Event.MachineName
            EventID  = $Event.Id
        }
        foreach ($d in $x.Event.EventData.Data) { $o[$d.Name] = $d.'#text' }
        [PSCustomObject]$o
    }
}

Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 500 |
  ConvertFrom-WinEvent |
  Select-Object Time, Computer, TargetUserName, LogonType, IpAddress
```

## Analysis patterns

```powershell
# frequency by account
$events | ConvertFrom-WinEvent | Group-Object TargetUserName |
  Sort-Object Count -Descending | Select-Object Name, Count

# an account seen on more hosts than usual
$events | ConvertFrom-WinEvent |
  Group-Object TargetUserName |
  ForEach-Object {
      [PSCustomObject]@{
          Account = $_.Name
          Hosts   = ($_.Group.Computer | Sort-Object -Unique).Count
      }
  } | Sort-Object Hosts -Descending

# activity outside business hours
$events | ConvertFrom-WinEvent |
  Where-Object { $_.Time.Hour -lt 6 -or $_.Time.Hour -gt 19 }

# failed-then-successful pattern per account
$parsed = $events | ConvertFrom-WinEvent
$parsed | Group-Object TargetUserName | ForEach-Object {
    $fail = ($_.Group | Where-Object EventID -eq 4625).Count
    $ok   = ($_.Group | Where-Object EventID -eq 4624).Count
    if ($fail -gt 10 -and $ok -gt 0) {
        [PSCustomObject]@{ Account = $_.Name; Failed = $fail; Succeeded = $ok }
    }
}
```

## Timeline building

```powershell
$parsed |
  Sort-Object Time |
  Select-Object Time, Computer, EventID, TargetUserName, IpAddress |
  Export-Csv .\timeline.csv -NoTypeInformation
```

Normalize to UTC before correlating across hosts:

```powershell
$parsed | Select-Object @{n='TimeUtc';e={$_.Time.ToUniversalTime()}}, *
```

## PowerShell's own logs

```powershell
# script block logging: decoded script content
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
  Where-Object { $_.Message -match "Invoke-|DownloadString|FromBase64String|IEX" }

# module logging
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103}
```

Event 4104 logs the script *after* deobfuscation, which is why script block logging is the single most valuable
setting to enable on a Windows estate.

## Decoding encoded commands

```powershell
$encoded = "<BASE64_STRING>"
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
```

`-EncodedCommand` uses UTF-16LE, not UTF-8. Decoding with the wrong encoding produces garbage and wastes time.

## Notes

- `Invoke-Command` needs WinRM. If it is unavailable, fall back to `Get-WinEvent -ComputerName` over RPC.
- Export raw `.evtx` for anything that might need to stand as evidence; CSV is for analysis, not preservation.
- Record the collection time and the time range queried in the case README. Gaps in coverage are findings.
