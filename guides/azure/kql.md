# KQL: Kusto Query Language

Interface for Log Analytics, Microsoft Sentinel, Defender XDR, and Azure Resource Graph.

## Structure

Queries read top to bottom. Filter early, project late.

```kql
TableName
| where TimeGenerated > ago(24h)
| where Field == "value"
| project TimeGenerated, Field1, Field2
| sort by TimeGenerated desc
| take 100
```

## Core operators

| Operator | Does |
|---|---|
| `where` | Filter rows |
| `project` / `project-away` | Choose or drop columns |
| `extend` | Add a calculated column |
| `summarize` | Aggregate |
| `join` | Combine tables |
| `union` | Stack tables |
| `parse` | Extract from unstructured text |
| `mv-expand` | Expand a dynamic array into rows |
| `let` | Name a value or subquery |

## Filtering

```kql
| where TimeGenerated between (ago(7d) .. now())
| where Computer has "SRV"              // fast, token-based
| where Computer contains "srv"         // slower, substring
| where Computer startswith "DC"
| where Account in ("svc_backup", "svc_sql")
| where ProcessCommandLine matches regex @"-enc\s+[A-Za-z0-9+/=]{50,}"
| where isnotempty(TargetUserName)
```

`has` beats `contains` on large tables, it matches whole tokens against the index.

## Aggregation

```kql
| summarize Count = count() by Account, Computer
| summarize arg_max(TimeGenerated, *) by Account     // latest row per account
| summarize dcount(Computer) by Account              // distinct hosts per account
| summarize Count = count() by bin(TimeGenerated, 1h)
| summarize make_set(Computer) by Account
```

## Baselining

Establish normal before declaring anomaly.

```kql
let baseline =
    SecurityEvent
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where EventID == 4624
    | summarize NormalHosts = make_set(Computer) by Account;
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
| join kind=inner baseline on Account
| where Computer !in (NormalHosts)
| project TimeGenerated, Account, Computer
```

## Joins

```kql
// process creation correlated with the logon that preceded it
SecurityEvent
| where EventID == 4688
| project TimeGenerated, Computer, Account, NewProcessName, ProcessCommandLine
| join kind=leftouter (
    SecurityEvent
    | where EventID == 4624
    | project LogonTime = TimeGenerated, Computer, Account, LogonType, IpAddress
) on Computer, Account
| where TimeGenerated - LogonTime between (0s .. 5m)
```

`kind=` matters: `inner`, `leftouter`, `leftanti` (rows with no match, useful for "what is missing").

## Common tables

| Table | Holds |
|---|---|
| `SecurityEvent` | Windows Security log via agent |
| `SigninLogs` | Entra ID interactive sign-ins |
| `AADNonInteractiveUserSignInLogs` | Token refresh, service sign-ins |
| `AuditLogs` | Entra ID directory changes, consent grants |
| `AzureActivity` | Azure control-plane operations |
| `DeviceProcessEvents` | Defender for Endpoint process creation |
| `DeviceNetworkEvents` | Defender for Endpoint network connections |
| `Event` | Sysmon and other Windows event logs |
| `Syslog` | Linux |

## Useful event IDs

```text
4624  successful logon            4672  special privileges assigned
4625  failed logon                4720  user account created
4688  process creation            4728  member added to global group
4634  logoff                      4768  Kerberos TGT requested
4769  Kerberos service ticket     1102  audit log cleared
```

Sysmon: `1` process create · `3` network connect · `7` image load · `8` remote thread · `10` process access · `11` file create · `13` registry set

## Hunting patterns

```kql
// encoded PowerShell
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand", "FromBase64String")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// LSASS access
DeviceEvents
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine

// impossible travel candidates
SigninLogs
| where ResultType == 0
| summarize Countries = make_set(LocationDetails.countryOrRegion),
            Count = dcount(tostring(LocationDetails.countryOrRegion))
  by UserPrincipalName, bin(TimeGenerated, 1h)
| where Count > 1

// audit log cleared
SecurityEvent
| where EventID == 1102
| project TimeGenerated, Computer, Account
```

## Notes

- Always bound `TimeGenerated` first. It is the partition key, and an unbounded query scans everything.
- `=~` is case-insensitive equality; `==` is case-sensitive.
- `take` is not ordered, use `top N by Field` when order matters.
- Test a hunt query interactively before converting it to a scheduled rule, and measure how often it fires on normal activity before calling it a detection.
