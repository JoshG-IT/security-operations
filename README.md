<!--
  Conventions
  Case IDs  SOC-<AZ|AWS|GCP|ONP>-NNN; numbering restarts per platform
  Folders   cases/<CASE-ID>-slug/ holds README + evidence always; diagrams, docs, queries as needed
  Guides    Guides/<platform>/ holds one file per interface
  Table     completed cases only; Key Finding = the result, not the topic
  Type      how far the arc went: Threat Hunt, Analysis, Detection,
            or Threat Hunt > Detection > Validation
  Access    Read-only | Contributor | Full control
  Scope     detection, hunting, incident response; identity design goes in identity-security
-->

# Security Operations

Security casework covering detection, threat hunting, incident response, and log analysis across cloud and on-premises environments: Microsoft Sentinel, Defender, Sysmon, Windows Event Logs, and KQL-based investigation.

Each case includes sanitized evidence, methodology, the queries used, findings, root-cause analysis, and recommendations.

> **How to read the table.** **Type** shows how far a case went: hunting and analysis, or the full arc through detection authoring and validation. **Access** shows the permission level I held, which determines what the case could cover. Both are stated in full in each case README.

---

## Cases

| Case | Name | Type | Environment | Access | Key Finding |
|---|---|---|---|---|---|
| **SOC-ONP-001** | [Support Session Misdirection](cases/SOC-ONP-001-support-session-misdirection/) | Threat Hunt | On-premises | *(confirm)* | *(replace: what the hunt confirmed or ruled out)* |

---

## Operational Work

| Project | Type | Focus | Outcome |
|---|---|---|---|
| [SOC Metrics and KPI Reporting](cases/soc-kpi-reporting/) | Implementation | SOC operations, reporting | *(replace: what the metrics surfaced or enabled)* |

---

## Skills Demonstrated

`KQL` · `Microsoft Sentinel` · `Defender for Endpoint` · `Sysmon` · `Windows Event Logs` · `PowerShell` · `MITRE ATT&CK` · `Threat Hunting` · `Incident Response`

---

## Approach

**Hunting**

1. State the hypothesis: what behavior would I expect to see, and where?
2. Identify the data source that would contain it.
3. Build the query, starting broad before filtering.
4. Establish what normal looks like before deciding what is anomalous.
5. Investigate outliers and rule them in or out with corroborating evidence.
6. Record the verdict, including hunts that come back clean.

**Detection**

7. Convert a confirmed hunt into a scheduled rule.
8. Test that it fires on the technique.
9. Measure the false-positive rate against normal activity.
10. Document tuning and what would need revisiting.

A hunt that returns nothing is still a documented result. The method is the product.

---

## Investigation Interfaces

### Microsoft Azure

| Interface | Best For | Guide |
|---|---|---|
| KQL | Log Analytics, Sentinel, Defender XDR, hunting, detection rules | [KQL](Guides/azure/kql.md) |
| Sysmon | Endpoint telemetry forwarded into Sentinel and queried with KQL | [Sysmon](Guides/on-prem/sysmon.md) |

```text
What am I investigating?
        |
        +-- Cloud logs, telemetry, or a detection rule
        |       --> KQL
        |
        +-- Process lineage, network connections, or process access
                --> Sysmon
```

### On-Premises

| Interface | Best For | Guide |
|---|---|---|
| Windows Event Logs | Authentication, process creation, service installation, log tampering | [Windows Event Logs](Guides/on-prem/windows-event-logs.md) |
| Sysmon | Process, network, image load, and process access telemetry | [Sysmon](Guides/on-prem/sysmon.md) |
| PowerShell Log Analysis | Multi-host collection, parsing, timelines, correlation | [PowerShell Log Analysis](Guides/on-prem/powershell-log-analysis.md) |

```text
What am I investigating?
        |
        +-- Authentication, account changes, or service installation
        |       --> Windows Event Logs
        |
        +-- Process lineage, network connections, or process access
        |       --> Sysmon
        |
        +-- Collecting or correlating across multiple hosts
                --> PowerShell Log Analysis
```

<!-- new platform sections mirror the blocks above -->

Guides for AWS and Google Cloud are added alongside the first case in those environments.

---

## Data Handling

These cases document method and reasoning. Hostnames, usernames, internal IP ranges, tenant and subscription IDs, and environment-specific identifiers are redacted from public evidence.
