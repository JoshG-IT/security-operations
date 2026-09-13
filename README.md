<!--
  Conventions
  Case IDs  SOC-<AZ|AWS|GCP|ONP>-NNN; numbering restarts per platform
  Folders   cases/<CASE-ID>-slug/ holds README + evidence always; diagrams, docs, queries as needed
  Guides    Guides/<platform>/ holds one file per interface
  Table     completed cases only; Key Finding = the result, not the topic
  Type      how far the arc went: Threat Hunt, Investigation, Detection,
            or Threat Hunt → Detection → Validation
  Scope     detection, hunting, incident response; identity design goes in identity-security
-->

# Security Operations

Security casework covering detection, threat hunting, incident response, and log analysis across cloud and on-premises environments: Microsoft Sentinel, Defender, Sysmon, Windows Event Logs, and KQL-based investigation.

Each case includes sanitized evidence, methodology, the queries used, findings, root-cause analysis, and recommendations.

> **How to read the Type column.** Cases in training environments are read-only, so they cover investigation and recommendation: the scope a SOC analyst actually works in. Cases in my own lab carry the full arc: hunt, write the detection, validate that it fires on the technique and not on normal activity.

---

## Cases

| Case | Investigation | Type | Environment | Key Finding |
|---|---|---|---|---|
| **SOC-ONP-001** | [Support Session Misdirection](cases/SOC-ONP-001-support-session-misdirection/) | Threat Hunt | On-prem · own lab | *(one-line result)* |

---

## Operational Work

| Project | Type | Focus | Outcome |
|---|---|---|---|
| [SOC Metrics and KPI Reporting](cases/soc-kpi-reporting/) | Implementation | SOC operations · reporting | *(one-line outcome)* |

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

### On-Premises

| Interface | Best For | Guide |
|---|---|---|
| Windows Event Logs | Authentication, process creation, service installation, log tampering | [Windows Event Logs](Guides/on-prem/windows-event-logs.md) |
| Sysmon | Process, network, image load, and process access telemetry | [Sysmon](Guides/on-prem/sysmon.md) |
| PowerShell Log Analysis | Multi-host collection, parsing, timelines, correlation | [PowerShell Log Analysis](Guides/on-prem/powershell-log-analysis.md) |

```text
What am I investigating?
        |
        +-- Cloud logs, telemetry, or a detection rule
        |       --> KQL
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
