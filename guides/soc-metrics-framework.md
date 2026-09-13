# SOC Metrics Framework

A model for tracking threat hunts, alert triage, and investigations week over week. This document defines the
metrics and the recording format. It contains no data.

---

## Why track this

Three reasons, in order of usefulness:

1. **Tuning.** False-positive rate per rule is the only objective argument for changing a detection.
2. **Coverage.** Hunts recorded against ATT&CK techniques show where you are blind.
3. **Trend.** A single week's numbers mean nothing. Twelve weeks show whether anything improved.

Metrics that do not change a decision are not worth collecting.

---

## Record format

One row per investigation or hunt.

| Field | Definition |
|---|---|
| **Case ID** | Unique identifier. `INC-YYYY-MM-DD-NNN` for alerts, `HUNT-YYYY-MM-DD-NNN` for hunts |
| **Event Time** | When the activity occurred on the host or in the logs |
| **Detection Time** | When the alert fired, or when the analyst first identified the activity during a hunt |
| **Closed Time** | When investigation and response completed |
| **Name** | Alert rule name, or the hunt title |
| **Source** | EDR alert, SIEM analytic, or manual hunt |
| **Technique** | MITRE ATT&CK ID where applicable |
| **Verdict** | True positive, false positive, benign true positive, or inconclusive |
| **TTD** | Detection Time minus Event Time |
| **TTR** | Closed Time minus Detection Time |
| **Disposition** | What was done: contained, escalated, closed, tuned |
| **Evidence** | Link to the screenshot or query output |

**TTD and TTR are per-incident values. MTTD and MTTR are the weekly averages of those values.** A single row
cannot have a mean. Getting this wrong in front of a SOC manager is an avoidable own goal.

---

## Verdicts

Four values, not two. The middle two are where the useful information lives.

| Verdict | Means |
|---|---|
| **True positive** | Confirmed malicious activity |
| **Benign true positive** | The rule fired correctly on the described behavior, but the behavior was authorized. Admin tooling, pen test, sanctioned script |
| **False positive** | The rule fired on something that does not match its intent |
| **Inconclusive** | Insufficient evidence to decide. Record it; do not quietly close it as benign |

Collapsing benign-true-positive into false-positive is the most common way tuning goes wrong. A rule firing
correctly on authorized activity needs an exclusion, not a rewrite. A rule firing on unrelated activity needs
a rewrite.

---

## Weekly rollup

The rollup is the point. Without it you have an incident log, not metrics.

| Metric | Calculation | Watch for |
|---|---|---|
| Investigations | Count of all rows | Volume alone says nothing |
| Hunts completed | Count of manual hunts | Proactive vs reactive balance |
| MTTD | Mean TTD, **alert-driven rows only** | Hunts have no detection delay and skew the average |
| MTTR | Mean TTR, all rows | Rising MTTR with flat volume means something got harder |
| True positive rate | TP / (TP + FP) | Very high can mean rules are too narrow |
| False positive rate | FP / total alerts | Above roughly 5% per rule, tune it |
| Escalation rate | Escalated / total | A proxy for severity mix |
| Techniques covered | Distinct ATT&CK IDs seen | Coverage, not volume |

Excluding hunts from MTTD and saying so is a small thing that demonstrates you understand the metric rather
than just computing it.

---

## Per-rule tracking

The highest-value table in the whole framework.

| Rule | Fired | TP | FP | FP Rate | Action |
|---|---|---|---|---|---|
| Encoded PowerShell Execution | 14 | 12 | 2 | 14% | Exclude two known admin scripts by hash |
| Impossible Travel | 31 | 1 | 30 | 97% | Add corporate VPN egress ranges to the allowed set |

A rule at 97% false positives is not a detection, it is noise that trains analysts to ignore alerts. Being
able to say that with a number behind it is the argument that gets it changed.

---

## Hunt records

Hunts need different fields. Verdict-only tracking loses the value.

| Field | Definition |
|---|---|
| **Hypothesis** | What behavior you expected to find, and why |
| **Data source** | Table or log queried |
| **Query** | The query itself, or a link to it |
| **Scope** | Hosts, users, and time range examined |
| **Result** | What was found, including nothing |
| **Verdict** | Confirmed, not confirmed, or inconclusive |
| **Follow-up** | Detection written, tuning applied, or none |

**A hunt returning nothing is a valid result.** It bounds the problem: you now know that behavior was not
present in that scope during that window. Record it with the same rigor as a hit.

---

## Monthly review

Four questions, answered from the data:

1. Which rules produced the most noise, and what was done about them?
2. Which ATT&CK techniques were hunted, and which have never been?
3. Did MTTR move, and does anything in the record explain why?
4. Which hunts produced a detection rule?

That last question is the one that matters. A hunting program that never produces detections is doing manual
work that should have been automated.

---

## Notes

- Record the hunt that found nothing. Selectively logging successes makes the data useless for tuning.
- Normalize to UTC. Correlating across hosts in local time produces wrong durations.
- Small sample sizes are noisy. Three hunts in a month is a starting point, not a trend.
