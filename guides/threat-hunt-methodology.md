# Threat Hunt Methodology

How a hunt is structured, from hypothesis to verdict. Applies regardless of platform or tooling.

---

## What a hunt is

Searching for activity that existing detections would not have alerted on. If a rule would have caught it,
that is detection, not hunting.

Two consequences:

- A hunt that finds nothing is still a result. It bounds the problem.
- A hunt that finds something should usually end in a detection rule, so the next occurrence is automatic.

---

## The structure

```text
1. HYPOTHESIS       what behavior, and why would it be here
2. DATA SOURCE      which log or table would contain it
3. SCOPE            which hosts, users, and time range
4. BASELINE         what does normal look like in this data
5. QUERY            broad first, then narrow
6. TRIAGE           rule outliers in or out with corroborating evidence
7. VERDICT          confirmed, not confirmed, or inconclusive
8. FOLLOW-UP        detection, tuning, or nothing
```

Steps 1 and 4 are the ones people skip, and they are the ones that separate hunting from querying.

---

## 1. Hypothesis

A hypothesis is falsifiable and specific.

```text
Weak     "Look for suspicious PowerShell"
Better   "If an attacker had credential access, I would expect encoded PowerShell
          spawned by a non-interactive parent process on servers, outside change windows"
```

The second version tells you the data source, the filters, and what would disprove it.

Sources of hypotheses:

| Source | Example |
|---|---|
| Threat intelligence | A reported campaign uses scheduled tasks for persistence |
| ATT&CK gap analysis | No detection exists for T1558.003 |
| Environment knowledge | Service accounts should never log on interactively |
| Prior incident | A technique seen once may have been used elsewhere |
| Anomaly | A host began beaconing on a regular interval |

---

## 2. Data source

Ask what would have to be true for the behavior to leave a trace, then check that the trace is actually being
collected.

**If the telemetry is not collected, that is itself the finding.** An unhuntable technique is a coverage gap,
and documenting it is more valuable than a query that was never going to return anything.

---

## 3. Scope

State it explicitly and record it:

- Which hosts or identities
- Which time range
- What is deliberately excluded and why

Scope is what makes a negative result meaningful. "No evidence found" means nothing. "No evidence across 40
domain-joined workstations over 30 days" is a bounded statement.

---

## 4. Baseline

Establish normal before declaring anomaly. This is the step that prevents a hunt from producing 400 false leads.

```text
Which accounts normally authenticate to this host?
Which parent processes normally spawn this binary?
What does this host's outbound traffic normally look like?
When do these scheduled tasks normally run?
```

Practically: run the query over a known-clean historical window first, and treat that output as the
comparison set.

---

## 5. Query

Broad, then narrow. Starting with a tight filter hides the thing you did not know to look for.

```text
1. All process creations for the binary            → how common is it at all
2. Group by parent process                         → what normally spawns it
3. Filter to unusual parents                       → the actual candidates
4. Add command line and user context               → enough to triage
```

Record the query as written. A hunt without its query cannot be repeated or reviewed.

---

## 6. Triage

For each candidate, ask:

- Is there a legitimate explanation, and can I evidence it?
- What happened immediately before and after on that host?
- Does the same pattern appear on other hosts?
- Does the account have a reason to be doing this?

Rule things out with evidence, not assumption. "Probably admin activity" is not a verdict; a change ticket or
a matching scheduled job is.

---

## 7. Verdict

| Verdict | Means |
|---|---|
| **Confirmed** | The hypothesized behavior was present |
| **Not confirmed** | Not present within the stated scope |
| **Inconclusive** | The data could not answer the question. Say why |

Inconclusive is a legitimate outcome and usually points at a telemetry gap worth documenting.

---

## 8. Follow-up

| Outcome | Action |
|---|---|
| Confirmed malicious | Escalate to incident response, then write the detection |
| Confirmed but authorized | Document the legitimate pattern so the next hunt does not re-triage it |
| Not confirmed | Record scope and query so the hunt can be repeated later |
| Telemetry gap | Raise it as a logging change |
| Repeatable signal | Convert to a scheduled detection and measure its false-positive rate |

**The measure of a hunting program is how many detections it produced.** Hunting the same thing manually every
month is work that should have been automated after the first time.

---

## Documenting a hunt

```markdown
## Hypothesis
If an attacker established persistence, I would expect scheduled tasks created by
non-administrative accounts outside of change windows.

## Data Source
Sysmon Event ID 1 and Windows Event ID 4698, 30 days.

## Scope
42 domain-joined workstations. Servers excluded; covered separately in HUNT-004.

## Baseline
Scheduled task creation on workstations averages 3 per week, all from SCCM
under the local SYSTEM account.

## Query
[query]

## Findings
7 tasks created by 2 user accounts. 6 traced to a documented software deployment.
1 remained unexplained and is detailed below.

## Verdict
Inconclusive. One task could not be attributed. Escalated for endpoint review.

## Follow-up
Detection rule authored for scheduled task creation by non-SYSTEM accounts on
workstations. False-positive rate measured at 2.1% over the baseline window.
```

That structure is what makes a hunt reviewable by someone who was not there.

---

## Common mistakes

| Mistake | Consequence |
|---|---|
| No hypothesis | You are querying, not hunting, and you cannot tell when you are done |
| Skipping the baseline | Every result looks anomalous |
| Filtering too early | You only find what you already assumed |
| Not recording negatives | The same ground gets covered repeatedly |
| Never producing detections | Manual repetition of work that should be automated |
| Unstated scope | A negative result that means nothing |
