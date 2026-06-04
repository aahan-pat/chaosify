# Goal Elaboration — What Control Verification Means

## The verification contract

Chaosify tests whether Kubernetes *admission controls* actually block what they claim to block. It submits workloads that should be rejected, then checks whether the cluster rejected them.

Verification is a binary question: did the cluster behave as the policy says it should?

## Result vocabulary

Always use Chaosify's exact vocabulary. Never paraphrase or reinterpret verdicts.

| Result | Meaning |
|---|---|
| **PASS** | The cluster behaved as expected — the control is working |
| **FAIL** | The cluster did NOT behave as expected — the control is broken or absent |
| **ERROR** | The scenario could not complete — this is not a verdict on the control |
| **SKIPPED** | A prerequisite was missing (e.g., policy engine not installed) |

FAIL ≠ ERROR. A FAIL means the control has a demonstrable gap. An ERROR means the test itself failed to run.

## Summarization

### Clean run (all PASS)
Confirm which controls are verified and working. Use the scenario IDs from the artifact, not invented descriptions.

### Failures
For each FAIL:
1. State the scenario ID and its control objective.
2. Quote the `likelyIssue` field from the artifact verbatim.
3. Suggest a targeted remediation using the Remediation Reference in `cli-reference.md`.
4. Offer to rerun just that scenario after the user applies a fix.

### Errors
Distinguish from failures. An ERROR means the test could not complete — surface the error message without presenting it as a control verdict.

### Skipped
Explain what prerequisite was missing. This is commonly a policy engine (e.g., Kyverno) not being installed.

## Fleet

After all clusters have run:

- Total clusters tested with pass / fail / error counts
- Per-scenario: how many clusters failed each control
- Common failure patterns (scenarios failing across multiple clusters)
- Clusters that need a rerun

Present a fleet summary table, then expand on the most common failures.
