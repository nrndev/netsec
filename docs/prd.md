# NetSec: product requirements

Background: [analysis.md](analysis.md). How we build it: [design.md](design.md).

## Problem

SREs on a shared Kubernetes cluster need two on-demand, reversible actions:

1. **Cut traffic between two workloads fast**, for example to contain a suspected compromise between tenants. Nothing else may break, and turning it off must restore exactly what was there before.
2. **Fix workloads** that are missing resource requests and limits or a hardened `securityContext` (the pod's Linux security settings). The SRE wants to see the changes first, and the fix must not break the workload.

Today both mean hand-written NetworkPolicies and `kubectl patch` under pressure. Both are easy to get wrong. A "deny" policy can quietly open access, and a patch can crash-loop a service.

## Users

- **Primary: an SRE or platform engineer** with cluster-admin rights.
- **Secondary: the take-home reviewer**, who reads the README, runs the demo and reads the tests.
- **Not a user: tenant developers.** They never create these objects.

## Goals

| ID | Goal |
|---|---|
| G1 | Isolate two workloads (each group = namespace(s) + label selector) in both directions, on demand. |
| G2 | Turn isolation off and get back exactly the previous connectivity. |
| G3 | Preview hardening changes, then apply only what was reviewed. |
| G4 | Never leave a workload broken: detect a bad rollout and revert automatically. |
| G5 | Undo hardening exactly. |
| G6 | Show clearly what the tool did, would do, or refused to do, and why. |
| G7 | Ship as one deployable service (a Kubernetes operator) that installs with kustomize or Helm on k3d. |

## Non-goals

- Continuous enforcement or admission control. Pod Security Admission and Kyverno already do that.
- Blocking indirect paths (A → C → B) or killing connections that were already open.
- Changing images, commands, or any field not listed in the design.
- Sizing resources from usage history. VPA (the Vertical Pod Autoscaler) does that.
- AdminNetworkPolicy or CNI-specific policy types in v1.
- A web UI, a separate CLI, or multi-cluster support.

## User stories and acceptance criteria

### Isolation

**US1: Isolate.** I create a `NetworkIsolation` naming two groups of pods. Traffic between them stops in both directions.
- From an A pod, connecting to a B pod fails, by pod IP and through B's Service. The same holds from B to A.
- The two groups can still reach other pods, DNS and the outside world. Other pods can still reach them, unless they couldn't before.
- Pods created later that match a group are isolated with no extra action.
- Within 10 seconds of creation, status shows `Ready=True` and how each direction is enforced.

**US2: Release.** I delete the `NetworkIsolation`, and connectivity returns to exactly what it was.
- Every object the tool created is gone. No object it didn't create was changed.
- The delete only finishes after cleanup.

**US3: Refuse instead of doing harm.** If the tool can't isolate safely, it says why and does nothing unsafe.
- Status shows `Ready=False`, a reason and the names of the conflicting policies. A Warning event is emitted.
- No policy that widens anyone's access is left in place.
- If a group's pod is outside the configured pod range, status says so (`Ready=False`, `PodRangeMismatch`) and names it.

**US4: Stay correct over time.**
- If someone edits or deletes a policy the tool owns, the tool restores it. A tenant's edit to a NetSec policy is reverted, even one that narrows its selector or adds a rule.
- If someone adds a policy that conflicts, the tool switches mechanism with no gap in blocking. If no switch is possible, it flags `Ready=False`.
- Editing a live isolation never lets blocked traffic through: new policies are applied before old ones are removed, and an edit the tool cannot plan (bad selector, protected namespace) leaves the existing policies in place.

### Hardening

**US5: Preview.** I create a `WorkloadHardening` (namespaces plus an optional workload selector) with `action: Plan`.
- Status lists every workload with each field change (old → new), or the reason it was skipped.
- Nothing in the cluster changes: workload `generation` (Kubernetes' spec version counter) stays the same.
- Every change is validated by the API server (server-side dry-run). Changes that would fail are reported.

**US6: Apply exactly what I reviewed.**
- `action: Apply` requires `approvedPlanHash` to equal the plan's hash.
- If any workload changed since the plan, nothing new is applied and status says `PlanStale`.
- Only unset fields are filled in. Values someone set explicitly are never changed.
- Changes to the spec or to opt-out labels after approval are not applied: each workload is checked again just before it is patched, and skipped if it no longer matches what was approved.

**US7: Don't break anything.**
- Workloads roll out one at a time (configurable).
- If a new pod fails (config error, crash loop, OOM kill, or timeout), our change is reverted and the workload returns to its previous state. This includes StatefulSets.
- Status says `Reverted` with the reason.
- Deleting a run mid-rollout still finishes the health gate and reverts a failing workload.

**US8: Undo.** `action: Undo` removes exactly the fields this run set. Fields that someone else changed since then are left alone.

**US9: Safety boundaries.** The tool never touches:
- `kube-*` namespaces or its own namespace
- namespaces or workloads with the opt-out label
- workloads owned by another controller or managed by GitOps tools

These appear as `Skipped` with the reason.

### Operations

**US10: Observability.** An Event for every action, status conditions, Prometheus metrics and structured logs.

**US11: Install and demo.**
- One command creates the k3d cluster.
- The repo includes demo workloads and a script that proves isolation blocks traffic.
- Install works with kustomize or Helm.

## Hardening defaults

| What | Default | Opt-in |
|---|---|---|
| `seccompProfile` | `RuntimeDefault` (always) | |
| `allowPrivilegeEscalation` | `false` (always, skipped for privileged containers) | |
| `runAsNonRoot` | | `true` |
| `capabilities.drop` | | `[ALL]` |
| `readOnlyRootFilesystem` | | `true` |
| CPU / memory requests | `100m` / `128Mi` | override per request |
| Memory limit | `512Mi` | override per request |
| CPU limit | never set (avoids throttling) | |

Rules:
- Only unset values are filled in.
- Requests are clamped so they never exceed an existing limit.
- A memory limit is never set below the request.
- Resource defaults never replace a namespace LimitRange's defaults.

Workload kinds:
- **Patched:** Deployment, StatefulSet, DaemonSet, CronJob.
- **Report only:** Job, bare Pod.
- **Size cap:** at most 200 workloads per run. A bigger run is refused with "narrow the selector".

## Safety requirements

| ID | Requirement |
|---|---|
| S1 | Never widen network access for any pod. |
| S2 | Isolation only changes or deletes objects it created. Hardening only fills unset fields. |
| S3 | Isolation fails closed: if the operator is down, existing isolation stays in place. |
| S4 | Refuse rather than guess. Every refusal says why. |
| S5 | Protected namespaces are never touched. |
| S6 | Least-privilege RBAC. The operator runs with a restricted security context. Only admins can create its objects. |

## Definition of done

- Every acceptance criterion is covered by an automated test (unit, envtest or k3d end-to-end). [traceability.md](traceability.md) maps each criterion to its test.
- `hack/verify-isolation.sh` prints the traffic matrix before, during and after isolation, and exits non-zero on any mismatch.
- The full gate `make lint test test-e2e` passes.
- The README covers setup, build, deploy and run, the decisions the brief left open, the tricky test and why it was chosen, and known limitations.

## Later (not v1)

- An AdminNetworkPolicy backend, for real deny rules that combine.
- An "already blocked" check, so a direction an existing policy already blocks is accepted instead of refused.
- Merging isolations that share the same group.
- Optional termination of open connections.
- Resource sizing from usage.
