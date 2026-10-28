# NetSec: design

What and why: [prd.md](prd.md). Risks: [analysis.md](analysis.md).

## 1. Overview

NetSec is one Go binary: a kubebuilder / controller-runtime "manager" running two controllers. A controller is a loop that watches objects and makes the cluster match what they ask for.

```
SRE ──kubectl──▶ NetworkIsolation  ──▶ isolation controller ──▶ NetworkPolicies (owned by NetSec)
SRE ──kubectl──▶ WorkloadHardening ──▶ hardening controller ──▶ Deployments / StatefulSets / DaemonSets / CronJobs
                                                                 (server-side apply, own field manager)
              both controllers ──▶ status, Events, /metrics, logs
```

All state lives in the custom resources' `status`. There is no database. A restart resumes from status.

### Why kubebuilder

- **What we get:**
  - On/off as create/delete
  - Status and finalizers
  - CRD and RBAC generated from Go markers
  - envtest, a real API server for tests
  - Metrics, leader election and health probes out of the box
  - A Helm plugin
- **What it costs:** a large scaffold. We keep it lean: no webhooks and no extra plugins. CRD validation uses CEL rules (checks the API server runs itself), so we don't need cert-manager.

## 2. API

Group `netsec.nrnx.dev`, version `v1alpha1`. Both kinds are **cluster-scoped**, because they span namespaces and only admins should create them.

### 2.1 NetworkIsolation (short name `iso`)

```yaml
apiVersion: netsec.nrnx.dev/v1alpha1
kind: NetworkIsolation
metadata:
  name: contain-gateway-dashboard
spec:
  reason: "INC-1234: suspected compromise"   # optional, for the audit trail
  between:                                   # exactly two groups; traffic is blocked both ways
  - name: gateway
    namespaces: [tenant-a]
    podSelector:
      matchLabels: {app: gateway}
  - name: dashboard
    namespaces: [tenant-b]
    podSelector:
      matchLabels: {app: dashboard}
```

- **On = create, off = delete.** A finalizer makes sure cleanup finishes before the object goes away.
- **Validation (CEL):**
  - `spec` can be edited while isolation is on (see §3.2 and §3.3 for how an edit stays safe).
  - `namespaces`: 1–10 unique DNS labels, none starting with `kube-`.
  - `podSelector` is a standard label selector; empty means every pod in those namespaces. CEL checks that each `matchExpressions` operator is `In`, `NotIn`, `Exists` or `DoesNotExist`, that `In`/`NotIn` have values and that `Exists`/`DoesNotExist` have none. Label key and value syntax is too costly for the CEL budget, so the controller checks it (`InvalidSelector`). `WorkloadHardening.spec.workloadSelector` has the same CEL rules.
  - `between` holds exactly 2 groups (a map list keyed by `name`). Each `name` is a DNS label of at most 63 characters, and the two names differ.
  - The two groups must differ (same namespaces and selector is refused).
  - `reason` is at most 256 characters.
- **Runtime checks:** the operator refuses namespaces on its `--protected-namespaces` list (default: `kube-*` and its own namespace).

```yaml
status:
  observedGeneration: 1
  summary: "gateway ⇄ dashboard: blocked both ways"
  conditions:
  - {type: Ready, status: "True", reason: Enforced}
  - {type: Degraded, status: "True", reason: HostNetworkPods, message: "tenant-b/dash-0 uses hostNetwork; not enforceable"}
  traffic:                           # always both directions
  - {from: gateway, to: dashboard, blocked: true, blockedBy: IngressPolicy, policies: [tenant-b/netsec-3f2a9c1e-dashboard-ingress]}
  - {from: dashboard, to: gateway, blocked: false, message: "tenant-a/allow-dashboard already allows this traffic and NetworkPolicy cannot deny it"}
  pods:
  - {group: gateway, count: 3}
  - {group: dashboard, count: 2}
```

- `blockedBy` is `IngressPolicy` (a policy on the receiving group's pods) or `EgressPolicy` (a policy on the sending group's pods). It is set only when `blocked` is true.
- A refused direction stays in `traffic` with `blocked: false` and a plain `message`.
- `summary` is built by a pure function (`isolation.Summary`): `gateway ⇄ dashboard: blocked both ways`, `gateway → dashboard blocked; dashboard → gateway NOT blocked (conflicting policy)`, or `not enforced: pod ranges unknown`. A group that matches no pods is named: `gateway ⇄ dashboard: blocked both ways (dashboard matches no pods)`. `Ready` stays `True`, because the policies cover future pods.

Printer columns: `READY`, `ISOLATED` (the summary), `AGE`.

### 2.2 WorkloadHardening (short name `wh`)

```yaml
apiVersion: netsec.nrnx.dev/v1alpha1
kind: WorkloadHardening
metadata:
  name: harden-tenants
spec:
  namespaces: [tenant-a, tenant-b]
  workloadSelector: {}              # workload's own labels (not the pod template's); empty = all
  workloadKinds: [Deployment, StatefulSet, DaemonSet, CronJob]   # default: all four
  strictSecurity:                   # extra settings that can stop some images; the safe ones are always applied
    runAsNonRoot: false             # opt-in
    dropAllCapabilities: false      # opt-in
    readOnlyRootFilesystem: false   # opt-in
  defaultResources:                 # set only on containers that have none; never lowered
    enabled: true
    requests: {cpu: 100m, memory: 128Mi}
    limits: {memory: 512Mi}
  action: Plan                      # Plan | Apply | Undo
  approvedPlanHash: ""              # copy status.plan.hash here, with action: Apply, to approve exactly that plan
  maxConcurrentRollouts: 1          # workloads rolling out at once (1–10)
  rolloutTimeout: 5m                # 1m–30m, per workload
```

**Validation (CEL):**
- `namespaces`: 1–20 names, none starting with `kube-`.
- `approvedPlanHash` is required when `action=Apply`.
- `requests.cpu` ≤ 2 and `requests.memory` ≤ 4Gi.
- `limits.memory` must be ≥ `requests.memory` and ≤ 8Gi.

```yaml
status:
  summary: "3 to change, 2 skipped, 1 already hardened, 1 would fail"
  phase: Planned        # Planning | Planned | Applying | Completed | Failed | Undoing | Undone
  plan:
    hash: 9c41e0d2a7b3f615
    workloads:
    - kind: Deployment
      namespace: tenant-a
      name: gateway
      generation: 4
      state: Pending    # Pending | Applying | Healthy | Unverified | Reverted | Failed | Skipped | NoChange | Undone
      changes:
      - "template.spec.securityContext.seccompProfile.type: <unset> → RuntimeDefault"
      - "containers[gateway].securityContext.allowPrivilegeEscalation: <unset> → false"
      - "containers[gateway].resources.requests.memory: <unset> → 128Mi"
      warnings:         # risks seen in this workload that NetSec will not fix
      - "containers[gateway].securityContext.capabilities.drop not set: container is privileged"
    - {kind: Deployment, namespace: tenant-b, name: argo-app, state: Skipped, reason: "managed by Argo CD"}
  conditions: [...]
```

**One apply per object.** A run applies once. After it has patched anything, `action: Plan` or `Apply` is refused (`Refused`, reason `AlreadyApplied`) and the plan is kept, so `Undo` still works. To harden again, create a new `WorkloadHardening`. Planning again under the same field manager would drop the fields recorded for Undo.

**How an SRE uses it:**
1. Create the object. It starts in `Plan` mode.
2. Read the plan: `kubectl get wh harden-tenants -o yaml`.
3. Approve it:
   ```bash
   kubectl patch wh harden-tenants --type merge -p '{"spec":{"action":"Apply","approvedPlanHash":"<hash>"}}'
   ```

Deleting the object does **not** undo anything. Security changes stay; undo is always explicit.

`status.summary` counts workloads by state in plain words and leaves out zero counts (`hardening.Summary`): planned `3 to change, 2 skipped, 1 already hardened, 1 would fail`; applying `1 rolling out, 2 healthy, 1 waiting`; done `3 healthy, 1 reverted`; undo `2 undone, 1 undoing`. Printer columns: `ACTION`, `PHASE`, `SUMMARY`, `PLAN` (the hash), `AGE`.

## 3. Isolation

### 3.1 Building blocks (pure functions, no cluster needed)

- **`complement(group)`** returns policy peers that match every pod *except* the group's pods:
  1. All pods in namespaces outside the group: `kubernetes.io/metadata.name NotIn [group namespaces]`.
  2. For each requirement in the group's selector, pods in the group's namespaces that fail that requirement. This is De Morgan: `app In [x]` becomes `app NotIn [x]`, and `Exists` becomes `DoesNotExist`, and the reverse of each.
  3. If the group's selector is empty, step 2 adds nothing.
- **`allExcept(group, podRange, extra)`** is `complement(group)` plus one `ipBlock` per IP family: `0.0.0.0/0` except the **cluster-wide** pod range (`--pod-cidrs`; if unset, the ranges Nodes report, and the isolation is `Degraded` with reason `PodRangeFromNodes`). A pod IP outside the ranges we last saw, such as a pod on a node added while the operator was down, or from a Calico/Cilium IP pool, would otherwise match `0.0.0.0/0`. This keeps nodes, kubelet probes and outside clients working. We add an IP family only when we know its pod ranges; otherwise a pod IP from the excluded group could match the block.

  It then appends each address of `--extra-allowed-cidrs` as its own `ipBlock` peer, sorted and without duplicates. These are node or tunnel addresses that sit *inside* the pod range, such as flannel's `flannel.1` (the network address of a node's pod range, for example `10.42.1.0/32`) or Calico's tunnel addresses. Outside traffic that enters a NodePort on one node and is forwarded to a pod on another arrives from such an address (confirmed in Phase 5). Nothing is guessed: the operator allows only what the flag lists. **`CheckExtraAllowed`** rejects an entry that is not a CIDR, or that overlaps a pod range without being a single address (`/32` or `/128`), because a wider block would let pods back in. Pods never get a tunnel address, so a single host lets no pod in.
- **`mayOverlap(sel1, sel2)`** returns false only when some label key has contradictory requirements (`app=x` vs `app=y`, `Exists` vs `DoesNotExist`, `In [x]` vs `NotIn [x]`). Otherwise it returns true, to be safe.

Example: the ingress policy on the dashboard group for the request above.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: netsec-3f2a9c1e-dashboard-ingress   # netsec-<first 8 of CR uid>-<group name>-<ingress|egress>
  namespace: tenant-b
  labels:
    app.kubernetes.io/managed-by: netsec
    netsec.nrnx.dev/isolation-uid: 3f2a9c1e-...   # names can be > 63 chars, UIDs can't
  annotations:
    netsec.nrnx.dev/isolation: contain-gateway-dashboard
  ownerReferences: [{kind: NetworkIsolation, name: contain-gateway-dashboard, controller: true}]
spec:
  podSelector: {matchLabels: {app: dashboard}}
  policyTypes: [Ingress]
  ingress:
  - from:
    - namespaceSelector:                 # every pod outside the gateway group's namespaces
        matchExpressions: [{key: kubernetes.io/metadata.name, operator: NotIn, values: [tenant-a]}]
    - namespaceSelector:                 # pods in tenant-a that are not app=gateway
        matchExpressions: [{key: kubernetes.io/metadata.name, operator: In, values: [tenant-a]}]
      podSelector:
        matchExpressions: [{key: app, operator: NotIn, values: [gateway]}]
    - ipBlock: {cidr: 0.0.0.0/0, except: [10.42.0.0/24, 10.42.1.0/24]}   # nodes and outside traffic
```

### 3.2 Planner: how each direction is blocked

For each direction X → Y (gateway → dashboard and dashboard → gateway, planned separately; X and Y are the two groups):

| Step | Check | Result |
|---|---|---|
| 1 | No other ingress policy in any Y namespace may overlap Y's selector. | **IngressPolicy**: in each Y namespace, select Y and allow from `allExcept(X)`. |
| 2 | Otherwise, no other egress policy in any X namespace may overlap X's selector. | **EgressPolicy**: in each X namespace, select X and allow to `allExcept(Y)`. |
| 3 | Otherwise | **Refused**. The direction shows `blocked: false` in `status.traffic`, with a message naming the conflicting policies. |

- "Other policy" means any NetworkPolicy not owned by *this* isolation. That includes user policies and other isolations' policies.
- **"Ours" is strict.** A policy is ours only if it carries this isolation's `isolation-uid` label *and* its `namespace/name` is either one of the four names this spec generates now (and it sits in a namespace of the group that holds it), or listed in `status.traffic[].policies`. The status entries cover policies from before an edit (for example a renamed group), so they are not mistaken for conflicts and cleanup can still delete them. Only the operator writes status, so a tenant cannot add entries there. Tenants can read our label on our policy in their own namespace and copy it onto their own policy. If the label alone counted, the planner would ignore their "allow the other group" policy, which would combine with ours and let that group in. The same rule decides what cleanup may delete.
- This rule is what guarantees S1 (never widen access). We only add an "allow all except" policy to pods that no other policy selects. So the union is our policy alone, and nothing widens.
- **Sticky.** A direction keeps its mechanism while it stays valid, so we don't flap.
- **Make before break.** When a new conflicting policy appears, we create the new mechanism's policy first, then delete the old one. If no mechanism is left, we delete ours (to keep S1), set `Ready=False` with reason `ConflictingPolicy`, and emit a Warning. Respecting an admin's explicit allow is better than silently overriding it.
- **Duplicates work.** Two isolations with the same groups both succeed: the second one falls through to egress. Deleting either leaves the other holding.

### 3.3 Reconcile loop

1. **Being deleted?** Delete our policies (by `isolation-uid` label), wait until a list returns none, remove the finalizer.
2. Add the finalizer if it's missing.
3. Check the selectors and protected namespaces. A bad selector (`InvalidSelector`) or a protected namespace (`ProtectedNamespace`) means `Refused`.
4. **Gather facts:**
   - the cluster-wide pod range: `--pod-cidrs` if set, else the ranges Nodes report (then `Degraded=True`, reason `PodRangeFromNodes`, because a node added later is not covered); none at all means `Refused/PodCIDRUnknown`
   - the address of every Node (`InternalIP`, `ExternalIP`), for the `NodesInPodRange` check
   - `--extra-allowed-cidrs`, checked against the pod range in use (`CheckExtraAllowed`); an error means `Refused/InvalidExtraAllowedCIDRs`
   - all policies in the group namespaces
   - which group namespaces exist
5. Plan both directions, keeping current mechanisms when they're still valid. Stickiness keys on the group names, so after a rename the mechanism is chosen fresh.
6. Write the desired policies as whole objects (field manager `netsec-isolation`): create if missing; if the spec, our labels, our annotation or the owner reference differ, set them and update. A server-side apply would only re-assert the fields we own, so a tenant who adds a `podSelector` key or an extra rule to our policy would keep it. Whole-object writes revert any such edit.
7. Delete our policies that aren't in the desired set. This runs after step 6, which is what makes it make-before-break. It also runs when step 6 failed: an old "allow all except X" policy must never stay next to a user's new default-deny. A failed apply then sets `Ready=False` (reason `ApplyFailed`, with the error), emits a Warning `ApplyFailed`, writes status (traffic shown as not blocked, summary `not enforced: apply failed`) and returns the error for backoff.
8. Run the **pre-flight checks** on the pod list that fills the counts (no second list):
   - **`PodRangeMismatch`:** any `status.podIPs` of a pod in either group (hostNetwork pods and pods with no IP yet are skipped) outside the pod range in use. Only IP families that have a range are checked: with none for a family there is no `ipBlock` for it, so such a pod IP cannot match one. Policies are still applied and pruned as in steps 5 to 7. If `Ready` would be `True`, it becomes `False` with reason `PodRangeMismatch`; the message names up to 5 pods with their IPs and says to set `--pod-cidrs` to the range those pods use. If `Ready` is already `False`, the mismatch goes into the `Degraded` message instead. The summary gets `(N pods outside the pod range)`. A Warning event is emitted once per distinct message, and the reason counts in `netsec_isolation_refusals_total` when it first appears.
   - **`NodesInPodRange`:** any Node `InternalIP` or `ExternalIP` inside the pod range and not covered by an `--extra-allowed-cidrs` entry (covered IPs are already allowed). `Degraded=True`; `Ready` is unchanged because isolation itself still works. The message says that traffic arriving from node IPs (NodePort, LoadBalancer with `externalTrafficPolicy: Cluster`, some health checks) is blocked. A change to a Node's addresses triggers a reconcile.
   - In `Degraded`, the reason is the first problem found, ordered by harm: `PodRangeMismatch` (isolation may not hold for those pods), `NodesInPodRange` (traffic is blocked), then the others.
9. Write status: conditions, `traffic`, `pods`, `summary` and warnings (hostNetwork pods, pods matching both groups, missing namespaces).
10. Requeue after 2 minutes to refresh pod counts.

**Fail closed.** When the reconciler cannot plan (`InvalidSelector`, `ProtectedNamespace`, `PodCIDRUnknown`, `InvalidExtraAllowedCIDRs`) it keeps the existing policies exactly as they are: no apply and no prune. So an edit with a typo never lifts a working isolation. If something was blocked before, the summary says so and adds `(edit not applied: <reason>)`; `not enforced: <reason>` appears only when nothing was blocked. Only `ConflictingPolicy` removes our policies for its direction, because of the never-widen rule (S1).

**Editing a live isolation.** Step 6 applies every wanted policy before step 7 prunes, so adding a namespace, renaming a group or changing a selector never opens a gap: the old policies stay until the new ones exist.

**Watches:**
- `NetworkIsolation` itself
- our own NetworkPolicies (`Owns`, to restore edits)
- all NetworkPolicies (mapped to the isolations whose namespaces they're in)
- Namespaces
- Nodes (pod ranges and addresses)

We don't cache Pods. The network engine enforces new pods by label on its own. We only list pods (uncached) to fill in the status counts. That keeps memory flat on big clusters.

### 3.4 Isolation edge cases

| Situation | Behaviour |
|---|---|
| A group's namespace doesn't exist yet | `Ready=False, NamespaceMissing`. Policies are created when the namespace appears. |
| A group matches 0 pods | Allowed. Count shows 0, plus a warning. |
| A pod uses hostNetwork | NetworkPolicy can't reach it. `Degraded` lists it. |
| One pod matches both groups | `Degraded, OverlappingGroups`. |
| A user edits or deletes our policy | Restored by the next reconcile (`Owns` watch). |
| A new node brings a new pod range | The Node watch triggers re-apply with the updated `except` list. |
| The operator is down | Policies stay, so isolation holds (fail closed). |
| The operator is uninstalled | Policies stay until the CRs are deleted. The README documents the cleanup order. |

## 4. Hardening

### 4.1 Targets and skip rules

- **Targets:** the listed `workloadKinds` in `namespaces`, matching `workloadSelector` (the workload's own labels, not the pod template's).
- **Skipped (reported, never patched):**
  - protected namespaces
  - namespaces or workloads labelled `netsec.nrnx.dev/ignore: "true"`
  - workloads with a controller `ownerReference` (another operator owns them)
  - GitOps markers: annotation `argocd.argoproj.io/tracking-id`, label `argocd.argoproj.io/instance`, labels `kustomize.toolkit.fluxcd.io/name` and `helm.toolkit.fluxcd.io/name`
  - workloads already in another WorkloadHardening's `Applying` set
  - Jobs and bare Pods (report only)
- **Size cap:** more than 200 targets means `Refused, TooManyWorkloads`.

### 4.2 Field rules

Apply to `containers` and `initContainers`. Only fill unset values.

| Field | Level | Tier | Not set (reported) when |
|---|---|---|---|
| `seccompProfile.type: RuntimeDefault` | pod | always | the pod-level profile is already set. Containers with their own profile keep it, because the container's setting wins; `Unconfined` is reported. |
| `allowPrivilegeEscalation: false` | container | always | `privileged: true`, or `capabilities.add` has `CAP_SYS_ADMIN` (the API rejects these combinations) or `SYS_ADMIN` |
| `runAsNonRoot: true` | pod | opt-in | the pod or any container sets `runAsUser: 0`, or a container sets `runAsNonRoot: false` |
| `capabilities.drop: [ALL]` | container | opt-in | `privileged: true`, or `drop` is already set |
| `readOnlyRootFilesystem: true` | container | opt-in | — |

Windows pods (`spec.os.name: windows`) skip all securityContext fields.

**Resources, per container:**
- **CPU or memory request missing:** set the default. If a limit exists and is smaller, use the limit.
- **Memory limit missing:** set the default, or the request if the request is larger.
- **CPU limit:** never set.
- **Never lower** an existing value.
- **LimitRange wins, per resource.** A resource (`cpu` or `memory`) is covered when any `Container` item of a LimitRange in the namespace has it in `default` or `defaultRequest`; `Pod` and `PersistentVolumeClaim` items are ignored. The API server stores `max` as `default` and `min` and `default` as `defaultRequest` when those are unset, so only the stored values are read. For a covered resource we set neither request nor limit, and the plan gets one warning naming the first LimitRange by name. Uncovered resources follow the rules above. The plan and apply-time `start` both list LimitRanges through `APIReader`, so a LimitRange added after approval changes the recomputed changes and the approval is not applied.

### 4.3 Plan

- For each target, build an **apply configuration**: the object's identity plus only our fields. Containers are matched by name.
- Server-side dry-run it. The API server runs validation and admission and tells us if it would fail. Those workloads get `state: Failed`, reason `WouldFail: <message>`, in the plan.
- `changes` is the list of fields we would set, as `path: old → new`.
- `plan.hash` is the first 16 hex characters of a sha256 over the sorted `(kind, namespace, name, generation, changes)`.

### 4.4 Apply

1. If `approvedPlanHash != plan.hash`, do nothing and set `PlanStale`.
2. If any workload's `generation` differs from the plan, re-plan, set `PlanStale` and wait for a new approval. A new hash makes the old approval invalid.
   - Plan mode builds a new plan only when there is none yet or `metadata.generation` differs from `status.observedGeneration`. There is no periodic re-plan; Apply re-plans live and checks the hash, so no safety is lost.
3. Roll out up to `maxConcurrentRollouts` workloads at a time:
   - Server-side apply with field manager `netsec-hardening-<first 8 of CR uid>`, `force=false`. Because the manager is per CR, Undo removes only this run's fields.
   - **Re-check on the live workload, just before the patch.** The skip rules run again on its labels, annotations, owner references and namespace labels, plus the protected list (the same `hardening.SkipReason` the plan uses): a label added after approval skips the workload. The changes are recomputed and compared with the approved ones; if they differ (for example `defaultResources` was edited) the workload is `Skipped` with `planned changes differ from the approval (spec or LimitRange changed)`.
   - Record `appliedAt` and the new `generation`. `appliedAt` is read from the response's `managedFields` entry for our manager (the API server's clock), falling back to the operator's clock.
4. **Health gate**, checked every 5 seconds while `Applying`:

| Kind | Healthy when | Unverified when |
|---|---|---|
| Deployment | rollout complete (`updated == available == replicas`, no old pods) | `replicas: 0`, or paused |
| StatefulSet | `updateRevision == currentRevision`, all replicas ready | `updateStrategy: OnDelete`, or a rolling update with `partition > 0` |
| DaemonSet | `updatedNumberScheduled == numberAvailable == desired` | `updateStrategy: OnDelete`, or 0 desired pods |
| CronJob | — | always (the change applies to the next run) |

   **Fail fast** on any pod of the workload created after `appliedAt` with:
   - a waiting reason: `CreateContainerConfigError`, `CreateContainerError`, `RunContainerError` or `CrashLoopBackOff`
   - or a last termination reason of `OOMKilled`
   
   Also fail on `ProgressDeadlineExceeded`, or when `rolloutTimeout` passes.

   **Unschedulable pods** also fail fast: a pod created after `appliedAt` whose `PodScheduled` condition has been `False` with reason `Unschedulable` for more than 60 seconds fails the gate with `Unschedulable: <message>`. The grace period is there because a cluster autoscaler may add a node. Without this, the new pods would wait for `rolloutTimeout` while a Deployment had already removed up to `maxUnavailable` old pods.

5. **Revert** on failure:
   - Server-side apply an empty configuration with our field manager. That removes exactly our fields, so the template goes back to what it was.
   - **StatefulSet:** also delete pods of the bad revision that aren't Ready. Kubernetes calls this "forced rollback"; without it, the StatefulSet stays stuck. The bad revision is saved in `status.plan.workloads[].failedRevision` **before** the revert is applied, because afterwards `updateRevision` points at the good one. A retry after a failed pod delete uses the saved revision.
   - Mark the workload `Reverted` with the reason, emit an Event and count it in metrics.
   - If the revert itself fails, retry with backoff until `appliedAt + 2 × rolloutTimeout`. After that, mark the workload `Failed` with reason `revert failed: <error>; fix it by hand`, emit a Warning, release its claim and let the run finish (`hardening.RevertExpired`).
6. When every workload is done, set the phase to `Completed`, or to `Failed` if any revert failed.

**Claims.** Before it patches (or undoes) a workload, a run creates a **Lease** (`coordination.k8s.io/v1`) named `netsec-claim-<first 16 hex of sha256("kind/namespace/name")>` in the operator's namespace (`POD_NAMESPACE`, default `netsec-system`). `holderIdentity` is the run's UID. Creating an object is atomic, so if two runs race for a workload only one create succeeds; the other marks the workload `Skipped` with `claimed by run <name>`. If the Lease exists:
- held by this run: carry on (a restart between claim and patch);
- held by a run that no longer exists, or that is not `Applying`/`Undoing` with the workload `Pending` or in flight: the Lease is stale and is taken over with an update, so the `resourceVersion` makes the takeover safe against a second taker.

The Lease is deleted when the workload reaches a final state and when the run is deleted. The plan-time `ActiveSet` skip stays as the friendly early path; the Lease is the guarantee.

**Deleting a run.** The finalizer `netsec.nrnx.dev/finish-rollouts` is added when a run first goes to `Applying` or `Undoing`. After deletion the run starts nothing new, but keeps gating every `Applying` or `Undoing` workload exactly as before, including the revert on failure. When none is in flight it releases all claims and removes the finalizer; with nothing in flight it does so at once. An Event `WaitingForRollouts` is emitted once when the deletion has to wait. Each workload settles within `rolloutTimeout`, so the wait is bounded. Deleting never undoes anything.

**Crash safety:** each step is written to status before the next one starts. After a restart, workloads in `Applying` are checked again. A crash can fall between our patch and the status write, leaving the workload patched but still `Pending` in status. So `start()` first looks at the live workload: if its `managedFields` already hold an `Apply` entry for our manager, this run patched it. It resumes as `Applying`, with that entry's time as `appliedAt` and the live `generation`, instead of skipping it as changed.

### 4.5 Undo

For each workload in state `Healthy`, `Unverified` or `Reverted`:
- Look at the workload first. If it is gone, the state is `Undone` with reason `deleted before the undo` (an empty apply to a missing object would try to create it).
- Take the workload's claim. If another run holds it, the workload keeps its state, gets the reason `waiting: claimed by run <name>`, and is tried again on later passes. The phase stays `Undoing`; a waiting workload does not use a rollout slot.
- Server-side apply an empty configuration with this CR's field manager.
- Fields that someone else has since taken over are kept, which is correct.
- Watch the rollout with the same health gate, but report failures only. The state we return to was working before.

The phase ends as `Undone`.

## 5. Observability

- **Conditions:** `Ready`, `Degraded`, `PlanStale`, `Refused`, all with `observedGeneration`.
- **Events:** `PolicyApplied`, `PolicyRemoved`, `MechanismSwitched`, `IsolationRefused`, `PlanReady`, `PlanStale`, `WorkloadPatched`, `WorkloadHealthy`, `WorkloadReverted`, `RevertFailed`, `WorkloadSkipped`, `UndoComplete`.
- **Metrics** (on top of controller-runtime's built-in reconcile metrics, served over the scaffold's authenticated HTTPS endpoint):
  - `netsec_isolation_ready{isolation}` (gauge: 1 when Ready, else 0)
  - `netsec_isolation_refusals_total{reason}`
  - `netsec_hardening_workloads_total{result}`

  Counters move once per transition, not once per reconcile. Refusals are tracked in memory per isolation, so a stale cache can't count one refusal twice; after a restart, the status seeds that memory. Plan-time results (Skipped, NoChange, WouldFail) aren't counted, only state changes during a run.
- **Logs:** structured, with the CR name and namespace on every line. Never secrets. They are JSON lines with ISO 8601 times by default; `--zap-devel=true` gives console logs (in the chart, set `manager.args`).

## 6. Security of the operator

| Resource | Verbs | Why |
|---|---|---|
| `networkisolations`, `workloadhardenings` (+ status, finalizers) | get, list, watch, update, patch | own CRs |
| `networkpolicies` | get, list, watch, create, update, patch, delete | isolation |
| `deployments`, `statefulsets`, `daemonsets`, `cronjobs` | get, list, watch, patch | hardening |
| `pods` | get, list, delete | health gate; StatefulSet forced rollback |
| `namespaces`, `nodes` | get, list, watch | facts |
| `events` | create, patch | reporting |
| `leases` (own namespace) | get, create, update | leader election |
| `leases` (own namespace, own Role) | get, create, update, delete | one claim per workload being hardened (§4.4) |

- **Restricted pod:** the operator runs non-root, drops all capabilities and has a read-only root filesystem. These are the scaffold defaults.
- **Own NetworkPolicy:** limits ingress to the operator's metrics port.
- **No dangerous fields:** it never writes images, commands, env vars or volumes.
- **Admin-only CRs:** creating either CR is admin-only. Kubebuilder's generated editor/viewer ClusterRoles are the grant points.
- **Known risk:** `pods/delete` cluster-wide is broad. RBAC can't scope it to "pods we broke". It's documented, and it's narrower than the template-patch right the operator already has.

## 7. What happens when…

| When… | Then… |
|---|---|
| input is invalid (bad names, `a == b`, `kube-*`, oversized lists, bad quantities) | rejected by CEL at `kubectl apply` with a clear message |
| the same isolation is created twice | both succeed; the second uses the other mechanism |
| two hardening runs target one workload | the later plan skips workloads in another run's `Applying` set; fields already set show as `NoChange` |
| the API server is slow or down | client calls time out after 30 s; controller-runtime retries with backoff; status keeps the last known state |
| applying a policy fails (permission denied, namespace terminating) | policies we no longer want are still removed; `Ready=False` with reason `ApplyFailed` and the error, a Warning event `ApplyFailed`, and the reconcile is retried with backoff |
| the operator crashes halfway | the next reconcile converges; isolation via apply plus label cleanup, hardening via status |
| a workload is deleted during apply | marked `Gone`, and the run continues |
| a rollout hangs | `rolloutTimeout`, then revert |
| the plan has gone stale | nothing is applied; re-approval needed |
| a NetworkIsolation is deleted while the operator is down | the finalizer holds it until the operator returns and cleans up |

## 8. Testing

| Layer | Tool | Covers |
|---|---|---|
| Unit | `go test`, table-driven | `complement`, `mayOverlap`, `allExcept`, the planner truth table, field rules (privileged skip, clamping, explicit values untouched, Windows skip), the health classifier, the plan hash |
| Integration | envtest (real API server, no kubelet or CNI) | policies created with owner refs and labels; finalizer cleanup leaves user policies untouched; a new user policy causes a make-before-break switch; Plan changes nothing; Apply needs the right hash; server-side apply sets only our fields; Undo removes exactly our fields; generation drift gives `PlanStale` |
| End to end | Ginkgo on k3d | a real traffic matrix (pod IP and Service) before, during and after isolation; the existing default-deny namespace case; nginx with `runAsNonRoot` gets reverted; `nginx-unprivileged` stays healthy; StatefulSet forced rollback; Undo |

**The tricky test: "isolation never widens access."**
- tenant-b has default-deny plus "allow from tenant-c". Then we isolate A↔B.
- **Expected:** C→B still works, D→B is still blocked and A↔B is blocked.
- **Why this one:** it fails on the obvious "allow all except A" design, which would let D in. That's the most dangerous bug in this problem.

**Runner-up: StatefulSet forced rollback.** It fails on a naive "revert the template" design.

**Test gate:** `make lint test test-e2e`. Unit and envtest go through `make test`. `make test-e2e` runs against k3d; we replace the scaffold's kind default.

## 9. Repo layout

```
api/v1alpha1/            CRD types and CEL markers
internal/isolation/      pure: complement, mayOverlap, allExcept, planner
internal/hardening/      pure: targets, field rules, resources, plan hash, health classifier
internal/controller/     the two reconcilers and the envtest suite
cmd/main.go              manager setup (flags: --protected-namespaces, --pod-cidrs)
config/                  kustomize: CRDs, RBAC, manager, samples
dist/chart/              Helm chart (from kubebuilder's Helm plugin)
hack/                    k3d cluster script, demo workloads, verify-isolation.sh
test/e2e/                k3d end-to-end tests
docs/                    analysis, prd, design
```

## 10. Build and run

- **Cluster:** `make k3d-up` creates cluster `netsec` with these settings:
  - one server and one agent node, so the e2e tests cover traffic between nodes
  - a pinned k3s image
  - `--no-lb`
  - `--kubeconfig-switch-context=false`, so the current kubectl context never moves

  `make k3d-down` deletes it. Every kubectl call, including the Makefile's `KUBECTL`, uses `--context k3d-netsec`.
- **Image:** `make docker-build k3d-load` builds the operator image and loads it into every node with `docker save --platform linux/<arch> | ctr -n k8s.io images import -`. It then checks the image shows in `crictl images`. (`k3d image import` silently failed on this machine; see §12.1.)
- **Install:** `make deploy` (kustomize) or `helm install netsec dist/chart`.
- **Demo:** `make demo` deploys these workloads:
  - tenant-a: `gateway`, `worker`
  - tenant-b: `dashboard`, `api`
  - tenant-c: `client`
  
  Servers use `nginx` and `nginx-unprivileged`; probes use `curl`.
- **Verify:** `make verify-isolation` runs `hack/verify-isolation.sh`.

## 11. Delivery plan

| Phase | Who | Work | Runs in parallel with |
|---|---|---|---|
| 0 | Opus | Spike on k3d: check the assumptions in §12 and record the results here | — |
| 1 | Opus | Lean scaffold (`kubebuilder init` + 2 APIs), k3d Makefile targets, demo manifests. Its own commit. | — |
| 2a | Sonnet builder A | `internal/isolation` + unit tests | 2b |
| 2b | Sonnet builder B | `internal/hardening` + unit tests | 2a |
| 3a | builder A | isolation controller + envtest | 3b |
| 3b | builder B | hardening controller (plan, apply, gate, revert, undo) + envtest | 3a |
| 4 | Opus | Review, merge, check for duplicated code | — |
| 5 | Sonnet | e2e on k3d + `verify-isolation.sh` | 6 |
| 6 | Haiku / Sonnet | metrics wiring, Helm chart, README draft | 5 |
| 7 | Opus | Full gate, final review, README decisions and limitations | — |

- Each finished step gets its own local commit.

## 12. Assumptions to check in Phase 0

1. kube-router (k3s's policy engine) keeps open connections after a policy lands. This is expected; the README will document it.
2. kube-router matches `ipBlock` against pod IPs. The `except` list makes us correct either way; the spike just tells us which.
3. `NotIn` and `DoesNotExist` peers behave as written.
4. Traffic through a Service ClusterIP is checked after address translation, so it's blocked like pod-IP traffic.
5. Kubelet probes still pass when an ingress policy selects the pod.
6. The scaffold's Helm plugin version works with the installed kubebuilder.

### 12.1 Phase 0 results (2026-10-25)

Setup: k3d v5.9.0, k3s v1.35.5+k3s1 with kube-router v2.6.3-k3s1 (one server node, pod range `10.42.0.0/24`), kubebuilder v4.16.0, Go 1.27.3. All test pods used `nginx:1.31.6-alpine`, which has `nc`, `curl` and `wget`. Every check below ran against real pods. Policies took effect about 1 second after `kubectl apply`.

| # | Result | Evidence |
|---|---|---|
| 1 | **Confirmed** | A pod sent a timestamp every second over one `nc` connection. After a deny-all ingress policy landed, new connections were refused at once. The open connection kept delivering every line, with no gap over 2s, for 6 minutes (368 lines). That spanned about ten other policy changes, each of which rebuilds kube-router's rules. kube-router accepts `ESTABLISHED` traffic before checking policies. |
| 2 | **Confirmed** | An ingress policy that allows only `ipBlock 0.0.0.0/0` let every pod in. With `except: [10.42.0.0/24]` (the node's `spec.podCIDRs`), every pod was blocked and the node still got through. So the `except` list is required, not just a safety net. |
| 3 | **Confirmed** | The §3.1 policy for side `spike-b, app In [client]` blocked only `app=client` in `spike-b`. It let in `app=other`, a pod with no `app` label (`NotIn` matches a missing label), and an `app=client` pod in another namespace. The `app DoesNotExist` variant let in only the unlabeled pod from `spike-b`. |
| 4 | **Confirmed** | With the §3.1 policy, the blocked pod failed by pod IP, ClusterIP, Service DNS name and NodePort. The other pods passed on all four. The egress version (EgressPolicy) also blocked pod IP and ClusterIP, while DNS and an allowed pod in the same namespace still worked. |
| 5 | **Confirmed** | An ingress policy allowing only `spike-b/app=client` was on the web pod for 60s, with HTTP readiness and liveness probes every 2s. The pod stayed Ready: 0 restarts and 0 `Unhealthy` events. Other pods were blocked at the same time. |
| 6 | **Confirmed** | kubebuilder v4.16.0 lists the Helm plugin as `helm/v2-alpha` (`helm.kubebuilder.io/v2-alpha`). `v1-alpha` is no longer listed. It builds the chart from `dist/install.yaml` (the output of `make build-installer`) into `dist/`. Not scaffolded yet; Phase 1 runs it. |

**What else we learned, and the impact on the design**

- **Node and probe traffic don't depend on our `ipBlock`.** The node reaches local pods from `10.42.0.1` (the `cni0` bridge), which is inside the pod range we except. It still passes because kube-router always accepts traffic from the pod's own node (`addrtype LOCAL`) before any policy runs. So on k3s, the `ipBlock` in `allExcept` matters only for sources outside the cluster's pod network. No change needed; the design stays correct.
- **Possible gap on clusters with more than one node (not tested; k3d here has one node).** When outside traffic enters through a NodePort or LoadBalancer on node 1 and goes to a pod on node 2, Kubernetes rewrites the source to node 1's flannel address. That address is inside node 1's pod range, which `allExcept` excepts. So those outside clients would likely be blocked, the opposite of what §3.1 promises. Impact: add a line to §14 (Known limitations), or test it with a second k3d node. The coordinator decides.
- **Blocked connections fail fast.** kube-router rejects instead of dropping, so a blocked connection gets "connection refused" (curl exit 7) at once, not a timeout. `verify-isolation.sh` and the e2e tests can use short timeouts.
- **`k3d cluster create` switches the current kubectl context by default.** On this machine that means plain `kubectl` silently moves off the production default. `make k3d-up` (§10) must pass `--kubeconfig-switch-context=false`.
- **`k3d image import` can silently do nothing.** It reported success, but the image never reached the node. This Docker Desktop uses the containerd image store, which saves multi-platform images. What worked: `docker save --platform linux/<arch> <image> | docker exec -i k3d-netsec-server-0 ctr -n k8s.io images import -`. `make k3d-load` (§10) should do this, then check the image is listed by `crictl images`.
- **The cluster was created with `--no-lb`.** k3d's load-balancer image wasn't on this machine and wasn't on the approved download list. Nothing in the design needs it.

## 13. Decisions the brief left open

| Question | Decision |
|---|---|
| How isolation behaves as pods come and go | Label-based, so the network engine covers new pods. Status counts refresh on a timer. |
| What counts as a "hardened" securityContext | §4.2: two always-safe fields, three opt-in (the Pod Security "restricted" set plus a read-only root filesystem). |
| Set or report resources? | Set static defaults, overridable. Never lower existing values, clamp to limits, no CPU limit. |
| Which workload types | Deployment, StatefulSet, DaemonSet and CronJob are patched. Job and Pod are reported only. |
| How actions are triggered and seen | CRDs via kubectl; status, Events and metrics. Hardening is plan → approve-by-hash → apply. |
| What it never touches | `kube-*`, its own namespace, opted-out objects, and (for hardening) operator-owned and GitOps-managed workloads. |

## 14. Known limitations

- Connections open before isolation keep working.
- Traffic that reaches B with its source rewritten to a node IP (a NodePort, or a hostNetwork proxy) isn't blocked.
- Anyone who can relabel pods can move a pod out of a group.
- Without real deny rules, some requests are refused. AdminNetworkPolicy is the upgrade path.
- Both directions need every namespace in a group to be "free" for the chosen mechanism. A per-namespace choice would refuse less often.
- CronJob changes are unverified until the next run.
- Whether an image runs as root is only learned at rollout. The health gate catches it and reverts.
- During a failed Deployment rollout, capacity can drop by up to `maxUnavailable` until the revert finishes.
- Jobs and bare Pods are listed in the `Ready` condition message, not as plan entries, because a plan entry's `kind` only allows the four patchable kinds.
- **Only k3s (flannel + kube-router) runs the full test suite.** kind (kindnet) passed the traffic check (`hack/verify-isolation.sh` with `KUBE_CONTEXT=kind-netsec`, kind v0.33.0), but not the full e2e suite. On other network plugins, isolation depends on two things NetSec cannot see directly: the pod range it was given, and which addresses outside traffic arrives from. Both are now explicit and checked. `--extra-allowed-cidrs` lists the node or tunnel addresses inside the pod range to allow (no flannel guess). `PodRangeMismatch` shows a pod outside the configured range (`Ready=False`, policies kept). `NodesInPodRange` shows node IPs inside it that no extra entry covers (`Degraded`). That is the state of AKS Azure CNI (flat) or EKS VPC CNI until every node IP is listed as a `/32` in `--extra-allowed-cidrs`; with `--pod-cidrs` set to the pod subnet that should work (untested), but nodes added later must be added to the list. It cannot tell whether the plugin enforces NetworkPolicy at all (flannel alone, or network policy "none"): `hack/verify-isolation.sh` is the check. The README has a support table (tested / expected / not supported).
- **Pods rejected when they are created are only caught by the rollout timeout.** Examples: a LimitRange `maxLimitRequestRatio`, a Pod-level LimitRange, or a ResourceQuota that our default requests exceed. The health gate does not detect "rejected at creation", so the revert waits for `rolloutTimeout`.
