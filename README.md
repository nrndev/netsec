# NetSec

NetSec is a Kubernetes operator written in Go. An operator is a program that runs in the cluster and keeps it matching what you asked for. NetSec has two jobs:

- **Isolation.** It cuts all traffic between two workloads, on demand, and puts it back when you ask.
- **Hardening.** It adds resource requests and safer security settings to workloads that lack them. You see a plan first, you approve it, and it can be undone.

Everything is driven by two custom resources (objects you create with `kubectl`). Design: [docs/design.md](docs/design.md). Product brief: [docs/prd.md](docs/prd.md).

## What it does

**Isolation.** You create a `NetworkIsolation` that names two groups of pods under `spec.between`: each group has a name, namespaces and a pod label selector. NetSec creates ordinary `NetworkPolicy` objects that block traffic both ways between the groups. Everything else keeps working: other pods, DNS, the nodes, kubelet probes. Deleting the `NetworkIsolation` deletes every policy NetSec made, and connectivity returns to what it was. Two rules shape the design:

- **Never widen access.** NetSec only adds its "allow everything except the other group" policy to pods that no other policy of the same kind (ingress or egress) selects. If another policy already selected those pods, its rules would combine with ours, and the result could let traffic in that was blocked before.
- **Fail closed.** If it cannot isolate safely, it refuses and says why in `status`. If the operator is down, existing policies stay and isolation holds.

**Hardening.** You create a `WorkloadHardening` for one or more namespaces. It first makes a **plan**: for each Deployment, StatefulSet, DaemonSet and CronJob, the exact fields it would set. Nothing changes yet. You approve the plan by copying its hash into the object. NetSec then patches one workload at a time and watches the rollout. One run applies once per object: to harden again, create a new `WorkloadHardening`. If the new pods fail, it reverts that workload. When you want the changes gone, you ask for **undo**.

## Quick start

You need: Docker, [k3d](https://k3d.io), kubectl, Go (the version in `go.mod`) and Helm.

> **Every command here uses the context `k3d-netsec`.** The Makefile and scripts pass `--context k3d-netsec` on every `kubectl` call. Your current kubectl context may point at a real cluster, and a plain `kubectl` or `helm` would act on it. Do the same in your own commands, and never change your current context.

```bash
make k3d-up                         # one server + one agent node, pinned k3s image
make docker-build k3d-load IMG=netsec:dev   # build the image, load it into both nodes
make deploy IMG=netsec:dev          # install CRDs, RBAC and the operator
make demo                           # sample workloads in tenant-a, tenant-b, tenant-c
```

To install with Helm instead of `make deploy`, see [dist/chart/README.md](dist/chart/README.md). `make helm-check` does a full install, a test and an uninstall.

`make k3d-up` does not move your kubectl context. `make k3d-down` deletes the cluster. `make undeploy` removes the operator.

## Using it

### Isolation

```yaml
apiVersion: netsec.nrnx.dev/v1alpha1
kind: NetworkIsolation
metadata:
  name: contain-gateway-dashboard
spec:
  reason: "INC-1234: suspected compromise"   # optional, for the audit trail
  between:                                   # exactly two groups
    - name: gateway
      namespaces:
        - tenant-a
      podSelector:
        matchLabels:
          app: gateway
    - name: dashboard
      namespaces:
        - tenant-b
      podSelector:
        matchLabels:
          app: dashboard
```

```bash
kubectl --context k3d-netsec apply -f config/samples/netsec_v1alpha1_networkisolation.yaml
kubectl --context k3d-netsec get iso
kubectl --context k3d-netsec get iso contain-gateway-dashboard -o yaml
```

```text
NAME                        READY   ISOLATED                                 AGE
contain-gateway-dashboard   True    gateway ⇄ dashboard: blocked both ways   8s
```

Read `status`:

- `status.summary` is one line you can read at a glance, for example `gateway ⇄ dashboard: blocked both ways`. It is the `Isolated` column of `kubectl get iso`.
- `status.traffic` always lists both directions. For each one: `blocked`, `blockedBy` (`IngressPolicy`: a policy on the receiving group's pods; `EgressPolicy`: a policy on the sending group's pods) and the policies. A direction NetSec had to refuse shows `blocked: false` and a `message` saying which policy is in the way.
- `status.pods` counts the pods in each group. A group with none is named in the summary, for example `gateway ⇄ dashboard: blocked both ways (dashboard matches no pods)`. It is still `Ready=True`, because the policies cover future pods; `Degraded` says `NoMatchingPods`.
- `Ready=True`, reason `Enforced`: both directions are blocked.
- `Ready=False`: NetSec refused. The reason is `ConflictingPolicy` (another policy makes it unsafe; the message names it), `PodCIDRUnknown`, `InvalidSelector`, `ProtectedNamespace` or `NamespaceMissing`. No widening policy is left behind.
- `Degraded`: it works but something is not enforceable, for example pods on `hostNetwork`, or one pod matching both groups.

**Change it while it's on.** Edit the spec (for example add a namespace to a group, or rename a group) with `kubectl edit` or `apply`. NetSec applies the new policies first, then removes the old ones, so blocked traffic is never let through. If an edit can't be planned (a bad selector or a protected namespace), the existing policies stay as they are and `Ready` says why.

**Turn it off** by deleting it. A finalizer (a hold on deletion) makes NetSec remove its policies first:

```bash
kubectl --context k3d-netsec delete iso contain-gateway-dashboard
```

Open connections survive isolation (see limitations); new connections are refused at once.

### Hardening

Every field except `namespaces` is optional. This example spells out the defaults:

```yaml
apiVersion: netsec.nrnx.dev/v1alpha1
kind: WorkloadHardening
metadata:
  name: harden-tenants
spec:
  namespaces:                   # where to look
    - tenant-a
    - tenant-b
  workloadSelector: {}          # the workloads' own labels; empty means all
  workloadKinds:
    - Deployment
    - StatefulSet
    - DaemonSet
    - CronJob
  strictSecurity:               # opt-in settings that can stop some images from starting
    runAsNonRoot: false
    dropAllCapabilities: false
    readOnlyRootFilesystem: false
  defaultResources:             # set only on containers that have none (and no LimitRange default)
    enabled: true
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      memory: 512Mi
  action: Plan                  # Plan, Apply or Undo
  approvedPlanHash: ""          # copy status.plan.hash here to approve
  maxConcurrentRollouts: 1
  rolloutTimeout: 5m            # per workload
```

The safe settings, seccomp `RuntimeDefault` and no privilege escalation, are always applied. `strictSecurity` only adds the risky ones.

Resource defaults are skipped per resource (CPU, memory) when a namespace LimitRange sets a default for it. The plan then warns and leaves that resource to the LimitRange.

```bash
# 1. Plan. Nothing changes.
kubectl --context k3d-netsec apply -f config/samples/netsec_v1alpha1_workloadhardening.yaml
kubectl --context k3d-netsec get wh harden-tenants -o jsonpath='{.status.plan.hash}{"\n"}'

# 2. Read the plan: every field it would set, and every workload it would skip and why.
kubectl --context k3d-netsec get wh harden-tenants -o yaml

# 3. Approve by hash. If anything changed since the plan, the hash no longer matches and nothing is applied.
kubectl --context k3d-netsec patch wh harden-tenants --type merge \
  -p '{"spec":{"action":"Apply","approvedPlanHash":"<hash>"}}'

# 4. Watch. Each workload goes Pending → Applying → Healthy, or Reverted if its pods fail.
kubectl --context k3d-netsec get wh harden-tenants -w

# 5. Undo. Removes exactly the fields this run set.
kubectl --context k3d-netsec patch wh harden-tenants --type merge -p '{"spec":{"action":"Undo"}}'
```

A run applies once. After it has patched anything, switching back to `Plan` or `Apply` is refused (`AlreadyApplied`); `Undo` still works. Create a new `WorkloadHardening` to harden again. Just before each patch, NetSec checks the workload again, so an opt-out label or a spec edit made after approval is not applied.

Deleting the `WorkloadHardening` does **not** undo anything. Undo is always explicit. If you delete a run while a rollout is in progress, a finalizer (`netsec.nrnx.dev/finish-rollouts`) keeps the object until every rollout has passed its health gate, so a failing workload is still reverted.

## How it works

One Go binary runs two controllers (loops that watch objects and make the cluster match). It is built with kubebuilder. All state is in each object's `status`; there is no database, and a restart resumes from status.

**Isolation controller.** For each direction (gateway → dashboard, dashboard → gateway, in the example) it picks one of two mechanisms. *IngressPolicy* adds a policy on the receiving group that allows everything except the sending group. *EgressPolicy* does the same on the sending group. It uses a mechanism only if no other policy of that kind selects those pods, which is what keeps the "never widen" rule true. If ingress on the target isn't free it tries egress on the source. If neither is free, it refuses and names the policies in the way. When a conflicting policy appears later, it creates the new policy first and deletes the old one second, so there is no gap. It restores its policies if someone edits or deletes them. Details: [design §3](docs/design.md).

**Hardening controller.** It builds a server-side apply configuration (the API server merges only our fields) per workload, dry-runs it, and hashes the result into the plan. Apply needs the matching hash. It rolls out `maxConcurrentRollouts` workloads at a time and checks health every 5 seconds. A pod that cannot start (`CreateContainerConfigError`, crash loop, OOM) or a rollout past `rolloutTimeout` triggers a revert. For a StatefulSet the revert also deletes the stuck pod, or the StatefulSet stays wedged. Details: [design §4](docs/design.md).

**Safety rails.** It never touches `kube-*` namespaces, its own namespace, or anything labelled `netsec.nrnx.dev/ignore: "true"`. Hardening also skips workloads owned by another controller and GitOps-managed ones. The operator pod runs non-root with a read-only filesystem, its RBAC is listed in [design §6](docs/design.md), and its own NetworkPolicy limits who can scrape its metrics. Pod IPs are kept out of the allowed address blocks using the cluster-wide pod range in `--pod-cidrs` (`manager.podCIDRs` in the chart). If it is not set, NetSec uses the ranges Nodes report and marks each isolation `Degraded` (`PodRangeFromNodes`), because a node added later is not covered.

**Logs** are JSON lines with ISO 8601 times. `--zap-devel=true` gives console logs (through Helm, set `manager.args`).

**Metrics** (HTTPS, token required): `netsec_isolation_ready{isolation}`, `netsec_isolation_refusals_total{reason}`, `netsec_hardening_workloads_total{result}`, plus controller-runtime's own.

## Decisions the brief left open

| Question | Decision |
|---|---|
| How isolation behaves as pods come and go | Label-based, so the network engine covers new pods. Status counts refresh on a timer. |
| What counts as a "hardened" securityContext | Two always-safe fields (seccomp `RuntimeDefault`, no privilege escalation). Three opt-in, under `strictSecurity` (`runAsNonRoot`, `dropAllCapabilities`, `readOnlyRootFilesystem`). |
| Set or report resources? | Set static defaults (100m / 128Mi request, 512Mi memory limit), overridable. Never lower an existing value, never set a CPU limit (throttling hurts more than it helps). |
| Which workload types | Deployment, StatefulSet, DaemonSet and CronJob are patched. Jobs and bare Pods are reported only. |
| How actions are triggered and seen | Custom resources via kubectl. Status, Events and metrics show what happened. Hardening is plan → approve by hash → apply. |
| What it never touches | `kube-*`, its own namespace, opted-out objects. For hardening also operator-owned and GitOps-managed workloads. |

The key calls behind those:

| Call | Why |
|---|---|
| Core `NetworkPolicy` only | It is the standard API. Any network plugin (CNI) that enforces NetworkPolicy understands it; k3s enforces it with its built-in kube-router. The cost: policies cannot deny, only allow, so some cases are refused. AdminNetworkPolicy is the upgrade. |
| Refuse rather than override | An admin's explicit allow rule is respected. A refusal with a clear reason is safer than a silent widening. |
| Plan hash | The hash covers each workload's generation and planned changes. If anyone edits a workload after the plan, the approval is void. You approve what you read. |
| Server-side apply, one field manager per run | Only our fields are written, so a user's values are never overwritten. Undo removes exactly this run's fields. A field someone else took over stays. |
| Fill unset fields only | We never change a value someone chose on purpose. |
| Cluster-scoped CRs | They span namespaces, and only admins should create them. |

## Verifying isolation

```bash
make verify-isolation     # deploys the operator, runs hack/verify-isolation.sh, undeploys
```

The script creates its own namespaces and workloads, sends real HTTP requests between every pair (by pod IP and by Service name) before isolation, during it and after deleting it, and exits non-zero on any mismatch. It cleans up after itself. Trimmed sample:

```text
== before isolation ==
PROBE                        HTTP  EXPECTED  RESULT
gateway>dashboard ip         200   200       ok
gateway>dashboard svc        200   200       ok
gateway>client ip            200   200       ok
gateway>client svc           200   200       ok
dashboard>gateway ip         200   200       ok
dashboard>gateway svc        200   200       ok

== during isolation (gateway and dashboard must not reach each other) ==
PROBE                        HTTP  EXPECTED  RESULT
gateway>dashboard ip         000   blocked   ok
gateway>dashboard svc        000   blocked   ok
gateway>client ip            200   200       ok
gateway>client svc           200   200       ok
dashboard>gateway ip         000   blocked   ok
dashboard>gateway svc        000   blocked   ok

== after deleting the isolation ==
(same 12 probes, all 200)

OK: every probe matched in all three phases
```

## Tests

| Layer | Command | What it covers |
|---|---|---|
| Unit | `make test` | Pure logic in `internal/isolation` and `internal/hardening`: selector complement, overlap, the planner, field rules, health, plan hash. |
| Integration | `make test` | envtest (a real API server without kubelet or CNI): policies, finalizer cleanup, make-before-break, plan/apply/undo, metrics counted once per change. |
| End to end | `make test-e2e` | Ginkgo on k3d: real traffic, real rollouts, NodePort, metrics scrape. It builds, loads and deploys the operator, then undeploys it. |

Which test proves which requirement: [docs/traceability.md](docs/traceability.md).

The full gate is `make lint test test-e2e`. Run `make test-e2e` and `make verify-isolation` one at a time: they share the cluster.

**The tricky test: "isolation never widens access."** tenant-b has a default-deny policy and an "allow from tenant-c" policy. We then isolate A↔B. C→B must still work, D→B must still be blocked, and A↔B must be blocked. The obvious design, "allow everything except A", would let D in, which is the worst bug this problem has. Where it is tested:

- `test/e2e/isolation_test.go`, spec "never widens access in a namespace that already has policies": real traffic on k3d, during the isolation and after it is deleted.
- `internal/isolation/isolation_test.go`, `TestPlanDirection`: the planner falls back to egress, or refuses, when a user policy selects the target.
- `internal/isolation/isolation_test.go`, `TestIsOwn`: a tenant cannot hide an "allow" policy from the planner by copying NetSec's label onto it.

**The NodePort finding.** On the two-node cluster, a request from outside through a NodePort on the node *without* B's pod was forwarded to B's node with its source rewritten to that node's flannel address. That address is the network address of the node's pod range, which the policy excepts, so outside clients were blocked: the opposite of "other traffic keeps working". The fix allows those tunnel addresses as single hosts, listed with `--extra-allowed-cidrs` (the k3d manifests list the two `flannel.1` addresses). No pod ever gets such an address, so no pod is let in. An e2e spec pins the result. Other network plugins have other tunnel addresses: see "Running on other clusters".

## Running on other clusters

NetSec was built and tested on k3s (flannel + kube-router). Its "allow everything except the other group" policies use an `ipBlock` that excepts the pod range, so two things must be right on any cluster: the **pod range** NetSec is given, and the **node or tunnel addresses** that sit inside it. NetSec cannot see your network plugin (CNI), so it asks you for both and checks what it can.

| Cluster / plugin | Enforces NetworkPolicy? | Own pod range? | Status | What to set | Known gaps |
|---|---|---|---|---|---|
| k3s / k3d (flannel + kube-router) | yes | yes | **tested** | `--pod-cidrs=10.42.0.0/16`, `--extra-allowed-cidrs` = each node's `flannel.1` address (the network address of its `spec.podCIDR`) | |
| kind (kindnet) | yes | yes | expected (untested) | `--pod-cidrs=10.244.0.0/16` | No tunnel addresses needed. |
| Calico (and AKS/EKS with Calico) | yes | yes | expected (untested) | `--extra-allowed-cidrs` = the nodes' tunnel addresses, from the `projectcalico.org/IPv4VXLANTunnelAddr` or `IPv4IPIPTunnelAddr` annotations | Untested. List every node, and update the list when nodes change. |
| Cilium (and GKE Dataplane V2) | yes | yes | expected (untested) | `--pod-cidrs`, and tunnel addresses if any | Cilium's CIDR rules don't match cluster nodes, so outside traffic forwarded between nodes may be blocked whatever you list. Untested. |
| AKS Azure CNI Overlay with Azure NPM, Calico or Cilium | yes | yes | expected (untested) | `--pod-cidrs` = the cluster's `podCidr` | |
| AKS Azure CNI (flat) / EKS VPC CNI | yes | **no**: pods share the nodes' subnet | possible (untested) | `--pod-cidrs` = the pod subnet; `--extra-allowed-cidrs` = every node IP as a `/32` | `NodesInPodRange` names any node you missed. Nodes added later must be added to the list. Until then, traffic from their IPs is blocked. |
| flannel alone, or network policy "none" | **no** | yes | does nothing | | NetworkPolicy is not enforced and NetSec cannot detect it. Run `hack/verify-isolation.sh` against the cluster. |

### The two flags

- **`--pod-cidrs`** (chart: `manager.podCIDRs`) is the whole range your cluster hands pod IPs from. Find it in:
  - AKS: `az aks show -g <group> -n <cluster> --query networkProfile.podCidr`
  - kind: `networking.podSubnet` in the kind config
  - k3s: the `cluster-cidr` setting (default `10.42.0.0/16`)
  
  If it is unset, NetSec uses the ranges Nodes report and marks each isolation `Degraded` (`PodRangeFromNodes`).
- **`--extra-allowed-cidrs`** (chart: `manager.extraAllowedCIDRs`) lists addresses inside the pod range that outside traffic can arrive from. Each must be a single address (`/32` or `/128`); a wider block inside the pod range would let pods in, so NetSec refuses it (at startup, and `Ready=False` with reason `InvalidExtraAllowedCIDRs` while keeping existing policies). Find the values:
  - flannel: the network address of each node's `spec.podCIDR` (for `10.42.1.0/24`, that is `10.42.1.0/32`)
  - Calico: the tunnel address annotations listed in the table

### What the two checks mean

- **`Ready=False`, `PodRangeMismatch`.** A pod in one of the groups has an IP outside the pod range (only IP families that have a configured range are checked). Policies are still applied and still block every in-range pod, but the isolated pod may not be covered by the `ipBlock` except list. Fix: set `--pod-cidrs` to the range those pods really use. The message names the pods and their IPs.
- **`Degraded=True`, `NodesInPodRange`.** A Node's IP is inside the pod range and not listed in `--extra-allowed-cidrs`, as on flat-network clusters. Isolation still works, but traffic that arrives from node IPs (NodePort, LoadBalancer with `externalTrafficPolicy: Cluster`, some health checks) is blocked by NetSec's policies. Fix: list each such node IP as a `/32` in `--extra-allowed-cidrs` (and add new nodes as they join), or accept the blocked node traffic.

## Known limitations

Limits:

- **Open connections survive.** The network engine accepts established connections before checking policies. We measured a connection that kept working for 6 minutes. Fix: optional connection termination (conntrack flush), not built.
- **Source-rewritten traffic is not blocked.** If A reaches B through something that rewrites the source to a node IP (a hostNetwork proxy, some NodePort paths), it looks like node traffic and passes.
- **No real deny rules.** Plain NetworkPolicy only allows, so a direction is refused when another policy already selects the pods. AdminNetworkPolicy would remove most refusals.
- **Mechanism is per group, not per namespace.** Every namespace in a group must be free for the chosen mechanism, so it refuses more than it needs to.
- **Relabelling escapes isolation.** Anyone who can change pod labels can move a pod out of a group.
- **Hardening cannot see everything.** Whether an image runs as root is only learned at rollout; the health gate then reverts. CronJob changes stay `Unverified` until the next run. During a failed Deployment rollout, capacity can dip by up to `maxUnavailable` until the revert finishes.
- **`pods/delete` is cluster-wide.** RBAC cannot scope it to "pods we broke". It is needed for the StatefulSet revert, and it is narrower than the template-patch right the operator already has.
- **Pods rejected when they are created are only caught by the rollout timeout.** Examples: a LimitRange `maxLimitRequestRatio`, a Pod-level LimitRange, or a ResourceQuota that our default requests exceed. The health gate does not detect "rejected at creation", so the revert waits for `rolloutTimeout`.
- **Other network plugins are untested.** Only k3d with flannel and kube-router is tested. See "Running on other clusters" for what is expected elsewhere and what NetSec checks for you.

With more time:

- An AdminNetworkPolicy backend, for real deny rules.
- An "already blocked" check, so a direction another policy already blocks is accepted instead of refused.
- Merging isolations that share a group.
- Optional termination of open connections.
- Resource sizing from observed usage instead of static defaults.
- A Prometheus alert rule for `netsec_isolation_ready == 0`.
- Tests on a second CNI, and on a multi-node cloud cluster.

## Tools and why

- **kubebuilder and controller-runtime** instead of plain client-go. A controller needs a shared cache, work queues with backoff, leader election, finalizers, status patching, health probes and metrics. controller-runtime gives all of these tested. Plain client-go would mean writing them by hand, and the time would go there instead of into the isolation and hardening rules. kubebuilder also generates the CRDs and RBAC from Go markers, gives us envtest, and has a Helm plugin. The cost is a larger scaffold, which we kept lean: no webhooks, no cert-manager (validation uses CEL rules the API server runs itself).
- **envtest** for integration tests: a real API server, so server-side apply and finalizers behave for real.
- **Ginkgo** for e2e, because the scaffold uses it and its `Eventually` waits on real conditions instead of sleeps.
- **k3d** for the cluster, instead of the kind cluster the brief asks for. We chose it for simplicity:
  - one tool for development and every test
  - NetworkPolicy enforced out of the box by k3s's kube-router
  - quick to start

  Two nodes, so tests cover traffic between nodes. The trade-offs are in [docs/analysis.md §6](docs/analysis.md#6-cluster-choice-k3d-not-kind).
- **Helm** for the chart, generated by kubebuilder's `helm/v2-alpha` plugin.

## Repo layout

```
api/v1alpha1/            CRD types and validation rules
internal/isolation/      pure logic: complement, overlap, planner, policy builders
internal/hardening/      pure logic: field rules, plan hash, health classifier
internal/controller/     the two reconcilers, metrics, envtest suite
cmd/main.go              manager setup and flags
config/                  kustomize: CRDs, RBAC, manager, network policy, samples
dist/chart/              Helm chart
hack/                    demo workloads, verify-isolation.sh
test/e2e/                k3d end-to-end specs
docs/                    analysis.md, prd.md, design.md
```

More: [docs/analysis.md](docs/analysis.md) (risks), [docs/prd.md](docs/prd.md) (what and why), [docs/design.md](docs/design.md) (how).
