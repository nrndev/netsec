# NetSec: critical analysis of the idea

## The short version

1. **The idea is sound, but network isolation is much harder than it looks.** Kubernetes NetworkPolicy can only *allow* traffic. It has no "deny" rule. To block A↔B while "everything else keeps working", you must write "allow everything except A" policies. Those break in three ways (section 1). This is the core risk of the project.
2. **"Patch without breaking workloads" is the second big risk.** Several "hardened" settings break common images such as nginx. The tool can't know in advance, because Kubernetes only checks if an image runs as root when the container starts.
3. **Kubebuilder fits well** if we keep the scaffold lean. A CRD (custom resource definition: our own Kubernetes object type) gives a natural on/off switch (create/delete), a place to show results (`status`) and generated RBAC (permissions). The brief warns to use it only if you know it, so the README must say why we chose it.
4. **"Production grade" should mean safe, observable and well tested, not feature-heavy.** The brief grades the core first and says bonuses don't make up for gaps.
5. **A few assumptions need a short test on real k3d** before the design is final (section 5).

## 1. Network isolation

### Why "allow all except A" is fragile

NetworkPolicy rules add up (a union). Once any policy selects a pod for incoming traffic, only what at least one policy allows gets in. So an "allow everything except A" policy on B:

- **Widens access if B already has policies.** Say B's namespace has default-deny plus "allow from the ingress controller". Adding our policy makes B reachable from every pod except A. The tool would silently *open up* a locked-down workload. This is the most dangerous bug in the naive design.
- **Can't remove A if an existing policy already allows A.** We can't subtract from someone else's allow rule without editing it. Editing user-owned policies breaks "turning off restores previous connectivity" and fights GitOps tools.
- **Two of our own isolations cancel each other out.** Isolating A↔B and A↔C puts two policies on A: "all except B" and "all except C". Their union allows both B and C.

### Ways around it

| Option | How it works | Good | Bad |
|---|---|---|---|
| **Core NetworkPolicy + safety planner** | Use "allow all except X" only where no other policy selects the same pods. For each direction, pick the target's ingress or the source's egress, whichever is free. If an existing policy already blocks the direction, just watch it. Otherwise refuse with a clear reason. | Stable core API. Runs on stock k3d. Exact restore: we only ever delete our own objects. | Refuses in some real setups. Partly overlapping isolations must be refused or merged. |
| **AdminNetworkPolicy (ANP)** | Upstream Kubernetes API with real `Deny` rules and priorities, checked before NetworkPolicy. | Deny rules combine correctly. Exact restore. | Alpha API, being reworked. Stock k3d's policy engine doesn't support it, so we'd install another CNI (the cluster's network plugin), such as Calico. Versions need checking. |
| **CNI-specific deny** (Calico, Cilium) | Vendor policy types that support Deny. | Mature. | Ties the tool to one CNI. Same k3d setup cost. |

**Recommendation: core NetworkPolicy with the safety planner for v1.** The brief points that way ("plain client-go is enough"), it runs on stock k3d, and refusing loudly is safe. Document ANP as the upgrade path.

### Other isolation edges

- **Open connections survive.** Most policy engines, including kube-router (which k3s uses), let already-open connections continue. A reverse shell opened before isolation keeps working. Killing it means restarting pods, which conflicts with "without breaking them". We must decide and document.
- **Non-pod traffic.** "Allow all except A" must still allow nodes, kubelet health probes and outside clients. That needs an `ipBlock` of `0.0.0.0/0` minus the pod network range. Some engines match pod IPs against `ipBlock`, so without the "minus" A would get back in. The pod range comes from each Node's `spec.podCIDRs`, and new nodes must be picked up.
- **Source rewriting (SNAT).** If A reaches B through a NodePort or a proxy that rewrites the source to a node IP, the traffic looks like it comes from a node and is allowed. Document as a limit.
- **hostNetwork pods.** NetworkPolicy doesn't apply to pods on the host network. If either side has one, say so in status.
- **Pods relabeling themselves.** Sides are label-based. Anyone allowed to edit pod labels in tenant-a can move a pod out of side A. Namespace names are safe, because the API server sets the `kubernetes.io/metadata.name` label.
- **Selector complement.** "All pods except `app=gateway`" is written `app NotIn [gateway]`, which also matches pods with no `app` label (correct, but surprising). A selector with several labels turns into several rules, one per label. This is easy to get wrong, so it gets heavy unit tests.
- **Pods coming and going.** Policies select by label, so the network engine covers new pods automatically. The controller still watches:
  - pods, for status and warnings
  - NetworkPolicies, because a new user policy can undo our block
  - Namespaces, because a side's namespace may not exist yet or may be recreated
  - Nodes, for pod ranges
- **Overlapping sides.** If one pod matches both A and B, the request makes no sense. Reject it when it's obvious; warn at runtime otherwise.
- **System namespaces.** Isolating `kube-system` (CoreDNS) would break the whole cluster. Refuse.
- **Fail closed.** If the operator crashes or is uninstalled, its policies stay and isolation keeps holding. That's the right default for a security tool, but uninstall needs a documented cleanup.

## 2. Workload hardening

### What can break

| Setting | Risk |
|---|---|
| `seccompProfile: RuntimeDefault` | Low. |
| `allowPrivilegeEscalation: false` | Low, but the API rejects it on `privileged` containers or ones that add `CAP_SYS_ADMIN`. |
| `runAsNonRoot: true` | High. Images that run as root (nginx and many others) fail with `CreateContainerConfigError`. |
| `capabilities.drop: [ALL]` | High. nginx needs `SETUID`/`SETGID` to switch users; root images often need `CHOWN`. |
| `readOnlyRootFilesystem: true` | High. Breaks anything that writes to `/tmp`, caches or pid files. |
| Resource requests | Medium. Pods may not fit on any node, stay `Pending`, and stall the rollout. |
| Memory limit | Medium. Too low means OOMKilled. |
| CPU limit | Causes throttling. Common advice is not to set it. |

A request higher than an existing limit is invalid, so defaults must be clamped.

### Patching is itself disruptive

- Pods are mostly immutable, so we patch the owner (Deployment, StatefulSet, DaemonSet, CronJob). Any pod-template change triggers a rolling restart.
- A failed Deployment rollout may already have removed up to `maxUnavailable` old pods.
- **StatefulSets don't recover by themselves.** If a new pod never becomes Ready, reverting the template isn't enough; the stuck pod must be deleted too (the Kubernetes docs call this "forced rollback"). A naive auto-revert leaves the StatefulSet broken.
- DaemonSets roll one node at a time. CronJobs only change for the next run, so we can't check health right away. Jobs and bare Pods can't be patched, so we report only.
- **Someone else may own the workload.** GitOps tools (Argo CD, Flux) and other operators will revert our patch, or fight it in a loop. Detect them and report instead of patching.
- Injected sidecars (for example Istio's init container, which needs root and `NET_ADMIN`) can break under pod-level settings.

### What makes it safe

- **Fill only unset fields.** Never override an explicit choice; report it instead.
- **Server-side apply (SSA) with our own field manager.** Kubernetes records which fields we own. Undo is then "apply an empty config", which removes exactly our fields and nothing else. Undo is nearly free this way, so it should be in scope even though it's a bonus.
- **Server-side dry-run for the preview.** The API server runs validation and admission checks (including Pod Security) and returns the result. The preview shows what would really happen, not our guess.
- **Plan, then approve.** Show the plan, then apply only that exact plan. If a workload changed since the preview, re-plan.
- **Health-gated rollout.** Apply to a few workloads at a time and watch each rollout. Fail fast on `CreateContainerConfigError`, `CrashLoopBackOff` or `OOMKilled`. Auto-revert (including deleting the stuck StatefulSet pod) and report.
- **Risk tiers.** Apply low-risk fields by default; make the stricter ones opt-in.

### Native features to mention

- **LimitRange** sets default requests and limits for *new* pods in a namespace, without touching workloads.
- **Pod Security Admission** blocks new insecure pods.
- **Kyverno or MutatingAdmissionPolicy** for continuous enforcement.

Our tool is the on-demand, reviewed, reversible fix for workloads that are already running. The README should say where it stops and those tools take over.

## 3. Operator-level concerns

- **The operator is a high-value target.** It can patch workloads and policies across the cluster. So:
  - least-privilege RBAC
  - a restricted security context and its own NetworkPolicy
  - never touch images or commands
  - only admins can create its CRs, since anyone who can isolate can cut traffic
- **Cluster-scoped CRDs.** An isolation spans namespaces. Owner references can't point across namespaces, but a cluster-scoped owner can own namespaced objects. So garbage collection cleans up as a backup to the finalizer (a hook that runs our cleanup before deletion).
- **Idempotent reconcile.** Each pass computes the desired state from the spec and the cluster, applies it, and deletes leftovers by label. A crash halfway is fixed by the next pass.
- **Readable status.** Conditions, matched pod counts, the mechanism chosen per direction, the policies we own, and warnings. Events for actions. Metrics.
- **No validating webhook.** CEL rules in the CRD (validation expressions run by the API server) cover it, so we don't need cert-manager.

## 4. Gaps and contradictions in the brief

- "Without requests and limits **or** a hardened securityContext": we treat each fix as independent.
- "Namespace(s) and label selectors": each side may span several namespaces. The example shows only one.
- Isolation must restore exactly when turned off, but hardening undo is optional. The two have different reversibility bars.
- No deadline or time budget is given, so scope is a risk.
- "Small internal tool" vs. "production grade": aim for safe and well tested, not big.

## 5. Check on real k3d before finalizing the design

1. Does kube-router keep open connections after a policy lands?
2. Does kube-router match `ipBlock` against pod IPs?
3. Do `NotIn` and `DoesNotExist` peers behave as expected?
4. Is traffic through a Service ClusterIP blocked (the policy applies after address translation)?
5. Do kubelet probes still pass when an ingress policy selects the pod?
6. If we pick ANP: which API version, and which Calico release supports it?

## 6. Cluster choice: k3d, not kind

The brief asks for a kind cluster, including for the integration tests. We swapped it for k3d, for simplicity, and use k3d for everything: development, the demo, the e2e suite, `hack/verify-isolation.sh` and `make helm-check`.

Why k3d is simpler here:

- **One cluster tool, one cluster.** A second tool would double the setup and the ways it can break, for no new coverage of our own code.
- **NetworkPolicy works out of the box.** k3s ships kube-router, which enforces NetworkPolicy. The Phase 0 spike confirmed it (design §12). kind's default network plugin, kindnet, only enforces NetworkPolicy in recent kind releases; with an older kind you must install Calico or Cilium first. An isolation test on a plugin that ignores policies would pass and prove nothing.
- **Small and quick.** k3s is a single binary per node, a two-node cluster starts in seconds, and our images load straight from the local Docker daemon.

What we give up:

- **kind is the Kubernetes project's own test cluster** and runs the upstream components, such as kube-proxy. k3s swaps some of them: kube-router for policies, flannel for networking, and an embedded datastore. A bug that only shows up on the upstream components would slip past our tests.
- **Our isolation results are kube-router's.** Another policy engine can differ at the edges, for example with open connections or with `ipBlock` and pod IPs. The README's "Running on other clusters" table therefore marks kind as "expected (untested)".

How to close the gap: run the same e2e suite on kind in CI. The specs don't depend on k3d itself; they need a kubectl context and a way to load images. So the change is:

- a second cluster target in the Makefile
- a configurable context in `test/utils`
- `kind load docker-image` in place of the k3d image import

No new tests are needed.
