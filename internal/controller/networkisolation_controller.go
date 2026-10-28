/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
	"github.com/nrndev/netsec/internal/isolation"
)

const (
	isolationFinalizer = "netsec.nrnx.dev/cleanup"
	isolationManager   = "netsec-isolation"
	// refreshInterval is how often pod counts are refreshed.
	refreshInterval = 2 * time.Minute
	// reconcileTimeout bounds one reconcile pass.
	reconcileTimeout = 30 * time.Second
	// maxNamedPods caps how many pod names go into a condition message.
	maxNamedPods = 5

	condReady    = "Ready"
	condDegraded = "Degraded"

	reasonPodRangeMismatch = "PodRangeMismatch"
)

// NetworkIsolationReconciler reconciles a NetworkIsolation object
type NetworkIsolationReconciler struct {
	client.Client
	// APIReader reads straight from the API server. It counts pods, which we never cache.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	Recorder  events.EventRecorder
	// ProtectedNamespaces are refused. Names starting with "kube-" are always refused.
	ProtectedNamespaces []string
	// PodCIDRs is the cluster-wide pod range (--pod-cidrs). It sets the ipBlock except list.
	// When empty we fall back to the ranges Nodes report, and say so in Degraded.
	PodCIDRs []string
	// ExtraAllowedCIDRs (--extra-allowed-cidrs) are single node or tunnel addresses inside the
	// pod range that every policy must still allow. See isolation.CheckExtraAllowed.
	ExtraAllowedCIDRs []string
}

// +kubebuilder:rbac:groups=netsec.nrnx.dev,resources=networkisolations,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=netsec.nrnx.dev,resources=networkisolations/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=netsec.nrnx.dev,resources=networkisolations/finalizers,verbs=update
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces;nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// result is what one reconcile pass decided, before it is written to status.
type result struct {
	desired []networkingv1.NetworkPolicy
	traffic []netsecv1alpha1.Traffic
	ready   metav1.Condition // Status False means a reason it is not enforced
	// refused says, per refused direction, which other policies stop us ("from → to: ns/name").
	refused []string
	// notEnforced is the short reason nothing is enforced, if so. It feeds status.summary.
	notEnforced string
	// keep means we cannot plan (pod ranges unknown, a bad selector or a protected namespace):
	// leave our existing policies exactly as they are.
	keep bool
	// badSelector means a group's selector cannot be read, so its pods cannot be counted.
	badSelector bool
	// podRangeFromNodes means --pod-cidrs is unset and the except list came from Node ranges.
	podRangeFromNodes bool
	// podRange is the pod range in use. The pre-flight checks compare addresses against it.
	podRange []string
	// mismatch lists pods with an IP outside podRange ("ns/name (ip)"). Set by finish.
	mismatch []string
	// nodesInRange lists nodes with an IP inside podRange ("name (ip)").
	nodesInRange []string
}

// Reconcile follows design §3.3: plan both directions, apply the policies, remove
// ours that are no longer wanted, then write status.
func (r *NetworkIsolationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Bound each pass. A client timeout would also cut the informers' long watches.
	ctx, cancel := context.WithTimeout(ctx, reconcileTimeout)
	defer cancel()
	log := logf.FromContext(ctx)
	iso := &netsecv1alpha1.NetworkIsolation{}
	if err := r.Get(ctx, req.NamespacedName, iso); err != nil {
		if apierrors.IsNotFound(err) {
			isolationReady.DeleteLabelValues(req.Name)
			lastReason.Delete(req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !iso.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, iso)
	}
	if controllerutil.AddFinalizer(iso, isolationFinalizer) {
		if err := r.Update(ctx, iso); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer to %s: %w", iso.Name, err)
		}
	}

	own, err := r.ownPolicies(ctx, iso)
	if err != nil {
		return ctrl.Result{}, err
	}
	res, err := r.plan(ctx, iso)
	if err != nil {
		return ctrl.Result{}, err
	}

	missing, err := r.missingNamespaces(ctx, iso)
	if err != nil {
		return ctrl.Result{}, err
	}
	if res.keep {
		return r.finish(ctx, iso, res, missing)
	}
	// A missing namespace has no pods yet; the Namespace watch applies the policy later.
	desired := res.desired[:0:0]
	for _, p := range res.desired {
		if !slices.Contains(missing, p.Namespace) {
			desired = append(desired, p)
		}
	}
	res.desired = desired
	for i := range res.traffic {
		res.traffic[i].Policies = keepExisting(res.traffic[i].Policies, missing)
	}

	// Make before break: apply everything wanted, then delete ours that are not wanted.
	// If an apply fails we still prune: a policy we no longer want, such as the old
	// "allow all except X" ingress policy, must never stay next to a user's new default-deny.
	var applyErr error
	for i := range desired {
		if applyErr = r.apply(ctx, &desired[i]); applyErr != nil {
			break
		}
	}
	// A conflict means our read was behind a concurrent write, not that applying failed.
	// Nothing is wrong: retry at once, without pruning, an event or a status change, so
	// Ready does not flap on a harmless race.
	if apierrors.IsConflict(applyErr) {
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	removed, err := r.prune(ctx, own, desired)
	if removed > 0 {
		r.Recorder.Eventf(iso, nil, corev1.EventTypeNormal, "PolicyRemoved", "Prune", "removed %d policies that are no longer needed", removed)
		log.Info("removed policies", "count", removed)
	}
	if applyErr != nil {
		return r.applyFailed(ctx, iso, res, missing, errors.Join(applyErr, err))
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	log.V(1).Info("applied", "policies", len(desired))
	return r.finish(ctx, iso, res, missing)
}

// applyFailed reports a failed apply: nothing we planned is trusted to be in place, so the
// traffic is shown as not blocked and Ready is False. It writes status, then returns the
// error so the request is retried with backoff.
func (r *NetworkIsolationReconciler) applyFailed(ctx context.Context, iso *netsecv1alpha1.NetworkIsolation, res *result, missing []string, cause error) (ctrl.Result, error) {
	traffic := make([]netsecv1alpha1.Traffic, len(res.traffic))
	for i, t := range res.traffic {
		traffic[i] = netsecv1alpha1.Traffic{From: t.From, To: t.To, Message: "policies could not be applied"}
	}
	res.traffic = traffic
	res.notEnforced = "apply failed"
	res.ready = notReady("ApplyFailed", cause.Error())
	r.Recorder.Eventf(iso, nil, corev1.EventTypeWarning, "ApplyFailed", "Apply", "%v", cause)
	if _, err := r.finish(ctx, iso, res, missing); err != nil {
		return ctrl.Result{}, errors.Join(cause, err)
	}
	return ctrl.Result{}, cause
}

// finish counts pods, reports events and writes status.
func (r *NetworkIsolationReconciler) finish(ctx context.Context, iso *netsecv1alpha1.NetworkIsolation, res *result, missing []string) (ctrl.Result, error) {
	var counts podCounts
	if res.badSelector {
		counts.groups = iso.Status.Pods // cannot count with a bad selector: keep the last counts
	} else {
		var err error
		if counts, err = r.countPods(ctx, iso, missing); err != nil {
			return ctrl.Result{}, err
		}
	}
	// Policies stay as they are; a pod outside the pod range only turns Ready off, so the
	// operator can see that isolation may not hold for it.
	if len(res.podRange) > 0 {
		var err error
		if res.mismatch, err = isolation.OutsideRange(counts.pods, res.podRange); err != nil {
			return ctrl.Result{}, fmt.Errorf("check pod addresses: %w", err)
		}
		if len(res.mismatch) > 0 && res.ready.Status == metav1.ConditionTrue {
			res.ready = notReady(reasonPodRangeMismatch, mismatchMessage(res.mismatch))
		}
	}
	r.emitEvents(iso, res)
	if err := r.writeStatus(ctx, iso, res, missing, counts); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: refreshInterval}, nil
}

// finalize deletes our policies and, once a fresh list shows none left, drops the finalizer.
func (r *NetworkIsolationReconciler) finalize(ctx context.Context, iso *netsecv1alpha1.NetworkIsolation) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(iso, isolationFinalizer) {
		return ctrl.Result{}, nil
	}
	own, err := r.ownPolicies(ctx, iso)
	if err != nil {
		return ctrl.Result{}, err
	}
	if len(own) > 0 {
		n, err := r.prune(ctx, own, nil)
		if err != nil {
			return ctrl.Result{}, err
		}
		if n > 0 {
			r.Recorder.Eventf(iso, nil, corev1.EventTypeNormal, "PolicyRemoved", "Cleanup", "removed %d policies", n)
		}
		// The cache may still show them; look again shortly. Policy delete events also wake us.
		return ctrl.Result{RequeueAfter: time.Second}, nil
	}
	if controllerutil.RemoveFinalizer(iso, isolationFinalizer) {
		if err := r.Update(ctx, iso); err != nil {
			return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("remove finalizer from %s: %w", iso.Name, err))
		}
	}
	return ctrl.Result{}, nil
}

// plan decides the desired policies and the Ready condition. It reads the cluster but writes nothing.
//
// Fail closed: when we cannot plan (InvalidSelector, ProtectedNamespace, PodCIDRUnknown) we
// keep the existing policies as they are, with no apply and no prune. An edit with a typo
// must not lift a working isolation. Only ConflictingPolicy removes our policies for its
// direction, because of the never-widen rule (S1).
func (r *NetworkIsolationReconciler) plan(ctx context.Context, iso *netsecv1alpha1.NetworkIsolation) (*result, error) {
	res := &result{}
	// Backstop for the CRD's selector rules, which cannot check label syntax.
	for _, g := range iso.Spec.Between {
		if _, err := metav1.LabelSelectorAsSelector(&g.PodSelector); err != nil {
			res.keep, res.badSelector = true, true
			res.traffic = iso.Status.Traffic
			res.notEnforced = "invalid selector in group " + g.Name
			res.ready = notReady("InvalidSelector", fmt.Sprintf("group %s has an invalid podSelector: %v; existing policies are left as they are", g.Name, err))
			return res, nil
		}
	}
	if hit := r.protectedHits(iso); len(hit) > 0 {
		res.keep = true
		res.traffic = iso.Status.Traffic
		res.notEnforced = "protected namespace"
		res.ready = notReady("ProtectedNamespace", fmt.Sprintf("protected namespaces cannot be isolated: %s", strings.Join(hit, ", ")))
		return res, nil
	}
	podRange, nodes, err := r.podCIDRs(ctx)
	if err != nil {
		return nil, err
	}
	if len(podRange) == 0 {
		// Fail closed: a Node blip must not lift isolation, so nothing is applied or pruned.
		res.keep = true
		res.traffic = iso.Status.Traffic
		res.notEnforced = "pod ranges unknown"
		res.ready = notReady("PodCIDRUnknown", "no pod ranges: no Node reports spec.podCIDRs and --pod-cidrs is not set; existing policies are left as they are")
		return res, nil
	}
	res.podRange = podRange
	if res.nodesInRange, err = isolation.InRange(nodes, podRange, r.ExtraAllowedCIDRs); err != nil {
		return nil, fmt.Errorf("check node addresses: %w", err)
	}
	if err := isolation.CheckExtraAllowed(r.ExtraAllowedCIDRs, podRange); err != nil {
		// Fail closed, like the other "cannot plan" cases: a bad flag must not lift isolation.
		res.keep = true
		res.traffic = iso.Status.Traffic
		res.notEnforced = "invalid extra allowed CIDRs"
		res.ready = notReady("InvalidExtraAllowedCIDRs", fmt.Sprintf("%v; existing policies are left as they are", err))
		return res, nil
	}
	res.podRangeFromNodes = len(r.PodCIDRs) == 0
	policies, err := r.policiesInGroups(ctx, iso)
	if err != nil {
		return nil, err
	}

	for _, from := range iso.Spec.Between {
		toGroup, _ := isolation.OtherGroup(iso, from.Name)
		p := isolation.PlanDirection(iso, from, toGroup, policies, currentMechanism(iso, from.Name))
		if p.Mechanism == isolation.Refused {
			// Rule S1: never widen access. None of our policies for this direction stay.
			res.refused = append(res.refused, fmt.Sprintf("%s → %s: %s", from.Name, toGroup.Name, strings.Join(p.Conflicts, ", ")))
			res.traffic = append(res.traffic, netsecv1alpha1.Traffic{From: from.Name, To: toGroup.Name, Message: refusedMessage(p.Conflicts)})
			continue
		}
		built, err := isolation.Policies(iso, from.Name, p.Mechanism, podRange, r.ExtraAllowedCIDRs)
		if err != nil {
			return nil, fmt.Errorf("build policies for %s->%s of %s: %w", from.Name, toGroup.Name, iso.Name, err)
		}
		t := netsecv1alpha1.Traffic{From: from.Name, To: toGroup.Name, Blocked: true, BlockedBy: p.Mechanism}
		for _, b := range built {
			t.Policies = append(t.Policies, b.Namespace+"/"+b.Name)
		}
		res.traffic = append(res.traffic, t)
		res.desired = append(res.desired, built...)
	}
	if len(res.refused) > 0 {
		res.ready = notReady("ConflictingPolicy", "another NetworkPolicy already allows this traffic and NetworkPolicy cannot deny it: "+strings.Join(res.refused, "; "))
	} else {
		res.ready = metav1.Condition{Type: condReady, Status: metav1.ConditionTrue, Reason: "Enforced", Message: "traffic is blocked both ways"}
	}
	return res, nil
}

// refusedMessage explains a direction we could not block, naming the policies in the way.
func refusedMessage(conflicts []string) string {
	conflicts = slices.Clone(conflicts)
	slices.Sort(conflicts)
	conflicts = slices.Compact(conflicts)
	verb := "already allows"
	if len(conflicts) > 1 {
		verb = "already allow"
	}
	return fmt.Sprintf("%s %s this traffic and NetworkPolicy cannot deny it", strings.Join(conflicts, ", "), verb)
}

func notReady(reason, msg string) metav1.Condition {
	return metav1.Condition{Type: condReady, Status: metav1.ConditionFalse, Reason: reason, Message: msg}
}

// protectedHits lists the group namespaces we must not touch.
func (r *NetworkIsolationReconciler) protectedHits(iso *netsecv1alpha1.NetworkIsolation) []string {
	var hit []string
	for _, ns := range allNamespaces(iso) {
		if strings.HasPrefix(ns, "kube-") || slices.Contains(r.ProtectedNamespaces, ns) {
			hit = append(hit, ns)
		}
	}
	return hit
}

// podCIDRs returns the cluster-wide pod range for the except list (the --pod-cidrs flag if
// set, else the ranges Nodes report) and the address of every Node.
func (r *NetworkIsolationReconciler) podCIDRs(ctx context.Context) ([]string, []isolation.Addrs, error) {
	nodes := &corev1.NodeList{}
	if err := r.List(ctx, nodes); err != nil {
		return nil, nil, fmt.Errorf("list nodes: %w", err)
	}
	var ranges []string
	addrs := make([]isolation.Addrs, 0, len(nodes.Items))
	for i := range nodes.Items {
		ranges = append(ranges, nodeCIDRs(&nodes.Items[i])...)
		addrs = append(addrs, isolation.Addrs{Name: nodes.Items[i].Name, IPs: nodeIPs(&nodes.Items[i])})
	}
	if len(r.PodCIDRs) > 0 {
		return r.PodCIDRs, addrs, nil
	}
	slices.Sort(ranges)
	return slices.Compact(ranges), addrs, nil
}

// nodeIPs returns the InternalIP and ExternalIP addresses of a Node.
func nodeIPs(n *corev1.Node) []string {
	var out []string
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP || a.Type == corev1.NodeExternalIP {
			out = append(out, a.Address)
		}
	}
	return out
}

func nodeCIDRs(n *corev1.Node) []string {
	if len(n.Spec.PodCIDRs) > 0 {
		return n.Spec.PodCIDRs
	}
	if n.Spec.PodCIDR != "" {
		return []string{n.Spec.PodCIDR}
	}
	return nil
}

// policiesInGroups lists every NetworkPolicy in the namespaces of both groups.
func (r *NetworkIsolationReconciler) policiesInGroups(ctx context.Context, iso *netsecv1alpha1.NetworkIsolation) ([]networkingv1.NetworkPolicy, error) {
	var out []networkingv1.NetworkPolicy
	for _, ns := range allNamespaces(iso) {
		list := &networkingv1.NetworkPolicyList{}
		if err := r.List(ctx, list, client.InNamespace(ns)); err != nil {
			return nil, fmt.Errorf("list policies in %s: %w", ns, err)
		}
		out = append(out, list.Items...)
	}
	return out, nil
}

// ownPolicies finds our policies cluster-wide by label, then keeps only those that pass
// IsOwn, so a forged label never gets a policy deleted.
func (r *NetworkIsolationReconciler) ownPolicies(ctx context.Context, iso *netsecv1alpha1.NetworkIsolation) ([]networkingv1.NetworkPolicy, error) {
	list := &networkingv1.NetworkPolicyList{}
	if err := r.List(ctx, list, client.MatchingLabels{isolation.LabelIsolationUID: string(iso.UID)}); err != nil {
		return nil, fmt.Errorf("list policies of isolation %s: %w", iso.Name, err)
	}
	var out []networkingv1.NetworkPolicy
	for _, p := range list.Items {
		if isolation.IsOwn(p, iso) {
			out = append(out, p)
		}
	}
	return out, nil
}

// missingNamespaces lists group namespaces that do not exist yet.
func (r *NetworkIsolationReconciler) missingNamespaces(ctx context.Context, iso *netsecv1alpha1.NetworkIsolation) ([]string, error) {
	var missing []string
	for _, name := range allNamespaces(iso) {
		err := r.Get(ctx, types.NamespacedName{Name: name}, &corev1.Namespace{})
		switch {
		case apierrors.IsNotFound(err):
			missing = append(missing, name)
		case err != nil:
			return nil, fmt.Errorf("get namespace %s: %w", name, err)
		}
	}
	return missing, nil
}

// keepExisting drops "namespace/name" entries whose namespace is missing.
func keepExisting(policies, missing []string) []string {
	var out []string
	for _, p := range policies {
		ns, _, _ := strings.Cut(p, "/")
		if !slices.Contains(missing, ns) {
			out = append(out, p)
		}
	}
	return out
}

// apply makes the policy match want. We write the whole object, not a server-side apply:
// apply only re-asserts the fields we own, so a tenant who adds a podSelector key or an
// extra rule would keep it. The policy is entirely ours, so any difference is overwritten.
func (r *NetworkIsolationReconciler) apply(ctx context.Context, want *networkingv1.NetworkPolicy) error {
	got := &networkingv1.NetworkPolicy{}
	err := r.APIReader.Get(ctx, client.ObjectKeyFromObject(want), got)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, want.DeepCopy(), client.FieldOwner(isolationManager)); err != nil {
			return fmt.Errorf("create policy %s/%s: %w", want.Namespace, want.Name, err)
		}
		logf.FromContext(ctx).Info("created policy", "policy", want.Namespace+"/"+want.Name)
		return nil
	}
	if err != nil {
		return fmt.Errorf("get policy %s/%s: %w", want.Namespace, want.Name, err)
	}
	if !differs(got, want) {
		return nil
	}
	got.Spec = want.Spec
	got.OwnerReferences = want.OwnerReferences
	if got.Labels == nil {
		got.Labels = map[string]string{}
	}
	maps.Copy(got.Labels, want.Labels)
	if got.Annotations == nil {
		got.Annotations = map[string]string{}
	}
	maps.Copy(got.Annotations, want.Annotations)
	if err := r.Update(ctx, got, client.FieldOwner(isolationManager)); err != nil {
		return fmt.Errorf("update policy %s/%s: %w", want.Namespace, want.Name, err)
	}
	logf.FromContext(ctx).Info("updated policy", "policy", want.Namespace+"/"+want.Name)
	return nil
}

// differs says whether got is missing anything want sets: the spec, our labels and
// annotation, or the owner reference. Labels and annotations others added are left alone.
func differs(got, want *networkingv1.NetworkPolicy) bool {
	hasAll := func(have, need map[string]string) bool {
		for k, v := range need {
			if have[k] != v {
				return false
			}
		}
		return true
	}
	return !equality.Semantic.DeepEqual(got.Spec, want.Spec) ||
		!equality.Semantic.DeepEqual(got.OwnerReferences, want.OwnerReferences) ||
		!hasAll(got.Labels, want.Labels) || !hasAll(got.Annotations, want.Annotations)
}

// prune deletes the policies in own that are not in desired. It returns how many it deleted.
func (r *NetworkIsolationReconciler) prune(ctx context.Context, own, desired []networkingv1.NetworkPolicy) (int, error) {
	want := map[types.NamespacedName]bool{}
	for _, p := range desired {
		want[client.ObjectKeyFromObject(&p)] = true
	}
	n := 0
	for i := range own {
		if want[client.ObjectKeyFromObject(&own[i])] {
			continue
		}
		err := r.Delete(ctx, &own[i])
		if apierrors.IsNotFound(err) {
			continue // already gone: not counted
		}
		if err != nil {
			return n, fmt.Errorf("delete policy %s/%s: %w", own[i].Namespace, own[i].Name, err)
		}
		n++
	}
	return n, nil
}

// podCounts is what we learn about pods, read straight from the API server.
type podCounts struct {
	groups      []netsecv1alpha1.GroupPods // in the order of spec.between
	hostNetwork []string                   // "namespace/name"
	overlap     []string
	pods        []isolation.Addrs // pod addresses, without hostNetwork pods, sorted by name
}

// countPods counts pods per group. The Pod list is not cached, to keep memory flat.
func (r *NetworkIsolationReconciler) countPods(ctx context.Context, iso *netsecv1alpha1.NetworkIsolation, missing []string) (podCounts, error) {
	var c podCounts
	seen := make([]map[string]bool, len(iso.Spec.Between))
	host := map[string]bool{}
	ips := map[string][]string{}
	for i, group := range iso.Spec.Between {
		seen[i] = map[string]bool{}
		sel, err := metav1.LabelSelectorAsSelector(&group.PodSelector)
		if err != nil {
			return c, fmt.Errorf("group %s has an invalid podSelector: %w", group.Name, err)
		}
		for _, ns := range group.Namespaces {
			if slices.Contains(missing, ns) {
				continue
			}
			pods := &corev1.PodList{}
			if err := r.APIReader.List(ctx, pods, client.InNamespace(ns), client.MatchingLabelsSelector{Selector: sel}); err != nil {
				return c, fmt.Errorf("list pods in %s: %w", ns, err)
			}
			for _, p := range pods.Items {
				key := p.Namespace + "/" + p.Name
				seen[i][key] = true
				if p.Spec.HostNetwork {
					host[key] = true
				} else {
					ips[key] = podIPs(&p)
				}
			}
		}
		c.groups = append(c.groups, netsecv1alpha1.GroupPods{Group: group.Name, Count: int32(len(seen[i]))})
	}
	if len(seen) == 2 {
		for k := range seen[0] {
			if seen[1][k] {
				c.overlap = append(c.overlap, k)
			}
		}
	}
	for k := range host {
		c.hostNetwork = append(c.hostNetwork, k)
	}
	slices.Sort(c.overlap)
	slices.Sort(c.hostNetwork)
	for k, v := range ips {
		if len(v) > 0 { // no IP yet: nothing to check
			c.pods = append(c.pods, isolation.Addrs{Name: k, IPs: v})
		}
	}
	slices.SortFunc(c.pods, func(a, b isolation.Addrs) int { return strings.Compare(a.Name, b.Name) })
	return c, nil
}

// podIPs returns every address in the pod's status, falling back to the single podIP.
func podIPs(p *corev1.Pod) []string {
	var out []string
	for _, ip := range p.Status.PodIPs {
		out = append(out, ip.IP)
	}
	if len(out) == 0 && p.Status.PodIP != "" {
		out = append(out, p.Status.PodIP)
	}
	return out
}

// emitEvents reports changes. Mechanism changes compare against the last written status.
func (r *NetworkIsolationReconciler) emitEvents(iso *netsecv1alpha1.NetworkIsolation, res *result) {
	for _, t := range res.traffic {
		if !t.Blocked {
			continue
		}
		cur := currentMechanism(iso, t.From)
		switch {
		case cur == "":
			r.Recorder.Eventf(iso, nil, corev1.EventTypeNormal, "PolicyApplied", "Apply", "%s → %s is blocked with an %s", t.From, t.To, t.BlockedBy)
		case cur != t.BlockedBy:
			r.Recorder.Eventf(iso, nil, corev1.EventTypeNormal, "MechanismSwitched", "Apply", "%s → %s switched from an %s to an %s", t.From, t.To, cur, t.BlockedBy)
		}
	}
	// Say these once per distinct message, not on every refresh.
	old := meta.FindStatusCondition(iso.Status.Conditions, condReady)
	changed := old == nil || old.Message != res.ready.Message
	switch {
	case res.ready.Reason == "ConflictingPolicy" && changed:
		r.Recorder.Eventf(iso, nil, corev1.EventTypeWarning, "IsolationRefused", "Plan", "%s", res.ready.Message)
	case res.ready.Reason == reasonPodRangeMismatch && changed:
		r.Recorder.Eventf(iso, nil, corev1.EventTypeWarning, "PodRangeMismatch", "Check", "%s", res.ready.Message)
	}
}

// writeStatus sets conditions, traffic, pod counts and the summary, and writes only when something changed.
func (r *NetworkIsolationReconciler) writeStatus(ctx context.Context, iso *netsecv1alpha1.NetworkIsolation, res *result, missing []string, c podCounts) error {
	base := iso.DeepCopy()
	old := iso.Status.DeepCopy()
	st := &iso.Status
	st.ObservedGeneration = iso.Generation
	st.Traffic = res.traffic
	st.Summary = isolation.WithMismatch(isolation.Summary(res.traffic, c.groups, res.notEnforced), len(res.mismatch))
	st.Pods = c.groups

	ready := res.ready
	if len(missing) > 0 && ready.Status == metav1.ConditionTrue {
		ready = notReady("NamespaceMissing", "namespaces do not exist yet: "+strings.Join(missing, ", "))
	}
	prev := meta.FindStatusCondition(old.Conditions, condReady)
	prevReason := ""
	if prev != nil {
		prevReason = prev.Reason
	}
	setCondition(st, iso.Generation, ready)
	setCondition(st, iso.Generation, degraded(res, missing, c))

	isolationReady.WithLabelValues(iso.Name).Set(boolToFloat(ready.Status == metav1.ConditionTrue))
	if equality.Semantic.DeepEqual(old, st) {
		noteReason(iso.Name, ready.Reason, prevReason)
		return nil
	}
	// Patch, not Update: a stale cached copy after the finalizer write must not cause a conflict.
	if err := r.Status().Patch(ctx, iso, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("update status of %s: %w", iso.Name, err)
	}
	// Count after the write, and only when the reason changed: refreshes don't count.
	if noteReason(iso.Name, ready.Reason, prevReason) {
		isolationRefusals.WithLabelValues(ready.Reason).Inc()
	}
	return nil
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func setCondition(st *netsecv1alpha1.NetworkIsolationStatus, gen int64, c metav1.Condition) {
	c.ObservedGeneration = gen
	meta.SetStatusCondition(&st.Conditions, c)
}

// degraded lists everything that works but is not fully enforced. The reason is the
// first problem found; the message names all of them. The order is by how much the problem
// can hurt: pods outside the pod range may escape isolation, nodes inside it get their
// traffic blocked, and the rest are about what is or is not covered yet.
func degraded(res *result, missing []string, c podCounts) metav1.Condition {
	var reasons, msgs []string
	add := func(reason, msg string) {
		reasons = append(reasons, reason)
		msgs = append(msgs, msg)
	}
	// When Ready is PodRangeMismatch, that condition already carries this message.
	if len(res.mismatch) > 0 && res.ready.Reason != reasonPodRangeMismatch {
		add(reasonPodRangeMismatch, mismatchMessage(res.mismatch))
	}
	if len(res.nodesInRange) > 0 {
		add("NodesInPodRange", "node addresses are inside the pod range: "+nameList(res.nodesInRange)+
			"; traffic that arrives from node IPs (NodePort, LoadBalancer with externalTrafficPolicy Cluster, some health checks) is blocked by NetSec's policies")
	}
	if len(missing) > 0 {
		add("NamespaceMissing", "namespaces do not exist yet: "+strings.Join(missing, ", "))
	}
	if len(c.hostNetwork) > 0 {
		add("HostNetworkPods", "hostNetwork pods cannot be isolated: "+nameList(c.hostNetwork))
	}
	if len(c.overlap) > 0 {
		add("OverlappingGroups", "pods match both groups: "+nameList(c.overlap))
	}
	if res.ready.Status == metav1.ConditionTrue && slices.ContainsFunc(c.groups, func(g netsecv1alpha1.GroupPods) bool { return g.Count == 0 }) {
		counts := make([]string, 0, len(c.groups))
		for _, g := range c.groups {
			counts = append(counts, fmt.Sprintf("%s: %d", g.Group, g.Count))
		}
		add("NoMatchingPods", fmt.Sprintf("no pods match yet (%s)", strings.Join(counts, ", ")))
	}
	if res.podRangeFromNodes && !res.keep {
		add("PodRangeFromNodes", "set --pod-cidrs to the cluster pod range")
	}
	if len(reasons) == 0 {
		return metav1.Condition{Type: condDegraded, Status: metav1.ConditionFalse, Reason: "NoIssues", Message: "no issues found"}
	}
	return metav1.Condition{Type: condDegraded, Status: metav1.ConditionTrue, Reason: reasons[0], Message: strings.Join(msgs, "; ")}
}

func mismatchMessage(mismatch []string) string {
	return fmt.Sprintf("%d pods have an IP outside the pod range: %s; policies are still applied, but they may not isolate these pods; set --pod-cidrs to the range those pods use",
		len(mismatch), nameList(mismatch))
}

func nameList(names []string) string {
	if len(names) <= maxNamedPods {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:maxNamedPods], ", "), len(names)-maxNamedPods)
}

// allNamespaces is the unique, sorted namespaces of both groups.
func allNamespaces(iso *netsecv1alpha1.NetworkIsolation) []string {
	var out []string
	for _, g := range iso.Spec.Between {
		out = append(out, g.Namespaces...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// currentMechanism reads the mechanism last written to status for the direction from -> other group.
func currentMechanism(iso *netsecv1alpha1.NetworkIsolation, from string) netsecv1alpha1.Mechanism {
	for _, t := range iso.Status.Traffic {
		if t.From == from && t.Blocked {
			return t.BlockedBy
		}
	}
	return ""
}

// SetupWithManager sets up the controller with the Manager.
func (r *NetworkIsolationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&netsecv1alpha1.NetworkIsolation{}).
		// Every policy, ours included: an edit or delete of ours restores it.
		Watches(&networkingv1.NetworkPolicy{}, handler.EnqueueRequestsFromMapFunc(r.isolationsForObject)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.isolationsForObject)).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.allIsolations),
			builder.WithPredicates(podRangeChanged())).
		Named("networkisolation").
		Complete(r)
}

// isolationsForObject maps a NetworkPolicy or Namespace to the isolations that have its namespace in a group.
func (r *NetworkIsolationReconciler) isolationsForObject(ctx context.Context, obj client.Object) []reconcile.Request {
	ns := obj.GetNamespace()
	if _, ok := obj.(*corev1.Namespace); ok {
		ns = obj.GetName()
	}
	list := &netsecv1alpha1.NetworkIsolationList{}
	if err := r.List(ctx, list); err != nil {
		logf.FromContext(ctx).Error(err, "list isolations for watch event")
		return nil
	}
	var out []reconcile.Request
	for i := range list.Items {
		if slices.Contains(allNamespaces(&list.Items[i]), ns) {
			out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return out
}

func (r *NetworkIsolationReconciler) allIsolations(ctx context.Context, _ client.Object) []reconcile.Request {
	list := &netsecv1alpha1.NetworkIsolationList{}
	if err := r.List(ctx, list); err != nil {
		logf.FromContext(ctx).Error(err, "list isolations for node event")
		return nil
	}
	out := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return out
}

// podRangeChanged lets Node events through only when a node appears, goes, or changes its
// pod ranges or its addresses.
func podRangeChanged() predicate.Predicate {
	return predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			o, ok1 := e.ObjectOld.(*corev1.Node)
			n, ok2 := e.ObjectNew.(*corev1.Node)
			return !ok1 || !ok2 || !slices.Equal(nodeCIDRs(o), nodeCIDRs(n)) || !slices.Equal(nodeIPs(o), nodeIPs(n))
		},
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}
