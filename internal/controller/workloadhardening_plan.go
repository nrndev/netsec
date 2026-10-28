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
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
	"github.com/nrndev/netsec/internal/hardening"
)

// maxListedSkips caps the skipped workloads written to status.
const maxListedSkips = 200

var errInvalidSelector = errors.New("invalid selector")

// found is a workload read during planning, with what we need to plan it.
type found struct {
	template   *corev1.PodTemplateSpec
	generation int64
	// limitRanges are the LimitRanges of the workload's namespace.
	limitRanges []corev1.LimitRange
}

// builtPlan is one fresh plan, before it is written to status.
type builtPlan struct {
	workloads []netsecv1alpha1.PlannedWorkload
	hash      string
	// moreSkipped is how many skipped workloads did not fit in the list.
	moreSkipped int
	// reportOnly lists Jobs and bare Pods. Status cannot hold them: its kind enum has only the four workload kinds.
	reportOnly []string
}

func (b *builtPlan) pending() int {
	n := 0
	for _, w := range b.workloads {
		if w.State == netsecv1alpha1.StatePending {
			n++
		}
	}
	return n
}

// message is the Ready condition message.
func (b *builtPlan) message() string {
	msg := fmt.Sprintf("%d workloads will change", b.pending())
	if len(b.reportOnly) > 0 {
		msg += "; report only (never changed): " + nameList(b.reportOnly)
	}
	if b.moreSkipped > 0 {
		msg += fmt.Sprintf("; %d more skipped workloads are not listed", b.moreSkipped)
	}
	return msg
}

// buildPlan follows design §4.3: list and classify candidates, plan each target, and
// dry-run the patch. It reads through rd and changes nothing.
func (p *pass) buildPlan(ctx context.Context, rd client.Reader) (*builtPlan, error) {
	spec := &p.wh.Spec
	sel, err := metav1.LabelSelectorAsSelector(&spec.WorkloadSelector)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidSelector, err)
	}
	candidates, workloads, err := p.candidates(ctx, rd, sel)
	if err != nil {
		return nil, err
	}
	targets, skipped, err := hardening.Classify(candidates, p.r.ProtectedNamespaces)
	if err != nil {
		return nil, err
	}

	// Another run that is rolling out these workloads owns them for now.
	runs := &netsecv1alpha1.WorkloadHardeningList{}
	if err := p.r.List(ctx, runs); err != nil {
		return nil, fmt.Errorf("list WorkloadHardenings: %w", err)
	}
	active := hardening.ActiveSet(runs.Items, p.wh.UID)
	var mine []hardening.Candidate
	for _, c := range targets {
		if run, ok := active[hardening.WorkloadKey(netsecv1alpha1.WorkloadKind(c.Kind), c.Namespace, c.Name)]; ok {
			skipped = append(skipped, hardening.Skip{Candidate: c, Reason: "being changed by WorkloadHardening " + run})
			continue
		}
		mine = append(mine, c)
	}

	bp := &builtPlan{}
	sortCandidates(mine)
	for _, c := range mine {
		w, err := p.planTarget(ctx, c, workloads[candidateKey(c)])
		if err != nil {
			return nil, err
		}
		bp.workloads = append(bp.workloads, w)
	}
	var pending []netsecv1alpha1.PlannedWorkload
	for _, w := range bp.workloads {
		if w.State == netsecv1alpha1.StatePending {
			pending = append(pending, w)
		}
	}
	bp.hash = hardening.PlanHash(pending)

	slices.SortFunc(skipped, func(a, b hardening.Skip) int { return compareCandidates(a.Candidate, b.Candidate) })
	listed := 0
	for _, s := range skipped {
		c := s.Candidate
		if c.Kind == "Job" || c.Kind == "Pod" {
			bp.reportOnly = append(bp.reportOnly, fmt.Sprintf("%s %s/%s", c.Kind, c.Namespace, c.Name))
			continue
		}
		if listed == maxListedSkips {
			bp.moreSkipped++
			continue
		}
		listed++
		bp.workloads = append(bp.workloads, netsecv1alpha1.PlannedWorkload{
			Kind: netsecv1alpha1.WorkloadKind(c.Kind), Namespace: c.Namespace, Name: c.Name,
			State: netsecv1alpha1.StateSkipped, Reason: s.Reason,
		})
	}
	return bp, nil
}

// planTarget plans one workload and dry-runs the patch.
func (p *pass) planTarget(ctx context.Context, c hardening.Candidate, f found) (netsecv1alpha1.PlannedWorkload, error) {
	spec := &p.wh.Spec
	w := netsecv1alpha1.PlannedWorkload{
		Kind: netsecv1alpha1.WorkloadKind(c.Kind), Namespace: c.Namespace, Name: c.Name, Generation: f.generation,
	}
	tp := hardening.PlanTemplate(f.template, spec.StrictSecurity, spec.DefaultResources, f.limitRanges)
	w.Warnings = tp.Warnings
	if len(tp.Changes) == 0 {
		w.State = netsecv1alpha1.StateNoChange
		return w, nil
	}
	ac, err := hardening.ApplyConfig(w.Kind, w.Namespace, w.Name, tp)
	if err != nil {
		return w, err
	}
	if _, err := p.ssa(ctx, w, ac, true); err != nil {
		msg, rejected := hardening.Rejection(err)
		if !rejected {
			return w, err
		}
		w.State, w.Reason = netsecv1alpha1.StateFailed, "WouldFail: "+msg
		return w, nil
	}
	w.State, w.Changes = netsecv1alpha1.StatePending, tp.Changes
	return w, nil
}

// candidates lists the workloads in the target namespaces that match the selector, and
// the Jobs and bare Pods in them, which are only reported. Workloads come from rd; Jobs and
// bare Pods are always read straight from the API server.
func (p *pass) candidates(ctx context.Context, rd client.Reader, sel labels.Selector) ([]hardening.Candidate, map[string]found, error) {
	var out []hardening.Candidate
	workloads := map[string]found{}
	kinds := p.wh.Spec.WorkloadKinds
	if len(kinds) == 0 {
		kinds = []netsecv1alpha1.WorkloadKind{netsecv1alpha1.KindDeployment, netsecv1alpha1.KindStatefulSet, netsecv1alpha1.KindDaemonSet, netsecv1alpha1.KindCronJob}
	}
	for _, ns := range p.wh.Spec.Namespaces {
		nsLabels, err := namespaceLabels(ctx, rd, ns)
		if err != nil {
			return nil, nil, err
		}
		if nsLabels == nil {
			continue // the namespace does not exist (yet): nothing to list
		}
		limitRanges, err := listLimitRanges(ctx, p.r.APIReader, ns)
		if err != nil {
			return nil, nil, err
		}
		opts := []client.ListOption{client.InNamespace(ns), client.MatchingLabelsSelector{Selector: sel}}
		add := func(kind string, m *metav1.ObjectMeta, tpl *corev1.PodTemplateSpec, gen int64) {
			c := hardening.Candidate{
				Kind: kind, Namespace: ns, Name: m.Name, Labels: m.Labels, Annotations: m.Annotations,
				OwnerReferences: m.OwnerReferences, NamespaceLabels: nsLabels,
			}
			out = append(out, c)
			if tpl != nil {
				workloads[candidateKey(c)] = found{template: tpl, generation: gen, limitRanges: limitRanges}
			}
		}
		for _, kind := range kinds {
			switch kind {
			case netsecv1alpha1.KindDeployment:
				l := &appsv1.DeploymentList{}
				if err := rd.List(ctx, l, opts...); err != nil {
					return nil, nil, fmt.Errorf("list Deployments in %s: %w", ns, err)
				}
				for i := range l.Items {
					add(string(kind), &l.Items[i].ObjectMeta, &l.Items[i].Spec.Template, l.Items[i].Generation)
				}
			case netsecv1alpha1.KindStatefulSet:
				l := &appsv1.StatefulSetList{}
				if err := rd.List(ctx, l, opts...); err != nil {
					return nil, nil, fmt.Errorf("list StatefulSets in %s: %w", ns, err)
				}
				for i := range l.Items {
					add(string(kind), &l.Items[i].ObjectMeta, &l.Items[i].Spec.Template, l.Items[i].Generation)
				}
			case netsecv1alpha1.KindDaemonSet:
				l := &appsv1.DaemonSetList{}
				if err := rd.List(ctx, l, opts...); err != nil {
					return nil, nil, fmt.Errorf("list DaemonSets in %s: %w", ns, err)
				}
				for i := range l.Items {
					add(string(kind), &l.Items[i].ObjectMeta, &l.Items[i].Spec.Template, l.Items[i].Generation)
				}
			case netsecv1alpha1.KindCronJob:
				l := &batchv1.CronJobList{}
				if err := rd.List(ctx, l, opts...); err != nil {
					return nil, nil, fmt.Errorf("list CronJobs in %s: %w", ns, err)
				}
				for i := range l.Items {
					add(string(kind), &l.Items[i].ObjectMeta, &l.Items[i].Spec.JobTemplate.Spec.Template, l.Items[i].Generation)
				}
			}
		}
		// Jobs are only reported, so read them live: the cache would start a cluster-wide Job
		// watch that our RBAC does not allow.
		jobs := &batchv1.JobList{}
		if err := p.r.APIReader.List(ctx, jobs, opts...); err != nil {
			return nil, nil, fmt.Errorf("list Jobs in %s: %w", ns, err)
		}
		for i := range jobs.Items {
			if metav1.GetControllerOf(&jobs.Items[i]) == nil {
				add("Job", &jobs.Items[i].ObjectMeta, nil, 0)
			}
		}
		pods := &corev1.PodList{}
		if err := p.r.APIReader.List(ctx, pods, opts...); err != nil {
			return nil, nil, fmt.Errorf("list Pods in %s: %w", ns, err)
		}
		for i := range pods.Items {
			if metav1.GetControllerOf(&pods.Items[i]) == nil {
				add("Pod", &pods.Items[i].ObjectMeta, nil, 0)
			}
		}
	}
	return out, workloads, nil
}

// namespaceLabels returns the namespace's labels (never nil), or nil if it does not exist.
func namespaceLabels(ctx context.Context, rd client.Reader, name string) (map[string]string, error) {
	ns := &corev1.Namespace{}
	if err := rd.Get(ctx, client.ObjectKey{Name: name}, ns); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return nil, nil
		}
		return nil, fmt.Errorf("get namespace %s: %w", name, err)
	}
	if ns.Labels == nil {
		return map[string]string{}, nil
	}
	return ns.Labels, nil
}

// listLimitRanges reads straight from the API server, like Pods and Jobs, so we need no
// cluster-wide LimitRange watch.
func listLimitRanges(ctx context.Context, rd client.Reader, ns string) ([]corev1.LimitRange, error) {
	l := &corev1.LimitRangeList{}
	if err := rd.List(ctx, l, client.InNamespace(ns)); err != nil {
		return nil, fmt.Errorf("list LimitRanges in %s: %w", ns, err)
	}
	return l.Items, nil
}

func candidateKey(c hardening.Candidate) string {
	return hardening.WorkloadKey(netsecv1alpha1.WorkloadKind(c.Kind), c.Namespace, c.Name)
}

func compareCandidates(a, b hardening.Candidate) int {
	return strings.Compare(candidateKey(a), candidateKey(b))
}

func sortCandidates(cs []hardening.Candidate) {
	slices.SortFunc(cs, compareCandidates)
}
