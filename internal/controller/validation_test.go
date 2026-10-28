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
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	netsecv1alpha1 "github.com/nrndev/netsec/api/v1alpha1"
)

// Names shared by the envtest specs in this package.
const (
	tenantA  = "tenant-a"
	tenantB  = "tenant-b"
	appLabel = "app"
)

// These tests send objects to envtest's real API server to check the CRD schema
// and CEL rules. Creates use server-side dry run, so nothing is stored.
var _ = Describe("API validation", func() {
	ctx := context.Background()

	group := func(ns string, labels map[string]string) netsecv1alpha1.PodGroup {
		return netsecv1alpha1.PodGroup{
			Namespaces:  []string{ns},
			PodSelector: metav1.LabelSelector{MatchLabels: labels},
		}
	}
	withExpr := func(s netsecv1alpha1.PodGroup, values ...string) netsecv1alpha1.PodGroup {
		s.PodSelector.MatchExpressions = []metav1.LabelSelectorRequirement{
			{Key: appLabel, Operator: metav1.LabelSelectorOpIn, Values: values},
		}
		return s
	}
	withNamespaces := func(ns ...string) netsecv1alpha1.PodGroup {
		return netsecv1alpha1.PodGroup{Namespaces: append([]string{}, ns...)} // never nil, so it is sent as []
	}
	// withGroups builds an isolation with any number of groups, named g0, g1, ...
	withGroups := func(gs ...netsecv1alpha1.PodGroup) *netsecv1alpha1.NetworkIsolation {
		for i := range gs {
			gs[i].Name = fmt.Sprintf("g%d", i)
		}
		return &netsecv1alpha1.NetworkIsolation{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "iso-"},
			Spec:       netsecv1alpha1.NetworkIsolationSpec{Between: gs},
		}
	}
	// named builds an isolation with the given group names.
	named := func(a netsecv1alpha1.PodGroup, an string, b netsecv1alpha1.PodGroup, bn string) *netsecv1alpha1.NetworkIsolation {
		a.Name, b.Name = an, bn
		return &netsecv1alpha1.NetworkIsolation{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "iso-"},
			Spec:       netsecv1alpha1.NetworkIsolationSpec{Between: []netsecv1alpha1.PodGroup{a, b}},
		}
	}
	// iso names the two groups "gateway" and "dashboard".
	iso := func(a, b netsecv1alpha1.PodGroup) *netsecv1alpha1.NetworkIsolation {
		return named(a, gatewayApp, b, dashboardApp)
	}
	wh := func(mutate func(*netsecv1alpha1.WorkloadHardeningSpec)) *netsecv1alpha1.WorkloadHardening {
		obj := &netsecv1alpha1.WorkloadHardening{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "wh-"},
			Spec:       netsecv1alpha1.WorkloadHardeningSpec{Namespaces: []string{tenantA}},
		}
		mutate(&obj.Spec)
		return obj
	}
	names := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("ns-%d", i)
		}
		return out
	}
	gateway := map[string]string{appLabel: gatewayApp}
	dashboard := map[string]string{appLabel: dashboardApp}

	DescribeTable("rejects an invalid NetworkIsolation",
		func(obj *netsecv1alpha1.NetworkIsolation, msg string) {
			Expect(k8sClient.Create(ctx, obj, client.DryRunAll)).To(MatchError(ContainSubstring(msg)))
		},
		Entry("two identical groups", iso(group(tenantA, gateway), group(tenantA, gateway)), "between: the two groups must differ"),
		Entry("two identical groups, both every pod", iso(group(tenantA, nil), group(tenantA, nil)), "between: the two groups must differ"),
		Entry("two identical groups with matchExpressions",
			iso(withExpr(group(tenantA, nil), "x"), withExpr(group(tenantA, nil), "x")), "between: the two groups must differ"),
		Entry("kube-system namespace", iso(group("kube-system", nil), group(tenantB, nil)), "namespaces must not start with kube-"),
		Entry("namespace is not a DNS label", iso(group("Tenant_A", nil), group(tenantB, nil)), "should match"),
		Entry("duplicate namespaces", iso(withNamespaces(tenantA, tenantA), group(tenantB, nil)), "Duplicate value"),
		Entry("no namespaces", iso(withNamespaces(), group(tenantB, nil)), "should have at least 1 items"),
		Entry("11 namespaces", iso(withNamespaces(names(11)...), group(tenantB, nil)), "must have at most 10 items"),
		Entry("one group", withGroups(group(tenantA, nil)), "should have at least 2 items"),
		Entry("three groups", withGroups(group(tenantA, nil), group(tenantB, nil), group("tenant-c", nil)), "must have at most 2 items"),
		Entry("same group name twice", named(group(tenantA, nil), "x", group(tenantB, nil), "x"), "Duplicate value"),
		Entry("group name is not a DNS label", named(group(tenantA, nil), "Gate_way", group(tenantB, nil), "dashboard"), "should match"),
		Entry("group name over 63 characters", named(group(tenantA, nil), strings.Repeat("x", 64), group(tenantB, nil), "dashboard"), "Too long"),
		Entry("group without a name", named(group(tenantA, nil), "", group(tenantB, nil), "dashboard"), "should match"),
	)

	// badSelector builds a gateway group whose selector is sel.
	badSelector := func(sel metav1.LabelSelector) *netsecv1alpha1.NetworkIsolation {
		g := group(tenantA, nil)
		g.PodSelector = sel
		return iso(g, group(tenantB, dashboard))
	}
	expr := func(op metav1.LabelSelectorOperator, key string, values ...string) metav1.LabelSelector {
		return metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: key, Operator: op, Values: values}}}
	}
	DescribeTable("rejects a bad label selector",
		func(sel metav1.LabelSelector, msg string) {
			Expect(k8sClient.Create(ctx, badSelector(sel), client.DryRunAll)).To(MatchError(ContainSubstring(msg)))
			// WorkloadHardening shares the rules.
			obj := wh(func(s *netsecv1alpha1.WorkloadHardeningSpec) { s.WorkloadSelector = sel })
			Expect(k8sClient.Create(ctx, obj, client.DryRunAll)).To(MatchError(ContainSubstring(msg)))
		},
		Entry("unknown operator", expr("Foo", appLabel, "x"), "operator must be In, NotIn, Exists or DoesNotExist"),
		Entry("In without values", expr(metav1.LabelSelectorOpIn, appLabel), "In and NotIn need at least one value"),
		Entry("NotIn without values", expr(metav1.LabelSelectorOpNotIn, appLabel), "In and NotIn need at least one value"),
		Entry("Exists with values", expr(metav1.LabelSelectorOpExists, appLabel, "x"), "Exists and DoesNotExist must have none"),
		Entry("DoesNotExist with values", expr(metav1.LabelSelectorOpDoesNotExist, appLabel, "x"), "Exists and DoesNotExist must have none"),
	)

	It("accepts well-formed selectors", func() {
		sel := expr(metav1.LabelSelectorOpIn, "example.com/tier", "front-end", "a_b.c")
		sel.MatchLabels = map[string]string{appLabel: "gw"}
		Expect(k8sClient.Create(ctx, badSelector(sel), client.DryRunAll)).To(Succeed())
		Expect(k8sClient.Create(ctx, badSelector(expr(metav1.LabelSelectorOpExists, appLabel)), client.DryRunAll)).To(Succeed())
	})

	It("rejects a reason over 256 characters", func() {
		obj := iso(group(tenantA, nil), group(tenantB, nil))
		obj.Spec.Reason = strings.Repeat("x", 257)
		Expect(k8sClient.Create(ctx, obj, client.DryRunAll)).To(MatchError(ContainSubstring("Too long")))
	})

	DescribeTable("accepts groups that differ",
		func(obj *netsecv1alpha1.NetworkIsolation) {
			Expect(k8sClient.Create(ctx, obj, client.DryRunAll)).To(Succeed())
		},
		Entry("different namespaces", iso(group(tenantA, nil), group(tenantB, nil))),
		Entry("same namespace, different labels", iso(group(tenantA, gateway), group(tenantA, dashboard))),
		Entry("same namespace, different matchExpressions",
			iso(withExpr(group(tenantA, nil), "x"), withExpr(group(tenantA, nil), "y"))),
		Entry("same labels, only one has matchExpressions",
			iso(group(tenantA, gateway), withExpr(group(tenantA, gateway), "y"))),
	)

	It("accepts a change to a NetworkIsolation spec", func() {
		obj := iso(group(tenantA, gateway), group(tenantB, dashboard))
		Expect(k8sClient.Create(ctx, obj)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, obj)).To(Succeed()) })

		obj.Spec.Reason = "changed"
		obj.Spec.Between[0].Namespaces = []string{tenantA, "tenant-c"}
		Expect(k8sClient.Update(ctx, obj)).To(Succeed())
	})

	DescribeTable("rejects an invalid WorkloadHardening",
		func(mutate func(*netsecv1alpha1.WorkloadHardeningSpec), msg string) {
			Expect(k8sClient.Create(ctx, wh(mutate), client.DryRunAll)).To(MatchError(ContainSubstring(msg)))
		},
		Entry("kube-system namespace", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.Namespaces = []string{tenantA, "kube-system"}
		}, "namespaces must not start with kube-"),
		Entry("21 namespaces", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.Namespaces = names(21)
		}, "must have at most 20 items"),
		Entry("Apply without approvedPlanHash", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.Action = netsecv1alpha1.ActionApply
		}, "approvedPlanHash is required when action is Apply"),
		Entry("approvedPlanHash is not a plan hash", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.ApprovedPlanHash = "not-a-hash"
		}, "should match"),
		Entry("unknown kind", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.WorkloadKinds = []netsecv1alpha1.WorkloadKind{"Job"}
		}, "Unsupported value"),
		Entry("memory limit below the request", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.DefaultResources.Requests.Memory = resource.MustParse("1Gi")
			s.DefaultResources.Limits.Memory = resource.MustParse("512Mi")
		}, "limits.memory must be at least requests.memory"),
		Entry("cpu request over 2", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.DefaultResources.Requests.CPU = resource.MustParse("3")
		}, "requests.cpu must be more than 0 and at most 2"),
		Entry("negative cpu request", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.DefaultResources.Requests.CPU = resource.MustParse("-100m")
		}, "requests.cpu must be more than 0 and at most 2"),
		Entry("memory request over 4Gi", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.DefaultResources.Requests.Memory = resource.MustParse("5Gi")
			s.DefaultResources.Limits.Memory = resource.MustParse("6Gi")
		}, "requests.memory must be more than 0 and at most 4Gi"),
		Entry("memory limit over 8Gi", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.DefaultResources.Limits.Memory = resource.MustParse("9Gi")
		}, "limits.memory must be at most 8Gi"),
		Entry("maxConcurrentRollouts over 10", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.MaxConcurrentRollouts = 11
		}, "should be less than or equal to 10"),
		Entry("rolloutTimeout under 1m", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.RolloutTimeout = metav1.Duration{Duration: 30 * time.Second}
		}, "rolloutTimeout must be between 1m and 30m"),
		Entry("rolloutTimeout over 30m", func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.RolloutTimeout = metav1.Duration{Duration: 31 * time.Minute}
		}, "rolloutTimeout must be between 1m and 30m"),
	)

	It("fills in the defaults and accepts an approved Apply", func() {
		obj := wh(func(s *netsecv1alpha1.WorkloadHardeningSpec) {
			s.Action = netsecv1alpha1.ActionApply
			s.ApprovedPlanHash = "0123456789abcdef"
		})
		Expect(k8sClient.Create(ctx, obj, client.DryRunAll)).To(Succeed())

		Expect(obj.Spec.WorkloadKinds).To(HaveLen(4))
		Expect(obj.Spec.MaxConcurrentRollouts).To(Equal(int32(1)))
		Expect(obj.Spec.RolloutTimeout.Duration).To(Equal(5 * time.Minute))
		Expect(*obj.Spec.DefaultResources.Enabled).To(BeTrue())
		Expect(obj.Spec.DefaultResources.Requests.CPU.String()).To(Equal("100m"))
		Expect(obj.Spec.DefaultResources.Requests.Memory.String()).To(Equal("128Mi"))
		Expect(obj.Spec.DefaultResources.Limits.Memory.String()).To(Equal("512Mi"))
	})
})
