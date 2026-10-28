//go:build e2e

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

package e2e

import (
	"fmt"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/nrndev/netsec/test/utils"
)

// endpoint is something a probe can reach: by pod IP and by Service name.
type endpoint struct {
	name string
	pod  utils.Pod
	port int
	svc  string
}

// world finds the pods and builds the traffic matrix for the e2e-a..d namespaces.
// Sources: gw (A, app=gateway), worker (A, app=worker), dash (B), c, d.
// Targets: gw, dash, c.
type world struct{ gw, worker, dash, c, d endpoint }

func findWorld() (world, error) {
	find := func(name, ns, app string, port int) (endpoint, error) {
		p, err := utils.PodByLabel(ns, "app="+app)
		return endpoint{name: name, pod: p, port: port, svc: fmt.Sprintf("http://%s.%s/", app, ns)}, err
	}
	var w world
	var err error
	for _, f := range []struct {
		dst           *endpoint
		name, ns, app string
		port          int
	}{
		{&w.gw, "gw", "e2e-a", "gateway", 80}, {&w.worker, "worker", "e2e-a", "worker", 8080},
		{&w.dash, "dash", "e2e-b", "dashboard", 80}, {&w.c, "c", "e2e-c", "client", 8080},
		{&w.d, "d", "e2e-d", "client", 8080},
	} {
		if *f.dst, err = find(f.name, f.ns, f.app, f.port); err != nil {
			return w, err
		}
	}
	return w, nil
}

// matrix sends every probe. Probes named in blocked must fail; all others must get through.
// A probe name is "<from>→<to> ip" or "<from>→<to> svc".
func matrix(blocked ...string) ([]utils.Result, error) {
	w, err := findWorld()
	if err != nil {
		return nil, err
	}
	isBlocked := map[string]bool{}
	for _, b := range blocked {
		isBlocked[b] = true
	}
	var probes []utils.Probe
	for _, from := range []endpoint{w.gw, w.worker, w.dash, w.c, w.d} {
		for _, to := range []endpoint{w.gw, w.dash, w.c} {
			if from.name == to.name {
				continue
			}
			for _, how := range []struct{ kind, url string }{
				{"ip", fmt.Sprintf("http://%s:%d/", to.pod.IP, to.port)}, {"svc", to.svc},
			} {
				name := fmt.Sprintf("%s→%s %s", from.name, to.name, how.kind)
				probes = append(probes, utils.Probe{Name: name, From: from.pod, URL: how.url, Want: !isBlocked[name]})
			}
		}
	}
	return utils.RunMatrix(probes)
}

// matrixMismatches is matrix for Eventually: policies take about a second to land.
func matrixMismatches(blocked ...string) func() ([]string, error) {
	return func() ([]string, error) {
		res, err := matrix(blocked...)
		return utils.Mismatches(res), err
	}
}

// both lists the ip and svc probe names for each from→to pair.
func both(pairs ...string) []string {
	var out []string
	for _, p := range pairs {
		out = append(out, p+" ip", p+" svc")
	}
	return out
}

func isolationYAML(name, nsA, appA, nsB, appB string) string {
	return fmt.Sprintf(`apiVersion: netsec.nrnx.dev/v1alpha1
kind: NetworkIsolation
metadata: {name: %[1]s}
spec:
  reason: e2e
  between:
  - {name: %[3]s, namespaces: [%[2]s], podSelector: {matchLabels: {app: %[3]s}}}
  - {name: %[5]s, namespaces: [%[4]s], podSelector: {matchLabels: {app: %[5]s}}}
`, name, nsA, appA, nsB, appB)
}

func isoField(name, path string) func() (string, error) {
	return func() (string, error) { return jsonpath([]string{"get", "networkisolation", name}, path) }
}

// mechanism is what blocks traffic sent by the group called from.
func mechanism(name, from string) func() (string, error) {
	return isoField(name, fmt.Sprintf(`{.status.traffic[?(@.from=="%s")].blockedBy}`, from))
}

// netsecPolicies lists the NetSec-made policies in the namespaces, as namespace/name.
func netsecPolicies(namespaces ...string) []string {
	GinkgoHelper()
	var found []string
	for _, ns := range namespaces {
		out := kubectl("-n", ns, "get", "networkpolicy", "-o", "name")
		for _, l := range strings.Fields(out) {
			if strings.HasPrefix(strings.TrimPrefix(l, "networkpolicy.networking.k8s.io/"), "netsec-") {
				found = append(found, ns+"/"+l)
			}
		}
	}
	return found
}

func waitReady(name string) {
	GinkgoHelper()
	Eventually(isoField(name, `{.status.conditions[?(@.type=="Ready")].status}`)).Should(Equal("True"))
}

// waitReadyWithin is waitReady with a deadline, for the "Ready within 10 seconds" criterion (US1).
func waitReadyWithin(name string, d time.Duration) {
	GinkgoHelper()
	Eventually(isoField(name, `{.status.conditions[?(@.type=="Ready")].status}`)).WithTimeout(d).WithPolling(time.Second).Should(Equal("True"))
}

var _ = Describe("NetworkIsolation", Ordered, func() {
	const iso = "e2e-gw-dash"
	nsAll := []string{"e2e-a", "e2e-b", "e2e-c", "e2e-d"}
	var baseline map[string]bool

	BeforeAll(func() {
		apply(namespaceYAML(nsAll...))
		apply(workloadYAML("e2e-a", "gateway", nginxImage, 80) + workloadYAML("e2e-a", "worker", unprivilegedImage, 8080) +
			workloadYAML("e2e-b", "dashboard", nginxImage, 80) +
			workloadYAML("e2e-c", "client", unprivilegedImage, 8080) + workloadYAML("e2e-d", "client", unprivilegedImage, 8080))
		for _, ns := range nsAll {
			kubectl("-n", ns, "wait", "--for=condition=Available", "deployment", "--all", "--timeout=120s")
		}
	})

	AfterAll(func() {
		deleteCR("networkisolation", iso)
		deleteNamespaces(nsAll...)
	})

	It("lets every probe through before any isolation", func() {
		Eventually(matrixMismatches()).Should(BeEmpty())
		res, err := matrix()
		Expect(err).NotTo(HaveOccurred())
		baseline = utils.Reachability(res)
	})

	It("blocks gateway and dashboard both ways and nothing else", func() {
		apply(isolationYAML(iso, "e2e-a", "gateway", "e2e-b", "dashboard"))
		waitReadyWithin(iso, 10*time.Second)
		// Blocked by pod IP and by Service. worker is in e2e-a but not a gateway, so it still reaches B.
		Eventually(matrixMismatches(both("gw→dash", "dash→gw")...)).Should(BeEmpty())

		Expect(mechanism(iso, "gateway")()).To(Equal("IngressPolicy"))
		Expect(mechanism(iso, "dashboard")()).To(Equal("IngressPolicy"))
		Expect(isoField(iso, "{.status.summary}")()).To(Equal("gateway ⇄ dashboard: blocked both ways"))

		// A→C by Service name needs DNS; check a lookup on its own too.
		w, err := findWorld()
		Expect(err).NotTo(HaveOccurred())
		_, err = utils.Kubectl("-n", "e2e-a", "exec", w.gw.pod.Name, "--", "nslookup", "client.e2e-c.svc.cluster.local")
		Expect(err).NotTo(HaveOccurred(), "DNS lookup from the gateway group")
	})

	It("covers new pods in the gateway group", func() {
		kubectl("-n", "e2e-a", "scale", "deployment/gateway", "--replicas=2")
		DeferCleanup(func() {
			kubectl("-n", "e2e-a", "scale", "deployment/gateway", "--replicas=1")
			Eventually(func() (int, error) {
				pods, err := utils.PodsByLabel("e2e-a", "app=gateway")
				return len(pods), err
			}).Should(Equal(1))
		})
		kubectl("-n", "e2e-a", "wait", "--for=condition=Available", "deployment/gateway", "--timeout=120s")
		Eventually(func() ([]string, error) {
			pods, err := utils.PodsByLabel("e2e-a", "app=gateway")
			if err != nil || len(pods) != 2 {
				return nil, fmt.Errorf("want 2 running gateway pods, got %d (%v)", len(pods), err)
			}
			dash, err := utils.PodByLabel("e2e-b", "app=dashboard")
			if err != nil {
				return nil, err
			}
			var probes []utils.Probe
			for _, p := range pods {
				probes = append(probes,
					utils.Probe{Name: p.Name + " ip", From: p, URL: "http://" + dash.IP + "/"},
					utils.Probe{Name: p.Name + " svc", From: p, URL: "http://dashboard.e2e-b/"})
			}
			res, err := utils.RunMatrix(probes)
			return utils.Mismatches(res), err
		}).Should(BeEmpty())
	})

	It("undoes a tenant's edit of our policy", func() {
		pols := netsecPolicies("e2e-b")
		Expect(pols).To(HaveLen(1))
		name := strings.TrimPrefix(pols[0], "e2e-b/networkpolicy.networking.k8s.io/")
		// Adding a matchLabels key makes the policy select nobody, so A->B would open.
		kubectl("-n", "e2e-b", "patch", "networkpolicy", name, "--type=merge",
			"-p", `{"spec":{"podSelector":{"matchLabels":{"tamper":"yes"}}}}`)
		Eventually(func() (string, error) {
			return jsonpath([]string{"-n", "e2e-b", "get", "networkpolicy", name}, "{.spec.podSelector.matchLabels.tamper}")
		}).Should(BeEmpty())
		Eventually(matrixMismatches(both("gw→dash", "dash→gw")...)).Should(BeEmpty())
	})

	It("restores exactly what was there when the isolation is deleted", func() {
		deleteCR("networkisolation", iso)
		Eventually(matrixMismatches()).Should(BeEmpty())
		res, err := matrix()
		Expect(err).NotTo(HaveOccurred())
		Expect(utils.Reachability(res)).To(Equal(baseline))
		Expect(netsecPolicies(nsAll...)).To(BeEmpty())
	})

	// The tricky test (design 8): isolation must never widen access.
	// B already denies all ingress except from C. A naive design that isolates by
	// "allow all except A" on B would add an allow rule next to the user's and let D
	// in. NetSec must keep C→B allowed, D→B blocked and A↔B blocked, and afterwards
	// leave B exactly as the user had it.
	It("never widens access in a namespace that already has policies", func() {
		const tricky = "e2e-gw-dash-tricky"
		apply(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: default-deny-ingress, namespace: e2e-b}
spec:
  podSelector: {}
  policyTypes: [Ingress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: allow-from-c, namespace: e2e-b}
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
  - from: [{namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: e2e-c}}}]
`)
		DeferCleanup(func() {
			deleteCR("networkisolation", tricky)
			kubectl("-n", "e2e-b", "delete", "networkpolicy", "--all", "--ignore-not-found")
		})
		// Everything into B is blocked except from C.
		userOnly := both("gw→dash", "worker→dash", "d→dash")
		Eventually(matrixMismatches(userOnly...)).Should(BeEmpty())

		apply(isolationYAML(tricky, "e2e-a", "gateway", "e2e-b", "dashboard"))
		waitReady(tricky)
		Eventually(matrixMismatches(append(both("dash→gw"), userOnly...)...)).Should(BeEmpty())
		Expect(mechanism(tricky, "gateway")()).To(Equal("EgressPolicy"), "dashboard has an ingress policy, so gateway→dashboard must be blocked on the gateway's egress")
		Expect(mechanism(tricky, "dashboard")()).To(Equal("IngressPolicy"))

		deleteCR("networkisolation", tricky)
		Eventually(matrixMismatches(userOnly...)).Should(BeEmpty())
		Expect(netsecPolicies(nsAll...)).To(BeEmpty())
		Expect(strings.Fields(kubectl("-n", "e2e-b", "get", "networkpolicy", "-o", "name"))).To(ConsistOf(
			"networkpolicy.networking.k8s.io/default-deny-ingress", "networkpolicy.networking.k8s.io/allow-from-c"))
	})
})

// Editing a live isolation must never let blocked traffic through (phase 9). A prober keeps
// sending A->B and B->A the whole time the isolation is edited and the operator reconciles.
var _ = Describe("NetworkIsolation edited while on", Ordered, func() {
	const iso = "e2e-edit"
	nsAll := []string{"e2e-g1", "e2e-g2", "e2e-g3"}

	BeforeAll(func() {
		apply(namespaceYAML(nsAll...))
		apply(workloadYAML("e2e-g1", "gateway", nginxImage, 80) + workloadYAML("e2e-g2", "dashboard", nginxImage, 80) +
			workloadYAML("e2e-g3", "dashboard", nginxImage, 80))
		for _, ns := range nsAll {
			kubectl("-n", ns, "wait", "--for=condition=Available", "deployment", "--all", "--timeout=120s")
		}
	})

	AfterAll(func() {
		deleteCR("networkisolation", iso)
		deleteNamespaces(nsAll...)
	})

	It("blocks nothing extra and lets nothing through while a namespace is added to a group", func() {
		apply(isolationYAML(iso, "e2e-g1", "gateway", "e2e-g2", "dashboard"))
		waitReady(iso)
		gw, err := utils.PodByLabel("e2e-g1", "app=gateway")
		Expect(err).NotTo(HaveOccurred())
		dash, err := utils.PodByLabel("e2e-g2", "app=dashboard")
		Expect(err).NotTo(HaveOccurred())
		probes := []utils.Probe{
			{Name: "gw→dash", From: gw, URL: "http://" + dash.IP + "/"},
			{Name: "dash→gw", From: dash, URL: "http://" + gw.IP + "/"},
		}
		Eventually(func() ([]string, error) {
			res, err := utils.RunMatrix(probes)
			return utils.Mismatches(res), err
		}).Should(BeEmpty(), "both directions must be blocked before the edit")

		// The prober runs until stop is closed. It records every probe that got through
		// (a leak) and every probe it could not run; it never calls Gomega from here.
		stop := make(chan struct{})
		done := make(chan struct{})
		var mu sync.Mutex // guards sent and bad
		var sent int
		var bad []string
		snapshot := func() (int, []string) {
			mu.Lock()
			defer mu.Unlock()
			return sent, append([]string(nil), bad...)
		}
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
				}
				res, err := utils.RunMatrix(probes)
				mu.Lock()
				if err != nil {
					bad = append(bad, "probe did not run: "+err.Error())
				} else {
					sent += len(res)
					bad = append(bad, utils.Mismatches(res)...)
				}
				mu.Unlock()
			}
		}()
		stopProber := func() {
			select {
			case <-stop:
			default:
				close(stop)
			}
			<-done
		}
		DeferCleanup(stopProber)

		// Add a namespace to the dashboard group, then wait for the reconcile to finish.
		kubectl("patch", "networkisolation", iso, "--type=json", "-p",
			`[{"op":"replace","path":"/spec/between/1/namespaces","value":["e2e-g2","e2e-g3"]}]`)
		Eventually(func() (string, error) {
			return jsonpath([]string{"-n", "e2e-g3", "get", "networkpolicy"}, "{.items[*].metadata.name}")
		}).Should(ContainSubstring("netsec-"), "policy in the new namespace")
		Eventually(func() (bool, error) {
			gen, err := isoField(iso, "{.metadata.generation}")()
			if err != nil {
				return false, err
			}
			obs, err := isoField(iso, "{.status.observedGeneration}")()
			return gen == obs, err
		}).Should(BeTrue(), "status catches up with the edit")
		waitReady(iso)

		// Keep probing a little after the reconcile too, then stop.
		sentAtReconcile, _ := snapshot()
		Eventually(func() int { n, _ := snapshot(); return n - sentAtReconcile }).Should(BeNumerically(">=", 6))
		stopProber()
		total, failures := snapshot()
		AddReportEntry("probes during the edit", fmt.Sprintf("%d probes sent while editing and reconciling, %d failed", total, len(failures)))
		Expect(failures).To(BeEmpty(), "blocked traffic got through during the edit")

		// The new namespace's pods are blocked too, both ways.
		dash3, err := utils.PodByLabel("e2e-g3", "app=dashboard")
		Expect(err).NotTo(HaveOccurred())
		Eventually(func() ([]string, error) {
			res, err := utils.RunMatrix([]utils.Probe{
				{Name: "gw→dash3", From: gw, URL: "http://" + dash3.IP + "/"},
				{Name: "dash3→gw", From: dash3, URL: "http://" + gw.IP + "/"},
			})
			return utils.Mismatches(res), err
		}).Should(BeEmpty(), "the new namespace's pods must be blocked")
	})
})

// podYAML is a bare pod pinned to a node, so the two groups can be put on different nodes.
func podYAML(ns, app, image string, port int, node string) string {
	return fmt.Sprintf(`---
apiVersion: v1
kind: Pod
metadata: {name: %[2]s, namespace: %[1]s, labels: {app: %[2]s}}
spec:
  nodeName: %[5]s
  containers:
  - name: %[2]s
    image: %[3]s
    imagePullPolicy: Never
    ports: [{name: http, containerPort: %[4]d}]
    readinessProbe: {httpGet: {path: /, port: http}}
`, ns, app, image, port, node)
}

var _ = Describe("NetworkIsolation across nodes", Ordered, func() {
	const iso = "e2e-nodes"
	var aNode, bNode, otherNodeIP, bNodeIP string
	var gw, dash utils.Pod
	var nodePort string

	// outsideGet sends an HTTP GET from inside a node container: traffic from outside the pod network.
	outsideGet := func(node, url string) bool {
		_, err := utils.Docker("exec", node, "wget", "-q", "-T", "3", "-O", "/dev/null", url)
		return err == nil
	}

	probes := func(want bool) []utils.Probe {
		return []utils.Probe{
			{Name: "A→B ip", From: gw, URL: "http://" + dash.IP + "/", Want: want},
			{Name: "A→B svc", From: gw, URL: "http://dashboard.e2e-n2/", Want: want},
			{Name: "B→A ip", From: dash, URL: "http://" + gw.IP + "/", Want: want},
			{Name: "B→A svc", From: dash, URL: "http://gateway.e2e-n1/", Want: want},
		}
	}
	check := func(want bool) func() ([]string, error) {
		return func() ([]string, error) {
			res, err := utils.RunMatrix(probes(want))
			return utils.Mismatches(res), err
		}
	}

	BeforeAll(func() {
		nodes := strings.Fields(kubectl("get", "nodes", "-o", `jsonpath={range .items[*]}{.metadata.name}={.status.addresses[?(@.type=="InternalIP")].address}{" "}{end}`))
		Expect(nodes).To(HaveLen(2), "the k3d cluster must have two nodes")
		nodeIP := map[string]string{}
		var names []string
		for _, n := range nodes {
			kv := strings.SplitN(n, "=", 2)
			nodeIP[kv[0]] = kv[1]
			names = append(names, kv[0])
		}
		aNode, bNode = names[0], names[1]
		otherNodeIP, bNodeIP = nodeIP[aNode], nodeIP[bNode]

		apply(namespaceYAML("e2e-n1", "e2e-n2"))
		apply(podYAML("e2e-n1", "gateway", nginxImage, 80, aNode) + podYAML("e2e-n2", "dashboard", nginxImage, 80, bNode) + `---
apiVersion: v1
kind: Service
metadata: {name: dashboard, namespace: e2e-n2}
spec:
  type: NodePort
  selector: {app: dashboard}
  ports: [{name: http, port: 80, targetPort: http}]
`)
		kubectl("-n", "e2e-n1", "wait", "--for=condition=Ready", "pod/gateway", "--timeout=120s")
		kubectl("-n", "e2e-n2", "wait", "--for=condition=Ready", "pod/dashboard", "--timeout=120s")
		var err error
		gw, err = utils.PodByLabel("e2e-n1", "app=gateway")
		Expect(err).NotTo(HaveOccurred())
		dash, err = utils.PodByLabel("e2e-n2", "app=dashboard")
		Expect(err).NotTo(HaveOccurred())
		nodePort = kubectl("-n", "e2e-n2", "get", "service", "dashboard", "-o", "jsonpath={.spec.ports[0].nodePort}")
	})

	AfterAll(func() {
		deleteCR("networkisolation", iso)
		deleteNamespaces("e2e-n1", "e2e-n2")
	})

	It("blocks A and B both ways when they run on different nodes", func() {
		Expect(aNode).NotTo(Equal(bNode))
		// The gateway pod has no Service of its own; give B→A svc something to resolve.
		apply(`apiVersion: v1
kind: Service
metadata: {name: gateway, namespace: e2e-n1}
spec:
  selector: {app: gateway}
  ports: [{name: http, port: 80, targetPort: http}]
`)
		Eventually(check(true)).Should(BeEmpty())

		// Control for the NodePort spec below: before isolation, outside traffic reaches B through either node.
		Expect(outsideGet(aNode, fmt.Sprintf("http://%s:%s/", otherNodeIP, nodePort))).To(BeTrue(), "NodePort via B's other node, before isolation")
		Expect(outsideGet(bNode, fmt.Sprintf("http://%s:%s/", bNodeIP, nodePort))).To(BeTrue(), "NodePort via B's own node, before isolation")

		apply(isolationYAML(iso, "e2e-n1", "gateway", "e2e-n2", "dashboard"))
		waitReady(iso)
		Eventually(check(false)).Should(BeEmpty())
	})

	// Design 14: outside traffic that enters a NodePort on the node WITHOUT B's pod is forwarded
	// to B's node with its source rewritten to the entry node's flannel address, which lies in
	// the pod range that NetSec excepts. The policy allows that address as a single host, so
	// outside clients keep reaching B through either node while A<->B stays blocked.
	It("lets NodePort traffic through on either node while A and B stay isolated", func() {
		viaOther := outsideGet(aNode, fmt.Sprintf("http://%s:%s/", otherNodeIP, nodePort))
		viaOwn := outsideGet(bNode, fmt.Sprintf("http://%s:%s/", bNodeIP, nodePort))
		Eventually(check(false)).Should(BeEmpty(), "A and B must stay blocked")
		_, _ = fmt.Fprintf(GinkgoWriter, "NODEPORT RESULT: via other node reaches B=%v, via B's own node reaches B=%v\n", viaOther, viaOwn)
		AddReportEntry("nodeport", fmt.Sprintf("via other node reaches isolated B: %v; via B's own node: %v", viaOther, viaOwn))
		Expect(viaOther).To(Equal(nodePortViaOtherNodeReachesB), "design 14 NodePort result changed")
		Expect(viaOwn).To(Equal(nodePortViaOwnNodeReachesB), "design 14 NodePort result changed")
	})
})

// What happens (design 14), on the two-node k3d cluster. Outside traffic through a NodePort
// reaches B on either node while A<->B is isolated. Entering on the node without B's pod,
// the forwarded request carries that node's flannel address (the network address of its
// pod range). AllExcept allows that address as a single host; without it this was blocked.
const (
	nodePortViaOtherNodeReachesB = true
	nodePortViaOwnNodeReachesB   = true
)
