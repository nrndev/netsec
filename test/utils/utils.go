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

// Package utils holds helpers shared by the e2e specs. Every call goes to the
// local k3d cluster through one fixed kubectl context; the machine's current
// context (production) is never read or used.
package utils

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Context is the only kubectl context the tests may use.
const Context = "k3d-netsec"

// CallTimeout bounds every kubectl call so a hung cluster fails a spec instead of the suite.
const CallTimeout = 90 * time.Second

// Kubectl runs kubectl against k3d-netsec and returns its stdout. On failure the
// error holds the command and stderr.
func Kubectl(args ...string) (string, error) {
	return KubectlStdin("", args...)
}

// KubectlStdin is Kubectl with stdin set to in (for "apply -f -").
func KubectlStdin(in string, args ...string) (string, error) {
	full := append([]string{"--context", Context}, args...)
	return run(in, "kubectl", full...)
}

func run(in, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if in != "" {
		cmd.Stdin = strings.NewReader(in)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start %s: %w", name, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return stdout.String(), fmt.Errorf("%s %s: %w: %s",
				name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), nil
	case <-time.After(CallTimeout):
		_ = cmd.Process.Kill()
		<-done
		return stdout.String(), fmt.Errorf("%s %s: timed out after %s", name, strings.Join(args, " "), CallTimeout)
	}
}

// Apply creates or updates the objects in a YAML document.
func Apply(yaml string) error {
	_, err := KubectlStdin(yaml, "apply", "-f", "-")
	return err
}

// Docker runs docker, for the checks that need a shell on a k3d node container.
func Docker(args ...string) (string, error) {
	return run("", "docker", args...)
}

// Pod is a running pod that specs send probes from or to.
type Pod struct {
	Namespace, Name, IP string
}

// PodsByLabel returns the running pods with the label (for example "app=gateway") in ns.
func PodsByLabel(ns, label string) ([]Pod, error) {
	out, err := Kubectl("-n", ns, "get", "pods", "-l", label,
		"--field-selector=status.phase=Running",
		"-o", `go-template={{range .items}}{{if not .metadata.deletionTimestamp}}`+
			`{{.metadata.name}} {{.status.podIP}}{{"\n"}}{{end}}{{end}}`)
	if err != nil {
		return nil, err
	}
	f := strings.Fields(out)
	pods := make([]Pod, 0, len(f)/2)
	for i := 0; i+1 < len(f); i += 2 {
		pods = append(pods, Pod{Namespace: ns, Name: f[i], IP: f[i+1]})
	}
	return pods, nil
}

// PodByLabel is PodsByLabel for a label that must match exactly one pod. It errors
// otherwise, so callers can wait on it with Eventually.
func PodByLabel(ns, label string) (Pod, error) {
	pods, err := PodsByLabel(ns, label)
	if err != nil {
		return Pod{}, err
	}
	if len(pods) != 1 {
		return Pod{}, fmt.Errorf("want exactly one running pod with %s in %s, got %d", label, ns, len(pods))
	}
	return pods[0], nil
}

// HTTPCode sends one HTTP GET from the pod with curl and returns the status code.
// A refused or timed-out connection gives "000" (blocked connections are refused at
// once, design 12.1, so a short timeout is enough). The pod's image must have curl.
func HTTPCode(from Pod, url string) (string, error) {
	out, err := Kubectl("-n", from.Namespace, "exec", from.Name, "--",
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3", url)
	// curl exits non-zero (7 refused, 28 timeout) when it cannot connect; that is an answer, not a failure.
	if code := strings.TrimSpace(out); code != "" {
		return code, nil
	}
	return "", err
}

// Reachable reports whether an HTTP status code means the request got through.
func Reachable(code string) bool { return code == "200" }

// Probe is one cell of the traffic matrix.
type Probe struct {
	Name string // for example "A→B ip"
	From Pod
	URL  string
	Want bool // true: the request must get through
}

// Result is what a probe saw.
type Result struct {
	Probe
	Code string
}

// Ok reports whether the result matches what was wanted.
func (r Result) Ok() bool { return Reachable(r.Code) == r.Want }

// RunMatrix sends every probe and returns the results in order.
func RunMatrix(probes []Probe) ([]Result, error) {
	res := make([]Result, 0, len(probes))
	for _, p := range probes {
		code, err := HTTPCode(p.From, p.URL)
		if err != nil {
			return nil, fmt.Errorf("probe %s: %w", p.Name, err)
		}
		res = append(res, Result{Probe: p, Code: code})
	}
	return res, nil
}

// Mismatches lists the results that differ from what was wanted, one line each.
func Mismatches(res []Result) []string {
	var bad []string
	for _, r := range res {
		if !r.Ok() {
			bad = append(bad, fmt.Sprintf("%s: want reachable=%v, got HTTP %s (%s)", r.Name, r.Want, r.Code, r.URL))
		}
	}
	return bad
}

// Reachability maps probe names to whether they got through, to compare two matrices.
func Reachability(res []Result) map[string]bool {
	m := make(map[string]bool, len(res))
	for _, r := range res {
		m[r.Name] = Reachable(r.Code)
	}
	return m
}
