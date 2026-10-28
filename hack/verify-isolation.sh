#!/usr/bin/env bash
# Checks NetworkIsolation with real traffic on the local k3d-netsec cluster.
#
# It deploys its own small workloads in namespaces verify-a, verify-b and verify-c
# (it does not use `make demo`), prints a traffic matrix before, during and after a
# sample isolation of verify-a/gateway and verify-b/dashboard, and exits non-zero if
# any probe differs from what is expected. It needs the operator to be running
# (`make deploy IMG=...` or `make run`). It removes what it created when it ends.
set -euo pipefail

KUBECTL=(kubectl --context k3d-netsec) # never the current context: it may be production
ISO=verify-gateway-dashboard
NSS=(verify-a verify-b verify-c)
failures=0

cleanup() {
  "${KUBECTL[@]}" delete networkisolation "$ISO" --ignore-not-found --wait --timeout=120s || true
  "${KUBECTL[@]}" delete namespace "${NSS[@]}" --ignore-not-found --wait --timeout=120s || true
}
trap cleanup EXIT

workload() { # ns name image port
  cat <<YAML
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: $2, namespace: $1}
spec:
  selector: {matchLabels: {app: $2}}
  template:
    metadata: {labels: {app: $2}}
    spec:
      containers:
      - name: $2
        image: $3
        imagePullPolicy: Never # test images are loaded by make k3d-load-test-images
        ports: [{name: http, containerPort: $4}]
        readinessProbe: {httpGet: {path: /, port: http}}
---
apiVersion: v1
kind: Service
metadata: {name: $2, namespace: $1}
spec:
  selector: {app: $2}
  ports: [{name: http, port: 80, targetPort: http}]
YAML
}

for ns in "${NSS[@]}"; do "${KUBECTL[@]}" create namespace "$ns"; done
{
  workload verify-a gateway nginx:1.31.6-alpine 80
  workload verify-b dashboard nginx:1.31.6-alpine 80
  workload verify-c client nginxinc/nginx-unprivileged:1.31.6-alpine 8080
} | "${KUBECTL[@]}" apply -f -
for ns in "${NSS[@]}"; do "${KUBECTL[@]}" -n "$ns" wait --for=condition=Available deployment --all --timeout=120s; done

pod() { "${KUBECTL[@]}" -n "$1" get pod -l "app=$2" -o jsonpath='{.items[0].metadata.name}'; }
podip() { "${KUBECTL[@]}" -n "$1" get pod -l "app=$2" -o jsonpath='{.items[0].status.podIP}'; }

# probe ns app url: prints the HTTP status ("000" when the connection failed or was refused).
# Blocked connections are refused at once, so a short timeout is enough. curl then exits
# non-zero, and kubectl reports "terminated with exit code 7" on stderr: expected, so it is
# dropped whenever curl printed a status. With no status at all (missing pod, kubectl error)
# stderr is shown and the probe fails.
probe() {
  local code rc=0 errf
  errf=$(mktemp)
  code=$("${KUBECTL[@]}" -n "$1" exec "$(pod "$1" "$2")" -- curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$3" 2>"$errf") || rc=$?
  if [ -z "$code" ]; then
    echo "probe from $1/$2 to $3 could not run (exit $rc): $(cat "$errf")" >&2
    rm -f "$errf"
    return 1
  fi
  rm -f "$errf"
  echo "$code"
}

# wait_for_code ns app url blocked|200: polls until a new policy (or its removal) shows in the
# traffic, up to 30s. kube-router needs about a second to program the rules.
wait_for_code() {
  local i code
  for i in $(seq 15); do
    code=$(probe "$1" "$2" "$3")
    if { [ "$4" = 200 ] && [ "$code" = 200 ]; } || { [ "$4" = blocked ] && [ "$code" != 200 ]; }; then return 0; fi
    sleep 2
  done
  echo "MISMATCH: $1/$2 to $3 never became $4 (last HTTP $code)" >&2
  failures=$((failures + 1))
}

# matrix title blocked...: probes every pair by pod IP and by Service name. Pairs listed in
# "blocked" (like "gateway>dashboard") must fail; all others must return 200.
matrix() {
  local title=$1; shift
  local blocked=" $* "
  printf '\n== %s ==\n%-28s %-5s %-9s %s\n' "$title" PROBE HTTP EXPECTED RESULT
  local from to how url code want result
  for from in verify-a/gateway verify-b/dashboard verify-c/client; do
    for to in verify-a/gateway verify-b/dashboard verify-c/client; do
      [ "$from" = "$to" ] && continue
      for how in ip svc; do
        if [ $how = ip ]; then
          port=80; [ "${to#*/}" = client ] && port=8080
          url="http://$(podip "${to%/*}" "${to#*/}"):$port/"
        else
          url="http://${to#*/}.${to%/*}/"
        fi
        code=$(probe "${from%/*}" "${from#*/}" "$url")
        want=200; case "$blocked" in *" ${from#*/}>${to#*/} "*) want=blocked ;; esac
        if { [ "$want" = 200 ] && [ "$code" = 200 ]; } || { [ "$want" = blocked ] && [ "$code" != 200 ]; }; then
          result=ok
        else
          result=MISMATCH; failures=$((failures + 1))
        fi
        printf '%-28s %-5s %-9s %s\n' "${from#*/}>${to#*/} $how" "$code" "$want" "$result"
      done
    done
  done
}

# New pods are not reachable for their first seconds, while the network engine programs them.
# Wait for the baseline to open, so the "before" matrix tests the cluster and not the start-up.
wait_for_code verify-a gateway "http://dashboard.verify-b/" 200
wait_for_code verify-a gateway "http://client.verify-c/" 200
wait_for_code verify-b dashboard "http://gateway.verify-a/" 200
matrix "before isolation"

"${KUBECTL[@]}" apply -f - <<YAML
apiVersion: netsec.nrnx.dev/v1alpha1
kind: NetworkIsolation
metadata: {name: $ISO}
spec:
  reason: verify-isolation.sh
  between:
    - {name: gateway, namespaces: [verify-a], podSelector: {matchLabels: {app: gateway}}}
    - {name: dashboard, namespaces: [verify-b], podSelector: {matchLabels: {app: dashboard}}}
YAML
"${KUBECTL[@]}" wait --for=condition=Ready "networkisolation/$ISO" --timeout=60s
wait_for_code verify-a gateway "http://$(podip verify-b dashboard):80/" blocked
"${KUBECTL[@]}" get networkisolation "$ISO"
matrix "during isolation (gateway and dashboard must not reach each other)" gateway\>dashboard dashboard\>gateway

"${KUBECTL[@]}" delete networkisolation "$ISO" --wait --timeout=120s
leftover=$("${KUBECTL[@]}" get networkpolicy -A -l app.kubernetes.io/managed-by=netsec -o name)
if [ -n "$leftover" ]; then echo "MISMATCH: NetSec policies remain: $leftover"; failures=$((failures + 1)); fi
wait_for_code verify-a gateway "http://$(podip verify-b dashboard):80/" 200
matrix "after deleting the isolation"

if [ "$failures" -ne 0 ]; then echo; echo "FAILED: $failures check(s) did not match"; exit 1; fi
echo; echo "OK: every probe matched in all three phases"
