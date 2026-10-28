# Image URL to use all building/pushing image targets
IMG ?= controller:latest
# YEAR defines the year value used for substituting the YEAR placeholder in the boilerplate header.
YEAR ?= $(shell date +%Y)

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Go builder image for docker-build.
BASE_IMAGE ?= golang:1.27.3-alpine

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt",year=$(YEAR) paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# End-to-end tests run on the local k3d cluster (design 8, 10). The manager image
# is built, loaded into every node and deployed from config/default, then the
# Ginkgo specs run. The operator is undeployed afterwards, pass or fail.
E2E_IMG ?= netsec:e2e

# operator-up builds the manager image, loads it into every k3d node and deploys it.
.PHONY: operator-up
operator-up: k3d-up
	$(MAKE) docker-build k3d-load deploy IMG=$(E2E_IMG)
	$(KUBECTL) -n netsec-system rollout status deployment/netsec-controller-manager --timeout=120s

.PHONY: test-e2e
test-e2e: manifests generate fmt vet operator-up k3d-load-test-images ## Run the e2e tests on the k3d-netsec cluster.
	@status=0; \
	go test -tags=e2e ./test/e2e/ -v -ginkgo.v -timeout 30m || status=$$?; \
	$(MAKE) undeploy ignore-not-found=true || status=$$?; \
	exit $$status

.PHONY: verify-isolation
verify-isolation: operator-up k3d-load-test-images ## Check isolation with real traffic on k3d-netsec (hack/verify-isolation.sh), then undeploy.
	@status=0; \
	hack/verify-isolation.sh || status=$$?; \
	$(MAKE) undeploy ignore-not-found=true || status=$$?; \
	exit $$status

.PHONY: rbac-check
rbac-check: manifests ## Check the chart RBAC rules match config/rbac.
	@hack/check-chart-rbac.sh

.PHONY: lint
lint: golangci-lint rbac-check ## Run golangci-lint linter and the chart RBAC check
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet $(LOCALBIN) ## Run a controller from your host against k3d-netsec.
	@# The manager has no --context flag, so give it a kubeconfig that holds only k3d-netsec.
	@$(KUBECTL) config view --minify --flatten > "$(LOCALBIN)/k3d-netsec.kubeconfig"
	go run ./cmd/main.go --zap-devel --kubeconfig "$(LOCALBIN)/k3d-netsec.kubeconfig"

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# BASE_IMAGE is already on this machine. Override it to build from another registry, e.g.
# make docker-build IMG=<img> BASE_IMAGE=docker.io/library/golang:1.26
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build --build-arg BASE_IMAGE=$(BASE_IMAGE) -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name netsec-builder
	$(CONTAINER_TOOL) buildx use netsec-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) $(if $(BASE_IMAGE),--build-arg BASE_IMAGE=$(BASE_IMAGE)) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm netsec-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | $(KUBECTL) apply -f -; else echo "No CRDs to install; skipping."; fi

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	@out="$$( "$(KUSTOMIZE)" build config/crd 2>/dev/null || true )"; \
	if [ -n "$$out" ]; then echo "$$out" | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -; else echo "No CRDs to delete; skipping."; fi

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to k3d-netsec with image $(IMG).
	@# sed sets the image, so kustomization.yaml in the repo is not edited.
	"$(KUSTOMIZE)" build config/default | sed 's#image: controller:latest#image: ${IMG}#' | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

##@ Local cluster (k3d)

K3D_CLUSTER := netsec
K3S_IMAGE ?= rancher/k3s:v1.35.5-k3s1
ARCH ?= $(shell go env GOARCH)

.PHONY: k3d-up
k3d-up: ## Create the k3d cluster (one server, one agent). Your current kubectl context stays as it is.
	@if k3d cluster get $(K3D_CLUSTER) >/dev/null 2>&1; then \
		echo "k3d cluster $(K3D_CLUSTER) already exists"; \
	else \
		k3d cluster create $(K3D_CLUSTER) --servers 1 --agents 1 --image $(K3S_IMAGE) --no-lb \
			--k3s-arg "--disable=traefik@server:*" \
			--kubeconfig-update-default --kubeconfig-switch-context=false --timeout 180s; \
	fi
	$(KUBECTL) wait --for=condition=Ready node --all --timeout=120s

# When the deleted cluster's context is the current one, k3d switches the current
# context to some other cluster. Put back what was there. If that was k3d-netsec,
# plain kubectl then fails ("context not found") until k3d-up, which is the safe outcome.
.PHONY: k3d-down
k3d-down: ## Delete the k3d cluster. Your current kubectl context stays as it is.
	@ctx="$$(kubectl config current-context 2>/dev/null)"; \
	k3d cluster delete $(K3D_CLUSTER) || exit 1; \
	if [ -n "$$ctx" ] && [ "$$(kubectl config current-context 2>/dev/null)" != "$$ctx" ]; then \
		kubectl config set current-context "$$ctx" >/dev/null || exit 1; \
		echo "k3d moved your kubectl context; set it back to $$ctx"; \
	fi

# k3d image import reports success but loads nothing with Docker Desktop's
# containerd image store (design 12.1), so import with ctr and check with crictl.
# IMGS is the list to load; it defaults to $(IMG).
.PHONY: k3d-load
k3d-load: IMGS ?= $(IMG)
k3d-load: ## Load $(IMG) (or $(IMGS)) into every k3d node, then check each node lists it.
	@nodes="$$(docker ps --filter label=k3d.cluster=$(K3D_CLUSTER) --format '{{.Names}} {{.Label "k3d.role"}}' \
		| awk '$$2 == "server" || $$2 == "agent" { print $$1 }')"; \
	[ -n "$$nodes" ] || { echo "no nodes found for k3d cluster $(K3D_CLUSTER); run make k3d-up"; exit 1; }; \
	for node in $$nodes; do \
		for img in $(IMGS); do \
			echo "loading $$img into $$node"; \
			docker save --platform linux/$(ARCH) $$img | docker exec -i $$node ctr -n k8s.io images import - || exit 1; \
			docker exec $$node crictl inspecti $$img >/dev/null || { echo "$$img is missing on $$node after import"; exit 1; }; \
		done; \
	done

# The images the e2e and verify-isolation workloads run. They must already be on the host
# (docker pull once); the nodes never download them, and the test pods use imagePullPolicy: Never.
TEST_IMAGES ?= nginx:1.31.6-alpine nginxinc/nginx-unprivileged:1.31.6-alpine

.PHONY: k3d-load-test-images
k3d-load-test-images: ## Load the pinned test workload images into every k3d node.
	$(MAKE) k3d-load IMGS="$(TEST_IMAGES)"

.PHONY: demo
demo: ## Deploy the demo workloads in hack/demo and wait until they are Ready.
	$(KUBECTL) apply -f hack/demo/
	$(KUBECTL) wait --for=condition=Available deployment -l app.kubernetes.io/part-of=netsec-demo -A --timeout=180s

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
# Every kubectl call goes to the local k3d cluster. This machine's default
# context is production, so the context is fixed here and never read from it.
KUBECTL := kubectl --context k3d-$(K3D_CLUSTER)
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.22.0

#ENVTEST_VERSION is the controller-runtime version to use for setup-envtest, derived from go.mod
ENVTEST_VERSION ?= $(shell v='$(call gomodver,sigs.k8s.io/controller-runtime)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_VERSION manually (controller-runtime replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v")

#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell v='$(call gomodver,k8s.io/api)'; \
  [ -n "$$v" ] || { echo "Set ENVTEST_K8S_VERSION manually (k8s.io/api replace has no tag)" >&2; exit 1; }; \
  printf '%s\n' "$$v" | sed -E 's/^v?[0-9]+\.([0-9]+).*/1.\1/')

GOLANGCI_LINT_VERSION ?= v2.14.0
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))
	@test -f .custom-gcl.yml && { \
		echo "Building custom golangci-lint with plugins..." && \
		$(GOLANGCI_LINT) custom --destination $(LOCALBIN) --name golangci-lint-custom && \
		mv -f $(LOCALBIN)/golangci-lint-custom $(GOLANGCI_LINT); \
	} || true

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] && [ "$$(readlink -- "$(1)" 2>/dev/null)" = "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(LOCALBIN)/$$(basename "$(1)")" "$(1)-$(3)" ;\
} ;\
ln -sf "$$(realpath "$(1)-$(3)")" "$(1)"
endef

define gomodver
$(shell go list -m -f '{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}' $(1) 2>/dev/null)
endef

##@ Helm chart

CHART_DIR := dist/chart
HELM := helm --kube-context k3d-$(K3D_CLUSTER)

# helm-check lints and renders the chart, then installs it on k3d-netsec, applies a sample
# NetworkIsolation, waits for Ready, and removes everything again (pass or fail).
# crd.keep=false makes the uninstall remove the CRDs too, so nothing is left behind.
.PHONY: helm-check
helm-check: k3d-up ## Lint and render the chart, then install, try and uninstall it on k3d-netsec.
	helm lint $(CHART_DIR)
	helm template netsec $(CHART_DIR) --namespace netsec-system >/dev/null
	$(MAKE) docker-build k3d-load IMG=$(E2E_IMG)
	@status=0; \
	{ $(HELM) install netsec $(CHART_DIR) --namespace netsec-system --create-namespace \
		--set manager.image.repository=$(firstword $(subst :, ,$(E2E_IMG))) \
		--set manager.image.tag=$(lastword $(subst :, ,$(E2E_IMG))) \
		--set 'manager.podCIDRs={10.42.0.0/16}' \
		--set 'manager.extraAllowedCIDRs={10.42.0.0/32,10.42.1.0/32}' \
		--set crd.keep=false --wait --timeout 3m \
	&& $(KUBECTL) -n netsec-system rollout status deployment/netsec-controller-manager --timeout=120s \
	&& $(KUBECTL) apply -f hack/helm-check.yaml \
	&& $(KUBECTL) wait --for=condition=Ready networkisolation/helm-check --timeout=60s; } || status=$$?; \
	$(KUBECTL) delete -f hack/helm-check.yaml --ignore-not-found --wait --timeout=120s || status=$$?; \
	$(HELM) uninstall netsec --namespace netsec-system --wait --timeout 3m || status=$$?; \
	$(KUBECTL) delete namespace netsec-system --ignore-not-found --wait --timeout=120s || status=$$?; \
	exit $$status
