# Tex born-in-a-box kind admission harness.
#
# Proves the operator control plane (mutating injector + ValidatingAdmissionPolicy
# + validating webhook) on a REAL local kind cluster: a non-compliant pod is
# DENIED by the live kube-apiserver, a compliant pod is ADMITTED and runs under
# the gVisor sandbox.
#
#   make kind-up     # build node image (gVisor), create cluster, install
#                    # cert-manager + the Tex chart with admission turned on
#   make kind-test   # apply a bad pod (assert DENIED) + a good pod (assert
#                    # ADMITTED and running under gVisor)
#   make kind-down   # delete the cluster
#
# Requires: docker (Colima on macOS), kind, kubectl, helm.

SHELL := /bin/bash

# kind v0.32.0's default node image. Override to match your kind version.
NODE_IMAGE        ?= kindest/node:v1.36.1
# The custom node image with gVisor (runsc) baked in (see Dockerfile.node).
TEX_NODE_IMAGE    ?= tex-kind-node:gvisor
CLUSTER_NAME      ?= tex-bib
KIND_CONFIG       := scripts/kind/kind-config.yaml
NODE_DOCKERFILE   := scripts/kind/Dockerfile.node
HELM_CHART        := deploy/helm/tex
HELM_RELEASE      ?= tex
TEX_NAMESPACE     ?= tex-system
# The Tex application image (PDP + operator share it). Built from the repo
# Dockerfile and loaded into the kind node so it never has to pull from a
# registry. For the INJECTED sidecar/init we use a tiny pullable image so the
# injected pod is schedulable in the harness without the full Tex image.
TEX_APP_IMAGE     ?= tex:kind
INJECT_IMAGE      ?= busybox:1.36
CERT_MANAGER_VER  ?= v1.16.2

.PHONY: kind-up kind-node-image kind-cluster cert-manager tex-image kind-install kind-test kind-down kind-status

# ── full bring-up ─────────────────────────────────────────────────────────────
kind-up: kind-node-image kind-cluster tex-image cert-manager kind-install
	@echo ">> kind-up complete. Run 'make kind-test'."

# Build the gVisor-enabled node image.
kind-node-image:
	@echo ">> building gVisor node image $(TEX_NODE_IMAGE) from $(NODE_IMAGE)"
	docker build \
	  --build-arg NODE_IMAGE=$(NODE_IMAGE) \
	  -t $(TEX_NODE_IMAGE) \
	  -f $(NODE_DOCKERFILE) scripts/kind

# Create the cluster from the gVisor node image with the runsc containerd patch.
kind-cluster:
	@echo ">> creating kind cluster $(CLUSTER_NAME)"
	kind create cluster \
	  --name $(CLUSTER_NAME) \
	  --image $(TEX_NODE_IMAGE) \
	  --config $(KIND_CONFIG) \
	  --wait 120s
	kubectl --context kind-$(CLUSTER_NAME) cluster-info

# Build the Tex app image (operator + PDP) and load it into the node so the
# operator Deployment can start without pulling from ghcr.
tex-image:
	@echo ">> building Tex app image $(TEX_APP_IMAGE)"
	docker build -t $(TEX_APP_IMAGE) .
	@echo ">> loading $(TEX_APP_IMAGE) into kind node"
	kind load docker-image $(TEX_APP_IMAGE) --name $(CLUSTER_NAME)
	@echo ">> pre-pulling injected sidecar image $(INJECT_IMAGE) onto the node"
	# Pull on the node directly (crictl): a stale docker-credential-* helper on
	# the host can break `kind load`, and the node has its own registry egress.
	docker exec $(CLUSTER_NAME)-control-plane crictl pull $(INJECT_IMAGE)

# cert-manager is the prerequisite for the operator's webhook serving cert.
cert-manager:
	@echo ">> installing cert-manager $(CERT_MANAGER_VER)"
	kubectl --context kind-$(CLUSTER_NAME) apply -f \
	  https://github.com/cert-manager/cert-manager/releases/download/$(CERT_MANAGER_VER)/cert-manager.yaml
	@echo ">> waiting for cert-manager to be ready"
	kubectl --context kind-$(CLUSTER_NAME) -n cert-manager wait --for=condition=Available \
	  deploy/cert-manager deploy/cert-manager-webhook deploy/cert-manager-cainjector --timeout=180s

# Install the Tex chart with the FULL admission stack on:
#   * the mutating injector (sidecarInjection)
#   * the validating WEBHOOK (admission.webhook.enabled)
#   * the in-apiserver VAP   (admission.validatingPolicy.enabled)
#   * the gVisor RuntimeClass (admission.shipRuntimeClass)
# Injected sidecar/init images point at the pullable busybox so the injected pod
# is schedulable in the harness. appEnv=dev relaxes the PDP's prod fail-closed
# startup guards (no Postgres/secrets in the harness).
kind-install:
	@echo ">> helm install $(HELM_RELEASE) with admission turned on"
	helm --kube-context kind-$(CLUSTER_NAME) upgrade --install $(HELM_RELEASE) $(HELM_CHART) \
	  --namespace $(TEX_NAMESPACE) --create-namespace \
	  --set image.pdp=$(TEX_APP_IMAGE) \
	  --set image.proxy=$(INJECT_IMAGE) \
	  --set image.init=$(INJECT_IMAGE) \
	  --set image.pullPolicy=IfNotPresent \
	  --set pdp.appEnv=dev \
	  --set pdp.persistence.enabled=false \
	  --set operator.enabled=true \
	  --set operator.certManager=true \
	  --set operator.installKubernetesClient=true \
	  --set sidecarInjection.enabled=true \
	  --set admission.webhook.enabled=true \
	  --set admission.validatingPolicy.enabled=true \
	  --set admission.shipRuntimeClass=true \
	  --wait --timeout 180s
	@echo ">> waiting for the operator (webhook backend) to be Available"
	kubectl --context kind-$(CLUSTER_NAME) -n $(TEX_NAMESPACE) wait --for=condition=Available \
	  deploy/tex-operator --timeout=180s

# ── the live assertion ────────────────────────────────────────────────────────
kind-test:
	CLUSTER_NAME=$(CLUSTER_NAME) ./scripts/kind/kind-test.sh

kind-status:
	kubectl --context kind-$(CLUSTER_NAME) get ns agents -o yaml 2>/dev/null | grep -A3 labels || true
	kubectl --context kind-$(CLUSTER_NAME) get validatingadmissionpolicy,validatingadmissionpolicybinding 2>/dev/null || true
	kubectl --context kind-$(CLUSTER_NAME) get runtimeclass 2>/dev/null || true
	kubectl --context kind-$(CLUSTER_NAME) -n $(TEX_NAMESPACE) get pods 2>/dev/null || true

# ── teardown ──────────────────────────────────────────────────────────────────
kind-down:
	kind delete cluster --name $(CLUSTER_NAME)
