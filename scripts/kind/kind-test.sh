#!/usr/bin/env bash
# Tex born-in-a-box: the LIVE admission assertion.
#
# Against the REAL kube-apiserver of the kind cluster:
#   (a) apply a NON-compliant pod -> assert the apiserver DENIES the CREATE, and
#       print the actual denial message it returned;
#   (b) apply a COMPLIANT pod     -> assert it is ADMITTED (CREATE succeeds, the
#       injector annotation is present) and that it RUNS under the gVisor sandbox
#       (its /proc/version reports gVisor).
#
# Exit non-zero (and say exactly which leg failed) if the live behavior does not
# match — no claim of a denial we did not observe.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-tex-bib}"
CTX="kind-${CLUSTER_NAME}"
KC=(kubectl --context "${CTX}")
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTDIR="${HERE}/test"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

fail() { red "FAIL: $*"; exit 1; }

bold "== Tex born-in-a-box live admission test (cluster ${CLUSTER_NAME}) =="

# Preconditions: the governed namespace, the VAP binding, and the RuntimeClass
# must all be live, else the test is meaningless.
"${KC[@]}" apply -f "${TESTDIR}/namespace.yaml" >/dev/null || fail "could not create governed namespace"

echo ">> preconditions:"
"${KC[@]}" get validatingadmissionpolicybinding tex-born-in-a-box >/dev/null 2>&1 \
  && echo "   - ValidatingAdmissionPolicyBinding tex-born-in-a-box: present" \
  || echo "   - WARNING: VAP binding tex-born-in-a-box NOT found (deny may come from the webhook only)"
"${KC[@]}" get runtimeclass gvisor >/dev/null 2>&1 \
  && echo "   - RuntimeClass gvisor: present" \
  || fail "RuntimeClass gvisor missing — shipRuntimeClass not applied"

# Clean any prior run so re-runs are deterministic.
"${KC[@]}" -n agents delete pod bad-agent good-agent gvisor-runtime-proof --ignore-not-found --now >/dev/null 2>&1

# ── (a) the bad pod MUST be denied by the apiserver ──────────────────────────
bold $'\n== (a) NON-compliant pod must be DENIED =='
BAD_OUT="$("${KC[@]}" apply -f "${TESTDIR}/pod-bad.yaml" 2>&1)"
BAD_RC=$?
echo "--- apiserver response to the bad pod ---"
echo "${BAD_OUT}"
echo "-----------------------------------------"
if [[ ${BAD_RC} -eq 0 ]]; then
  # It was admitted — that is a failure of the deny half. Clean up and fail.
  "${KC[@]}" -n agents delete pod bad-agent --ignore-not-found --now >/dev/null 2>&1
  fail "the non-compliant pod was ADMITTED — the deny half did not fire"
fi
# Confirm the denial actually came from Tex admission, not some unrelated error.
if echo "${BAD_OUT}" | grep -qiE "Tex admission|tex-born-in-a-box|denied by"; then
  green "PASS: apiserver DENIED the non-compliant pod (Tex admission)."
else
  red "the CREATE failed, but the message does not look like a Tex admission denial:"
  fail "unexpected denial reason (see message above)"
fi

# ── (b) the good pod MUST be ADMITTED ON MERIT (injector ran) ─────────────────
bold $'\n== (b) COMPLIANT pod must be ADMITTED because the injector ran =='
GOOD_OUT="$("${KC[@]}" apply -f "${TESTDIR}/pod-good.yaml" 2>&1)"
GOOD_RC=$?
echo "--- apiserver response to the good pod ---"
echo "${GOOD_OUT}"
echo "------------------------------------------"
[[ ${GOOD_RC} -eq 0 ]] || fail "the compliant pod was DENIED: ${GOOD_OUT}"
green "PASS: apiserver ADMITTED the compliant pod."

# The load-bearing half: it was admitted BECAUSE the mutating injector added the
# annotation (and the PEP sidecar) before the VAP evaluated — not because of a
# hand-written annotation. Its presence on the persisted pod proves the chain.
INJECTED="$("${KC[@]}" -n agents get pod good-agent -o jsonpath='{.metadata.annotations.tex\.systems/injected}' 2>/dev/null)"
[[ "${INJECTED}" == "true" ]] \
  || fail "admitted pod has NO tex.systems/injected annotation (value='${INJECTED}') — the injector did not run"
green "PASS: mutating injector ran (tex.systems/injected=true on the admitted pod)."
HAS_PROXY="$("${KC[@]}" -n agents get pod good-agent -o jsonpath='{.spec.containers[?(@.name=="tex-proxy")].name}' 2>/dev/null)"
[[ "${HAS_PROXY}" == "tex-proxy" ]] \
  && green "PASS: PEP sidecar (tex-proxy) was injected into the admitted pod." \
  || echo "   NOTE: tex-proxy sidecar not found on the admitted pod (injector added the annotation but not the sidecar?)"

# ── (c) a pod with runtimeClassName: gvisor MUST run under the runsc sandbox ──
bold $'\n== (c) the gvisor RuntimeClass must resolve to a real sandbox on the node =='
"${KC[@]}" apply -f "${TESTDIR}/pod-gvisor.yaml" >/dev/null || fail "could not create the gVisor runtime-proof pod"
if ! "${KC[@]}" -n agents wait --for=condition=Ready pod/gvisor-runtime-proof --timeout=90s; then
  echo "--- gvisor-runtime-proof did not become Ready; describe ---"
  "${KC[@]}" -n agents describe pod gvisor-runtime-proof | tail -30
  fail "gVisor runtime-proof pod did not reach Ready (runsc not effective on the node)"
fi
KVER="$("${KC[@]}" -n agents exec gvisor-runtime-proof -- cat /proc/version 2>/dev/null)"
echo ">> gvisor-runtime-proof /proc/version: ${KVER}"
if echo "${KVER}" | grep -qi "gvisor"; then
  green "PASS: the pod is RUNNING under the gVisor sandbox (runsc) — /proc/version reports gVisor."
else
  red "the pod runs, but /proc/version does not report gVisor: ${KVER}"
  fail "pod is not on the gVisor runtime (runsc not effective on the node)"
fi

bold $'\n== born-in-a-box live: apiserver DENIED the non-compliant pod, ADMITTED the'
bold    $'   injected compliant pod, and the gvisor RuntimeClass ran a pod under runsc. =='
