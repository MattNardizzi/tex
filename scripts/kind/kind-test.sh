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
"${KC[@]}" -n agents delete pod bad-agent good-agent --ignore-not-found --now >/dev/null 2>&1

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

# ── (b) the good pod MUST be admitted AND run under gVisor ────────────────────
bold $'\n== (b) COMPLIANT pod must be ADMITTED and run under gVisor =='
GOOD_OUT="$("${KC[@]}" apply -f "${TESTDIR}/pod-good.yaml" 2>&1)"
GOOD_RC=$?
echo "--- apiserver response to the good pod ---"
echo "${GOOD_OUT}"
echo "------------------------------------------"
[[ ${GOOD_RC} -eq 0 ]] || fail "the compliant pod was DENIED: ${GOOD_OUT}"
green "PASS: apiserver ADMITTED the compliant pod."

# Prove the injector ran (the mutating webhook added the annotation).
INJECTED="$("${KC[@]}" -n agents get pod good-agent -o jsonpath='{.metadata.annotations.tex\.systems/injected}' 2>/dev/null)"
if [[ "${INJECTED}" == "true" ]]; then
  green "PASS: mutating injector ran (tex.systems/injected=true on the admitted pod)."
else
  red "NOTE: the admitted pod has NO tex.systems/injected annotation (value='${INJECTED}')."
  red "      The VAP would normally DENY that. If you see this, the injector did not run"
  red "      yet admission passed — investigate the mutating webhook wiring."
fi

# Wait for it to schedule + run, then read /proc/version from inside.
bold $'\n>> waiting for good-agent to run under gVisor...'
if ! "${KC[@]}" -n agents wait --for=condition=Ready pod/good-agent --timeout=120s; then
  echo "--- good-agent did not become Ready; describe + container states ---"
  "${KC[@]}" -n agents describe pod good-agent | tail -40
  fail "compliant pod was admitted but did not reach Ready (see describe above)"
fi

KVER="$("${KC[@]}" -n agents exec good-agent -c app -- cat /proc/version 2>/dev/null)"
echo ">> good-agent /proc/version: ${KVER}"
if echo "${KVER}" | grep -qi "gvisor"; then
  green "PASS: the admitted pod is RUNNING under the gVisor sandbox (runsc)."
else
  red "the pod runs, but /proc/version does not report gVisor:"
  red "  ${KVER}"
  fail "compliant pod is not on the gVisor runtime (runsc not effective on the node)"
fi

bold $'\n== born-in-a-box: live apiserver DENIED the bad pod and ADMITTED the good one under gVisor =='
