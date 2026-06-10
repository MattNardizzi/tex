# Tex web image — the PDP (decision plane). Multi-stage, non-root.
#
# What this image runs
# --------------------
#   uvicorn tex.main:app --host 0.0.0.0 --port 8080 --workers 1
#
# It is a SINGLE-PROCESS, SINGLE-WORKER image on purpose (see deploy/DURABILITY.md):
#   * The authoritative evidence record is a hash-CHAINED append-only JSONL file
#     (src/tex/evidence/recorder.py). EvidenceRecorder continues the chain from
#     the file's last record on boot (recorder.py:_load_last_record_hash), so the
#     chain survives a restart IFF the file survives — hence the volume below.
#   * In-process telemetry counters and the /metrics exposition are per-process;
#     multiple workers would each hold an independent, divergent view. One worker
#     keeps the scrape coherent without Prometheus multiprocess gymnastics.
# Durable shared state (decisions, policies, evidence MIRROR, agent registry,
# discovery ledger, ...) is written through to Postgres when DATABASE_URL is set
# (src/tex/db/connection.py, src/tex/memory/_db.py). Set DATABASE_URL in prod.
#
# Evidence path is CWD-relative in the served app: main.py's create_app() uses
# DEFAULT_EVIDENCE_PATH = "var/tex/evidence/evidence.jsonl" and does NOT read
# TEX_EVIDENCE_PATH (settings.evidence_path is unused by the module-level app).
# WORKDIR is pinned to /app so the chain deterministically lands at
# /app/var/tex/evidence/evidence.jsonl — the mount point the Helm PVC and the
# Render disk both target. (Honoring TEX_EVIDENCE_PATH in create_app() is a
# recommended one-line follow-up owned by whoever owns main.py.)

# ---- builder: resolve deps into an isolated venv ----------------------------
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /app

# Only the requirements file busts this layer, so deps cache across code edits.
COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt

# ---- runtime: slim, non-root ------------------------------------------------
FROM python:3.12-slim AS runtime

# A fixed non-root UID so a mounted volume can be chowned predictably.
RUN groupadd --gid 10001 tex \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin tex

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
# Application code (src layout — no package install, PYTHONPATH=src). Keeps the
# image to the runtime surface; tests/docs/deploy manifests are excluded via
# .dockerignore.
COPY src/ ./src/
COPY requirements.txt ./

# The durable state directory. Holds BOTH the evidence-chain JSONL
# (var/tex/evidence) and the evidence-seal signing key (var/tex/keys, which is
# regenerated if lost — losing it breaks signature continuity). Declared a
# VOLUME at the parent so an unmounted run still persists for the container's
# life, and a real PVC/disk mounts here in production. Owned by the runtime user
# because the process drops to it below.
RUN mkdir -p /app/var/tex/evidence /app/var/tex/keys && chown -R tex:tex /app/var
VOLUME ["/app/var/tex"]

USER tex

EXPOSE 8080

# Liveness without curl/wget in the slim image: use the venv's Python directly.
# Port-aware so it matches the actual bind port (Render injects $PORT).
HEALTHCHECK --interval=30s --timeout=3s --start-period=25s --retries=3 \
    CMD python -c "import os,sys,urllib.request; p=os.environ.get('PORT','8080'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+p+'/health', timeout=2).status == 200 else 1)"

# Single worker on purpose (see header). Binds $PORT (default 8080) so the same
# image works on Render (dynamic PORT) and standalone; the Helm chart overrides
# `command` with an explicit --port. `exec` makes uvicorn PID 1 for clean
# SIGTERM. Override --workers only with a coherent multi-replica/multi-worker
# design (deploy/DURABILITY.md "Multi-replica").
CMD ["sh", "-c", "exec uvicorn tex.main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1"]
