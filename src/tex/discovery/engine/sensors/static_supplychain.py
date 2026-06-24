"""
P8 — the STATIC SUPPLY-CHAIN / PROVENANCE plane (``PlaneId.STATIC_SUPPLYCHAIN``).

The LEADING-INDICATOR leg (ARCHITECTURE.md §8 P8; RESEARCH_LOG.md §1 P8, §6
P8): **an agent exists in code before it egresses a packet.** Every other plane
in the roster is a RUNTIME vantage — it can only see an agent that has already
asked for a decision, opened a socket, written a file, or run a syscall. This
plane is the one PRE-RUNTIME vantage: it scans a repository / source tree for
the DECLARATION of an agent and emits its footprint the moment the definition
exists, weeks before the agent first runs. An SDK pinned in a lockfile predicts
a future agent; an IaC resource with an attached IAM role declares its
pre-runtime blast radius; a provenance-ABSENCE fraction is an assumption-free
lower bound on un-attributable agents (RESEARCH_LOG.md §6 P8). [Qualys TotalAI
MCP-as-shadow-IT 2026-03; AgentDiscover Scanner; Agentproof arXiv 2603.20356
2026; CycloneDX AIBOM v1.7 + SLSA/in-toto 2026.]

What this sensor recognizes (PURE PARSING, NO NETWORK):

1. **Agent-framework graph constructs** — LangGraph (``StateGraph(...)`` /
   ``add_node`` / ``.compile()``), CrewAI (``Agent(...)`` / ``Crew(...)``),
   AutoGen (``AssistantAgent(...)`` / ``ConversableAgent(...)``), LangChain
   (``initialize_agent`` / ``create_*_agent`` / ``AgentExecutor``). The bound
   variable name is the ``agent_def_symbol`` (the declared agent's handle).
2. **MCP server manifests** — ``mcp.json`` / ``.mcp.json`` and
   ``.well-known/mcp.json`` / ``.well-known/ai-plugin.json`` style files, whose
   declared tools become ``declared_tools`` (the CLAIMED tool surface).
3. **IaC / serverless agent resources + attached IAM** — Terraform
   (``aws_lambda_function`` / ``aws_bedrock_agent`` + ``role``/``iam_role``) and
   Serverless-framework / SAM functions with an attached ``role`` — the
   PLATFORM_ATTESTED pre-runtime IAM blast radius.
4. **CI/CD configs + lockfiles / SBOM / provenance** — a workflow that runs an
   agent SDK, or a lockfile / CycloneDX-AIBOM listing an agent-framework package,
   is a leading indicator that an agent is about to exist.

ADMISSIBILITY (ARCHITECTURE.md §4): a DECLARED agent definition / manifest is
``CLAIMED`` — the code asserts it, but a claim is never load-bearing alone. An
IaC-granted IAM role is ``PLATFORM_ATTESTED`` — the infra-as-code platform
attests the grant (the pre-runtime reachable-resource surface).

CROSS-PLANE FUSION (ARCHITECTURE.md §2; fuse.py): the ``agent_def_symbol`` is
ALSO emitted as ``agent_external_id`` — the IDENTITY-grade cross-plane join key —
so a code-declared ``AssayPilot`` fuses to the SAME ``SieveEntity`` as that
agent's runtime ACTIONS_TRAIL / GOVERNANCE_STREAM / FS_WRITE footprints. The
declared-but-never-seen-at-runtime case (a symbol on THIS plane only) is the
leading-indicator shadow the estimator names. ``repo_path`` / ``framework`` /
``manifest_path`` ride as BRIDGING-grade declared-claim evidence (fuse.py
``_BRIDGING_KEYS``): two agents declared in one repo share a coarse cohort but
never over-merge on it.

SOURCE (configurable; degrade-empty): the scan root is supplied at construction
(``StaticSupplyChainSensor(roots=[...])``) or via the registry factory from
``TEX_SIEVE_P8_REPO`` (a colon/os-pathsep-separated list of dirs). It NEVER
hardcodes a path. A missing/unreadable directory, an unparseable file, or no
root at all degrades to EMPTY (fewer incidences, never an exception), honoring
the default-safe / flag-gated-OFF posture (``TEX_SIEVE_P8_SUPPLY``).

Catchability here is an ASSERTED plane recall (a slice constant): a DECLARED
agent is recovered with near-certainty by parsing, but an agent that was never
committed to a scanned source tree (hand-deployed, dynamically generated) is
out-of-cohort and is the estimator's job (named in the blind-spot ledger), not
faked here. The count-based slice estimator carries-but-does-not-consume this.

References: ARCHITECTURE.md §8 (P8 flag table: parse-only, no network), §4
(admissibility grades), §11 (vantage independence); RESEARCH_LOG.md §1 P8, §6 P8.
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence

from tex.discovery.engine.models import (
    Admissibility,
    FootprintField,
    FootprintVector,
    Incidence,
    PlaneId,
)
from tex.discovery.engine.sensors.base import SenseContext

_logger = logging.getLogger(__name__)

#: ASSERTED recall of the static supply-chain plane over DECLARED agents (a slice
#: constant, NOT measured; measurement deferred to Phase 5). A committed agent
#: definition / manifest / IaC resource is recovered with near-certainty by
#: parsing; agents never committed to a scanned tree are out-of-cohort and are
#: surfaced by the estimator's blind-spot ledger, not faked here.
STATIC_SUPPLYCHAIN_CATCHABILITY = 1.0

#: The registry env var naming the scan root(s): an os-pathsep-separated list of
#: directories to scan. Absent → the sensor has no root and senses nothing.
ENV_REPO_ROOTS = "TEX_SIEVE_P8_REPO"

#: Cap on files walked per root and bytes read per file — pure parsing must stay
#: cheap and bounded (RESEARCH_LOG.md §6 P8: "fast / parse-time"). A huge tree
#: degrades to a partial (still honest) scan rather than hanging.
_MAX_FILES_PER_ROOT = 20_000
_MAX_FILE_BYTES = 2_000_000

#: Directories never worth walking (vendored deps, VCS, build caches). Skipped to
#: keep the parse bounded and to avoid re-discovering third-party SDK internals as
#: first-party agents.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".terraform",
        "dist",
        "build",
        ".next",
        ".cache",
    }
)


# ---------------------------------------------------------------------------
# Framework agent-DEFINITION recognizers (Python source, pure regex/AST-lite)
# ---------------------------------------------------------------------------

#: Each recognizer is ``(framework_tag, compiled_pattern)``. The pattern captures
#: the bound agent symbol in group ``sym`` where a name is declared (assignment),
#: or the constructed class where the definition is anonymous. These are
#: deliberately conservative — they match the canonical construction call of each
#: framework's agent/graph primitive, not arbitrary prose.
_PY_FRAMEWORK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # LangGraph: a StateGraph / Graph compiled into a runnable agent.
    (
        "langgraph",
        re.compile(
            r"^\s*(?P<sym>[A-Za-z_]\w*)\s*=\s*(?:StateGraph|Graph|MessageGraph)\s*\(",
            re.MULTILINE,
        ),
    ),
    # CrewAI: an Agent(...) or a Crew(...) definition.
    (
        "crewai",
        re.compile(
            r"^\s*(?P<sym>[A-Za-z_]\w*)\s*=\s*(?:Agent|Crew)\s*\(",
            re.MULTILINE,
        ),
    ),
    # AutoGen: AssistantAgent / ConversableAgent / UserProxyAgent.
    (
        "autogen",
        re.compile(
            r"^\s*(?P<sym>[A-Za-z_]\w*)\s*=\s*"
            r"(?:AssistantAgent|ConversableAgent|UserProxyAgent|GroupChatManager)\s*\(",
            re.MULTILINE,
        ),
    ),
    # LangChain: an AgentExecutor / initialize_agent / create_*_agent.
    (
        "langchain",
        re.compile(
            r"^\s*(?P<sym>[A-Za-z_]\w*)\s*=\s*"
            r"(?:AgentExecutor|initialize_agent|create_\w+_agent)\s*\(",
            re.MULTILINE,
        ),
    ),
)

#: A LangGraph ``name=`` / CrewAI ``role=`` keyword that names the agent, to
#: prefer a human-readable declared name over the bound python variable when one
#: is present in the construction call's first line.
_NAME_KW = re.compile(
    r"""(?:name|role)\s*=\s*['"](?P<name>[^'"]{1,120})['"]""",
)

#: Lockfile / SBOM framework-package tells: a pinned agent-SDK package is a
#: LEADING indicator (an agent is about to exist). Matched against the raw text of
#: lockfiles / requirements / pyproject / package.json / SBOM docs.
_SDK_PACKAGES: tuple[tuple[str, str], ...] = (
    ("langgraph", "langgraph"),
    ("crewai", "crewai"),
    ("autogen", "pyautogen"),
    ("autogen", "autogen-agentchat"),
    ("langchain", "langchain"),
    ("openai-agents", "openai-agents"),
    ("llama-index", "llama-index"),
    ("semantic-kernel", "semantic-kernel"),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _as_str(val: object | None) -> str | None:
    """Coerce a present value to a trimmed string, or ``None``."""
    if val is None:
        return None
    s = str(val).strip()
    return s or None


def _canon_tools(tools: object) -> str | None:
    """Canonicalize a declared tool list/dict into a sorted, deduped CSV.

    Accepts the MCP ``tools`` array (list of ``{"name": ...}`` or strings) or a
    mapping of tool-name → schema. Returns a stable comma-joined string so the
    same declared surface compares equal across scans, or ``None`` if empty.
    """
    names: set[str] = set()
    if isinstance(tools, Mapping):
        names.update(str(k).strip() for k in tools.keys() if str(k).strip())
    elif isinstance(tools, (list, tuple)):
        for item in tools:
            if isinstance(item, Mapping):
                nm = _as_str(item.get("name"))
                if nm:
                    names.add(nm)
            else:
                nm = _as_str(item)
                if nm:
                    names.add(nm)
    return ",".join(sorted(names)) if names else None


def _read_text(path: Path) -> str | None:
    """Read a bounded amount of a file as text, or ``None`` (never raise)."""
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _rel(root: Path, path: Path) -> str:
    """Path of ``path`` relative to ``root`` (POSIX-style), best-effort."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


# ---------------------------------------------------------------------------
# The sensor
# ---------------------------------------------------------------------------


class StaticSupplyChainSensor:
    """Emits one ``Incidence`` per DECLARED agent / manifest / IaC resource (P8).

    Construct with ``roots`` — the directories to scan (configurable so a verifier
    can point it at a planted repo; NEVER hardcoded). ``sense`` ALSO honors
    ``SenseContext.workspace_dir`` as an additional root when supplied, so the
    pipeline can drive it the same way as the slice planes. With no roots at all,
    or roots that do not exist, it degrades to EMPTY and never raises.

    PURE PARSING — opens and reads files only; performs NO network I/O.
    """

    plane_id: PlaneId = PlaneId.STATIC_SUPPLYCHAIN

    def __init__(
        self,
        roots: Sequence[str | os.PathLike[str]] | None = None,
        *,
        catchability: float = STATIC_SUPPLYCHAIN_CATCHABILITY,
    ) -> None:
        self._roots = tuple(roots or ())
        self._catchability = catchability

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    def sense(self, context: SenseContext) -> Iterable[Incidence]:  # noqa: D401
        """Scan the configured roots into ``Incidence`` records (parse-only).

        - Walks each root (skipping vendored/VCS/build dirs), recognizing agent
          DEFINITIONS in Python source, MCP manifests, IaC/serverless resources,
          and lockfile/SBOM framework tells.
        - Emits one P8 incidence per recognized declaration, keyed on
          ``{agent_external_id, agent_def_symbol, repo_path, framework,
          manifest_path?, declared_tools?, iam_role?}`` — ``agent_external_id`` is
          the IDENTITY-grade cross-plane fusion join key; ``repo_path`` /
          ``framework`` / ``manifest_path`` are BRIDGING-grade declared cohorts.
        - ``admissibility=CLAIMED`` for declared defs/manifests;
          ``PLATFORM_ATTESTED`` for an IaC resource carrying an attached IAM role.
        - Returns an empty iterable on a missing/unreadable/empty source; NEVER
          raises.
        """
        return list(self._iter(context))

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _resolve_roots(self, context: SenseContext) -> list[Path]:
        roots: list[Path] = []
        for r in self._roots:
            try:
                p = Path(r)
            except TypeError:
                continue
            if p.is_dir():
                roots.append(p)
        ws = context.workspace_dir
        if ws is not None:
            try:
                wp = Path(ws)
                if wp.is_dir() and wp not in roots:
                    roots.append(wp)
            except TypeError:
                pass
        return roots

    def _iter(self, context: SenseContext) -> Iterator[Incidence]:
        for root in self._resolve_roots(context):
            try:
                yield from self._scan_root(root)
            except Exception as exc:  # noqa: BLE001 — degrade-to-empty is the contract
                _logger.info(
                    "sieve: static_supplychain root %s degraded: %s", root, exc
                )

    def _walk(self, root: Path) -> Iterator[Path]:
        """Bounded, skip-listed file walk under ``root`` (never raises)."""
        count = 0
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip dirs in place so os.walk doesn't descend them.
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                count += 1
                if count > _MAX_FILES_PER_ROOT:
                    return
                yield Path(dirpath) / name

    def _scan_root(self, root: Path) -> Iterator[Incidence]:
        for path in self._walk(root):
            name = path.name.lower()
            suffix = path.suffix.lower()
            try:
                if suffix == ".py":
                    yield from self._scan_python(root, path)
                elif self._is_mcp_manifest(path):
                    yield from self._scan_mcp_manifest(root, path)
                elif suffix == ".tf":
                    yield from self._scan_terraform(root, path)
                elif name in ("serverless.yml", "serverless.yaml", "template.yaml", "template.yml"):
                    yield from self._scan_serverless(root, path)
                elif self._is_lockfile(name):
                    yield from self._scan_lockfile(root, path)
            except Exception as exc:  # noqa: BLE001 — one bad file never aborts the scan
                _logger.info("sieve: static_supplychain file %s skipped: %s", path, exc)

    # ----- (1) framework agent definitions in Python source --------------

    def _scan_python(self, root: Path, path: Path) -> Iterator[Incidence]:
        text = _read_text(path)
        if not text:
            return
        repo_path = _rel(root, path)
        for framework, pattern in _PY_FRAMEWORK_PATTERNS:
            for match in pattern.finditer(text):
                symbol = match.group("sym")
                if not symbol:
                    continue
                # Prefer a declared name=/role= literal on the construction line.
                line_end = text.find("\n", match.end())
                window = text[match.start(): line_end if line_end != -1 else match.end() + 200]
                name_kw = _NAME_KW.search(window)
                declared_name = name_kw.group("name") if name_kw else symbol
                inc = self._emit(
                    repo_path=repo_path,
                    agent_def_symbol=symbol,
                    agent_external_id=declared_name,
                    framework=framework,
                    admissibility=Admissibility.CLAIMED,
                    evidence_ref=f"static:{repo_path}#{symbol}",
                )
                if inc is not None:
                    yield inc

    # ----- (2) MCP server manifests --------------------------------------

    @staticmethod
    def _is_mcp_manifest(path: Path) -> bool:
        name = path.name.lower()
        if name in ("mcp.json", ".mcp.json", "ai-plugin.json"):
            return True
        # .well-known/mcp.json (or any json under a .well-known dir).
        return path.suffix.lower() == ".json" and ".well-known" in (
            p.lower() for p in path.parts
        )

    def _scan_mcp_manifest(self, root: Path, path: Path) -> Iterator[Incidence]:
        text = _read_text(path)
        if not text:
            return
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            return
        if not isinstance(doc, Mapping):
            return
        manifest_path = _rel(root, path)

        # An MCP server manifest may declare ONE server (name + tools) or a map of
        # named servers under "mcpServers"/"servers". Handle both.
        servers = doc.get("mcpServers") or doc.get("servers")
        if isinstance(servers, Mapping) and servers:
            for srv_name, srv in servers.items():
                tools = srv.get("tools") if isinstance(srv, Mapping) else None
                inc = self._emit_manifest(
                    root, path, manifest_path, _as_str(srv_name), tools
                )
                if inc is not None:
                    yield inc
            return

        # Single-server / ai-plugin manifest.
        srv_name = _as_str(doc.get("name") or doc.get("name_for_model"))
        tools = doc.get("tools")
        inc = self._emit_manifest(root, path, manifest_path, srv_name, tools)
        if inc is not None:
            yield inc

    def _emit_manifest(
        self,
        root: Path,
        path: Path,
        manifest_path: str,
        srv_name: str | None,
        tools: object,
    ) -> Incidence | None:
        # The manifest's declared name is the agent handle; fall back to the file
        # stem so a nameless manifest still yields a footprint (never dropped).
        symbol = srv_name or path.stem
        declared_tools = _canon_tools(tools)
        return self._emit(
            repo_path=_rel(root, path),
            agent_def_symbol=symbol,
            agent_external_id=symbol,
            framework="mcp",
            manifest_path=manifest_path,
            declared_tools=declared_tools,
            admissibility=Admissibility.CLAIMED,
            evidence_ref=f"static:{manifest_path}#{symbol}",
        )

    # ----- (3) IaC / serverless agent resources + attached IAM -----------

    #: Terraform resource header: ``resource "aws_lambda_function" "assay" {``.
    _TF_RESOURCE = re.compile(
        r'resource\s+"(?P<rtype>[A-Za-z0-9_]+)"\s+"(?P<rname>[A-Za-z0-9_\-]+)"\s*\{',
    )
    #: An attached IAM role/arn reference inside a resource body.
    _TF_ROLE = re.compile(
        r'(?:role|iam_role|role_arn|execution_role_arn)\s*=\s*"?(?P<role>[^"\n#]+)"?',
    )
    #: IaC resource TYPES that declare an agent-capable compute / agent service.
    _IAC_AGENT_TYPES = (
        "aws_lambda_function",
        "aws_bedrock_agent",
        "aws_bedrockagent_agent",
        "google_cloudfunctions_function",
        "google_cloudfunctions2_function",
        "azurerm_function_app",
    )

    def _scan_terraform(self, root: Path, path: Path) -> Iterator[Incidence]:
        text = _read_text(path)
        if not text:
            return
        repo_path = _rel(root, path)
        for match in self._TF_RESOURCE.finditer(text):
            rtype = match.group("rtype")
            if rtype not in self._IAC_AGENT_TYPES:
                continue
            rname = match.group("rname")
            # Scan the resource body (to the next blank-line-balanced brace) for an
            # attached IAM role. Cheap heuristic: the window to the next top-level
            # ``}`` that begins a line, capped.
            body = text[match.end(): match.end() + 4000]
            role_match = self._TF_ROLE.search(body)
            iam_role = role_match.group("role").strip() if role_match else None
            yield from self._emit_iac(
                root, repo_path, symbol=rname, framework="terraform", iam_role=iam_role
            )

    def _scan_serverless(self, root: Path, path: Path) -> Iterator[Incidence]:
        text = _read_text(path)
        if not text:
            return
        repo_path = _rel(root, path)
        # Parse-only YAML-lite: find ``functions:`` then each ``  <name>:`` and a
        # nearby ``role:``. Avoid a YAML dependency — stay pure-stdlib, bounded.
        funcs_idx = re.search(r"^functions:\s*$", text, re.MULTILINE)
        if not funcs_idx:
            return
        block = text[funcs_idx.end():]
        # A function entry is a 2-space-indented ``name:`` key.
        for fn in re.finditer(r"^\s{2}(?P<fn>[A-Za-z0-9_\-]+):\s*$", block, re.MULTILINE):
            fn_name = fn.group("fn")
            window = block[fn.end(): fn.end() + 1500]
            role_match = re.search(r"role:\s*(?P<role>[^\n#]+)", window)
            iam_role = role_match.group("role").strip() if role_match else None
            yield from self._emit_iac(
                root, repo_path, symbol=fn_name, framework="serverless", iam_role=iam_role
            )

    def _emit_iac(
        self,
        root: Path,
        repo_path: str,
        *,
        symbol: str,
        framework: str,
        iam_role: str | None,
    ) -> Iterator[Incidence]:
        # An IaC resource carrying an attached IAM role is PLATFORM_ATTESTED (the
        # infra-as-code platform attests the pre-runtime grant); without a role it
        # is still a CLAIMED declared resource.
        admissibility = (
            Admissibility.PLATFORM_ATTESTED if iam_role else Admissibility.CLAIMED
        )
        inc = self._emit(
            repo_path=repo_path,
            agent_def_symbol=symbol,
            agent_external_id=symbol,
            framework=framework,
            iam_role=iam_role,
            admissibility=admissibility,
            evidence_ref=f"static:{repo_path}#{symbol}",
        )
        if inc is not None:
            yield inc

    # ----- (4) lockfiles / SBOM framework tells --------------------------

    @staticmethod
    def _is_lockfile(name: str) -> bool:
        return name in (
            "requirements.txt",
            "pyproject.toml",
            "poetry.lock",
            "uv.lock",
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "pipfile.lock",
        ) or name.endswith(("bom.json", "sbom.json", ".cdx.json"))

    def _scan_lockfile(self, root: Path, path: Path) -> Iterator[Incidence]:
        text = _read_text(path)
        if not text:
            return
        lowered = text.lower()
        repo_path = _rel(root, path)
        seen: set[str] = set()
        for framework, pkg in _SDK_PACKAGES:
            if framework in seen:
                continue
            # Word-ish boundary so ``langchain`` doesn't match ``mylangchainfork``
            # as the declared dependency line.
            if re.search(rf"(?<![\w.\-]){re.escape(pkg)}(?![\w.])", lowered):
                seen.add(framework)
                # A lockfile SDK tell is a LEADING indicator: it names a framework
                # cohort, not a specific agent symbol. The package name is the
                # def-symbol; admissibility is CLAIMED (the manifest declares it).
                inc = self._emit(
                    repo_path=repo_path,
                    agent_def_symbol=pkg,
                    agent_external_id=None,  # no specific agent yet — cohort only
                    framework=framework,
                    manifest_path=repo_path,
                    admissibility=Admissibility.CLAIMED,
                    evidence_ref=f"static:{repo_path}#dep:{pkg}",
                    sbom_tell=True,
                )
                if inc is not None:
                    yield inc

    # ----- emit ----------------------------------------------------------

    def _emit(
        self,
        *,
        repo_path: str,
        agent_def_symbol: str,
        agent_external_id: str | None,
        framework: str,
        admissibility: Admissibility,
        evidence_ref: str,
        manifest_path: str | None = None,
        declared_tools: str | None = None,
        iam_role: str | None = None,
        sbom_tell: bool = False,
    ) -> Incidence | None:
        """Build one P8 incidence (or ``None`` if it carries no footprint key)."""
        keys: dict[str, str] = {
            FootprintField.REPO_PATH: repo_path,
            FootprintField.AGENT_DEF_SYMBOL: agent_def_symbol,
            FootprintField.FRAMEWORK: framework,
        }
        # ``agent_external_id`` is the IDENTITY-grade cross-plane join key. It is
        # omitted for a pure SBOM/lockfile cohort tell (no specific agent yet), so
        # a leading-indicator dependency never spuriously fuses with a runtime
        # agent that merely shares a framework.
        if agent_external_id:
            keys["agent_external_id"] = agent_external_id
        if manifest_path:
            keys[FootprintField.MANIFEST_PATH] = manifest_path
        if declared_tools:
            keys[FootprintField.DECLARED_TOOLS] = declared_tools
        if iam_role:
            keys[FootprintField.IAM_ROLE] = iam_role

        attrs: dict[str, str] = {
            "pre_runtime": "true",  # this plane sees an agent BEFORE it runs
            "sbom_tell": str(bool(sbom_tell)).lower(),
        }

        footprint = FootprintVector.of(
            plane_id=PlaneId.STATIC_SUPPLYCHAIN, keys=keys, attrs=attrs
        )
        try:
            return Incidence(
                plane_id=PlaneId.STATIC_SUPPLYCHAIN,
                footprint=footprint,
                catchability=self._catchability,
                admissibility=admissibility,
                raw_evidence_ref=evidence_ref,
                observed_at=datetime.now(UTC),
            )
        except ValueError:
            # A verifier-injected out-of-range catchability degrades to a dropped
            # row, never a raised exception.
            return None


# ---------------------------------------------------------------------------
# Registry factory
# ---------------------------------------------------------------------------


def build_static_supplychain_sensor(env: Mapping[str, str]) -> StaticSupplyChainSensor:
    """Registry factory for the P8 static supply-chain sensor (degrade-empty).

    Reads the scan root(s) from ``TEX_SIEVE_P8_REPO`` (an os-pathsep-separated
    list of directories). With the var unset/blank the sensor is constructed with
    NO root and therefore senses nothing — keeping the flag-gated activation path
    (``TEX_SIEVE_P8_SUPPLY``) default-safe: enabling the flag without configuring a
    repo root yields an empty plane, never a crash. Pure parsing, no network.
    """
    raw = (env.get(ENV_REPO_ROOTS) or "").strip()
    roots = tuple(p for p in raw.split(os.pathsep) if p.strip()) if raw else ()
    return StaticSupplyChainSensor(roots=roots)


__all__ = [
    "StaticSupplyChainSensor",
    "build_static_supplychain_sensor",
    "STATIC_SUPPLYCHAIN_CATCHABILITY",
    "ENV_REPO_ROOTS",
]
