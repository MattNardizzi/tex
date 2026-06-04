"""
tex.sim CLI.

  python -m tex.sim run reference --base-url http://localhost:8000
  python -m tex.sim run smoke
  python -m tex.sim run reference --dry-run        # inspect offline, no backend
  python -m tex.sim describe reference             # dump the estate
  python -m tex.sim hook                            # print the main.py snippet
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="tex.sim", description="Tex sandbox simulator")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run a scenario against a Tex backend")
    r.add_argument("scenario", choices=["smoke", "reference", "soak"])
    r.add_argument("--base-url", default="http://localhost:8000")
    r.add_argument("--api-key", default=None)
    r.add_argument("--report", default=None, help="write JSON report to this path")
    r.add_argument("--proof-sample", type=int, default=20)
    r.add_argument("--dry-run", action="store_true", help="inspect estate + plan offline")

    lv = sub.add_parser("live", help="run a continuous, wall-clock-paced estate for stress testing")
    lv.add_argument("scenario", nargs="?", default="reference", choices=["smoke", "reference", "soak"],
                    help="estate sizing (verdicts are NOT asserted in live mode)")
    lv.add_argument("--base-url", default="http://localhost:8000")
    lv.add_argument("--api-key", default=None)
    lv.add_argument("--rate", type=float, default=1.0, help="mean actions/second across the estate")
    lv.add_argument("--duration", default=None, help="e.g. 2d, 36h, 90m, 3600s (default: until Ctrl-C)")
    lv.add_argument("--heartbeat", type=float, default=60.0, help="seconds between heartbeat readouts")
    lv.add_argument("--onboard", default="standard",
                    choices=["none", "standard", "trusted", "privileged"],
                    help="verify the governed cohort to this tier; 'none' stresses the cold path")
    lv.add_argument("--forbid-rate", type=float, default=0.06)
    lv.add_argument("--abstain-rate", type=float, default=0.18)
    lv.add_argument("--seed", type=int, default=7)
    lv.add_argument("--report", default=None, help="write a JSON summary on stop")

    d = sub.add_parser("describe", help="print the estate a scenario generates")
    d.add_argument("scenario", choices=["smoke", "reference", "soak"])
    d.add_argument("--json", action="store_true")

    sub.add_parser("hook", help="print the tex.main snippet that enables sandbox mode")

    args = ap.parse_args(argv)

    if args.cmd == "run":
        from tex.sim.runner import run
        report = run(args.scenario, base_url=args.base_url, api_key=args.api_key,
                     report_path=args.report, proof_sample=args.proof_sample,
                     dry_run=args.dry_run)
        print(report.console())
        return 0 if report.ok else 1

    if args.cmd == "live":
        from tex.sim.live import LiveConfig, parse_duration, run_live
        config = LiveConfig(
            scenario=args.scenario, rate=args.rate,
            duration_seconds=parse_duration(args.duration),
            heartbeat_seconds=args.heartbeat, onboard=args.onboard,
            forbid_rate=args.forbid_rate, abstain_rate=args.abstain_rate, seed=args.seed,
        )
        return run_live(config, base_url=args.base_url, api_key=args.api_key,
                        report_path=args.report)

    if args.cmd == "describe":
        from tex.sim.estate import generate_estate
        from tex.sim import scenarios
        sc = scenarios.get(args.scenario)
        est = generate_estate(seed=sc.seed, idp_agents=sc.idp_agents,
                              shadow_agents=sc.shadow_agents, mcp_agents=sc.mcp_agents)
        if args.json:
            print(json.dumps(est.summary(), indent=2))
        else:
            s = est.summary()
            print(f"{s['org']}  ({s['total']} agents, seed {s['seed']})")
            print(f"  IdP-visible : {s['idp_visible']}")
            print(f"  shadow      : {s['shadow']}")
            print(f"  by risk     : {s['by_risk']}")
            print(f"  by dept     : {s['by_department']}")
        return 0

    if args.cmd == "hook":
        from tex.sim.connectors import install_hint
        print(install_hint())
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
