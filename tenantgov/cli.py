"""Command line: `demo` builds everything from a fictional tenant, `report` runs on your own export."""
from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

from . import report, simulate
from .checks import Config, run_all
from .model import load, parse_date


def run(data: Path, out: Path, title: str, c: Config, as_of: date | None = None) -> dict:
    t = load(data, as_of)
    findings = run_all(t, c)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(report.render_html(t, findings, title, c), encoding="utf-8")
    (out / "review.md").write_text(report.review_md(t, findings, c), encoding="utf-8")
    report.write_findings(findings, out / "findings.csv")
    report.write_actions(findings, out / "actions.csv")
    report.write_privileged(t, out / "privileged-access.csv")
    report.write_licences(t, c, out / "licence-reclaim.csv")
    report.write_changes(t, c, out / "admin-changes.csv")
    sm = report.summary(t, findings, c)
    sm["currency"] = t.currency
    return sm


def _date(value: str) -> date:
    d = parse_date(value)
    if not d:
        raise argparse.ArgumentTypeError(f"not a date (YYYY-MM-DD): {value}")
    return d


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tenantgov", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="write the fictional tenant to sample_data/ and build the outputs")
    d.add_argument("--data", type=Path, default=Path("sample_data"))
    d.add_argument("--out", type=Path, default=Path("output"))

    r = sub.add_parser("report", help="build the outputs from your own export")
    r.add_argument("data", type=Path, help="folder with tenant.json (and changes.csv, settings.json)")
    r.add_argument("--out", type=Path, default=Path("output"))
    r.add_argument("--title", default="Microsoft 365 tenant governance")
    r.add_argument("--as-of", type=_date, help="review date, YYYY-MM-DD (default: settings.json or the export date)")
    r.add_argument("--max-global-admins", type=int, default=Config.max_global_admins)
    r.add_argument("--stale-days", type=int, default=Config.stale_days)
    r.add_argument("--report-only-days", type=int, default=Config.report_only_days)
    a = p.parse_args(argv)

    if a.cmd == "demo":
        simulate.write(a.data)
        sm = run(a.data, a.out, "Microsoft 365 tenant governance · Wide World Importers", Config())
    else:
        c = Config(max_global_admins=a.max_global_admins, stale_days=a.stale_days, report_only_days=a.report_only_days)
        try:
            sm = run(a.data, a.out, a.title, c, a.as_of)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    print(f"{sm['users']} accounts · {sm['global_admins']} Global Admins · {sm['standing']} standing admin assignments · "
          f"CA basics {sm['ca_ok']}/{sm['ca_total']} · settings {sm['settings_ok']}/{sm['settings_checked']} on baseline · "
          f"changes with a ticket {sm['changes_ok']}/{sm['changes']} · {sm['currency']}{sm['reclaim_month']:,.0f}/month to "
          f"reclaim · {sm['critical']} critical, {sm['warning']} warnings · outputs in {a.out}/")
    return 0
