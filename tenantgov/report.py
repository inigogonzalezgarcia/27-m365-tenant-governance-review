"""Outputs: report.html, review.md, actions.csv, findings.csv, privileged-access.csv, licence-reclaim.csv, admin-changes.csv."""
from __future__ import annotations

import csv
import html
import re
from pathlib import Path

from .checks import (AREAS, CRITICAL, INFO, WARNING, Config, Finding, area_status, baseline, ca_essentials, ca_matrix,
                     change_rows, licence_rows, licence_usage, role_holders, _show)
from .model import Tenant

e = html.escape
CHANGE_LABEL = {"covered": "Approved change", "emergency": "Emergency change", "rejected": "Change rejected",
                "no_change": "No change", "break_glass": "Emergency account"}
CHANGE_CLASS = {"covered": "ok", "emergency": "info", "rejected": "critical", "no_change": "critical",
                "break_glass": "warning"}


def summary(t: Tenant, findings: list[Finding], c: Config | None = None) -> dict:
    c = c or Config()
    holders = role_holders(t)
    ga = {r["assignment"].principal.lower() for r in holders if r["assignment"].role == "Global Administrator"
          and r["assignment"].principal_type == "user" and r["org"] != "emergency"
          and not (r["assignment"].end and r["assignment"].end < t.as_of)}
    standing = sum(1 for r in holders if r["assignment"].kind == "permanent" and r["org"] not in ("emergency", "app")
                   and r["assignment"].principal_type == "user" and not (r["assignment"].end and r["assignment"].end < t.as_of))
    base = baseline(t)
    ch = change_rows(t, c)
    reclaim = licence_rows(t, c)
    return {"users": len(t.users), "privileged": len(holders), "global_admins": len(ga), "standing": standing,
            "ca_ok": sum(r["ok"] for r in ca_essentials(t)), "ca_total": len(ca_essentials(t)),
            "settings_ok": sum(r["status"] == "ok" for r in base),
            "settings_checked": sum(r["status"] != "not_collected" for r in base),
            "changes": len(ch), "changes_ok": sum(r["state"] == "covered" for r in ch),
            "changes_provider": sum(r["provider"] for r in ch),
            "reclaim_count": len(reclaim), "reclaim_month": sum(r["monthly_cost"] for r in reclaim),
            "critical": sum(f.severity == CRITICAL for f in findings),
            "warning": sum(f.severity == WARNING for f in findings),
            "info": sum(f.severity == INFO for f in findings)}


def write_findings(findings: list[Finding], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["severity", "area", "code", "subject", "owner", "ref", "monthly_cost", "detail", "next_step"])
        for f in findings:
            w.writerow([f.severity, f.area, f.code, f.subject, f.owner, f.ref, f"{f.cost:.2f}" if f.cost else "",
                        f.detail, f.fix])


def write_actions(findings: list[Finding], path: Path) -> int:
    """One row per action, worst first, with the owner (internal team or the provider) and a 'done' column."""
    rows = [f for f in findings if f.severity != INFO]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["priority", "severity", "area", "owner", "subject", "action", "why", "done"])
        for i, f in enumerate(rows, 1):
            w.writerow([i, f.severity, f.area, f.owner, f.subject, f.fix, f.detail, ""])
    return len(rows)


def write_privileged(t: Tenant, path: Path) -> None:
    """The list for the quarterly access review: one row per privileged assignment."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["principal", "type", "organisation", "role", "tier0", "assignment", "start", "end", "mfa",
                    "last_signin", "issues", "keep_yes_no", "reviewer"])
        for r in role_holders(t):
            a, u = r["assignment"], r["user"]
            w.writerow([a.principal, a.principal_type, r["org"], a.role, "yes" if a.tier0 else "no", a.kind.replace("_", "-"),
                        a.start or "", a.end or "", "" if not u or u.mfa is None else ("yes" if u.mfa else "no"),
                        r["last_signin"] or ("never" if u else ""), "; ".join(r["issues"]), "", ""])


def write_licences(t: Tenant, c: Config, path: Path) -> float:
    rows = licence_rows(t, c)
    names = {s.sku: s.name or s.sku for s in t.skus}
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["user", "display", "licence", "reason", "last_signin", "monthly_cost", "reclaim_yes_no"])
        for r in sorted(rows, key=lambda r: (r["why"] != "account disabled", r["user"].upn)):
            u = r["user"]
            w.writerow([u.upn, u.display, names.get(r["sku"], r["sku"]), r["why"], u.last_signin or "never",
                        f"{r['monthly_cost']:.2f}", ""])
    return sum(r["monthly_cost"] for r in rows)


def write_changes(t: Tenant, c: Config, path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["when", "actor", "organisation", "operation", "target", "change", "change_status", "result"])
        for r in change_rows(t, c):
            ev, ch = r["event"], r["change"]
            w.writerow([f"{ev.when:%Y-%m-%d %H:%M}", ev.actor,
                        "emergency" if r["state"] == "break_glass" else (t.provider or "provider") if r["provider"] else "internal",
                        ev.operation, ev.target, ch.ref if ch else "", ch.status if ch else "", CHANGE_LABEL[r["state"]]])


def review_md(t: Tenant, findings: list[Finding], c: Config | None = None) -> str:
    c = c or Config()
    sm, st = summary(t, findings, c), area_status(findings)
    who = f" · operated with {t.provider}" if t.provider else ""
    lines = [f"# Microsoft 365 tenant governance · {t.name} · {t.as_of:%Y-%m-%d}", "",
             f"{sm['users']} accounts{who} · {sm['global_admins']} named Global Administrators · {sm['standing']} standing "
             f"admin assignments · Conditional Access basics {sm['ca_ok']}/{sm['ca_total']} · settings on baseline "
             f"{sm['settings_ok']}/{sm['settings_checked']} · admin changes with an approved ticket "
             f"{sm['changes_ok']}/{sm['changes']} · {t.currency}{sm['reclaim_month']:,.2f} a month in licences to reclaim · "
             f"{sm['critical']} critical, {sm['warning']} warnings.", "",
             "| Area | Status |", "|---|---|"] + [f"| {a} | {'OK' if st[a] == 'ok' else st[a].upper()} |" for a in AREAS]
    for sev, title in ((CRITICAL, "Fix first"), (WARNING, "This month")):
        items = [f for f in findings if f.severity == sev]
        if items:
            lines += ["", f"## {title}", ""]
            for f in items:
                lines.append(f"- **{f.subject}** · {f.owner or '?'}: {f.detail}  \n  Next step: {f.fix}")
    prov = [f for f in findings if t.provider and f.owner == t.provider and f.severity != INFO]
    if prov:
        lines += ["", f"## For the service review with {t.provider}", ""] + [f"- {f.subject}: {f.detail}" for f in prov]
    infos = [f for f in findings if f.severity == INFO]
    if infos:
        lines += ["", "## For information", ""] + [f"- {f.subject}: {f.detail}" for f in infos]
    lines += ["", "Work list: `actions.csv` · access review: `privileged-access.csv` · licences: `licence-reclaim.csv` · "
              "changes: `admin-changes.csv`.", ""]
    return "\n".join(lines)


CSS = """
:root{--bg:#f6f7f8;--card:#fff;--ink:#1b2128;--muted:#66717c;--line:#e2e5e9;--ok:#1e7a4c;--warn:#a46200;--bad:#b42318;--info:#0b6bcb;--na:#8a94a0}
@media (prefers-color-scheme:dark){:root{--bg:#13171b;--card:#1b2127;--ink:#e7eaee;--muted:#9aa5b0;--line:#2b333b;--ok:#4cc38a;--warn:#f0a83a;--bad:#f2685c;--info:#5aa9f0;--na:#6d7782}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 12px}
.muted{color:var(--muted)}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(118px,1fr));gap:12px;margin-top:20px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.tile b{display:block;font-size:26px}
.areas{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.area{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--ok);border-radius:10px;padding:10px 14px}
.area.critical{border-left-color:var(--bad)}.area.warning{border-left-color:var(--warn)}
.area .lbl{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin-bottom:4px}.area .cnt{display:block;font-size:13px;color:var(--muted);margin-top:4px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}.wrap{overflow-x:auto}.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;white-space:nowrap;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;border:1px solid currentColor}
.critical{color:var(--bad)}.warning{color:var(--warn)}.info{color:var(--info)}.ok{color:var(--ok)}.na{color:var(--na)}
.area.critical,.area.warning,.area.ok{color:inherit}
.ess{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px}.ess div{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 14px}
.ess b{display:block}.tag{display:inline-block;font-size:12px;padding:0 6px;margin:2px 4px 0 0;border-radius:5px;background:var(--line)}
.bar{height:10px;border-radius:5px;background:var(--line);overflow:hidden;min-width:120px}.bar i{display:block;height:100%;background:var(--ok)}.bar i.over{background:var(--bad)}
td.nw{white-space:nowrap}td.fix{font-size:13px;color:var(--muted);max-width:380px}code{font-size:12px}
footer{margin-top:40px;font-size:13px}
"""


def _pill(s: str, label: str | None = None) -> str:
    return f"<span class='pill {s}'>{e(label or ('OK' if s == 'ok' else s.upper()))}</span>"


def _short(text: str) -> str:
    """Guest UPNs (name_domain#EXT#@tenant.onmicrosoft.com) shown as the original address part only."""
    return re.sub(r"#EXT#@[A-Za-z0-9.-]+", "", text, flags=re.I)


def render_html(t: Tenant, findings: list[Finding], title: str, c: Config | None = None) -> str:
    c = c or Config()
    sm, st = summary(t, findings, c), area_status(findings)
    cur = t.currency
    who = f" · operated with {e(t.provider)}" if t.provider else ""
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
         f"<title>{e(title)}</title><style>{CSS}</style></head><body><main>",
         f"<h1>{e(title)}</h1><p class='muted'>{e(t.name)} · {sm['users']} accounts{who} · as of {t.as_of:%d %b %Y}</p>",
         "<div class='tiles'>"]
    tiles = [("Global Administrators", str(sm["global_admins"]), f"named, limit {c.max_global_admins}"),
             ("Standing admin access", str(sm["standing"]), "always-on assignments"),
             ("Conditional Access basics", f"{sm['ca_ok']}/{sm['ca_total']}", "enforced"),
             ("Settings on baseline", f"{sm['settings_ok']}/{sm['settings_checked']}", "tenant-wide settings"),
             ("Admin changes with a ticket", f"{sm['changes_ok']}/{sm['changes']}", f"{sm['changes_provider']} by the provider"),
             ("Licences to reclaim", f"{cur}{sm['reclaim_month']:,.0f}", f"a month · {sm['reclaim_count']} licences"),
             ("Critical", str(sm["critical"]), f"{sm['warning']} warnings · {sm['info']} for information")]
    h += [f"<div class='tile'><span class='muted'>{e(a)}</span><b>{e(b)}</b><span class='muted'>{e(x)}</span></div>"
          for a, b, x in tiles]
    h.append("</div><h2>Status by area</h2><div class='areas'>")
    for a in AREAS:
        n = sum(f.area == a and f.severity != INFO for f in findings)
        h.append(f"<div class='area {st[a]}'><span class='lbl'>{e(a)}</span>{_pill(st[a])}<span class='cnt'>{n} to act on</span></div>")
    h.append("</div>")

    act = [f for f in findings if f.severity == CRITICAL]
    if act:
        h.append("<h2>Fix first</h2><div class='wrap'><table><tr><th>Subject</th><th>What</th><th>Next step</th><th>Owner</th></tr>")
        h += [f"<tr><td><b>{e(_short(f.subject))}</b><br><span class='muted'>{e(f.area)}</span></td><td>{e(f.detail)}</td>"
              f"<td class='fix'>{e(f.fix)}</td><td class='nw'>{e(f.owner or '?')}</td></tr>" for f in act]
        h.append("</table></div>")

    # privileged access
    h.append("<h2>Privileged access</h2><div class='wrap'><table><tr><th>Who</th><th>Role</th><th>Assignment</th>"
             "<th>MFA</th><th>Last sign-in</th><th>Issues</th></tr>")
    for r in role_holders(t):
        a, u = r["assignment"], r["user"]
        kind_cls = "" if a.kind != "permanent" or r["org"] == "emergency" else "critical" if a.tier0 else "warning"
        mfa = "–" if not u or u.mfa is None else ("<span class='ok'>yes</span>" if u.mfa else "<span class='critical'>no</span>")
        end = f" · until {a.end}" if a.end else ""
        issues = " ".join(_pill("critical" if i in ("no MFA", "guest", "emergency account not permanent") else "warning", i)
                          for i in r["issues"]) or \
            "<span class='ok'>–</span>"
        h.append(f"<tr><td>{e(_short(a.principal))}<br><span class='muted'>{e(r['org'])}</span></td>"
                 f"<td>{'<b>' if a.tier0 else ''}{e(a.role)}{'</b>' if a.tier0 else ''}</td>"
                 f"<td class='nw {kind_cls}'>{e(a.kind.replace('_', '-'))}{e(end)}</td><td>{mfa}</td>"
                 f"<td class='nw'>{r['last_signin'] or ('never' if u else '–')}</td><td>{issues}</td></tr>")
    h.append("</table></div><p class='muted'>Bold: tenant-wide (tier 0) roles. Emergency accounts are expected to be "
             "permanent Global Administrators.</p>")

    # conditional access
    h.append("<h2>Conditional Access</h2><div class='ess'>")
    for r in ca_essentials(t):
        cls = "ok" if r["ok"] else "critical"
        extra = "".join(f"<span class='tag'>{e(p)}</span>" for p in r["policies"])
        if not r["ok"] and r["report_only"]:
            extra = "<span class='muted'>only in report-only: </span>" + "".join(
                f"<span class='tag'>{e(p)}</span>" for p in r["report_only"])
        h.append(f"<div><b class='{cls}'>{'✓' if r['ok'] else '✗'} {e(r['label'])}</b>{extra}</div>")
    h.append("</div><p></p><div class='wrap'><table><tr><th>Policy</th><th>State</th><th>Users</th><th>Excluded</th>"
             "<th>Clients</th><th>Control</th></tr>")
    for r in ca_matrix(t):
        p = r["policy"]
        cls = "ok" if p.on else "warning" if p.state == "reportOnly" else "na"
        h.append(f"<tr><td>{e(p.name)}</td><td class='nw {cls}'>{e(p.state)}</td><td>{e(r['who'])}</td>"
                 f"<td class='fix'>{e(', '.join(_short(x) for x in p.exclude_users) or '–')}</td>"
                 f"<td>{e(r['clients'])}</td><td>{e(r['control'])}</td></tr>")
    h.append("</table></div>")

    # settings baseline
    h.append("<h2>Tenant settings against the baseline</h2><div class='wrap'><table><tr><th>Setting</th><th>Now</th>"
             "<th>Baseline</th><th>Status</th><th>Why it matters</th></tr>")
    for r in baseline(t):
        rule = r["rule"]
        stc = {"ok": "ok", "drift": rule.severity, "not_collected": "na"}[r["status"]]
        lbl = {"ok": "OK", "drift": "Drift", "not_collected": "Not collected"}[r["status"]]
        now = "–" if r["actual"] is None else _show(r["actual"])
        h.append(f"<tr><td>{e(rule.label)}<br><span class='muted'><code>{e(rule.key)}</code></span></td><td>{e(now)}</td>"
                 f"<td>{e(' or '.join(_show(a) for a in rule.allowed))}</td><td>{_pill(stc, lbl)}</td>"
                 f"<td class='fix'>{e(rule.why)}</td></tr>")
    h.append("</table></div>")

    # licences
    h.append("<h2>Licences</h2><div class='wrap'><table><tr><th>Licence</th><th class='num'>Bought</th><th class='num'>Assigned</th>"
             "<th>Use</th><th class='num'>Per month</th></tr>")
    for r in licence_usage(t):
        s = r["sku"]
        pct = r["assigned"] / s.purchased if s.purchased else 0
        bar = f"<div class='bar'><i class='{'over' if pct > 1 else ''}' style='width:{min(pct, 1) * 100:.0f}%'></i></div>"
        h.append(f"<tr><td>{e(s.name or s.sku)}</td><td class='num'>{s.purchased}</td>"
                 f"<td class='num {'critical' if pct > 1 else ''}'>{r['assigned']}</td><td>{bar}</td>"
                 f"<td class='num'>{cur}{s.monthly_cost:,.2f}</td></tr>")
    rec = licence_rows(t, c)
    dis = sum(r["monthly_cost"] for r in rec if r["why"] == "account disabled")
    h.append(f"</table></div><p class='muted'>To reclaim: {cur}{dis:,.2f} a month on disabled accounts and "
             f"{cur}{sm['reclaim_month'] - dis:,.2f} on accounts with no sign-in for {c.stale_days}+ days "
             f"({len(rec)} licences, list in <code>licence-reclaim.csv</code>). Prices come from settings.json.</p>")

    # admin changes
    rows = change_rows(t, c)
    if rows:
        h.append("<h2>Admin changes and change tickets</h2><div class='wrap'><table><tr><th>When</th><th>Who</th>"
                 "<th>What</th><th>Change</th><th>Result</th></tr>")
        for r in rows:
            ev, ch = r["event"], r["change"]
            org = "emergency account" if r["state"] == "break_glass" else (t.provider or "provider") if r["provider"] else "internal"
            h.append(f"<tr><td class='nw'>{ev.when:%d %b %H:%M}</td><td>{e(ev.actor)}<br><span class='muted'>{e(org)}</span></td>"
                     f"<td>{e(ev.operation)}<br><span class='muted'>{e(ev.target)}</span></td>"
                     f"<td>{e(ch.ref + ' · ' + ch.title) if ch else '–'}</td>"
                     f"<td>{_pill(CHANGE_CLASS[r['state']], CHANGE_LABEL[r['state']])}</td></tr>")
        h.append("</table></div><p class='muted'>Sensitive operations only (roles, Conditional Access, tenant and mail "
                 "flow settings). A change counts when its implementer and window match the audit entry.</p>")

    h.append("<h2>All findings</h2><div class='wrap'><table><tr><th>Severity</th><th>Area</th><th>Subject</th><th>Detail</th><th>Next step</th></tr>")
    h += [f"<tr><td>{_pill(f.severity)}</td><td class='nw'>{e(f.area)}</td><td>{e(_short(f.subject))}</td><td>{e(f.detail)}</td>"
          f"<td class='fix'>{e(f.fix)}</td></tr>" for f in findings]
    h.append("</table></div><footer class='muted'>Generated by tenantgov from a read-only export of the tenant and the "
             "change tickets. Fictional demo data unless you ran it on your own export.</footer></main></body></html>")
    return _short("".join(h))
