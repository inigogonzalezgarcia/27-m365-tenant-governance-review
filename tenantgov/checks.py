"""Checks: privileged access, emergency accounts, Conditional Access, tenant settings, licences and admin changes."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta

from .model import AuditEvent, CAPolicy, Change, RoleAssignment, Tenant

CRITICAL, WARNING, INFO = "critical", "warning", "info"
SEV_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2}
AREAS = ("Privileged access", "Emergency access", "Conditional Access", "Tenant settings", "Licences", "Admin changes")


@dataclass
class Config:
    max_global_admins: int = 4      # named Global Administrators, emergency accounts not counted
    stale_days: int = 90            # no sign-in for this long: privileged role or licence to review
    report_only_days: int = 30      # a report-only policy older than this should be switched on or removed
    break_glass_signin_days: int = 30
    change_window_grace_minutes: int = 60   # admin change this long after the window still counts as in the window


@dataclass
class Finding:
    severity: str
    area: str
    code: str
    subject: str
    detail: str
    fix: str
    owner: str = ""
    ref: str = ""
    cost: float = 0.0


# --- tenant settings baseline --------------------------------------------------------------------------------------
@dataclass
class Rule:
    key: str
    label: str
    allowed: tuple
    severity: str
    why: str
    fix: str
    owner: str = "Identity"


BASELINE = (
    Rule("entra.user_consent", "Users can consent to apps", ("none", "low_risk"), CRITICAL,
         "any user can grant an app access to company data",
         "Allow consent only for verified publishers and low-risk permissions, and turn on the admin consent workflow."),
    Rule("entra.guest_invite", "Who can invite guests", ("none", "adminsAndGuestInviters"), WARNING,
         "every member can invite external users without a review",
         "Limit invitations to admins and the Guest Inviter role."),
    Rule("entra.users_can_register_apps", "Users can register applications", (False,), WARNING,
         "app registrations appear without an owner or a review", "Turn off user app registration; request them through IT."),
    Rule("entra.users_can_create_tenants", "Users can create tenants", (False,), WARNING,
         "users can create unmanaged tenants with company identities", "Restrict non-admin users from creating tenants."),
    Rule("spo.sharing", "SharePoint and OneDrive external sharing",
         ("disabled", "existingExternalUserSharingOnly", "externalUserSharingOnly"), WARNING,
         "'Anyone' links share files with no sign-in",
         "Set organisation sharing to 'New and existing guests' and allow Anyone links only on sites that need them.",
         "Collaboration"),
    Rule("exo.auto_forwarding", "Automatic forwarding to external addresses", ("Off", "Automatic"), CRITICAL,
         "mailbox rules can forward mail outside the company, a common data leak after a phishing compromise",
         "Set the outbound spam policy to block automatic forwarding and allow it only for named mailboxes.", "Messaging"),
    Rule("exo.smtp_auth_disabled", "SMTP AUTH disabled for the organisation", (True,), WARNING,
         "basic SMTP authentication bypasses MFA and Conditional Access",
         "Disable SMTP AUTH at organisation level and enable it only on the mailboxes of the devices that need it.",
         "Messaging"),
    Rule("exo.dkim_missing", "Domains without DKIM signing", ((),), WARNING,
         "mail from these domains is easier to spoof and more likely to land in spam",
         "Publish the two DKIM CNAME records and enable DKIM signing for each domain.", "Messaging"),
    Rule("exo.mailbox_audit_disabled", "Mailbox auditing turned off", (False,), CRITICAL,
         "mailbox access is not recorded, so an investigation has nothing to work with",
         "Turn mailbox auditing back on for the organisation.", "Messaging"),
    Rule("purview.unified_audit", "Unified audit log ingestion", (True,), CRITICAL,
         "admin and user activity is not recorded in the audit log", "Turn on audit log ingestion in Microsoft Purview.",
         "Security"),
)


def _norm(v):
    if isinstance(v, list):
        return tuple(sorted(v))
    return v


def baseline(t: Tenant) -> list[dict]:
    rows = []
    for r in BASELINE:
        if r.key not in t.settings:
            rows.append({"rule": r, "actual": None, "status": "not_collected"})
            continue
        actual = _norm(t.settings[r.key])
        ok = actual in r.allowed or (isinstance(actual, str) and actual.lower() in {str(a).lower() for a in r.allowed})
        rows.append({"rule": r, "actual": actual, "status": "ok" if ok else "drift"})
    return rows


def _show(v) -> str:
    if isinstance(v, tuple):
        return ", ".join(v) or "none"
    if isinstance(v, bool):
        return "yes" if v else "no"
    return str(v)


# --- helpers --------------------------------------------------------------------------------------------------------
def days_since(d: date | None, as_of: date) -> int | None:
    return None if d is None else (as_of - d).days


def active_roles(t: Tenant) -> list[RoleAssignment]:
    """Assignments that are still in force on the review date."""
    return [r for r in t.roles if not (r.end and r.end < t.as_of)]


def role_holders(t: Tenant) -> list[dict]:
    """One row per privileged assignment with its state, for the report and privileged-access.csv."""
    rows = []
    for r in sorted(t.roles, key=lambda r: (not r.tier0, r.role, r.principal.lower())):
        if not r.privileged:
            continue
        u = t.user(r.principal) if r.principal_type == "user" else None
        issues = []
        if r.end and r.end < t.as_of:
            issues.append("expired")
        if r.kind == "permanent" and not t.is_break_glass(r.principal) and r.principal_type == "user":
            issues.append("standing access")
        if u and u.mfa is False and not t.is_break_glass(r.principal):
            issues.append("no MFA")
        if u and u.guest:
            issues.append("guest")
        if u and not u.enabled:
            issues.append("disabled")
        ds = days_since(u.last_signin, t.as_of) if u else None
        if u and (ds is None or ds > 90) and not t.is_break_glass(r.principal):
            issues.append("no sign-in 90 d")
        if t.is_break_glass(r.principal) and not (r.role == "Global Administrator" and r.kind == "permanent"):
            issues.append("emergency account not permanent")
        if r.principal_type == "servicePrincipal" and r.tier0:
            issues.append("app with tier 0 role")
        org = ("emergency" if t.is_break_glass(r.principal) else
               "guest" if u and u.guest else
               (t.provider or "provider") if t.is_provider(r.principal) else
               "app" if r.principal_type == "servicePrincipal" else "internal")
        rows.append({"assignment": r, "user": u, "org": org, "issues": issues, "last_signin": u.last_signin if u else None})
    return rows


def _sev_cmp(f: Finding):
    return (SEV_ORDER[f.severity], AREAS.index(f.area), f.subject.lower())


# --- checks ---------------------------------------------------------------------------------------------------------
def check_privileged(t: Tenant, c: Config) -> list[Finding]:
    out = []
    A = "Privileged access"
    roles = active_roles(t)
    ga = {r.principal.lower() for r in roles if r.role == "Global Administrator" and r.principal_type == "user"
          and not t.is_break_glass(r.principal)}
    if len(ga) > c.max_global_admins:
        out.append(Finding(WARNING, A, "GA_TOO_MANY", f"{len(ga)} Global Administrators",
                           f"{len(ga)} named accounts can hold Global Administrator (limit {c.max_global_admins}, "
                           "emergency accounts not counted)",
                           "Move day-to-day admins to the least-privileged role that covers their work "
                           "(Exchange, SharePoint, User Administrator…).", "Identity"))
    if len(ga) < 2:
        out.append(Finding(WARNING, A, "GA_TOO_FEW", f"{len(ga)} named Global Administrator",
                           "fewer than two named people can take over if the only admin is away",
                           "Make a second person eligible for Global Administrator through PIM.", "Identity"))
    per_user: dict[str, list[RoleAssignment]] = defaultdict(list)
    for r in t.roles:
        if not r.privileged:
            continue
        who, bg = r.principal, t.is_break_glass(r.principal)
        prov = t.is_provider(who)
        owner = t.provider if prov and t.provider else "Identity"
        if r.end and r.end < t.as_of:
            out.append(Finding(WARNING, A, "ROLE_EXPIRED_KEPT", f"{who} · {r.role}",
                               f"assignment ended on {r.end} but is still in the list", "Remove the assignment.",
                               owner, r.role))
            continue
        if r.principal_type == "servicePrincipal":
            if r.tier0:
                out.append(Finding(WARNING, A, "APP_TIER0", f"{who} · {r.role}",
                                   "an application holds a tenant-wide admin role; its secret or certificate is a key "
                                   "to the whole tenant", "Replace the role with the Graph permissions the app needs, "
                                   "or document why it needs it and who owns it.", "Identity", r.role))
            continue
        if r.principal_type == "group" or bg:
            continue
        per_user[who].append(r)
        u = t.user(who)
        if u and u.guest:
            continue
        if r.kind == "permanent":
            if r.tier0:
                out.append(Finding(CRITICAL, A, "PERMANENT_TIER0", f"{who} · {r.role}",
                                   ("provider account with " if prov else "") + "standing (always-on) " + r.role +
                                   " assignment", "Convert to eligible in PIM with approval and a maximum activation "
                                   "of a few hours.", owner, r.role))
            else:
                out.append(Finding(WARNING, A, "PERMANENT_PRIV", f"{who} · {r.role}",
                                   ("provider account with " if prov else "") + f"standing {r.role} assignment",
                                   "Convert to eligible in PIM.", owner, r.role))
        if prov and not r.end:
            out.append(Finding(WARNING, A, "PROVIDER_NO_END", f"{who} · {r.role}",
                               f"{t.provider or 'provider'} assignment with no end date",
                               "Give provider assignments an end date that matches the contract or the project, "
                               "and renew them at the access review.", owner, r.role))
    # checks about the person: once per account, with all of their roles
    for who, rs in per_user.items():
        u = t.user(who)
        names = ", ".join(r.role for r in rs)
        owner = t.provider if t.is_provider(who) and t.provider else "Identity"
        if u is None:
            out.append(Finding(WARNING, A, "PRIV_UNKNOWN", f"{who} · {names}", "role holder not found in the user list",
                               "Check the export or remove the assignment.", owner, names))
            continue
        if u.guest:
            out.append(Finding(CRITICAL, A, "PRIV_GUEST", f"{who} · {names}",
                               "a guest account holds an admin role in this tenant",
                               "Remove the role; give the person a member account from this tenant if they need it.",
                               owner, names))
        if u.mfa is False:
            out.append(Finding(CRITICAL, A, "PRIV_NO_MFA", f"{who} · {names}", "admin with no MFA method registered",
                               "Register a phishing-resistant method (FIDO2 key or Windows Hello) before the role is "
                               "used again.", owner, names))
        if not u.enabled:
            out.append(Finding(WARNING, A, "PRIV_DISABLED", f"{who} · {names}",
                               "disabled account still holds admin roles", "Remove the roles from the disabled account.",
                               owner, names))
        else:
            ds = days_since(u.last_signin, t.as_of)
            if ds is None or ds > c.stale_days:
                out.append(Finding(WARNING, A, "PRIV_STALE", f"{who} · {names}",
                                   "never signed in" if ds is None else f"no sign-in for {ds} days",
                                   "Remove the role, or confirm at the access review that it is still needed.",
                                   owner, names))
    return out


def check_break_glass(t: Tenant, c: Config) -> list[Finding]:
    out = []
    A = "Emergency access"
    if len(t.break_glass) < 2:
        out.append(Finding(WARNING, A, "BG_COUNT", f"{len(t.break_glass)} emergency account(s) declared",
                           "Microsoft recommends two cloud-only emergency access accounts",
                           "Create two cloud-only accounts on the onmicrosoft.com domain with permanent Global "
                           "Administrator, list them in settings.json and alert on every sign-in.", "Identity"))
    for bg in t.break_glass:
        u = t.user(bg)
        if not u:
            out.append(Finding(CRITICAL, A, "BG_MISSING", bg, "declared emergency account not found in the tenant",
                               "Recreate it or fix the name in settings.json.", "Identity"))
            continue
        if not any(r.principal.lower() == bg.lower() and r.role == "Global Administrator" and r.kind == "permanent"
                   and not (r.end and r.end < t.as_of) for r in t.roles):
            out.append(Finding(CRITICAL, A, "BG_NOT_GA", bg,
                               "emergency account is not a permanent Global Administrator, so it cannot rescue the "
                               "tenant if PIM or MFA fail", "Assign Global Administrator permanently (active, no end "
                               "date).", "Identity"))
        if not u.enabled:
            out.append(Finding(CRITICAL, A, "BG_DISABLED", bg, "emergency account is disabled",
                               "Enable it and test the sign-in in a planned exercise.", "Identity"))
        ds = days_since(u.last_signin, t.as_of)
        if ds is not None and ds <= c.break_glass_signin_days:
            out.append(Finding(WARNING, A, "BG_SIGNIN", bg, f"emergency account signed in {ds} days ago",
                               "Confirm it was a planned test or a real emergency, and that the sign-in alert fired.",
                               "Security"))
        for p in t.policies:
            if p.on and p.all_users and (p.blocks or p.requires_mfa) and not _excluded(p, bg, t) and \
                    "phishingresistantmfa" not in {g.lower() for g in p.grant}:
                out.append(Finding(WARNING, A, "BG_NOT_EXCLUDED", f"{bg} · {p.name}",
                                   "the policy applies to the emergency account; a fault in MFA or in the policy "
                                   "itself could lock everyone out", "Exclude the emergency accounts from the policy "
                                   "(or require a FIDO2 key for them) and cover them with sign-in alerts.", "Identity",
                                   p.name))
    return out


def _excluded(p: CAPolicy, upn: str, t: Tenant | None = None) -> bool:
    ex = {x.lower() for x in p.exclude_users}
    return upn.lower() in ex or bool(t and any(t.is_break_glass(x) and x.lower() not in
                                               {b.lower() for b in t.break_glass} for x in p.exclude_users))


ADMIN_TARGETS = {"global administrator", "admins", "all admins", "directory roles"}


def _covers_admins(p: CAPolicy) -> bool:
    return p.all_users or any(x.lower() in ADMIN_TARGETS for x in p.include_users)


def check_conditional_access(t: Tenant, c: Config) -> list[Finding]:
    out = []
    A = "Conditional Access"
    on = [p for p in t.policies if p.on]
    legacy = lambda p: p.blocks and p.all_users and (p.legacy_only or "legacy" in p.name.lower())  # noqa: E731
    if not any(legacy(p) for p in on):
        pending = [p.name for p in t.policies if p.state == "reportOnly" and legacy(p)]
        out.append(Finding(CRITICAL, A, "CA_NO_LEGACY_BLOCK", "Legacy authentication not blocked",
                           "no enabled policy blocks Exchange ActiveSync and other legacy clients for all users; "
                           "legacy protocols skip MFA" + (f" ({pending[0]} is only in report-only)" if pending else ""),
                           (f"Check the report-only results of {pending[0]}, move the last legacy clients, then switch "
                            "it on." if pending else "Create (in report-only for a week, then on) a policy that blocks "
                            "legacy authentication for all users."), "Identity"))
    if not any(p.requires_mfa and _covers_admins(p) for p in on):
        out.append(Finding(CRITICAL, A, "CA_NO_ADMIN_MFA", "MFA not enforced for admins",
                           "no enabled policy requires MFA for admin roles",
                           "Require phishing-resistant MFA for all admin roles, on all apps.", "Identity"))
    if not any(p.requires_mfa and p.all_users for p in on):
        out.append(Finding(WARNING, A, "CA_NO_ALL_MFA", "MFA not enforced for all users",
                           "no enabled policy requires MFA for every user",
                           "Require MFA for all users on all cloud apps, with the emergency accounts excluded.", "Identity"))
    if not any(p.requires_mfa and (p.all_users or any(x.lower() in ("guests", "guestsorexternalusers")
                                                      for x in p.include_users)) for p in on):
        out.append(Finding(WARNING, A, "CA_NO_GUEST_MFA", "Guests not covered by MFA",
                           "no enabled MFA policy applies to guests and external users",
                           "Include guests in the MFA policy, or add one for them.", "Identity"))
    for p in t.policies:
        age = days_since(p.modified, t.as_of)
        if p.state == "reportOnly" and (age is None or age > c.report_only_days):
            out.append(Finding(WARNING, A, "CA_REPORT_ONLY", p.name,
                               f"in report-only for {age if age is not None else 'an unknown number of'} days",
                               "Review the sign-in impact in the report and switch it on, or delete it.", "Identity", p.name))
        elif p.state == "disabled":
            out.append(Finding(INFO, A, "CA_DISABLED", p.name, "policy is switched off",
                               "Delete it if it is no longer needed, so the policy list stays readable.", "Identity", p.name))
        if p.on:
            extra = [x for x in p.exclude_users if not t.is_break_glass(x)]
            if extra:
                out.append(Finding(WARNING, A, "CA_EXCLUSIONS", p.name,
                                   f"{len(extra)} exclusion(s) besides the emergency accounts: {', '.join(extra)}",
                                   "Give each exclusion an owner and an end date, or remove it.", "Identity", p.name))
    return out


def check_settings(t: Tenant, c: Config) -> list[Finding]:
    out = []
    for row in baseline(t):
        r = row["rule"]
        if row["status"] == "not_collected":
            out.append(Finding(INFO, "Tenant settings", "NOT_COLLECTED", r.label, "not in the export",
                               "Export it (see the script options) or check it by hand in the admin centre.", r.owner, r.key))
        elif row["status"] == "drift":
            out.append(Finding(r.severity, "Tenant settings", "DRIFT", r.label,
                               f"is '{_show(row['actual'])}', baseline '{' or '.join(_show(a) for a in r.allowed)}': {r.why}",
                               r.fix, r.owner, r.key))
    return out


def licence_rows(t: Tenant, c: Config) -> list[dict]:
    """Licences that can be reclaimed: on disabled accounts or unused for `stale_days`."""
    cost = {s.sku: s.monthly_cost for s in t.skus}
    rows = []
    for u in t.users:
        if not u.licences:
            continue
        ds = days_since(u.last_signin, t.as_of)
        if not u.enabled:
            why = "account disabled"
        elif ds is None and u.created and (t.as_of - u.created).days > c.stale_days:
            why = "never signed in"
        elif ds is not None and ds > c.stale_days:
            why = f"no sign-in for {ds} days"
        else:
            continue
        for sku in u.licences:
            rows.append({"user": u, "sku": sku, "why": why, "monthly_cost": cost.get(sku, 0.0)})
    return rows


def licence_usage(t: Tenant) -> list[dict]:
    assigned = defaultdict(int)
    for u in t.users:
        for s in u.licences:
            assigned[s] += 1
    return [{"sku": s, "assigned": assigned[s.sku]} for s in t.skus]


def check_licences(t: Tenant, c: Config) -> list[Finding]:
    out = []
    A = "Licences"
    rows = licence_rows(t, c)
    by = defaultdict(list)
    for r in rows:
        by[("disabled" if r["why"] == "account disabled" else "inactive", r["sku"])].append(r)
    names = {s.sku: s.name or s.sku for s in t.skus}
    for (kind, sku), items in sorted(by.items()):
        total = sum(r["monthly_cost"] for r in items)
        if kind == "disabled":
            out.append(Finding(WARNING, A, "LIC_DISABLED", f"{len(items)} × {names.get(sku, sku)} on disabled accounts",
                               f"{t.currency}{total:,.2f} a month paid for accounts nobody can use",
                               "Remove the licences in the leaver process (group-based licensing on an 'active "
                               "employees' group does it automatically).", "Licensing", sku, total))
        else:
            out.append(Finding(INFO, A, "LIC_INACTIVE", f"{len(items)} × {names.get(sku, sku)} unused for {c.stale_days}+ days",
                               f"{t.currency}{total:,.2f} a month on accounts with no recent sign-in",
                               "Check with the managers (long leave, shared mailbox, leaver) and reclaim.", "Licensing",
                               sku, total))
    for row in licence_usage(t):
        s = row["sku"]
        if s.purchased and row["assigned"] > s.purchased:
            out.append(Finding(CRITICAL, A, "LIC_OVER", f"{s.name or s.sku}: {row['assigned']} assigned, {s.purchased} bought",
                               "more licences assigned than purchased: a true-up or a compliance finding",
                               "Reclaim the unused ones above, then buy the difference.", "Licensing", s.sku))
        elif s.purchased and s.purchased - row["assigned"] >= max(5, s.purchased * 0.1):
            free = s.purchased - row["assigned"]
            out.append(Finding(INFO, A, "LIC_SPARE", f"{s.name or s.sku}: {free} unassigned",
                               f"{t.currency}{free * s.monthly_cost:,.2f} a month in spare seats",
                               "Lower the quantity at the next renewal if the spare seats are not planned for "
                               "new joiners.", "Licensing", s.sku, free * s.monthly_cost))
    return out


SENSITIVE = ("Add member to role", "Add eligible member to role", "Remove member from role", "Update conditional access policy",
             "Add conditional access policy", "Delete conditional access policy", "Update authorization policy",
             "Set Company Information", "Update SharePoint tenant settings", "Set-HostedOutboundSpamFilterPolicy",
             "Set-TransportConfig", "New-TransportRule", "Set-TransportRule", "Set-OrganizationConfig",
             "Add service principal credentials", "Consent to application", "Set federation settings on domain",
             "Add domain to company")


def sensitive(ev: AuditEvent) -> bool:
    return ev.operation in SENSITIVE or ev.category.lower() in ("rolemanagement", "policy", "conditionalaccess")


def match_change(t: Tenant, ev: AuditEvent, c: Config) -> Change | None:
    """The change ticket that covers an admin action: same implementer (UPN or domain) and inside the window."""
    grace = timedelta(minutes=c.change_window_grace_minutes)
    best = None
    for ch in t.changes:
        who = ch.implementer.lower()
        actor = ev.actor.lower()
        if not who or not (who == actor or actor.endswith("@" + who) or (t.provider and who == t.provider.lower()
                                                                        and t.is_provider(actor))):
            continue
        if ch.start and ch.end and ch.start - grace <= ev.when <= ch.end + grace:
            if best is None or ch.status in ("approved", "emergency"):
                best = ch
    return best


def change_rows(t: Tenant, c: Config) -> list[dict]:
    rows = []
    for ev in sorted(t.audit, key=lambda x: x.when):
        if not sensitive(ev):
            continue
        ch = match_change(t, ev, c)
        state = ("break_glass" if t.is_break_glass(ev.actor) else
                 "covered" if ch and ch.status == "approved" else
                 "emergency" if ch and ch.status == "emergency" else
                 "rejected" if ch and ch.status == "rejected" else "no_change")
        rows.append({"event": ev, "change": ch, "state": state, "provider": t.is_provider(ev.actor)})
    return rows


def check_changes(t: Tenant, c: Config) -> list[Finding]:
    out = []
    A = "Admin changes"
    for r in change_rows(t, c):
        ev, ch = r["event"], r["change"]
        subj = f"{ev.when:%Y-%m-%d %H:%M} · {ev.operation}"
        who = f"{ev.actor} ({t.provider})" if r["provider"] and t.provider else ev.actor
        owner = t.provider if r["provider"] and t.provider else "IT"
        tgt = f" on {ev.target}" if ev.target else ""
        if r["state"] == "break_glass":
            out.append(Finding(WARNING, A, "CHG_BREAK_GLASS", subj, f"made with the emergency account{tgt}",
                               "Record why, rotate the account's credentials if it was a real emergency, and raise "
                               "a retrospective change.", "Security"))
        elif r["state"] == "rejected":
            out.append(Finding(CRITICAL, A, "CHG_REJECTED", subj, f"by {who}{tgt}, inside the window of {ch.ref}, which "
                               "was rejected", "Roll back or raise an emergency change, and review it with the provider.",
                               owner, ch.ref))
        elif r["state"] == "no_change":
            out.append(Finding(CRITICAL if r["provider"] else WARNING, A, "CHG_NO_TICKET", subj,
                               f"by {who}{tgt}: no approved change covers that time",
                               "Ask for the change reference; if there is none, review the change at the next CAB "
                               + ("and in the monthly service review with the provider." if r["provider"] else "."),
                               owner))
        elif r["state"] == "emergency":
            out.append(Finding(INFO, A, "CHG_EMERGENCY", subj, f"by {who}{tgt}, under emergency change {ch.ref}",
                               "Check it went through the retrospective CAB.", owner, ch.ref))
    return out


def run_all(t: Tenant, c: Config | None = None) -> list[Finding]:
    c = c or Config()
    out = (check_privileged(t, c) + check_break_glass(t, c) + check_conditional_access(t, c) + check_settings(t, c)
           + check_licences(t, c) + check_changes(t, c))
    return sorted(out, key=_sev_cmp)


def area_status(findings: list[Finding]) -> dict[str, str]:
    st = {}
    for a in AREAS:
        sev = [f.severity for f in findings if f.area == a]
        st[a] = CRITICAL if CRITICAL in sev else WARNING if WARNING in sev else "ok"
    return st


def ca_matrix(t: Tenant) -> list[dict]:
    """What each enabled or report-only policy does, for the report: who, which clients, which control."""
    rows = []
    for p in t.policies:
        rows.append({"policy": p, "who": ", ".join(p.include_users) or "nobody",
                     "except": ", ".join(p.exclude_users) or "–",
                     "clients": "legacy only" if p.legacy_only else ", ".join(p.client_apps),
                     "control": ", ".join(p.grant) or "–"})
    return rows


def ca_essentials(t: Tenant) -> list[dict]:
    """The four Conditional Access basics and which enabled policies provide each one."""
    on = [p for p in t.policies if p.on]
    tests = (
        ("Block legacy authentication", lambda p: p.blocks and p.all_users and (p.legacy_only or "legacy" in p.name.lower())),
        ("MFA for admin roles", lambda p: p.requires_mfa and _covers_admins(p)),
        ("MFA for all users", lambda p: p.requires_mfa and p.all_users),
        ("MFA for guests", lambda p: p.requires_mfa and (p.all_users or any(
            x.lower() in ("guests", "guestsorexternalusers") for x in p.include_users))),
    )
    rows = []
    for label, test in tests:
        hit = [p.name for p in on if test(p)]
        pending = [p.name for p in t.policies if p.state == "reportOnly" and test(p)]
        rows.append({"label": label, "ok": bool(hit), "policies": hit, "report_only": pending})
    return rows
