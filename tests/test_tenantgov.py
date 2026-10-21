import csv
import json
import tempfile
import unittest
from datetime import date, datetime
from pathlib import Path

from tenantgov import cli, model, report, simulate
from tenantgov.checks import CRITICAL, INFO, WARNING, Config, baseline, ca_essentials, change_rows, licence_rows, run_all
from tenantgov.model import AuditEvent, CAPolicy, Change, RoleAssignment, Sku, Tenant, User

T = date(2026, 10, 21)
D = "contoso.example"
BG = ["bg1@contoso.onmicrosoft.com", "bg2@contoso.onmicrosoft.com"]
GOOD_SETTINGS = {"entra.user_consent": "low_risk", "entra.guest_invite": "adminsAndGuestInviters",
                 "entra.users_can_register_apps": False, "entra.users_can_create_tenants": False,
                 "spo.sharing": "externalUserSharingOnly", "exo.auto_forwarding": "Off", "exo.smtp_auth_disabled": True,
                 "exo.dkim_missing": [], "exo.mailbox_audit_disabled": False, "purview.unified_audit": True}
GOOD_POLICIES = [
    CAPolicy("Admins MFA", include_users=["Directory roles"], exclude_users=BG, grant=["phishingResistantMfa"]),
    CAPolicy("All users MFA", include_users=["All"], exclude_users=BG, grant=["mfa"]),
    CAPolicy("Block legacy", include_users=["All"], exclude_users=BG, client_apps=["exchangeActiveSync", "other"],
             grant=["block"]),
]


def u(name, **kw):
    base = dict(upn=name if "@" in name else f"{name}@{D}", mfa=True, last_signin=date(2026, 10, 20))
    base.update(kw)
    return User(**base)


def tenant(users=(), roles=(), policies=None, settings=None, **kw):
    """A clean tenant: two emergency accounts, two eligible Global Admins, the CA basics and the baseline settings."""
    us = [u(BG[0], last_signin=None), u(BG[1], last_signin=None), u("ana"), u("luis")] + list(users)
    rs = [RoleAssignment(BG[0], "Global Administrator"), RoleAssignment(BG[1], "Global Administrator"),
          RoleAssignment(f"ana@{D}", "Global Administrator", "eligible"),
          RoleAssignment(f"luis@{D}", "Global Administrator", "eligible")] + list(roles)
    base = dict(name="Test", as_of=T, provider="Fabrikam IT", provider_domains=["fabrikam.example"], break_glass=list(BG),
                users=us, roles=rs, policies=list(GOOD_POLICIES if policies is None else policies),
                settings=dict(GOOD_SETTINGS if settings is None else settings))
    base.update(kw)
    return Tenant(**base)


def codes(t, c=None):
    out = {}
    for f in run_all(t, c):
        out.setdefault(f.code, []).append(f)
    return out


class ParsingTests(unittest.TestCase):
    def test_dates_roles_and_change_csv(self):
        self.assertEqual(model.parse_date("2026-10-07T23:40:00Z"), date(2026, 10, 7))
        self.assertEqual(model.parse_date("07/10/2026"), date(2026, 10, 7))
        self.assertEqual(model.parse_dt("2026-10-07T23:40:00.1234567Z"), datetime(2026, 10, 7, 23, 40))
        self.assertEqual(model.norm_role("Company Administrator"), "Global Administrator")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "changes.csv"
            p.write_text("﻿Referencia;Título;Estado;Implementador;Inicio;Fin\n"
                         "CHG-1;Política MFA;Aprobado;fabrikam.example;07/10/2026 22:00;08/10/2026 01:00\n"
                         "CHG-2;Reenvío;Rechazado;ana@contoso.example;2026-10-09 09:00;2026-10-09 11:00\n", encoding="utf-8")
            ch = model.read_changes(p)
        self.assertEqual([c.status for c in ch], ["approved", "rejected"])
        self.assertEqual(ch[0].start, datetime(2026, 10, 7, 22, 0))

    def test_load_snapshot_with_settings_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "tenant.json").write_text(json.dumps({
                "tenant": "X", "exported": "2026-10-20T07:00:00Z",
                "users": [{"userPrincipalName": "a@x.example", "accountEnabled": "false", "mfa": "yes", "licences": "E3;PBI"}],
                "roles": [{"principal": "a@x.example", "role": "GA", "kind": "Active", "end": "2027-01-01"}],
                "conditional_access": [{"name": "P", "state": "enabledForReportingButNotEnforced", "grant": "block"}],
                "settings": {"exo.auto_forwarding": "On"}, "skus": [{"sku": "E3", "purchased": 10}]}), encoding="utf-8")
            Path(tmp, "settings.json").write_text(json.dumps({"settings_override": {"exo.auto_forwarding": "Off"},
                                                              "licence_costs": {"E3": 30}}), encoding="utf-8")
            t = model.load(Path(tmp))
        self.assertEqual(t.as_of, date(2026, 10, 20))
        self.assertFalse(t.users[0].enabled)
        self.assertEqual(t.users[0].licences, ["E3", "PBI"])
        self.assertEqual((t.roles[0].role, t.roles[0].kind), ("Global Administrator", "time_bound"))
        self.assertEqual(t.policies[0].state, "reportOnly")
        self.assertEqual(t.settings["exo.auto_forwarding"], "Off")
        self.assertEqual(t.skus[0].monthly_cost, 30.0)


class CleanTenantTests(unittest.TestCase):
    def test_clean_tenant_has_no_findings(self):
        t = tenant()
        self.assertEqual([(f.code, f.subject) for f in run_all(t) if f.severity != INFO], [])
        self.assertTrue(all(r["ok"] for r in ca_essentials(t)))
        self.assertTrue(all(r["status"] == "ok" for r in baseline(t)))


class PrivilegedTests(unittest.TestCase):
    def test_standing_tier0_and_other_roles(self):
        t = tenant(roles=[RoleAssignment(f"ana@{D}", "Privileged Role Administrator"),
                          RoleAssignment(f"luis@{D}", "Exchange Administrator"),
                          RoleAssignment(f"luis@{D}", "Security Reader")])
        k = codes(t)
        self.assertEqual(k["PERMANENT_TIER0"][0].severity, CRITICAL)
        self.assertEqual([f.ref for f in k["PERMANENT_PRIV"]], ["Exchange Administrator"])   # Security Reader ignored

    def test_global_admin_count_ignores_emergency_accounts(self):
        extra = [u(f"ga{i}") for i in range(3)]
        t = tenant(users=extra, roles=[RoleAssignment(x.upn, "Global Administrator", "eligible") for x in extra])
        self.assertIn("GA_TOO_MANY", codes(t))                      # 5 named
        self.assertNotIn("GA_TOO_MANY", codes(t, Config(max_global_admins=5)))
        t2 = tenant()
        t2.roles = [r for r in t2.roles if r.principal != f"luis@{D}"]
        self.assertIn("GA_TOO_FEW", codes(t2))

    def test_person_checks_are_grouped_per_account(self):
        t = tenant(users=[u("pablo", mfa=False), u("elena", last_signin=date(2026, 6, 1)), u("jorge", enabled=False),
                          u("x_partner.example#EXT#@contoso.onmicrosoft.com", user_type="Guest")],
                   roles=[RoleAssignment(f"pablo@{D}", "SharePoint Administrator", "eligible"),
                          RoleAssignment(f"pablo@{D}", "Teams Administrator", "eligible"),
                          RoleAssignment(f"elena@{D}", "Intune Administrator", "eligible"),
                          RoleAssignment(f"jorge@{D}", "Teams Administrator", "eligible"),
                          RoleAssignment("x_partner.example#EXT#@contoso.onmicrosoft.com", "User Administrator"),
                          RoleAssignment("ghost@contoso.example", "User Administrator", "eligible")])
        k = codes(t)
        self.assertEqual(len(k["PRIV_NO_MFA"]), 1)
        self.assertIn("Teams Administrator", k["PRIV_NO_MFA"][0].subject)
        self.assertEqual(k["PRIV_STALE"][0].detail, "no sign-in for 142 days")
        self.assertIn("PRIV_DISABLED", k)
        self.assertEqual(k["PRIV_GUEST"][0].severity, CRITICAL)
        self.assertNotIn("PERMANENT_PRIV", k)                       # the guest is reported once, as a guest
        self.assertIn("PRIV_UNKNOWN", k)

    def test_provider_apps_and_expired_assignments(self):
        t = tenant(users=[u("ops1@fabrikam.example")],
                   roles=[RoleAssignment("ops1@fabrikam.example", "Exchange Administrator", "eligible"),
                          RoleAssignment("ops1@fabrikam.example", "Intune Administrator", "eligible", end=date(2027, 3, 31)),
                          RoleAssignment("ops1@fabrikam.example", "User Administrator", "time_bound", end=date(2026, 9, 30)),
                          RoleAssignment("Old sync app", "Global Administrator", principal_type="servicePrincipal")])
        k = codes(t)
        self.assertEqual([f.ref for f in k["PROVIDER_NO_END"]], ["Exchange Administrator"])
        self.assertEqual(k["PROVIDER_NO_END"][0].owner, "Fabrikam IT")
        self.assertIn("ROLE_EXPIRED_KEPT", k)
        self.assertIn("APP_TIER0", k)
        self.assertNotIn("PRIV_UNKNOWN", k)                         # apps are not looked up as users


class EmergencyAccessTests(unittest.TestCase):
    def test_emergency_account_rules(self):
        t = tenant(break_glass=[BG[0], BG[1], "bg3@contoso.onmicrosoft.com"])
        t.roles[1] = RoleAssignment(BG[1], "Global Administrator", "eligible")
        t.users[0].last_signin = date(2026, 10, 9)
        t.policies[1] = CAPolicy("All users MFA", include_users=["All"], exclude_users=[BG[0]], grant=["mfa"])
        k = codes(t)
        self.assertEqual(k["BG_NOT_GA"][0].subject, BG[1])
        self.assertEqual(k["BG_MISSING"][0].subject, "bg3@contoso.onmicrosoft.com")
        self.assertEqual(k["BG_SIGNIN"][0].detail, "emergency account signed in 12 days ago")
        self.assertEqual({f.subject.split(" · ")[0] for f in k["BG_NOT_EXCLUDED"]}, {BG[1]})
        self.assertIn("BG_COUNT", codes(tenant(break_glass=[BG[0]])))

    def test_phishing_resistant_policy_may_include_emergency_accounts(self):
        t = tenant()
        t.policies[0] = CAPolicy("Admins FIDO2", include_users=["All"], grant=["phishingResistantMfa"])
        self.assertNotIn("BG_NOT_EXCLUDED", codes(t))


    def test_emergency_group_counts_as_exclusion(self):
        pols = [CAPolicy(p.name, include_users=p.include_users, client_apps=p.client_apps, grant=p.grant,
                         exclude_users=["group:Emergency access"]) for p in GOOD_POLICIES]
        k = codes(tenant(policies=pols, break_glass_groups=["Emergency access"]))
        self.assertNotIn("BG_NOT_EXCLUDED", k)
        self.assertNotIn("CA_EXCLUSIONS", k)
        self.assertIn("BG_NOT_EXCLUDED", codes(tenant(policies=pols)))


class ConditionalAccessTests(unittest.TestCase):
    def test_missing_basics_and_report_only(self):
        pols = [CAPolicy("Block legacy", state="reportOnly", include_users=["All"], client_apps=["other"], grant=["block"],
                         modified=date(2026, 7, 2)),
                CAPolicy("Guests MFA", include_users=["GuestsOrExternalUsers"], grant=["mfa"]),
                CAPolicy("Old", state="disabled", include_users=["All"], grant=["block"])]
        k = codes(tenant(policies=pols))
        self.assertIn("only in report-only", k["CA_NO_LEGACY_BLOCK"][0].detail)
        self.assertIn("CA_NO_ADMIN_MFA", k)
        self.assertIn("CA_NO_ALL_MFA", k)
        self.assertNotIn("CA_NO_GUEST_MFA", k)
        self.assertEqual(k["CA_REPORT_ONLY"][0].detail, "in report-only for 111 days")
        self.assertEqual(k["CA_DISABLED"][0].severity, INFO)
        recent = [CAPolicy("New", state="reportOnly", include_users=["All"], grant=["mfa"], modified=date(2026, 10, 1))]
        self.assertNotIn("CA_REPORT_ONLY", codes(tenant(policies=GOOD_POLICIES + recent)))

    def test_exclusions_other_than_emergency_accounts(self):
        pols = list(GOOD_POLICIES)
        pols[1] = CAPolicy("All users MFA", include_users=["All"], exclude_users=BG + [f"svc@{D}"], grant=["mfa"])
        f = codes(tenant(policies=pols))["CA_EXCLUSIONS"][0]
        self.assertIn(f"svc@{D}", f.detail)
        self.assertNotIn(BG[0], f.detail)


class SettingsTests(unittest.TestCase):
    def test_drift_and_not_collected(self):
        s = dict(GOOD_SETTINGS, **{"entra.user_consent": "all", "exo.auto_forwarding": "on", "exo.dkim_missing": ["b.example"],
                                   "spo.sharing": "externalUserAndGuestSharing"})
        del s["purview.unified_audit"]
        k = codes(tenant(settings=s))
        drift = {f.ref: f.severity for f in k["DRIFT"]}
        self.assertEqual(drift, {"entra.user_consent": CRITICAL, "exo.auto_forwarding": CRITICAL,
                                 "exo.dkim_missing": WARNING, "spo.sharing": WARNING})
        self.assertEqual([f.ref for f in k["NOT_COLLECTED"]], ["purview.unified_audit"])
        self.assertIn("'b.example'", next(f.detail for f in k["DRIFT"] if f.ref == "exo.dkim_missing"))
        self.assertTrue(any(r["status"] == "ok" for r in baseline(tenant(settings={"exo.auto_forwarding": "automatic"}))))


class LicenceTests(unittest.TestCase):
    def test_reclaim_over_assignment_and_spare_seats(self):
        users = ([u(f"left{i}", enabled=False, licences=["E3"]) for i in range(2)] +
                 [u(f"idle{i}", last_signin=date(2026, 5, 1), licences=["E3", "PBI"]) for i in range(3)] +
                 [u("new", last_signin=None, created=date(2026, 10, 10), licences=["E3"]),
                  u("never", last_signin=None, created=date(2025, 1, 10), licences=["E3"])] +
                 [u(f"pbi{i}", licences=["PBI"]) for i in range(2)])
        t = tenant(users=users, skus=[Sku("E3", "M365 E3", 30, 36.0), Sku("PBI", "Power BI Pro", 4, 14.0)])
        k = codes(t)
        self.assertEqual(k["LIC_DISABLED"][0].cost, 72.0)
        inactive = {f.ref: f for f in k["LIC_INACTIVE"]}
        self.assertEqual(inactive["E3"].subject, "4 × M365 E3 unused for 90+ days")        # 3 idle + never signed in
        self.assertEqual(k["LIC_OVER"][0].subject, "Power BI Pro: 5 assigned, 4 bought")
        self.assertEqual(k["LIC_SPARE"][0].subject, "M365 E3: 23 unassigned")
        self.assertEqual(round(sum(r["monthly_cost"] for r in licence_rows(t, Config())), 2), 72 + 4 * 36 + 3 * 14)


class ChangeTests(unittest.TestCase):
    def test_audit_entries_matched_to_change_tickets(self):
        ev = lambda h, who, op="Update conditional access policy": AuditEvent(datetime(2026, 10, 7, h, 30), who, op, "CA")  # noqa
        t = tenant(users=[u("ops1@fabrikam.example")],
                   audit=[ev(10, "ops1@fabrikam.example"), ev(13, "ops1@fabrikam.example"), ev(16, f"ana@{D}"),
                          ev(18, "ops1@fabrikam.example"), ev(20, BG[0]), ev(21, f"ana@{D}", "Update user"),
                          ev(22, "ops1@fabrikam.example")],
                   changes=[Change("C1", status="approved", implementer="Fabrikam IT", start=datetime(2026, 10, 7, 9),
                                   end=datetime(2026, 10, 7, 12)),
                            Change("C2", status="rejected", implementer="fabrikam.example",
                                   start=datetime(2026, 10, 7, 18), end=datetime(2026, 10, 7, 19)),
                            Change("C3", status="emergency", implementer="ops1@fabrikam.example",
                                   start=datetime(2026, 10, 7, 21), end=datetime(2026, 10, 7, 21, 45))])
        states = [r["state"] for r in change_rows(t, Config())]
        # 13:30 is outside C1 even with the 60-minute grace; 22:30 is inside C3's grace; "Update user" is not sensitive
        self.assertEqual(states, ["covered", "no_change", "no_change", "rejected", "break_glass", "emergency"])
        k = codes(t)
        sev = sorted((f.severity, f.subject[11:16]) for f in k["CHG_NO_TICKET"])
        self.assertEqual(sev, [(CRITICAL, "13:30"), (WARNING, "16:30")])   # provider without ticket is critical
        self.assertIn("C2", k["CHG_REJECTED"][0].detail)
        self.assertIn("CHG_BREAK_GLASS", k)
        self.assertEqual(k["CHG_EMERGENCY"][0].severity, INFO)


class DemoTests(unittest.TestCase):
    def test_demo_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, out = Path(tmp, "data"), Path(tmp, "out")
            self.assertEqual(cli.main(["demo", "--data", str(data), "--out", str(out)]), 0)
            names = {p.name for p in out.iterdir()}
            self.assertEqual(names, {"report.html", "review.md", "actions.csv", "findings.csv", "privileged-access.csv",
                                     "licence-reclaim.csv", "admin-changes.csv"})
            found = {r["code"] for r in csv.DictReader(open(out / "findings.csv", encoding="utf-8"))}
            for code in ("PERMANENT_TIER0", "PRIV_GUEST", "PRIV_NO_MFA", "PRIV_STALE", "PRIV_DISABLED", "PROVIDER_NO_END",
                         "APP_TIER0", "GA_TOO_MANY", "BG_NOT_GA", "BG_SIGNIN", "BG_NOT_EXCLUDED", "CA_NO_LEGACY_BLOCK",
                         "CA_REPORT_ONLY", "CA_EXCLUSIONS", "CA_DISABLED", "DRIFT", "LIC_DISABLED", "LIC_INACTIVE",
                         "LIC_OVER", "CHG_NO_TICKET", "CHG_REJECTED", "CHG_BREAK_GLASS", "CHG_EMERGENCY"):
                self.assertIn(code, found)
            html = (out / "report.html").read_text(encoding="utf-8")
            self.assertNotIn("#EXT#", html)
            self.assertIn("Change rejected", html)
            review = (out / "review.md").read_text(encoding="utf-8")
            self.assertIn("## For the service review with Proseware", review)
            t = model.load(data)
            self.assertEqual(report.summary(t, run_all(t))["changes_ok"], 2)


if __name__ == "__main__":
    unittest.main()
