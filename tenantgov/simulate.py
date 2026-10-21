"""Fictional tenant for the demo: Wide World Importers, operated day to day by a managed service provider (Proseware)."""
from __future__ import annotations

import csv
import json
import random
from datetime import date, timedelta
from pathlib import Path

AS_OF = date(2026, 10, 21)
TENANT = "wideworldimporters.onmicrosoft.com"
D = "wideworldimporters.example"
P = "proseware.example"
BG = [f"bg-01@{TENANT}", f"bg-02@{TENANT}"]
GUEST = f"j.doe_litware.example#EXT#@{TENANT}"

FIRST = ("Ana", "Luis", "Marta", "Pablo", "Elena", "Jorge", "Carlos", "Lucía", "Sergio", "Irene", "Raúl", "Nuria", "David",
         "Sara", "Javier", "Paula", "Óscar", "Laura", "Diego", "Clara", "Iván", "Rosa", "Hugo", "Alba", "Rubén", "Eva")
LAST = ("Martín", "Romero", "Vidal", "Sanz", "Ruiz", "Díaz", "Gil", "Navarro", "Torres", "Molina", "Ortega", "Delgado",
        "Castro", "Rubio", "Marín", "Iglesias", "Medina", "Garrido", "Cortés", "Lozano", "Cano", "Prieto")
SKUS = [{"sku": "SPE_E3", "name": "Microsoft 365 E3", "purchased": 300},
        {"sku": "SPE_F3", "name": "Microsoft 365 F3", "purchased": 160},
        {"sku": "POWER_BI_PRO", "name": "Power BI Pro", "purchased": 40},
        {"sku": "VISIOCLIENT", "name": "Visio Plan 2", "purchased": 5}]
COSTS = {"SPE_E3": 36.0, "SPE_F3": 8.0, "POWER_BI_PRO": 14.0, "VISIOCLIENT": 15.0}   # illustrative, per user per month


def _plain(s: str) -> str:
    return s.lower().translate(str.maketrans("áéíóúñ", "aeioun"))


def d(days_ago: int | None) -> str | None:
    return None if days_ago is None else (AS_OF - timedelta(days=days_ago)).isoformat()


def build() -> tuple[dict, list[dict], dict]:
    rnd = random.Random(27)
    users = []
    named = [  # (upn, display, mfa, last sign-in days ago, enabled, licences)
        (f"ana.martin@{D}", "Ana Martín (IT Operations Lead)", True, 0, True, ["SPE_E3", "VISIOCLIENT"]),
        (f"luis.romero@{D}", "Luis Romero (IT Director)", True, 1, True, ["SPE_E3", "POWER_BI_PRO"]),
        (f"carlos.gil@{D}", "Carlos Gil (Infrastructure)", True, 3, True, ["SPE_E3"]),
        (f"marta.vidal@{D}", "Marta Vidal (Messaging)", True, 0, True, ["SPE_E3"]),
        (f"pablo.sanz@{D}", "Pablo Sanz (Collaboration)", False, 6, True, ["SPE_E3"]),
        (f"elena.ruiz@{D}", "Elena Ruiz (Endpoints)", True, 140, True, ["SPE_E3"]),
        (f"jorge.diaz@{D}", "Jorge Díaz (left in August)", True, 70, False, ["SPE_E3"]),
        (f"ops1@{P}", "Proseware Ops 1", True, 0, True, []),
        (f"ops2@{P}", "Proseware Ops 2", True, 2, True, []),
        (f"ops3@{P}", "Proseware Ops 3", True, 25, True, []),
        (BG[0], "Emergency access 01", True, 12, True, []),
        (BG[1], "Emergency access 02", True, None, True, []),
        (f"svc-scanner@{D}", "Scan to mail (service account)", False, 1, True, []),
        (f"ceo.office@{D}", "CEO office", True, 0, True, ["SPE_E3"]),
    ]
    for upn, name, mfa, seen, en, lic in named:
        users.append({"upn": upn, "display": name, "enabled": en, "type": "Member", "mfa": mfa, "last_signin": d(seen),
                      "licences": lic, "created": "2023-02-01"})
    users.append({"upn": GUEST, "display": "John Doe (Litware consulting)", "enabled": True, "type": "Guest", "mfa": True,
                  "last_signin": d(9), "licences": [], "created": "2025-11-10"})
    seen_names = set()
    # head office staff on E3, shops on F3
    plan = ([("SPE_E3", "office")] * 262) + ([("SPE_F3", "shop")] * 118)
    for i, (sku, kind) in enumerate(plan):
        while True:
            f, l = rnd.choice(FIRST), rnd.choice(LAST)
            upn = f"{_plain(f)}.{_plain(l)}{'' if (f, l) not in seen_names else i}@{D}"
            if upn not in {u['upn'] for u in users}:
                break
        seen_names.add((f, l))
        lic = [sku]
        if kind == "office" and rnd.random() < 0.15:
            lic.append("POWER_BI_PRO")
        enabled, seen = True, rnd.randint(0, 20)
        if i < 9:                       # leavers still licensed
            enabled, seen = False, rnd.randint(25, 120)
        elif i < 23:                    # long absence or forgotten accounts
            seen = rnd.randint(95, 300)
        elif 262 <= i < 268:            # shop accounts nobody uses
            seen = rnd.randint(100, 200)
        users.append({"upn": upn, "display": f"{f} {l}", "enabled": enabled, "type": "Member", "mfa": True,
                      "last_signin": d(seen), "licences": lic, "created": "2024-01-15"})
    # Power BI: three more than bought
    pbi = [u for u in users if "POWER_BI_PRO" in u["licences"]]
    for u in users:
        if len(pbi) >= 43:
            break
        if u["upn"].endswith("@" + D) and "SPE_E3" in u["licences"] and "POWER_BI_PRO" not in u["licences"] and u["enabled"]:
            u["licences"].append("POWER_BI_PRO")
            pbi.append(u)
    while len(pbi) > 43:
        pbi.pop()["licences"].remove("POWER_BI_PRO")

    roles = [
        {"principal": BG[0], "role": "Global Administrator", "kind": "permanent"},
        {"principal": BG[1], "role": "Global Administrator", "kind": "eligible"},
        {"principal": f"ana.martin@{D}", "role": "Global Administrator", "kind": "permanent"},
        {"principal": f"luis.romero@{D}", "role": "Global Administrator", "kind": "eligible"},
        {"principal": f"carlos.gil@{D}", "role": "Global Administrator", "kind": "eligible"},
        {"principal": f"ops1@{P}", "role": "Global Administrator", "kind": "permanent", "start": "2024-03-01"},
        {"principal": f"ops2@{P}", "role": "Global Administrator", "kind": "eligible", "start": "2025-06-01"},
        {"principal": f"ops2@{P}", "role": "Exchange Administrator", "kind": "eligible", "start": "2025-06-01",
         "end": "2027-03-31"},
        {"principal": f"ops3@{P}", "role": "SharePoint Administrator", "kind": "permanent", "start": "2026-10-07"},
        {"principal": f"ops3@{P}", "role": "Intune Administrator", "kind": "eligible", "start": "2026-01-10",
         "end": "2027-03-31"},
        {"principal": f"marta.vidal@{D}", "role": "Exchange Administrator", "kind": "permanent"},
        {"principal": f"pablo.sanz@{D}", "role": "SharePoint Administrator", "kind": "eligible"},
        {"principal": f"pablo.sanz@{D}", "role": "Teams Administrator", "kind": "eligible"},
        {"principal": f"elena.ruiz@{D}", "role": "Intune Administrator", "kind": "eligible"},
        {"principal": f"jorge.diaz@{D}", "role": "Teams Administrator", "kind": "eligible"},
        {"principal": GUEST, "role": "User Administrator", "kind": "permanent"},
        {"principal": f"luis.romero@{D}", "role": "Security Reader", "kind": "permanent"},
        {"principal": "Legacy HR provisioning", "role": "Global Administrator", "kind": "permanent",
         "principal_type": "servicePrincipal"},
    ]
    policies = [
        {"name": "CA001 Require phishing-resistant MFA for admins", "state": "enabled", "include_users": ["Directory roles"],
         "exclude_users": BG, "grant": ["phishingResistantMfa"], "modified": "2026-02-10"},
        {"name": "CA002 Require MFA for all users", "state": "enabled", "include_users": ["All"],
         "exclude_users": [BG[0], f"svc-scanner@{D}", f"ceo.office@{D}"], "grant": ["mfa"], "modified": "2026-10-02"},
        {"name": "CA003 Block legacy authentication", "state": "reportOnly", "include_users": ["All"],
         "exclude_users": BG, "client_apps": ["exchangeActiveSync", "other"], "grant": ["block"], "modified": "2026-07-02"},
        {"name": "CA004 Compliant device for Office apps", "state": "enabled", "include_users": ["All"],
         "exclude_users": BG + [GUEST], "client_apps": ["browser", "mobileAppsAndDesktopClients"],
         "grant": ["compliantDevice"], "modified": "2026-05-18"},
        {"name": "CA-old Pilot block outside EU", "state": "disabled", "include_users": ["All"], "grant": ["block"],
         "modified": "2025-04-01"},
    ]
    settings = {"entra.user_consent": "all", "entra.guest_invite": "everyone", "entra.users_can_register_apps": False,
                "entra.users_can_create_tenants": True, "spo.sharing": "externalUserAndGuestSharing",
                "exo.auto_forwarding": "On", "exo.smtp_auth_disabled": False, "exo.dkim_missing": ["wwi.example"],
                "exo.mailbox_audit_disabled": False, "purview.unified_audit": True}
    audit = [
        ("2026-10-02T10:15:00", f"ops1@{P}", "Update conditional access policy", "CA002 Require MFA for all users", "Policy"),
        ("2026-10-02T10:40:00", f"ops1@{P}", "Update user", f"ceo.office@{D}", "UserManagement"),
        ("2026-10-07T23:40:00", f"ops2@{P}", "Add member to role", f"SharePoint Administrator · ops3@{P}", "RoleManagement"),
        ("2026-10-09T03:10:00", BG[0], "Update conditional access policy", "CA002 Require MFA for all users", "Policy"),
        ("2026-10-09T09:20:00", f"ops1@{P}", "Set-HostedOutboundSpamFilterPolicy", "Default (AutoForwardingMode On)", "Exchange"),
        ("2026-10-12T17:05:00", f"ana.martin@{D}", "Update authorization policy", "Guest invite settings", "Policy"),
        ("2026-10-14T18:30:00", f"ops1@{P}", "Add eligible member to role", f"Intune Administrator · ops3@{P}",
         "RoleManagement"),
        ("2026-10-15T09:20:00", f"ana.martin@{D}", "Add conditional access policy", "CA004 Compliant device for Office apps",
         "Policy"),
        ("2026-10-16T11:00:00", f"ops3@{P}", "Update device", "SHOP-0412", "Device"),
    ]
    tenant = {"tenant": "Wide World Importers", "exported": f"{AS_OF}T07:30:00Z",
              "domains": [D, "wwi.example", TENANT], "users": users, "roles": roles, "conditional_access": policies,
              "settings": settings, "skus": SKUS,
              "audit": [{"when": w, "actor": a, "operation": o, "target": t, "category": c} for w, a, o, t, c in audit]}
    changes = [
        {"ref": "CHG-2041", "title": "Exclude CEO office mailbox from MFA policy (board meeting room)", "status": "approved",
         "implementer": P, "start": "2026-10-02 10:00", "end": "2026-10-02 12:00"},
        {"ref": "CHG-2055", "title": "Allow automatic forwarding for the logistics partner mailbox", "status": "rejected",
         "implementer": P, "start": "2026-10-09 09:00", "end": "2026-10-09 11:00"},
        {"ref": "CHG-2060", "title": "Emergency: Intune admin for shop device recovery", "status": "emergency",
         "implementer": P, "start": "2026-10-14 18:00", "end": "2026-10-14 20:00"},
        {"ref": "CHG-2062", "title": "Compliant device policy for Office apps", "status": "approved",
         "implementer": f"ana.martin@{D}", "start": "2026-10-15 09:00", "end": "2026-10-15 10:00"},
    ]
    cfg = {"tenant": "Wide World Importers", "as_of": AS_OF.isoformat(), "provider": "Proseware",
           "provider_domains": [P], "break_glass": BG, "licence_costs": COSTS}
    return tenant, changes, cfg


def _dump(obj: dict) -> str:
    """JSON with one list item per line: readable in a diff, and small enough to commit."""
    parts = []
    for k, v in obj.items():
        if isinstance(v, list) and v and isinstance(v[0], dict):
            body = ",\n".join("  " + json.dumps(x, ensure_ascii=False) for x in v)
            parts.append(f" {json.dumps(k)}: [\n{body}\n ]")
        else:
            parts.append(f" {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)}")
    return "{\n" + ",\n".join(parts) + "\n}\n"


def write(folder: Path) -> None:
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    tenant, changes, cfg = build()
    (folder / "tenant.json").write_text(_dump(tenant), encoding="utf-8")
    (folder / "settings.json").write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    with open(folder / "changes.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["ref", "title", "status", "implementer", "start", "end"])
        w.writeheader()
        w.writerows(changes)
