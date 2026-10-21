"""Load a tenant snapshot (tenant.json), the change tickets (changes.csv) and the review settings (settings.json)."""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

TIER0 = ("Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator")
PRIVILEGED = TIER0 + ("Security Administrator", "Conditional Access Administrator", "Exchange Administrator",
                      "SharePoint Administrator", "Teams Administrator", "User Administrator", "Authentication Administrator",
                      "Application Administrator", "Cloud Application Administrator", "Intune Administrator",
                      "Compliance Administrator", "Hybrid Identity Administrator", "Billing Administrator")
ROLE_ALIASES = {"company administrator": "Global Administrator", "global admin": "Global Administrator",
                "ga": "Global Administrator", "pra": "Privileged Role Administrator",
                "exchange service administrator": "Exchange Administrator",
                "sharepoint service administrator": "SharePoint Administrator",
                "teams service administrator": "Teams Administrator"}
KIND_ALIASES = {"active": "permanent", "assigned": "permanent", "permanente": "permanent", "eligible": "eligible",
                "elegible": "eligible", "time-bound": "time_bound", "timebound": "time_bound", "temporal": "time_bound"}
CHANGE_STATUS_ALIASES = {"approved": "approved", "aprobado": "approved", "implemented": "approved", "closed": "approved",
                         "emergency": "emergency", "urgente": "emergency", "rejected": "rejected", "rechazado": "rejected",
                         "cancelled": "rejected", "draft": "draft", "borrador": "draft", "pending": "draft"}
LEGACY_CLIENTS = {"exchangeactivesync", "other"}


def parse_date(value) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    v = str(value or "").strip()
    if not v:
        return None
    v = v.replace("Z", "")[:19]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%d/%m/%Y %H:%M",
                "%d/%m/%Y"):
        try:
            return datetime.strptime(v[:len(datetime(2000, 1, 1).strftime(fmt))], fmt).date()
        except ValueError:
            continue
    return None


def parse_dt(value) -> datetime | None:
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    v = str(value or "").strip().replace("Z", "")
    if not v:
        return None
    v = v.split("+")[0].split(".")[0]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M"):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    d = parse_date(v)
    return datetime(d.year, d.month, d.day) if d else None


def norm_role(name: str) -> str:
    n = (name or "").strip()
    return ROLE_ALIASES.get(n.lower(), n)


def _bool(v) -> bool | None:
    if isinstance(v, bool):
        return v
    s = str(v if v is not None else "").strip().lower()
    if s in ("true", "yes", "y", "1", "si", "sí", "on", "enabled"):
        return True
    if s in ("false", "no", "n", "0", "off", "disabled"):
        return False
    return None


def _list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v).replace(",", ";").split(";") if x.strip()]


@dataclass
class User:
    upn: str
    display: str = ""
    enabled: bool = True
    user_type: str = "Member"           # Member / Guest
    mfa: bool | None = None             # MFA method registered
    last_signin: date | None = None
    licences: list[str] = field(default_factory=list)
    created: date | None = None

    @property
    def guest(self) -> bool:
        return self.user_type.lower() == "guest" or "#ext#" in self.upn.lower()


@dataclass
class RoleAssignment:
    principal: str                      # UPN, or the app / group name
    role: str
    kind: str = "permanent"             # permanent / eligible / time_bound
    principal_type: str = "user"        # user / servicePrincipal / group
    start: date | None = None
    end: date | None = None

    @property
    def tier0(self) -> bool:
        return self.role in TIER0

    @property
    def privileged(self) -> bool:
        return self.role in PRIVILEGED


@dataclass
class CAPolicy:
    name: str
    state: str = "enabled"              # enabled / reportOnly / disabled
    include_users: list[str] = field(default_factory=list)   # All, Guests, a role name, UPNs or group names
    exclude_users: list[str] = field(default_factory=list)
    client_apps: list[str] = field(default_factory=lambda: ["all"])
    grant: list[str] = field(default_factory=list)            # mfa, block, compliantDevice, phishingResistantMfa
    apps: list[str] = field(default_factory=lambda: ["All"])
    modified: date | None = None

    @property
    def on(self) -> bool:
        return self.state == "enabled"

    @property
    def all_users(self) -> bool:
        return any(x.lower() == "all" for x in self.include_users)

    @property
    def requires_mfa(self) -> bool:
        return any(g.lower() in ("mfa", "phishingresistantmfa") for g in self.grant)

    @property
    def blocks(self) -> bool:
        return any(g.lower() == "block" for g in self.grant)

    @property
    def legacy_only(self) -> bool:
        apps = {c.lower() for c in self.client_apps}
        return bool(apps) and apps <= LEGACY_CLIENTS


@dataclass
class Sku:
    sku: str
    name: str = ""
    purchased: int = 0
    monthly_cost: float = 0.0


@dataclass
class AuditEvent:
    when: datetime
    actor: str
    operation: str
    target: str = ""
    category: str = ""


@dataclass
class Change:
    ref: str
    title: str = ""
    status: str = "approved"            # approved / emergency / rejected / draft
    implementer: str = ""               # a UPN, or a domain like provider.example
    start: datetime | None = None
    end: datetime | None = None


@dataclass
class Tenant:
    name: str
    as_of: date
    domains: list[str] = field(default_factory=list)
    provider: str = ""                  # managed service provider name
    provider_domains: list[str] = field(default_factory=list)
    break_glass: list[str] = field(default_factory=list)
    break_glass_groups: list[str] = field(default_factory=list)   # groups that hold only the emergency accounts
    users: list[User] = field(default_factory=list)
    roles: list[RoleAssignment] = field(default_factory=list)
    policies: list[CAPolicy] = field(default_factory=list)
    settings: dict = field(default_factory=dict)
    skus: list[Sku] = field(default_factory=list)
    audit: list[AuditEvent] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    exported: datetime | None = None
    currency: str = "€"

    def user(self, upn: str) -> User | None:
        k = upn.lower()
        return next((u for u in self.users if u.upn.lower() == k), None)

    def is_provider(self, upn: str) -> bool:
        d = upn.lower().rsplit("@", 1)[-1]
        return any(d == p.lower() or d.endswith("." + p.lower()) for p in self.provider_domains)

    def is_break_glass(self, upn: str) -> bool:
        """An emergency account, or (in Conditional Access exclusions) the group that holds them."""
        k = upn.lower()
        groups = {g.lower() for g in self.break_glass_groups} | {"group:" + g.lower() for g in self.break_glass_groups}
        return k in {b.lower() for b in self.break_glass} or k in groups


def _user(d: dict) -> User:
    return User(upn=d.get("upn") or d.get("userPrincipalName", ""), display=d.get("display") or d.get("displayName", ""),
                enabled=_bool(d.get("enabled", d.get("accountEnabled", True))) is not False,
                user_type=d.get("type") or d.get("userType") or "Member", mfa=_bool(d.get("mfa")),
                last_signin=parse_date(d.get("last_signin") or d.get("lastSignIn")),
                licences=_list(d.get("licences") or d.get("licenses")), created=parse_date(d.get("created")))


def _role(d: dict) -> RoleAssignment:
    kind = KIND_ALIASES.get(str(d.get("kind", "permanent")).strip().lower(), "permanent")
    end = parse_date(d.get("end"))
    if kind == "permanent" and end:
        kind = "time_bound"
    return RoleAssignment(principal=d.get("principal", ""), role=norm_role(d.get("role", "")), kind=kind,
                          principal_type=d.get("principal_type", "user"), start=parse_date(d.get("start")), end=end)


def _policy(d: dict) -> CAPolicy:
    state = str(d.get("state", "enabled"))
    state = {"enabledforreportingbutnotenforced": "reportOnly", "reportonly": "reportOnly", "report-only": "reportOnly",
             "on": "enabled", "off": "disabled"}.get(state.lower(), state)
    return CAPolicy(name=d.get("name", ""), state=state, include_users=_list(d.get("include_users")),
                    exclude_users=_list(d.get("exclude_users")), client_apps=_list(d.get("client_apps")) or ["all"],
                    grant=_list(d.get("grant")), apps=_list(d.get("apps")) or ["All"], modified=parse_date(d.get("modified")))


def read_changes(path: Path) -> list[Change]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8-sig")
    delim = ";" if raw.splitlines()[0].count(";") > raw.splitlines()[0].count(",") else ","
    out = []
    alias = {"referencia": "ref", "number": "ref", "titulo": "title", "título": "title", "estado": "status", "state": "status",
             "implementador": "implementer", "assigned_to": "implementer", "inicio": "start", "planned_start": "start",
             "fin": "end", "planned_end": "end"}
    for row in csv.DictReader(raw.splitlines(), delimiter=delim):
        r = {alias.get(k.strip().lower(), k.strip().lower()): (v or "").strip() for k, v in row.items() if k}
        if not r.get("ref"):
            continue
        out.append(Change(ref=r["ref"], title=r.get("title", ""),
                          status=CHANGE_STATUS_ALIASES.get(r.get("status", "").lower(), r.get("status", "").lower() or "draft"),
                          implementer=r.get("implementer", ""), start=parse_dt(r.get("start")), end=parse_dt(r.get("end"))))
    return out


def load(folder: Path, as_of: date | None = None) -> Tenant:
    folder = Path(folder)
    snap = folder / "tenant.json"
    if not snap.exists():
        raise FileNotFoundError(f"{snap} not found (export it with scripts/Export-TenantGovernance.ps1)")
    data = json.loads(snap.read_text(encoding="utf-8-sig"))
    cfg_path = folder / "settings.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8-sig")) if cfg_path.exists() else {}
    exported = parse_dt(data.get("exported"))
    when = as_of or parse_date(cfg.get("as_of")) or (exported.date() if exported else None) or date.today()
    t = Tenant(name=cfg.get("tenant") or data.get("tenant", "Tenant"), as_of=when,
               domains=_list(data.get("domains")), provider=cfg.get("provider", ""),
               provider_domains=_list(cfg.get("provider_domains")), break_glass=_list(cfg.get("break_glass")),
               break_glass_groups=_list(cfg.get("break_glass_groups")),
               users=[_user(u) for u in data.get("users", [])], roles=[_role(r) for r in data.get("roles", [])],
               policies=[_policy(p) for p in data.get("conditional_access", [])], settings=dict(data.get("settings", {})),
               skus=[Sku(sku=s.get("sku", ""), name=s.get("name", ""), purchased=int(s.get("purchased") or 0),
                         monthly_cost=float((cfg.get("licence_costs") or {}).get(s.get("sku", ""), s.get("monthly_cost") or 0)))
                     for s in data.get("skus", [])],
               audit=[AuditEvent(when=parse_dt(a.get("when")), actor=a.get("actor", ""), operation=a.get("operation", ""),
                                 target=a.get("target", ""), category=a.get("category", ""))
                      for a in data.get("audit", []) if parse_dt(a.get("when"))],
               changes=read_changes(folder / "changes.csv"), exported=exported,
               currency=cfg.get("currency", "€"))
    t.settings.update(cfg.get("settings_override", {}))
    return t
