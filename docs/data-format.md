# Data format

`python -m tenantgov report data/` reads one folder:

| File | Required | What |
|---|---|---|
| `tenant.json` | yes | The tenant snapshot. `scripts/Export-TenantGovernance.ps1` writes it; you can also build it by hand. |
| `changes.csv` | no | Change tickets from the ITSM tool, to match admin actions against. |
| `settings.json` | no | Review date, provider, emergency accounts, licence prices, overrides. |

## tenant.json

```json
{
 "tenant": "Wide World Importers",
 "exported": "2026-10-21T07:30:00Z",
 "domains": ["wideworldimporters.example"],
 "users": [{"upn": "ana@x.example", "display": "Ana", "enabled": true, "type": "Member", "mfa": true,
            "last_signin": "2026-10-20", "created": "2023-02-01", "licences": ["SPE_E3"]}],
 "roles": [{"principal": "ana@x.example", "role": "Global Administrator", "kind": "eligible",
            "principal_type": "user", "start": "2025-01-01", "end": null}],
 "conditional_access": [{"name": "CA002 Require MFA for all users", "state": "enabled", "include_users": ["All"],
                         "exclude_users": ["bg-01@x.onmicrosoft.com"], "client_apps": ["all"], "grant": ["mfa"],
                         "modified": "2026-10-02"}],
 "settings": {"entra.user_consent": "low_risk", "exo.auto_forwarding": "Off"},
 "skus": [{"sku": "SPE_E3", "name": "Microsoft 365 E3", "purchased": 300}],
 "audit": [{"when": "2026-10-07T23:40:00", "actor": "ops2@provider.example", "operation": "Add member to role",
            "target": "SharePoint Administrator · ops3@provider.example", "category": "RoleManagement"}]
}
```

- **users**: `type` is `Member` or `Guest` (a `#EXT#` UPN is also read as a guest). `mfa` is "has an MFA method registered"; leave it out if you do not know. Also accepted: `userPrincipalName`, `displayName`, `accountEnabled`, `userType`, `licenses`.
- **roles**: `kind` is `permanent`, `eligible` (PIM) or `time_bound`; a permanent assignment with an `end` date is read as time-bound. `principal_type` is `user`, `servicePrincipal` or `group`. Role names follow the Entra admin centre; `Company Administrator` and `GA` are read as Global Administrator.
- **conditional_access**: `state` is `enabled`, `reportOnly` (or Graph's `enabledForReportingButNotEnforced`) or `disabled`. `include_users` takes `All`, `GuestsOrExternalUsers`, `Directory roles` or a role name, UPNs and `group:<name>`. `client_apps` with only `exchangeActiveSync` and `other` is a legacy-authentication policy. `grant` takes `mfa`, `phishingResistantMfa`, `block`, `compliantDevice`…
- **audit**: any directory or Exchange admin entries. Only the sensitive ones are reviewed: role changes, Conditional Access, the authorization policy, SharePoint tenant settings and mail-flow cmdlets (`Set-HostedOutboundSpamFilterPolicy`, `Set-TransportConfig`, transport rules…). The list is `SENSITIVE` in `tenantgov/checks.py`.

### Settings checked against the baseline

| Key | Baseline | Severity if not |
|---|---|---|
| `entra.user_consent` | `none` or `low_risk` (not `all`) | critical |
| `entra.guest_invite` | `none` or `adminsAndGuestInviters` | warning |
| `entra.users_can_register_apps` | `false` | warning |
| `entra.users_can_create_tenants` | `false` | warning |
| `spo.sharing` | not `externalUserAndGuestSharing` (Anyone links) | warning |
| `exo.auto_forwarding` | `Off` or `Automatic` | critical |
| `exo.smtp_auth_disabled` | `true` | warning |
| `exo.dkim_missing` | empty list | warning |
| `exo.mailbox_audit_disabled` | `false` | critical |
| `purview.unified_audit` | `true` | critical |

A key missing from the export is listed as "not collected", not as a failure. Change the baseline in `BASELINE` in `tenantgov/checks.py`.

## changes.csv

| Column | Example | Notes |
|---|---|---|
| `ref` | `CHG-2041` | also `number`, `referencia` |
| `title` | `Exclude CEO office mailbox from MFA policy` | |
| `status` | `approved` | `approved` (or implemented/closed), `emergency`, `rejected` (or cancelled), `draft` |
| `implementer` | `provider.example` | a UPN, a domain, or the provider name from settings.json |
| `start`, `end` | `2026-10-02 10:00` | the change window; `DD/MM/YYYY HH:MM` also works |

Comma or semicolon separated, UTF-8 with or without BOM, Spanish headers accepted. An admin action is covered when the implementer matches the actor (same UPN, same domain, or the provider name for a provider account) and the time falls inside the window, with 60 minutes of grace after the end.

## settings.json

```json
{
  "tenant": "Wide World Importers",
  "as_of": "2026-10-21",
  "provider": "Proseware",
  "provider_domains": ["proseware.example"],
  "break_glass": ["bg-01@x.onmicrosoft.com", "bg-02@x.onmicrosoft.com"],
  "break_glass_groups": ["Emergency access accounts"],
  "currency": "€",
  "licence_costs": {"SPE_E3": 36.0, "SPE_F3": 8.0},
  "settings_override": {"exo.dkim_missing": []}
}
```

- `provider_domains` marks the accounts of the managed service provider: their findings are owned by the provider and go to the service review section of `review.md`.
- `break_glass_groups`: Conditional Access exclusions of these groups count as emergency-account exclusions.
- `licence_costs` are your prices per user per month; the demo prices are illustrative.
- `settings_override` corrects a value the export got wrong or could not read.
