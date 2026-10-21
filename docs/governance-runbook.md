# Monthly tenant governance review

A one-hour review, once a month, with the internal owner of the platform and, when the tenant is operated by a managed service provider, their service manager.

## The week before

1. Run the export with a Global Reader account (no write roles needed):
   ```powershell
   .\scripts\Export-TenantGovernance.ps1 -OutputPath .\data\tenant.json -IncludeExchange -Days 31
   ```
2. Export the change tickets of the month from the ITSM tool to `data/changes.csv`: reference, status, implementer, window.
3. Build the review:
   ```bash
   python -m tenantgov report data/ --title "M365 governance · October"
   ```
4. Send `review.md` to the provider two days before the meeting, so every "no change" entry comes back with a reference or an explanation.

## In the meeting (60 minutes)

| Minutes | Topic | Output |
|---|---|---|
| 10 | **Fix first**: critical findings, one owner and one date each | `actions.csv` |
| 15 | **Admin changes** with no ticket or under a rejected ticket: reference, reason, roll back or retrospective CAB | `admin-changes.csv` |
| 10 | **Privileged access**: standing roles to convert to eligible, provider assignments without an end date, stale admins | `privileged-access.csv` |
| 10 | **Conditional Access and settings drift**: what changed since last month and who approved it | report |
| 10 | **Licences**: reclaim list for the leaver process, spare seats before the next renewal | `licence-reclaim.csv` |
| 5 | Actions from last month, closed or carried over | `actions.csv` |

## Every quarter

- **Access review**: send `privileged-access.csv` to each role owner; the columns `keep_yes_no` and `reviewer` are there for that. Remove what nobody confirms.
- **Emergency accounts**: sign in with each one in a planned test, confirm the alert fires, and record the date.
- **Baseline**: check the baseline in `tenantgov/checks.py` against the latest Microsoft guidance and your own security policy, and agree any change with security.

## Rules that keep the review short

- Every admin action on roles, Conditional Access, tenant settings or mail flow has a change reference, including the provider's.
- Admin roles are eligible in PIM; permanent roles are only for the two emergency accounts.
- Provider assignments end when the contract or the project ends.
- Exclusions from Conditional Access have an owner and an end date.
- Licences follow the leaver process, not the monthly review.
