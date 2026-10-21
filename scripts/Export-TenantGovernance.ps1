<#
.SYNOPSIS
    Exports what tenantgov reviews from a Microsoft 365 tenant into one tenant.json file. Read-only.

.DESCRIPTION
    Microsoft Graph (always):
      - users: UPN, enabled, member or guest, licences, created, last sign-in, MFA registered;
      - directory roles: permanent and time-bound assignments, and PIM eligible assignments;
      - Conditional Access policies: state, users and roles included or excluded, client apps, grant controls;
      - tenant settings: user consent, guest invitations, app and tenant creation, SharePoint external sharing;
      - licences bought (subscribed SKUs);
      - directory audit log for the last -Days days (role changes, Conditional Access, policies).
    Exchange Online (with -IncludeExchange, needs the ExchangeOnlineManagement module):
      - automatic forwarding, SMTP AUTH, DKIM per domain, mailbox auditing, unified audit log ingestion;
      - Exchange admin cmdlets from the unified audit log for the same period.

    Graph scopes requested: User.Read.All, AuditLog.Read.All, Directory.Read.All, RoleManagement.Read.Directory,
    Policy.Read.All, UserAuthenticationMethod.Read.All, SharePointTenantSettings.Read.All.
    Sign-in activity and the MFA registration report need Entra ID P1; PIM eligible assignments need Entra ID P2
    (without it, only the active assignments are exported).

.EXAMPLE
    .\Export-TenantGovernance.ps1 -OutputPath .\data\tenant.json
    .\Export-TenantGovernance.ps1 -OutputPath .\data\tenant.json -IncludeExchange -Days 30
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\tenant.json",
    [int]$Days = 30,
    [switch]$IncludeExchange
)

$ErrorActionPreference = "Stop"
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw "Install the Microsoft Graph PowerShell SDK first: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}
Connect-MgGraph -NoWelcome -Scopes "User.Read.All", "AuditLog.Read.All", "Directory.Read.All",
    "RoleManagement.Read.Directory", "Policy.Read.All", "UserAuthenticationMethod.Read.All",
    "SharePointTenantSettings.Read.All"

$G = "https://graph.microsoft.com/v1.0"
function Get-All([string]$Uri) {
    $items = @()
    while ($Uri) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $Uri
        if ($null -ne $page.value) { $items += $page.value } else { $items += $page }
        $Uri = $page.'@odata.nextLink'
    }
    return $items
}
function Try-Get([string]$What, [scriptblock]$Block) {
    try { & $Block } catch { Write-Warning "$What not exported: $($_.Exception.Message)"; $null }
}
function Day($value) { if ($value) { ([datetime]$value).ToString("yyyy-MM-dd") } else { $null } }

$org = (Invoke-MgGraphRequest -Method GET -Uri "$G/organization").value[0]
Write-Host "Tenant: $($org.displayName)"

# --- licences ------------------------------------------------------------------------------------------------------
$skuName = @{}
$skus = foreach ($s in Get-All "$G/subscribedSkus") {
    $skuName[[string]$s.skuId] = $s.skuPartNumber
    [ordered]@{ sku = $s.skuPartNumber; name = $s.skuPartNumber; purchased = [int]$s.prepaidUnits.enabled }
}

# --- users, sign-in and MFA ----------------------------------------------------------------------------------------
$mfa = @{}
Try-Get "MFA registration report" {
    foreach ($r in Get-All "$G/reports/authenticationMethods/userRegistrationDetails") { $mfa[$r.id] = [bool]$r.isMfaRegistered }
} | Out-Null
$select = "id,userPrincipalName,displayName,accountEnabled,userType,assignedLicenses,createdDateTime"
$rawUsers = Try-Get "Sign-in activity" { Get-All "$G/users?`$top=999&`$select=$select,signInActivity" }
if (-not $rawUsers) { $rawUsers = Get-All "$G/users?`$top=999&`$select=$select" }
$upnById = @{}
$users = foreach ($u in $rawUsers) {
    $upnById[$u.id] = $u.userPrincipalName
    $last = $u.signInActivity.lastSignInDateTime
    if ($u.signInActivity.lastNonInteractiveSignInDateTime -and ($u.signInActivity.lastNonInteractiveSignInDateTime -gt $last)) {
        $last = $u.signInActivity.lastNonInteractiveSignInDateTime
    }
    [ordered]@{ upn = $u.userPrincipalName; display = $u.displayName; enabled = [bool]$u.accountEnabled
                type = $u.userType; mfa = $(if ($mfa.ContainsKey($u.id)) { $mfa[$u.id] } else { $null })
                last_signin = Day $last; created = Day $u.createdDateTime
                licences = @($u.assignedLicenses | ForEach-Object { $skuName[[string]$_.skuId] }) }
}
Write-Host "Users: $($users.Count)"

# --- directory roles -----------------------------------------------------------------------------------------------
function Principal($p) {
    $type = switch -Wildcard ($p.'@odata.type') { "*servicePrincipal" { "servicePrincipal" } "*group" { "group" } default { "user" } }
    $name = if ($type -eq "user") { $p.userPrincipalName } else { $p.displayName }
    return $type, $name
}
$roles = @()
$active = Try-Get "PIM assignment schedules" {
    Get-All "$G/roleManagement/directory/roleAssignmentSchedules?`$expand=principal,roleDefinition"
}
if ($active) {
    foreach ($a in $active | Where-Object { $_.assignmentType -ne "Activated" }) {   # activations belong to eligible roles
        $type, $name = Principal $a.principal
        $end = $a.scheduleInfo.expiration.endDateTime
        $roles += [ordered]@{ principal = $name; principal_type = $type; role = $a.roleDefinition.displayName
                              kind = $(if ($end) { "time_bound" } else { "permanent" })
                              start = Day $a.scheduleInfo.startDateTime; end = Day $end }
    }
    $eligible = Try-Get "PIM eligible assignments" {
        Get-All "$G/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition"
    }
    foreach ($a in @($eligible)) {
        if (-not $a) { continue }
        $type, $name = Principal $a.principal
        $roles += [ordered]@{ principal = $name; principal_type = $type; role = $a.roleDefinition.displayName
                              kind = "eligible"; start = Day $a.scheduleInfo.startDateTime
                              end = Day $a.scheduleInfo.expiration.endDateTime }
    }
} else {
    foreach ($a in Get-All "$G/roleManagement/directory/roleAssignments?`$expand=principal,roleDefinition") {
        $type, $name = Principal $a.principal
        $roles += [ordered]@{ principal = $name; principal_type = $type; role = $a.roleDefinition.displayName; kind = "permanent" }
    }
}
Write-Host "Role assignments: $($roles.Count)"

# --- Conditional Access --------------------------------------------------------------------------------------------
$groupName = @{}
function Names($ids) {
    @($ids | ForEach-Object {
        if ($_ -in "All", "None", "GuestsOrExternalUsers") { $_ }
        elseif ($upnById.ContainsKey($_)) { $upnById[$_] }
        else {
            if (-not $groupName.ContainsKey($_)) {
                $groupName[$_] = Try-Get "Group $_" { (Invoke-MgGraphRequest -Method GET -Uri "$G/groups/$_`?`$select=displayName").displayName }
            }
            if ($groupName[$_]) { "group:$($groupName[$_])" } else { $_ }
        }
    })
}
$ca = foreach ($p in Get-All "$G/identity/conditionalAccess/policies") {
    $cu = $p.conditions.users
    $include = @(Names $cu.includeUsers) + @(Names $cu.includeGroups)
    if ($cu.includeRoles) { $include += "Directory roles" }
    if ($cu.includeGuestsOrExternalUsers) { $include += "GuestsOrExternalUsers" }
    $grant = @($p.grantControls.builtInControls)
    if ($p.grantControls.authenticationStrength) {
        $grant += $(if ($p.grantControls.authenticationStrength.displayName -match "phishing") { "phishingResistantMfa" } else { "mfa" })
    }
    [ordered]@{ name = $p.displayName; state = $p.state; include_users = @($include | Where-Object { $_ -ne "None" })
                exclude_users = @(Names $cu.excludeUsers) + @(Names $cu.excludeGroups)
                client_apps = @($p.conditions.clientAppTypes); grant = $grant
                apps = @($p.conditions.applications.includeApplications); modified = Day $p.modifiedDateTime }
}
Write-Host "Conditional Access policies: $($ca.Count)"

# --- tenant settings -----------------------------------------------------------------------------------------------
$settings = [ordered]@{}
$auth = Get-All "$G/policies/authorizationPolicy" | Select-Object -First 1
$grants = @($auth.defaultUserRolePermissions.permissionGrantPoliciesAssigned) -join " "
$settings["entra.user_consent"] = if ($grants -match "default-legacy") { "all" } elseif ($grants -match "default-low") { "low_risk" } else { "none" }
$settings["entra.guest_invite"] = $auth.allowInvitesFrom
$settings["entra.users_can_register_apps"] = [bool]$auth.defaultUserRolePermissions.allowedToCreateApps
$settings["entra.users_can_create_tenants"] = [bool]$auth.defaultUserRolePermissions.allowedToCreateTenants
$spo = Try-Get "SharePoint settings" { Invoke-MgGraphRequest -Method GET -Uri "$G/admin/sharepoint/settings" }
if ($spo) { $settings["spo.sharing"] = $spo.sharingCapability }

# --- directory audit -----------------------------------------------------------------------------------------------
$since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString("yyyy-MM-ddTHH:mm:ssZ")
$audit = @(foreach ($a in Get-All "$G/auditLogs/directoryAudits?`$filter=activityDateTime ge $since") {
    $actor = if ($a.initiatedBy.user.userPrincipalName) { $a.initiatedBy.user.userPrincipalName } else { $a.initiatedBy.app.displayName }
    $t = $a.targetResources | Select-Object -First 1
    [ordered]@{ when = ([datetime]$a.activityDateTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"); actor = $actor
                operation = $a.activityDisplayName; category = $a.category
                target = $(if ($t.userPrincipalName) { $t.userPrincipalName } else { $t.displayName }) }
})

# --- Exchange Online (optional) ------------------------------------------------------------------------------------
if ($IncludeExchange) {
    Import-Module ExchangeOnlineManagement
    Connect-ExchangeOnline -ShowBanner:$false
    $settings["exo.auto_forwarding"] = (Get-HostedOutboundSpamFilterPolicy -Identity Default).AutoForwardingMode.ToString()
    $settings["exo.smtp_auth_disabled"] = [bool](Get-TransportConfig).SmtpClientAuthenticationDisabled
    $settings["exo.dkim_missing"] = @(Get-DkimSigningConfig | Where-Object { -not $_.Enabled -and $_.Domain -notlike "*.onmicrosoft.com" } |
                                      ForEach-Object { $_.Domain })
    $settings["exo.mailbox_audit_disabled"] = [bool](Get-OrganizationConfig).AuditDisabled
    $settings["purview.unified_audit"] = [bool](Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled
    $records = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-$Days) -EndDate (Get-Date) -RecordType ExchangeAdmin -ResultSize 5000
    foreach ($r in $records) {
        $d = $r.AuditData | ConvertFrom-Json
        $audit += [ordered]@{ when = ([datetime]$d.CreationTime).ToString("yyyy-MM-ddTHH:mm:ss"); actor = $d.UserId
                              operation = $d.Operation; target = $d.ObjectId; category = "Exchange" }
    }
    Disconnect-ExchangeOnline -Confirm:$false
}
Write-Host "Audit entries: $($audit.Count)"

$out = [ordered]@{
    tenant = $org.displayName; exported = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    domains = @($org.verifiedDomains | ForEach-Object { $_.name })
    users = @($users); roles = @($roles); conditional_access = @($ca); settings = $settings; skus = @($skus); audit = $audit
}
$dir = Split-Path -Parent $OutputPath
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir | Out-Null }
$out | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Written $OutputPath. Next: python -m tenantgov report $(if ($dir) { $dir } else { '.' })"
Disconnect-MgGraph | Out-Null
