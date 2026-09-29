<#
.SYNOPSIS
    Assigns Cost Management Reader and Security Reader on every subscription your az login can manage.

.DESCRIPTION
    Uses only the Azure CLI and your own az login session. For every subscription the session can see (all
    signed-in tenants, states Enabled / Warned / PastDue) it assigns the missing roles to the assignee and skips
    the ones already in place, including inherited ones. Subscriptions where you cannot assign roles (you need
    Owner or User Access Administrator) are skipped with the reason; the others carry on. A summary lists what
    was added, what was already there and what was skipped.

    Typical uses:
    - the local scanner and portal: give yourself (or a colleague) the reader roles they need;
    - the Docker stack: give the service principal arg-scanner the roles (python -m scripts.connect_azure
      does this too, together with the ARG registration).

    Read-only roles only. Nothing else in Azure is changed.

.PARAMETER Assignee
    Who gets the roles: 'me' (the signed-in user, default), 'arg-scanner' or another service principal
    display name, a user principal name (name@contoso.com), or an object / application ID of a user, group or
    service principal. Resolved per tenant.

.PARAMETER IncludeReader
    Also assign Reader (needed when the assignee has no read access at all yet).

.PARAMETER SubscriptionId
    Only these subscriptions. Default: every subscription your az login can read.

.PARAMETER CurrentTenantOnly
    Only subscriptions of the tenant az is signed in to right now.

.EXAMPLE
    az login
    .\scripts\Grant-ArgRoles.ps1 -WhatIf              # preview, changes nothing

.EXAMPLE
    .\scripts\Grant-ArgRoles.ps1 -Assignee arg-scanner -IncludeReader

.EXAMPLE
    .\scripts\Grant-ArgRoles.ps1 -Assignee colleague@contoso.com -SubscriptionId 0edccb92-f126-4d66-93e4-ad1e7e7ce9d3

.OUTPUTS
    One summary object per subscription (Subscription, Tenant, Added, AlreadyThere, Skipped).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string] $Assignee = 'me',

    [Parameter()]
    [switch] $IncludeReader,

    [Parameter()]
    [string[]] $SubscriptionId,

    [Parameter()]
    [switch] $CurrentTenantOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$roles = @('Cost Management Reader', 'Security Reader')
if ($IncludeReader) { $roles = @('Reader') + $roles }
$usableStates = @('Enabled', 'Warned', 'PastDue')

function Invoke-Az {
    # Runs az and returns parsed JSON; throws with az's own message on failure.
    param([Parameter(Mandatory)] [string[]] $Arguments)
    $output = & az @Arguments --only-show-errors -o json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw (($output | Out-String).Trim())
    }
    $text = ($output | Out-String).Trim()
    # ForEach-Object unrolls arrays: Windows PowerShell 5.1 ConvertFrom-Json emits a JSON array as one object.
    if ($text) { return $text | ConvertFrom-Json | ForEach-Object { $_ } }
    return $null
}

function Get-ShortReason {
    param([string] $Message)
    if ($Message -match 'AuthorizationFailed|does not have authorization') {
        return 'you cannot assign roles here (needs Owner or User Access Administrator)'
    }
    return ($Message -split "`n")[0]
}

function Resolve-Assignee {
    # Returns @{ Id; Type; Name } for the assignee in the active tenant.
    param([string] $Value)
    if ($Value -eq 'me') {
        $user = Invoke-Az @('ad', 'signed-in-user', 'show', '--query', '{id:id, name:userPrincipalName}')
        return @{ Id = $user.id; Type = 'User'; Name = $user.name }
    }
    if ($Value -match '@') {
        $user = Invoke-Az @('ad', 'user', 'show', '--id', $Value, '--query', '{id:id, name:userPrincipalName}')
        return @{ Id = $user.id; Type = 'User'; Name = $user.name }
    }
    if ($Value -match '^[0-9a-fA-F-]{36}$') {
        foreach ($probe in @(
                @{ Args = @('ad', 'sp', 'show', '--id', $Value, '--query', '{id:id, name:displayName}'); Type = 'ServicePrincipal' },
                @{ Args = @('ad', 'user', 'show', '--id', $Value, '--query', '{id:id, name:userPrincipalName}'); Type = 'User' },
                @{ Args = @('ad', 'group', 'show', '--group', $Value, '--query', '{id:id, name:displayName}'); Type = 'Group' })) {
            try {
                $found = Invoke-Az $probe.Args
                if ($found) { return @{ Id = $found.id; Type = $probe.Type; Name = $found.name } }
            } catch { }
        }
        throw "No user, group or service principal with ID $Value in this tenant."
    }
    $sp = Invoke-Az @('ad', 'sp', 'list', '--filter', "displayName eq '$Value'", '--query', '[0].{id:id, name:displayName}')
    if (-not $sp) { throw "No service principal named '$Value' in this tenant." }
    return @{ Id = $sp.id; Type = 'ServicePrincipal'; Name = $sp.name }
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw 'Azure CLI (az) not found. Install it, then run az login.'
}
$account = Invoke-Az @('account', 'show')
if (-not $account) { throw 'No az login session. Run az login first.' }

$subscriptions = @(Invoke-Az @('account', 'list', '--all') | Where-Object {
        $_.state -in $usableStates -and (-not $CurrentTenantOnly -or $_.tenantId -eq $account.tenantId)
    })
if ($SubscriptionId) {
    $wanted = $SubscriptionId | ForEach-Object { $_.ToLowerInvariant() }
    $unknown = $wanted | Where-Object { $_ -notin ($subscriptions | ForEach-Object { $_.id.ToLowerInvariant() }) }
    if ($unknown) { throw "Not a subscription this az login can use: $($unknown -join ', ')" }
    $subscriptions = @($subscriptions | Where-Object { $_.id.ToLowerInvariant() -in $wanted })
}
if (-not $subscriptions) { throw 'This az login sees no subscriptions it can read.' }

# Current tenant first; az ad works on the tenant of the active subscription.
$groups = $subscriptions | Group-Object tenantId | Sort-Object { $_.Name -ne $account.tenantId }
Write-Host "Azure: $($account.user.name) - $($subscriptions.Count) subscription(s) in $(@($groups).Count) tenant(s); roles: $($roles -join ', ')"

$results = New-Object System.Collections.Generic.List[object]
try {
    foreach ($group in $groups) {
        $tenantSubs = @($group.Group)
        $tenantName = if ($tenantSubs[0].PSObject.Properties['tenantDisplayName']) { $tenantSubs[0].tenantDisplayName } else { $group.Name }
        Write-Host "Tenant $tenantName ($($group.Name))"
        try {
            if ($group.Name -ne $account.tenantId) {
                Invoke-Az @('account', 'set', '--subscription', $tenantSubs[0].id) | Out-Null
            }
            $principal = Resolve-Assignee $Assignee
            Write-Host "  Assignee: $($principal.Name) ($($principal.Type), $($principal.Id))"
        } catch {
            $reason = Get-ShortReason $_.Exception.Message
            if ($group.Name -ne $account.tenantId) { $reason += " (sign in to it with: az login --tenant $($group.Name))" }
            Write-Warning "  Skipped tenant - $reason"
            foreach ($sub in $tenantSubs) {
                $results.Add([pscustomobject]@{ Subscription = $sub.name; Tenant = $tenantName; Added = ''; AlreadyThere = ''; Skipped = $reason })
            }
            continue
        }

        foreach ($sub in $tenantSubs) {
            $scope = "/subscriptions/$($sub.id)"
            $added = @(); $already = @(); $skipped = @()
            try {
                $have = @(Invoke-Az @('role', 'assignment', 'list', '--assignee', $principal.Id, '--scope', $scope,
                        '--include-inherited', '--query', '[].roleDefinitionName'))
            } catch {
                $have = @()
            }
            foreach ($role in $roles) {
                # Owner already reads everything these roles grant.
                if ($role -in $have -or 'Owner' -in $have) { $already += $role; continue }
                if (-not $PSCmdlet.ShouldProcess("$($sub.name) ($scope)", "Assign '$role' to $($principal.Name)")) {
                    $skipped += "$role (WhatIf)"; continue
                }
                try {
                    Invoke-Az @('role', 'assignment', 'create', '--assignee-object-id', $principal.Id,
                        '--assignee-principal-type', $principal.Type, '--role', $role, '--scope', $scope) | Out-Null
                    $added += $role
                } catch {
                    $skipped += "$role - $(Get-ShortReason $_.Exception.Message)"
                }
            }
            $line = "  $($sub.name): "
            $line += if ($added) { "added $($added -join ', ')" } else { 'nothing added' }
            if ($already) { $line += "; already there: $($already -join ', ')" }
            Write-Host $line
            foreach ($item in $skipped) { Write-Warning "  $($sub.name): skipped $item" }
            $results.Add([pscustomobject]@{
                    Subscription = $sub.name; Tenant = $tenantName
                    Added = $added -join ', '; AlreadyThere = $already -join ', '; Skipped = $skipped -join '; '
                })
        }
    }
} finally {
    if (@($groups | Where-Object { $_.Name -ne $account.tenantId }).Count) {
        Invoke-Az @('account', 'set', '--subscription', $account.id) | Out-Null
    }
}

$results
