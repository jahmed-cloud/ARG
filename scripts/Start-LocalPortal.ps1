<#
.SYNOPSIS
    Starts the ARG local portal on http://127.0.0.1:8765 using your az login session.

.DESCRIPTION
    Can be run from any folder. Creates .venv-local in the ARG repository root on first run,
    installs requirements-local.txt, checks that the Azure CLI is signed in, and starts
    `python -m scripts.local_portal`. No Docker, database or service principal is needed.
    Reports are written to <ARG repo>\reports\<subscription>\ unless -ReportsPath is given.

.PARAMETER Port
    Local port for the portal. Default 8765.

.PARAMETER ReportsPath
    Folder holding one sub-folder per analysed subscription. Relative paths are resolved from the
    current folder. Default: <ARG repo>\reports.

.PARAMETER TenantId
    Optional tenant of the az login session to use.

.PARAMETER NoBrowser
    Do not open the browser automatically.

.EXAMPLE
    az login
    C:\src\ARG\scripts\Start-LocalPortal.ps1

.EXAMPLE
    $env:ARG_PORTAL_PASSWORD = 'choose-a-password'
    .\scripts\Start-LocalPortal.ps1 -Port 9000 -ReportsPath 'D:\arg-reports'

.OUTPUTS
    None. Runs the portal in the foreground until Ctrl+C.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1024, 65535)]
    [int] $Port = 8765,

    [Parameter()]
    [string] $ReportsPath,

    [Parameter()]
    [string] $TenantId,

    [Parameter()]
    [switch] $NoBrowser
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'ArgLocal.psm1') -Force

$portalArguments = @('-m', 'scripts.local_portal', '--port', $Port)
if ($ReportsPath) {
    $portalArguments += @('--reports-dir', $PSCmdlet.GetUnresolvedProviderPathFromPSPath($ReportsPath))
}
if ($TenantId) {
    $portalArguments += @('--tenant', $TenantId)
}
if ($NoBrowser) {
    $portalArguments += '--no-browser'
}

Push-Location -Path $repositoryRoot
try {
    $pythonPath = Initialize-ArgLocalEnvironment -RepositoryRoot $repositoryRoot
    $null = Test-ArgAzureCliSession
    & $pythonPath @portalArguments
}
finally {
    Pop-Location
}
