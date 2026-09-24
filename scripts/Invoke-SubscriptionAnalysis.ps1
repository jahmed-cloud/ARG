<#
.SYNOPSIS
    Runs the ARG subscription analysis from the command line using your az login session.

.DESCRIPTION
    Can be run from any folder. Creates .venv-local in the ARG repository root on first run,
    installs requirements-local.txt, checks the Azure CLI session and runs
    `python -m scripts.subscription_analysis`. Each subscription is written to
    <ReportsPath>\<subscription>\ (README.md, summary.json, 01-... to 05-...) and
    <ReportsPath>\README.md indexes all analysed subscriptions.

.PARAMETER Subscription
    One or more subscription IDs or display names.

.PARAMETER All
    Analyse every enabled subscription visible to the az login session.

.PARAMETER ReportsPath
    Root folder for reports. Relative paths are resolved from the current folder.
    Default: <ARG repo>\reports.

.PARAMETER TenantId
    Optional tenant of the az login session to use.

.PARAMETER SkipCost
    Skip the Cost Management datasets (faster; cost sections stay empty).

.PARAMETER Pdf
    Also export a PDF of each report: 'summary' (executive pages) or 'full' (everything).
    Uses the locally installed Microsoft Edge or Google Chrome in headless mode.

.EXAMPLE
    az login
    C:\src\ARG\scripts\Invoke-SubscriptionAnalysis.ps1 -Subscription 'pp-buehler_insights_leybold_optics' -Pdf summary

.EXAMPLE
    .\scripts\Invoke-SubscriptionAnalysis.ps1 -All -ReportsPath 'D:\arg-reports'

.OUTPUTS
    None. Progress and the report location are printed by the analysis.
#>
[CmdletBinding(DefaultParameterSetName = 'BySubscription')]
param(
    [Parameter(Mandatory, ParameterSetName = 'BySubscription')]
    [ValidateNotNullOrEmpty()]
    [string[]] $Subscription,

    [Parameter(Mandatory, ParameterSetName = 'All')]
    [switch] $All,

    [Parameter()]
    [string] $ReportsPath,

    [Parameter()]
    [string] $TenantId,

    [Parameter()]
    [switch] $SkipCost,

    [Parameter()]
    [ValidateSet('summary', 'full')]
    [string] $Pdf
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'ArgLocal.psm1') -Force

$analysisArguments = @('-m', 'scripts.subscription_analysis')
if ($All) {
    $analysisArguments += '--all'
}
else {
    foreach ($item in $Subscription) {
        $analysisArguments += @('--subscription', $item)
    }
}
if ($ReportsPath) {
    $analysisArguments += @('--reports-dir', $PSCmdlet.GetUnresolvedProviderPathFromPSPath($ReportsPath))
}
if ($TenantId) {
    $analysisArguments += @('--tenant', $TenantId)
}
if ($SkipCost) {
    $analysisArguments += '--skip-cost'
}
if ($Pdf) {
    $analysisArguments += @('--pdf', $Pdf)
}

Push-Location -Path $repositoryRoot
try {
    $pythonPath = Initialize-ArgLocalEnvironment -RepositoryRoot $repositoryRoot
    if (-not (Test-ArgAzureCliSession)) {
        throw 'Sign in with "az login" first.'
    }
    & $pythonPath @analysisArguments
    if ($LASTEXITCODE -ne 0) {
        throw ('Subscription analysis finished with exit code {0}.' -f $LASTEXITCODE)
    }
}
finally {
    Pop-Location
}
