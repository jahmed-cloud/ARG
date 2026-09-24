#Requires -Version 5.1
<#
.SYNOPSIS
    Shared helpers for the ARG local launchers (Start-LocalPortal.ps1, Invoke-SubscriptionAnalysis.ps1).

.DESCRIPTION
    Initialize-ArgLocalEnvironment creates .venv-local in the ARG repository root on first use and
    installs requirements-local.txt. Test-ArgAzureCliSession checks that the Azure CLI is installed
    and signed in (the only way the local tools reach Azure - no service principal).
#>

function Initialize-ArgLocalEnvironment {
    <#
    .SYNOPSIS
        Ensures .venv-local exists with requirements-local.txt installed and returns its python path.
    .PARAMETER RepositoryRoot
        ARG repository root (the folder that contains requirements-local.txt).
    .OUTPUTS
        System.String - full path of the virtual environment's python executable.
    .EXAMPLE
        $python = Initialize-ArgLocalEnvironment -RepositoryRoot 'C:\src\ARG'
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -Path (Join-Path -Path $_ -ChildPath 'requirements-local.txt') })]
        [string] $RepositoryRoot
    )

    $venvPath = Join-Path -Path $RepositoryRoot -ChildPath '.venv-local'
    $isWindowsHost = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
    $relativePython = if ($isWindowsHost) { 'Scripts\python.exe' } else { 'bin/python' }
    $pythonPath = Join-Path -Path $venvPath -ChildPath $relativePython

    if (-not (Test-Path -Path $pythonPath)) {
        $bootstrapPython = Get-Command -Name 'python', 'python3' -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $bootstrapPython) {
            throw 'Python 3.10+ was not found on PATH. Install it from https://www.python.org/downloads/.'
        }
        Write-Verbose ('Creating virtual environment in {0}' -f $venvPath)
        & $bootstrapPython.Source -m venv $venvPath
        if ($LASTEXITCODE -ne 0) {
            throw ('Creating the virtual environment in {0} failed.' -f $venvPath)
        }
        & $pythonPath -m pip install --disable-pip-version-check --quiet --upgrade pip
    }

    Write-Verbose 'Installing / verifying requirements-local.txt'
    $requirements = Join-Path -Path $RepositoryRoot -ChildPath 'requirements-local.txt'
    & $pythonPath -m pip install --disable-pip-version-check --quiet -r $requirements
    if ($LASTEXITCODE -ne 0) {
        throw 'pip install -r requirements-local.txt failed.'
    }
    Write-Output $pythonPath
}

function Test-ArgAzureCliSession {
    <#
    .SYNOPSIS
        Returns $true when the Azure CLI is installed and signed in; writes a warning otherwise.
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        if (-not (Test-ArgAzureCliSession)) { az login }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not (Get-Command -Name 'az' -ErrorAction SilentlyContinue)) {
        Write-Warning 'Azure CLI (az) not found on PATH. Install it and run "az login" - the ARG local tools use that session.'
        return $false
    }
    $signedIn = $false
    try {
        $null = & az account show --output none 2>$null
        $signedIn = $LASTEXITCODE -eq 0
    }
    catch {
        $signedIn = $false
    }
    if (-not $signedIn) {
        Write-Warning 'Azure CLI is not signed in. Run "az login" (optionally --tenant <id>) and try again.'
    }
    return $signedIn
}

Export-ModuleMember -Function Initialize-ArgLocalEnvironment, Test-ArgAzureCliSession
