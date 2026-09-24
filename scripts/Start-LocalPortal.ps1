<#
.SYNOPSIS
    Starts the ARG local portal on http://127.0.0.1:8765 using your az login session.

.DESCRIPTION
    Creates a local virtual environment (.venv-local) on first run, installs
    requirements-local.txt, checks that the Azure CLI is signed in, and starts
    `python -m scripts.local_portal`. No Docker, database or service principal
    is needed. Reports are written to <ReportsPath>\<subscription>\*.md.

.PARAMETER Port
    Local port for the portal. Default 8765.

.PARAMETER ReportsPath
    Folder holding one sub-folder per analysed subscription. Default .\reports.

.PARAMETER TenantId
    Optional tenant of the az login session to use.

.PARAMETER NoBrowser
    Do not open the browser automatically.

.EXAMPLE
    az login
    .\scripts\Start-LocalPortal.ps1

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
    [ValidateNotNullOrEmpty()]
    [string] $ReportsPath = 'reports',

    [Parameter()]
    [string] $TenantId,

    [Parameter()]
    [switch] $NoBrowser
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Path $PSScriptRoot -Parent
Push-Location -Path $repoRoot
try {
    $venvPath = Join-Path -Path $repoRoot -ChildPath '.venv-local'
    $isWindowsHost = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
    $pythonPath = if ($isWindowsHost) { Join-Path -Path $venvPath -ChildPath 'Scripts\python.exe' } else { Join-Path -Path $venvPath -ChildPath 'bin/python' }

    if (-not (Test-Path -Path $pythonPath)) {
        $bootstrapPython = Get-Command -Name 'python', 'python3' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $bootstrapPython) {
            throw 'Python 3.10+ was not found on PATH.'
        }
        Write-Verbose ('Creating virtual environment in {0}' -f $venvPath)
        & $bootstrapPython.Source -m venv $venvPath
        & $pythonPath -m pip install --disable-pip-version-check --quiet --upgrade pip
    }

    Write-Verbose 'Installing / verifying requirements-local.txt'
    & $pythonPath -m pip install --disable-pip-version-check --quiet -r (Join-Path -Path $repoRoot -ChildPath 'requirements-local.txt')
    if ($LASTEXITCODE -ne 0) {
        throw 'pip install -r requirements-local.txt failed.'
    }

    $azCommand = Get-Command -Name 'az' -ErrorAction SilentlyContinue
    if (-not $azCommand) {
        Write-Warning 'Azure CLI (az) not found on PATH. Install it and run "az login" - the portal uses that session.'
    }
    else {
        $azSignedIn = $false
        try {
            $null = & az account show --output none 2>$null
            $azSignedIn = $LASTEXITCODE -eq 0
        }
        catch {
            $azSignedIn = $false
        }
        if (-not $azSignedIn) {
            Write-Warning 'Azure CLI is not signed in. Run "az login" in another terminal, then click Refresh in the portal.'
        }
    }

    $portalArguments = @('-m', 'scripts.local_portal', '--port', $Port, '--reports-dir', $ReportsPath)
    if ($TenantId) {
        $portalArguments += @('--tenant', $TenantId)
    }
    if ($NoBrowser) {
        $portalArguments += '--no-browser'
    }
    & $pythonPath @portalArguments
}
finally {
    Pop-Location
}
