<#
.SYNOPSIS
    Builds the Docker stack's images with Podman and starts the stack on http://localhost:3000 (Windows).

.DESCRIPTION
    For Windows with Podman Desktop (a WSL Podman machine). Can be run from any folder. It avoids what breaks
    `podman compose up --build` on Windows:
      - podman-compose drops the compose file's `dockerfile:` path, so the images are built here with
        `podman build`, under the names compose expects (<folder>_<service>);
      - the Windows client does not apply .dockerignore, so the build context is a clean export of the
        committed code (git archive HEAD): no reports, virtual environments or .env;
      - rootful containers publish ports with firewall rules that WSL does not forward to Windows, so the
        stack runs on the machine's rootless connection, whose ports appear on localhost.
    Uses the Podman CLI installed by Podman Desktop when present, so the client matches the machine.
    Needs podman-compose (python -m pip install podman-compose) and a .env in the repository root.

.PARAMETER Build
    Rebuild the images even if they exist, and recreate the containers. Use after committing code changes:
    the build uses the committed code (HEAD), not uncommitted edits.

.PARAMETER Down
    Stop and remove the stack's containers. The database volume is kept.

.PARAMETER Connection
    Podman connection to use. Default: the rootless connection of the default machine.

.EXAMPLE
    .\scripts\Start-PodmanStack.ps1            # first run builds the images, later runs only start the stack

.EXAMPLE
    .\scripts\Start-PodmanStack.ps1 -Build     # after pulling or committing code changes

.EXAMPLE
    .\scripts\Start-PodmanStack.ps1 -Down

.OUTPUTS
    None. The containers keep running in the Podman machine.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [switch] $Build,

    [Parameter()]
    [switch] $Down,

    [Parameter()]
    [string] $Connection = 'podman-machine-default'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Path $PSScriptRoot -Parent
$project = (Split-Path -Path $repositoryRoot -Leaf).ToLowerInvariant()

$desktopPodman = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Programs\Podman'
if (Test-Path -Path (Join-Path -Path $desktopPodman -ChildPath 'podman.exe')) {
    $env:PATH = "$desktopPodman;$env:PATH"   # podman-compose calls podman from PATH
}
foreach ($tool in 'podman', 'podman-compose', 'git') {
    if (-not (Get-Command -Name $tool -ErrorAction SilentlyContinue)) {
        throw "$tool not found. Install Podman Desktop and Git, then: python -m pip install podman-compose"
    }
}
$envFile = Join-Path -Path $repositoryRoot -ChildPath '.env'
if (-not (Test-Path -Path $envFile)) {
    throw "No .env in $repositoryRoot. Copy .env.example to .env and set POSTGRES_PASSWORD, SECRET_KEY, ENCRYPTION_KEY and ADMIN_PASSWORD."
}
$env:CONTAINER_CONNECTION = $Connection
$compose = @('compose', '-f', (Join-Path -Path $repositoryRoot -ChildPath 'docker-compose.yml'),
             '--env-file', $envFile, '-p', $project)

if ($Down) {
    & podman @compose down
    return
}

$images = @(
    @{ Dockerfile = 'docker/Dockerfile.backend'; Services = @('backend'); BuildArguments = @() },
    @{ Dockerfile = 'docker/Dockerfile.worker'; Services = @('worker', 'beat'); BuildArguments = @() },
    @{ Dockerfile = 'docker/Dockerfile.frontend'; Services = @('frontend')
       BuildArguments = @('--build-arg', 'VITE_API_URL=/api/v1') }
)
$toBuild = @($images | Where-Object {
    $Build -or @($_.Services | Where-Object { & podman image exists "${project}_$_"; $LASTEXITCODE -ne 0 })
})

if ($toBuild) {
    if (git -C $repositoryRoot status --porcelain --untracked-files=no) {
        Write-Warning 'Uncommitted changes are not part of the build: it uses the committed code (HEAD).'
    }
    $context = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$project-podman-build"
    $archive = "$context.zip"
    Remove-Item -Path $context, $archive -Recurse -Force -ErrorAction SilentlyContinue
    git -C $repositoryRoot archive --format=zip "--output=$archive" HEAD
    if ($LASTEXITCODE -ne 0) {
        throw 'git archive failed'
    }
    Expand-Archive -Path $archive -DestinationPath $context
    Push-Location -Path $context
    try {
        foreach ($image in $toBuild) {
            $tags = $image.Services | ForEach-Object { '-t'; "${project}_$_" }
            # docker format keeps the Dockerfiles' HEALTHCHECK (the default OCI format drops it)
            & podman build --format docker -f $image.Dockerfile @tags @($image.BuildArguments) .
            if ($LASTEXITCODE -ne 0) {
                throw "podman build $($image.Dockerfile) failed. 'Temporary failure in name resolution': see local-run.md, section 8."
            }
        }
    }
    finally {
        Pop-Location
        Remove-Item -Path $context, $archive -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$upArguments = @('up', '-d')
if ($Build) {
    $upArguments += '--force-recreate'
}
& podman @compose @upArguments
if ($LASTEXITCODE -ne 0) {
    throw 'podman compose up failed'
}

$port = Get-Content -Path $envFile | Where-Object { $_ -match '^\s*FRONTEND_PORT\s*=\s*(\d+)' } |
    ForEach-Object { $Matches[1] } | Select-Object -First 1
$url = "http://localhost:$(if ($port) { $port } else { 3000 })"
foreach ($attempt in 1..30) {
    try {
        $null = Invoke-WebRequest -Uri "$url/api/v1/health/live" -UseBasicParsing -TimeoutSec 5
        Write-Host "Stack is up: $url (sign in with ADMIN_USERNAME / ADMIN_PASSWORD from .env)"
        return
    }
    catch {
        Start-Sleep -Seconds 2
    }
}
Write-Warning "The containers started but $url does not answer yet. Logs: podman --connection $Connection logs ${project}_backend_1"
