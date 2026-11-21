# Clean Code V12 installer for Windows (x64).
#
#   irm https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.ps1 | iex
#
# Environment overrides:
#   CC_VERSION      release tag to install (default: latest), e.g. v0.1.0
#   CC_INSTALL_DIR  install directory (default: %LOCALAPPDATA%\Programs\clean-code\bin)
#   CC_BIN_NAME     installed command name (default: cc, or ccv12 when a
#                   different cc.exe is already on PATH)
#   CC_REPO         GitHub owner/repo to download from

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-InstallSetting([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

function Get-ReleaseBaseUrl([string]$Repo, [string]$Version) {
    if ($Version -eq 'latest') { return "https://github.com/$Repo/releases/latest/download" }
    return "https://github.com/$Repo/releases/download/$Version"
}

function Assert-Checksum([string]$Archive, [string]$ChecksumFile) {
    $expected = ((Get-Content $ChecksumFile -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "cc-install: checksum mismatch for $(Split-Path $Archive -Leaf) (expected $expected, got $actual). Re-run; if it persists, report it."
    }
}

function Get-BinName([string]$InstallDir) {
    $override = [Environment]::GetEnvironmentVariable('CC_BIN_NAME')
    if (-not [string]::IsNullOrWhiteSpace($override)) { return $override }
    $existing = Get-Command cc -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $existing -or (Split-Path $existing.Source -Parent) -eq $InstallDir) { return 'cc' }
    return 'ccv12'
}

function Add-ToUserPath([string]$Dir) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @($userPath -split ';' | Where-Object { $_ })
    if ($entries -contains $Dir) { return }
    [Environment]::SetEnvironmentVariable('Path', (($entries + $Dir) -join ';'), 'User')
    $env:Path = "$env:Path;$Dir"
    Write-Host "cc-install: added $Dir to your user PATH (open a new terminal to pick it up)"
}

function Install-CleanCode {
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'cc-install: only 64-bit Windows is supported. Build from source: cargo install --git https://github.com/LiquidLava1990/clean-code-v12 cc-cli'
    }
    $repo = Get-InstallSetting 'CC_REPO' 'LiquidLava1990/clean-code-v12'
    $version = Get-InstallSetting 'CC_VERSION' 'latest'
    $installDir = Get-InstallSetting 'CC_INSTALL_DIR' (Join-Path $env:LOCALAPPDATA 'Programs\clean-code\bin')
    $target = 'x86_64-pc-windows-msvc'
    $archiveName = "cc-$target.zip"
    $base = Get-ReleaseBaseUrl $repo $version

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("cc-install-" + [Guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "cc-install: downloading $archiveName ($version)"
        $archive = Join-Path $tmp $archiveName
        Invoke-WebRequest -UseBasicParsing "$base/$archiveName" -OutFile $archive
        Invoke-WebRequest -UseBasicParsing "$base/$archiveName.sha256" -OutFile "$archive.sha256"
        Assert-Checksum $archive "$archive.sha256"
        Expand-Archive -Path $archive -DestinationPath $tmp -Force

        New-Item -ItemType Directory -Force -Path $installDir | Out-Null
        $binName = Get-BinName $installDir
        Copy-Item (Join-Path $tmp "cc-$target\cc.exe") (Join-Path $installDir "$binName.exe") -Force
        Copy-Item (Join-Path $tmp "cc-$target\cc-lsp.exe") (Join-Path $installDir 'cc-lsp.exe') -Force
        Write-Host "cc-install: installed $installDir\$binName.exe and cc-lsp.exe"
        if ($binName -ne 'cc') {
            Write-Host "cc-install: a different cc.exe is already on PATH, so the linter was installed as '$binName'."
        }
        Add-ToUserPath $installDir
        & (Join-Path $installDir "$binName.exe") --version
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

Install-CleanCode
