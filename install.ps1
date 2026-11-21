# Clean Code V12 installer for Windows (x64) — installs ccv12.exe + cc-lsp.exe.
#
#   irm https://github.com/LiquidLava1990/clean-code-v12/releases/latest/download/install.ps1 | iex
#
# Environment overrides:
#   CCV12_VERSION         release tag to install (default: latest), e.g. v0.1.0
#   CCV12_INSTALL_DIR     install directory (default: %LOCALAPPDATA%\Programs\ccv12\bin)
#   CCV12_REPO            GitHub owner/repo to download from
#   CCV12_DOWNLOAD_URL    base URL holding the release assets (mirrors,
#                         air-gapped installs); overrides REPO and VERSION
#   CCV12_NO_MODIFY_PATH  set to 1 to leave the user PATH untouched

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-InstallSetting([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
    return $value
}

function Get-ReleaseBaseUrl([string]$Repo, [string]$Version) {
    $mirror = [Environment]::GetEnvironmentVariable('CCV12_DOWNLOAD_URL')
    if (-not [string]::IsNullOrWhiteSpace($mirror)) { return $mirror.TrimEnd('/') }
    if ($Version -eq 'latest') { return "https://github.com/$Repo/releases/latest/download" }
    return "https://github.com/$Repo/releases/download/$Version"
}

function Assert-Checksum([string]$Archive, [string]$ChecksumFile) {
    $expected = ((Get-Content $ChecksumFile -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "ccv12-install: checksum mismatch for $(Split-Path $Archive -Leaf) (expected $expected, got $actual). Re-run; if it persists, report it."
    }
}

function Add-ToUserPath([string]$Dir) {
    if ([Environment]::GetEnvironmentVariable('CCV12_NO_MODIFY_PATH') -eq '1') {
        Write-Host "ccv12-install: CCV12_NO_MODIFY_PATH=1, so add $Dir to PATH yourself"
        return
    }
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @($userPath -split ';' | Where-Object { $_ })
    if ($entries -contains $Dir) { return }
    [Environment]::SetEnvironmentVariable('Path', (($entries + $Dir) -join ';'), 'User')
    $env:Path = "$env:Path;$Dir"
    Write-Host "ccv12-install: added $Dir to your user PATH (open a new terminal to pick it up)"
}

function Install-CleanCode {
    if (-not [Environment]::Is64BitOperatingSystem) {
        throw 'ccv12-install: only 64-bit Windows is supported. Build from source: cargo install --git https://github.com/LiquidLava1990/clean-code-v12 cc-cli'
    }
    $repo = Get-InstallSetting 'CCV12_REPO' 'LiquidLava1990/clean-code-v12'
    $version = Get-InstallSetting 'CCV12_VERSION' 'latest'
    $installDir = Get-InstallSetting 'CCV12_INSTALL_DIR' (Join-Path $env:LOCALAPPDATA 'Programs\ccv12\bin')
    $name = 'ccv12-x86_64-pc-windows-msvc'
    $archiveName = "$name.zip"
    $base = Get-ReleaseBaseUrl $repo $version

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("ccv12-install-" + [Guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-Host "ccv12-install: downloading $archiveName ($version)"
        $archive = Join-Path $tmp $archiveName
        Invoke-WebRequest -UseBasicParsing "$base/$archiveName" -OutFile $archive
        Invoke-WebRequest -UseBasicParsing "$base/$archiveName.sha256" -OutFile "$archive.sha256"
        Assert-Checksum $archive "$archive.sha256"
        Expand-Archive -Path $archive -DestinationPath $tmp -Force

        New-Item -ItemType Directory -Force -Path $installDir | Out-Null
        foreach ($exe in 'ccv12.exe', 'cc-lsp.exe') {
            Copy-Item (Join-Path $tmp "$name\$exe") (Join-Path $installDir $exe) -Force
        }
        Write-Host "ccv12-install: installed $installDir\ccv12.exe and cc-lsp.exe"
        Add-ToUserPath $installDir
        & (Join-Path $installDir 'ccv12.exe') --version
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}

Install-CleanCode
