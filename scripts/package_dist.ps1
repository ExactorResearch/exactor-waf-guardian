# ==============================================================================
# Exactor WAF Guardian - Windows Distribution Packager
# Generates a standalone, zero-dependency ZIP bundle for client distribution.
# ==============================================================================

param(
    [string]$Version = "v0.2.0",
    [switch]$NoRebuild = $false
)

$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$DistDir = "$ProjectRoot\dist"
$StagingDir = "$DistDir\exactor-waf-guardian-$Version-windows-x86_64"
$ZipFile = "$DistDir\exactor-waf-guardian-$Version-windows-x86_64.zip"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Packaging Exactor WAF Guardian for Windows ($Version)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Verify / Build Release Binary
$ReleaseExe = ""
if (Test-Path "$ProjectRoot\target\release\exactor-waf-guardian.exe") {
    $ReleaseExe = "$ProjectRoot\target\release\exactor-waf-guardian.exe"
} elseif (Test-Path "$ProjectRoot\..\target\release\exactor-waf-guardian.exe") {
    $ReleaseExe = "$ProjectRoot\..\target\release\exactor-waf-guardian.exe"
}

if ((-not $ReleaseExe) -or (-not $NoRebuild)) {
    Write-Host "Building optimized release binary..." -ForegroundColor Yellow
    Push-Location $ProjectRoot
    try {
        cargo build --release -p exactor-waf-guardian -j 1
    } finally {
        Pop-Location
    }
    if (Test-Path "$ProjectRoot\target\release\exactor-waf-guardian.exe") {
        $ReleaseExe = "$ProjectRoot\target\release\exactor-waf-guardian.exe"
    } elseif (Test-Path "$ProjectRoot\..\target\release\exactor-waf-guardian.exe") {
        $ReleaseExe = "$ProjectRoot\..\target\release\exactor-waf-guardian.exe"
    }
}

if (-not $ReleaseExe -or (-not (Test-Path $ReleaseExe))) {
    Write-Error "Release executable not found in $ProjectRoot\target\release or workspace target\release"
    exit 1
}

# 2. Prepare Dist & Staging Directory
if (Test-Path $StagingDir) {
    Remove-Item -Recurse -Force $StagingDir
}
New-Item -ItemType Directory -Force -Path $StagingDir | Out-Null
New-Item -ItemType Directory -Force -Path "$StagingDir\bin" | Out-Null

# 3. Copy Assets
Copy-Item -Path $ReleaseExe -Destination "$StagingDir\exactor-waf-guardian.exe" -Force
Copy-Item -Path $ReleaseExe -Destination "$StagingDir\bin\exactor-waf-guardian.exe" -Force
Copy-Item -Path "$ProjectRoot\waf_config.toml" -Destination "$StagingDir\waf_config.toml" -Force
Copy-Item -Path "$ProjectRoot\install.ps1" -Destination "$StagingDir\install.ps1" -Force
Copy-Item -Path "$ProjectRoot\uninstall.ps1" -Destination "$StagingDir\uninstall.ps1" -Force

# 4. Generate README_INSTALL.txt for End Clients
$ReadmeLines = @(
    "================================================================================",
    "  GUARDIAN WAF - ZERO-DEPENDENCY CLIENT INSTALLATION PACKAGE",
    "  Deterministic SAT Cyber-Defense and Sub-millisecond Reverse Proxy",
    "  Powered by EXACTOR Core and https://exactor.tech",
    "================================================================================",
    "",
    "This package is 100% self-contained. The client does NOT need Rust,",
    "Cargo, Python, GCC, Visual Studio, or any other dependency installed on their server.",
    "",
    "OPTION A: AUTOMATIC INSTALLATION (RECOMMENDED)",
    "--------------------------------------------------------------------------------",
    "1. Open PowerShell as Administrator.",
    "2. Navigate to this extracted directory:",
    "     cd exactor-waf-guardian-$Version-windows-x86_64",
    "3. Run the installer:",
    "     powershell -ExecutionPolicy Bypass -File .\install.ps1",
    "",
    "   The installer will automatically:",
    "   - Install the binary to C:\Program Files\Exactor\WAF",
    "   - Create configuration at C:\ProgramData\Exactor\WAF\waf_config.toml",
    "   - Add the binary directory to the System PATH",
    "   - Register and start the Windows Service 'ExactorWAF' with automatic startup.",
    "",
    "OPTION B: PORTABLE EXECUTION (WITHOUT INSTALLING)",
    "--------------------------------------------------------------------------------",
    "If you only wish to test the firewall without installing system services:",
    "1. Run in CMD or PowerShell:",
    "     .\exactor-waf-guardian.exe proxy --config .\waf_config.toml",
    "2. Test payload inspection:",
    "     .\exactor-waf-guardian.exe inspect --query `"id=1' OR 1=1--`"",
    "",
    "CLEAN UNINSTALLATION:",
    "--------------------------------------------------------------------------------",
    "To completely uninstall the service and binaries:",
    "   powershell -ExecutionPolicy Bypass -File .\uninstall.ps1",
    "================================================================================"
)
$ReadmeClient = $ReadmeLines -join "`r`n"
Set-Content -Path "$StagingDir\README_INSTALL.txt" -Value $ReadmeClient -Encoding utf8

# 5. Compress into ZIP
if (Test-Path $ZipFile) {
    Remove-Item -Force $ZipFile
}
Write-Host "Compressing distribution zip..." -ForegroundColor Yellow
Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipFile -Force

# 6. Checksum & Summary
$Hash = (Get-FileHash -Path $ZipFile -Algorithm SHA256).Hash
$SizeMB = [math]::Round((Get-Item $ZipFile).Length / 1MB, 2)

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "Client Distribution Package ready!" -ForegroundColor Green
Write-Host "   Archive  : $ZipFile" -ForegroundColor Cyan
Write-Host "   Size     : $SizeMB MB" -ForegroundColor Cyan
Write-Host "   SHA256   : $Hash" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Green
