<#
.SYNOPSIS
    Exactor WAF Guardian - Windows Server Automated Installer
    Installs exactor-waf-guardian binary, configuration, and runs as a background service.
#>

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\Exactor\WAF",
    [string]$ConfigDir = "C:\ProgramData\Exactor\WAF"
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "🛡️  Installing Exactor WAF Guardian on Windows Server" -ForegroundColor Cyan
Write-Host "   Engine: EXACTOR Core & https://exactor.tech" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Compile or Locate Binary
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BinarySrc = ""

if (Test-Path "$ScriptDir\target\release\exactor-waf-guardian.exe") {
    $BinarySrc = "$ScriptDir\target\release\exactor-waf-guardian.exe"
} elseif (Test-Path "$ScriptDir\..\target\release\exactor-waf-guardian.exe") {
    $BinarySrc = "$ScriptDir\..\target\release\exactor-waf-guardian.exe"
} else {
    Write-Host "Compiling release binary with cargo..." -ForegroundColor Yellow
    Push-Location $ScriptDir
    try {
        cargo build --release
    } finally {
        Pop-Location
    }
    $BinarySrc = "$ScriptDir\target\release\exactor-waf-guardian.exe"
}

# 2. Create Target Directories
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

# 3. Copy Binary
Copy-Item -Path $BinarySrc -Destination "$InstallDir\exactor-waf-guardian.exe" -Force
Write-Host "✓ Installed executable to: $InstallDir\exactor-waf-guardian.exe" -ForegroundColor Green

# 4. Copy Default Configuration if not exists
if (-not (Test-Path "$ConfigDir\waf_config.toml")) {
    Copy-Item -Path "$ScriptDir\waf_config.toml" -Destination "$ConfigDir\waf_config.toml" -Force
    Write-Host "✓ Initialized configuration: $ConfigDir\waf_config.toml" -ForegroundColor Green
} else {
    Write-Host "ℹ️  Preserved existing configuration: $ConfigDir\waf_config.toml" -ForegroundColor Gray
}

# 5. Add to System PATH
$CurrentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
if ($CurrentPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$InstallDir", [EnvironmentVariableTarget]::Machine)
    Write-Host "✓ Added $InstallDir to System PATH" -ForegroundColor Green
}

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "🎉 Installation complete!" -ForegroundColor Green
Write-Host "   To run reverse proxy : exactor-waf-guardian proxy --config `"$ConfigDir\waf_config.toml`"" -ForegroundColor Cyan
Write-Host "   To test inspection   : exactor-waf-guardian inspect --query `"id=1' OR 1=1--`"" -ForegroundColor Cyan
Write-Host "   To run benchmarks    : exactor-waf-guardian benchmark" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Green
