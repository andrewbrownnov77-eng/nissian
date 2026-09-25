# Garand — Windows 11 desktop shortcut installer.
# Run from the repo root in PowerShell:  powershell -ExecutionPolicy Bypass -File assets\install-windows.ps1
$ErrorActionPreference = "Stop"
$repo    = Split-Path -Parent $PSScriptRoot            # repo root (assets\..)
$icon    = Join-Path $PSScriptRoot "garand.ico"
$target  = Join-Path $PSScriptRoot "garand.cmd"
$desktop = [Environment]::GetFolderPath("Desktop")
$lnk     = Join-Path $desktop "Garand.lnk"

if (-not (Test-Path $icon))   { throw "garand.ico not found next to this script." }
if (-not (Test-Path $target)) { throw "garand.cmd not found next to this script." }

$sh = New-Object -ComObject WScript.Shell
$s  = $sh.CreateShortcut($lnk)
$s.TargetPath       = $target
$s.WorkingDirectory = $repo
$s.IconLocation     = $icon
$s.Description       = "Garand - authorized bug bounty recon & validation"
$s.Save()

Write-Host "Created desktop shortcut: $lnk"
Write-Host "Icon: $icon"
Write-Host "If Node.js isn't installed yet, install it and run 'npm install; npm run build' in the repo first."
