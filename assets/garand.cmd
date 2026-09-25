@echo off
REM Garand launcher for Windows. Garand is a COMMAND-LINE tool, so this opens a
REM PowerShell terminal parked in the project with a `garand` command ready to
REM use, and keeps it open (double-clicking a CLI otherwise just flashes shut).
start "" powershell -NoExit -Command "Set-Location '%~dp0..'; if (-not (Test-Path 'dist\index.js')) { Write-Host 'Garand is not built yet. In this folder run:  npm install ; npm run build' -ForegroundColor Yellow } else { function garand { node dist\index.js @args }; Write-Host ('Garand ready in ' + (Get-Location)) -ForegroundColor Green; Write-Host 'Example:  garand discover --scope scope.json --seed https://app.example.com' -ForegroundColor Cyan; Write-Host ''; garand }"
