@echo off
REM Garand launcher for Windows. Runs the built CLI via Node.
REM Expects Node.js installed and the project built (npm run build).
node "%~dp0..\dist\index.js" %*
