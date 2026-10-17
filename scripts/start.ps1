$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Install and start Docker Desktop with Linux containers first.' }
& "$PSScriptRoot/setup.ps1"
docker compose -p labguard up --build -d --wait
if ($LASTEXITCODE -ne 0) { throw 'Lab startup failed. Run docker compose -p labguard logs.' }
Write-Host 'Manager: http://127.0.0.1:5100 | Vulnerable: :5101 | Fixed: :5102'
Write-Host 'Manager account: admin. Read MANAGER_PASSWORD from .env.'

