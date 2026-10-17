$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
docker compose -p labguard stop
if ($LASTEXITCODE -ne 0) { throw 'Stop failed' }

