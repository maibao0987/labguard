$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
docker compose -p labguard exec -T worker python scripts/check_compose.py
if ($LASTEXITCODE -ne 0) { throw 'Static isolation check failed' }
foreach ($port in @(5100,5101,5102)) {
  $r = Invoke-RestMethod -Uri "http://127.0.0.1:$port/health" -TimeoutSec 5
  if ($r.status -ne 'ok') { throw "Health failed on fixed local port $port" }
  Write-Host "Healthy: $port"
}
docker compose -p labguard exec -T worker python scripts/check_isolation.py
if ($LASTEXITCODE -ne 0) { throw 'Runtime isolation check failed' }
Write-Host 'Review docs/isolation.md for remaining host-boundary limitations.'

