param([switch]$ConfirmReset)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if ((Split-Path $root -Leaf) -ne 'labguard' -or -not (Test-Path -LiteralPath (Join-Path $root 'compose.yaml'))) {
  throw 'Unexpected project directory; refusing reset.'
}
Set-Location $root
Write-Host 'This resets ONLY Compose project labguard.'
Write-Host 'Volumes: labguard_manager_data, labguard_vulnerable_data, labguard_fixed_data'
docker compose -p labguard ps -a
if (-not $ConfirmReset) { Write-Host 'Preview only. Run again with -ConfirmReset to erase this lab data.'; exit 0 }
docker compose -p labguard down --volumes
if ($LASTEXITCODE -ne 0) { throw 'Reset failed' }
Write-Host 'Project reset. Secrets in .env were preserved. Run start.ps1 to seed fresh fake data.'

