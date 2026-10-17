$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (Test-Path -LiteralPath '.env') { Write-Host '.env exists; keeping existing secrets.'; exit 0 }
function New-LabSecret {
  $bytes = New-Object byte[] 32
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}
$lines = @('MANAGER_PASSWORD=' + (New-LabSecret))
foreach ($name in @('MANAGER_SECRET','VULNERABLE_SECRET','FIXED_SECRET','MANAGER_DB_PASSWORD','VULNERABLE_DB_PASSWORD','FIXED_DB_PASSWORD')) {
  $lines += $name + '=' + (New-LabSecret)
}
$lines += 'REPAIRED_SERVICE=vulnerable'
[IO.File]::WriteAllLines((Join-Path (Get-Location) '.env'), $lines, (New-Object Text.UTF8Encoding $false))
Write-Host 'Created .env. Find MANAGER_PASSWORD there. Never upload this file.'

