$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
  py -3.12 -m venv .venv
  if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.12 first' }
  & ./.venv/Scripts/python.exe -m pip install -r requirements-dev.lock
  if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
}
& ./.venv/Scripts/python.exe scripts/dev.py --allow-local-lab

