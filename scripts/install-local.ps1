$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
cargo install --path $root --locked --force
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$cargoBin = Join-Path $cargoHome 'bin'
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$paths = @($userPath -split ';' | Where-Object { $_ })
if ($paths -notcontains $cargoBin) {
  [Environment]::SetEnvironmentVariable('Path', ((@($paths) + $cargoBin) -join ';'), 'User')
}
if (($env:Path -split ';') -notcontains $cargoBin) { $env:Path = "$cargoBin;$env:Path" }
icli --version
Write-Host 'Local icli is ready. Try: icli help'
