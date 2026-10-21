$ErrorActionPreference = 'Stop'
$repo = 'manvankaliber/icli'
$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
$target = switch ($arch) {
  { $_ -match '^(AMD64|X64)$' } { 'x86_64-pc-windows-msvc' }
  { $_ -match '^ARM64$' } { 'aarch64-pc-windows-msvc' }
  default { throw "No Windows binary is published for $arch yet." }
}

$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest"
$tag = $release.tag_name
$asset = "icli-$tag-$target.zip"
$checksumAsset = "$asset.sha256"
$download = "https://github.com/$repo/releases/download/$tag/$asset"
$checksumDownload = "https://github.com/$repo/releases/download/$tag/$checksumAsset"
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\icli\bin'
New-Item -ItemType Directory -Force -Path $temp, $installDir | Out-Null

try {
  $archive = Join-Path $temp $asset
  $checksumFile = Join-Path $temp $checksumAsset
  Invoke-WebRequest -Uri $download -OutFile $archive
  Invoke-WebRequest -Uri $checksumDownload -OutFile $checksumFile
  $expectedHash = (Get-Content -Raw $checksumFile).Trim().ToLowerInvariant()
  $actualHash = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
  if ($actualHash -ne $expectedHash) { throw 'Release checksum did not match.' }
  Expand-Archive -Path $archive -DestinationPath $temp -Force
  Copy-Item (Join-Path $temp 'icli.exe') (Join-Path $installDir 'icli.exe') -Force
} finally {
  Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$paths = @($userPath -split ';' | Where-Object { $_ -and $_.Trim().TrimEnd('\') -ine $installDir.TrimEnd('\') })
$newPath = (@($installDir) + $paths) -join ';'
if ($newPath -ne $userPath) {
  [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
}
$processPaths = @($env:Path -split ';' | Where-Object { $_ -and $_.Trim().TrimEnd('\') -ine $installDir.TrimEnd('\') })
$env:Path = (@($installDir) + $processPaths) -join ';'

Write-Host "Installed icli $tag to $installDir"
Write-Host 'Run: icli --help'
