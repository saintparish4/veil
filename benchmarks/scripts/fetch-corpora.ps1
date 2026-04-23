<#
.SYNOPSIS
  Clone the Veil precision corpus at pinned revs.
.DESCRIPTION
  Same contract as fetch-corpora.sh. Idempotent; pass -Update to force
  re-fetch even when the resolved SHA is current.
#>
[CmdletBinding()]
param(
  [switch]$Update
)

$ErrorActionPreference = 'Stop'
$Root       = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$CorpusToml = Join-Path $Root 'benchmarks\precision\corpus.toml'
$VendorDir  = Join-Path $Root 'benchmarks\vendor\precision'

if (-not (Test-Path $CorpusToml)) {
  Write-Error "fetch-corpora: missing $CorpusToml"
  exit 1
}

New-Item -ItemType Directory -Force $VendorDir | Out-Null

# Ask xtask to parse the TOML and emit TSV: name<TAB>url<TAB>rev.
$tsv = & cargo run --quiet -p xtask -- fetch --emit-tsv
if ($LASTEXITCODE -ne 0) { throw 'xtask fetch --emit-tsv failed' }

foreach ($line in $tsv -split "`r?`n") {
  if (-not $line) { continue }
  $parts = $line -split "`t"
  if ($parts.Count -ne 3) { continue }
  $name, $url, $rev = $parts

  $target       = Join-Path $VendorDir $name
  $resolvedFile = Join-Path $target '.veil-resolved-sha'
  if ((Test-Path $resolvedFile) -and (-not $Update)) {
    $existing = (Get-Content $resolvedFile).Trim().Substring(0, 12)
    Write-Host "fetch-corpora: $name — already at $existing (skip; use -Update to bump)"
    continue
  }

  if (Test-Path $target) { Remove-Item -Recurse -Force $target }
  New-Item -ItemType Directory -Force $target | Out-Null
  Push-Location $target
  try {
    git init -q
    git remote add origin $url
    # Try as rev first, fall back to tag ref.
    git fetch --depth 1 origin $rev -q
    if ($LASTEXITCODE -ne 0) { git fetch --depth 1 origin "refs/tags/$rev" -q }
    git checkout --detach FETCH_HEAD -q
    git rev-parse HEAD | Set-Content $resolvedFile
  } finally {
    Pop-Location
  }
  $short = (Get-Content $resolvedFile).Trim().Substring(0, 12)
  Write-Host "fetch-corpora: $name — $rev → $short"
}

Write-Host "fetch-corpora: done (vendor tree at $VendorDir)"
