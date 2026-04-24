<#
.SYNOPSIS
  Clone pinned Veil corpora into benchmarks\vendor\<family>\<name>\.
.DESCRIPTION
  Same contract as fetch-corpora.sh. `-Corpus` picks the family
  (all | precision | recall). Idempotent; pass `-Update` to force re-fetch
  even when the resolved SHA is current. The TSV (family, name, url, rev)
  comes from `cargo xtask fetch --emit-tsv`, so the canonical corpus
  schema lives in benchmarks\<family>\corpus.toml — not in this script.
#>
[CmdletBinding()]
param(
  [ValidateSet('all','precision','recall')]
  [string]$Corpus = 'all',
  [switch]$Update
)

$ErrorActionPreference = 'Stop'
$Root      = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$VendorRt  = Join-Path $Root 'benchmarks\vendor'
New-Item -ItemType Directory -Force $VendorRt | Out-Null

# xtask emits: family<TAB>name<TAB>url<TAB>rev (one row per corpus entry).
$tsv = & cargo run --quiet -p xtask -- fetch --corpus $Corpus --emit-tsv
if ($LASTEXITCODE -ne 0) { throw 'xtask fetch --emit-tsv failed' }

foreach ($line in $tsv -split "`r?`n") {
  if (-not $line) { continue }
  $parts = $line -split "`t"
  if ($parts.Count -ne 4) { continue }
  $family, $name, $url, $rev = $parts

  $familyDir    = Join-Path $VendorRt $family
  New-Item -ItemType Directory -Force $familyDir | Out-Null
  $target       = Join-Path $familyDir $name
  $resolvedFile = Join-Path $target '.veil-resolved-sha'

  if ((Test-Path $resolvedFile) -and (-not $Update)) {
    $existing = (Get-Content $resolvedFile).Trim().Substring(0, 12)
    Write-Host "fetch-corpora: $family/$name — already at $existing (skip; use -Update to bump)"
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
  Write-Host "fetch-corpora: $family/$name — $rev → $short"
}

Write-Host "fetch-corpora: done (vendor tree at $VendorRt)"
