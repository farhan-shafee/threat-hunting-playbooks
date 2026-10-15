#Requires -Version 7.0
<#
.SYNOPSIS
  Validate KQL syntax AND static semantics using Microsoft's Kusto.Language.
.DESCRIPTION
  Loads version-pinned Kusto.Language from a hash-checked NuGet archive into
  a temporary cache (never into the repository). Supplies minimal column
  subsets manually confirmed against official vendor schema documentation.
  This is NOT a tenant-side compilation, connector coverage test, or query run.
  It never reads credentials or contacts Azure/Defender/Sentinel endpoints.
#>
[CmdletBinding()]
param(
    [string]$PackageArchivePath = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$directory = Join-Path $root 'queries/schema-reviewed'
$manifestPath = Join-Path $directory 'manifest.json'
$manifest = Get-Content -Raw -Encoding UTF8 $manifestPath | ConvertFrom-Json -AsHashtable
$package = $manifest.kusto_language_package
if ($package.id -ne 'Microsoft.Azure.Kusto.Language' -or
    $package.version -ne '12.4.1' -or
    $package.archive_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Unapproved parser dependency or checksum'
}

$cache = Join-Path ([System.IO.Path]::GetTempPath()) ('threat-hunt-kql-' + $package.version)
[System.IO.Directory]::CreateDirectory($cache) | Out-Null
$archive = if ($PackageArchivePath) {
    (Resolve-Path $PackageArchivePath).Path
} else {
    Join-Path $cache ('microsoft.azure.kusto.language.' + $package.version + '.nupkg')
}
if (-not (Test-Path $archive)) {
    $url = 'https://api.nuget.org/v3-flatcontainer/microsoft.azure.kusto.language/' +
           $package.version + '/microsoft.azure.kusto.language.' +
           $package.version + '.nupkg'
    Write-Output ('Fetching pinned Microsoft Kusto.Language package ' + $package.version)
    Invoke-WebRequest -Uri $url -OutFile $archive -TimeoutSec 40
}
$hash = (Get-FileHash -Algorithm SHA256 -Path $archive).Hash.ToLowerInvariant()
if ($hash -ne $package.archive_sha256) {
    throw ('Kusto.Language NuGet archive checksum mismatch: ' + $hash)
}

$extract = Join-Path $cache 'extracted'
$dll = Join-Path $extract 'lib/net6.0/Kusto.Language.dll'
# Re-extract from the verified archive on each run; do not trust a
# potentially stale or modified DLL in a shared temporary cache.
[System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $extract, $true)
if (-not (Test-Path $dll)) {
    throw ('Kusto.Language .NET 6 assembly unavailable in ' + $extract)
}
Add-Type -Path $dll

$symbols = [System.Collections.Generic.List[Kusto.Language.Symbols.Symbol]]::new()
foreach ($tableName in @($manifest.tables.Keys | Sort-Object)) {
    $table = $manifest.tables[$tableName]
    if (-not $table.reference.StartsWith('https://learn.microsoft.com/')) {
        throw ('Schema URL must point to Microsoft Learn: ' + $tableName)
    }
    $symbols.Add([Kusto.Language.Symbols.TableSymbol]::new(
        $tableName, $table.schema, 'Curated vendor schema subset, not tenant metadata'
    ))
}
$db = [Kusto.Language.Symbols.DatabaseSymbol]::new('CuratedSchemaReview', $symbols.ToArray())
$globals = [Kusto.Language.GlobalState]::Default.WithDatabase($db)
# Fail closed if the semantic analyzer ever treats an unknown native field
# as valid; otherwise a zero-diagnostic result would be meaningless.
$negative = [Kusto.Language.KustoCode]::ParseAndAnalyze(
    'SigninLogs | project ThisFieldMustNotExistInCuratedSchema', $globals
)
$negativeErrors = @($negative.GetDiagnostics() | Where-Object {
    $_.Severity.ToString() -eq 'Error'
})
if ($negativeErrors.Count -eq 0) {
    throw 'Kusto static semantic analyzer failed its missing-column negative control'
}
$errors = 0
$files = @(Get-ChildItem -LiteralPath $directory -Filter '*.kql' -File | Sort-Object Name)
$allowed = @($manifest.queries | ForEach-Object { $_.file } | Sort-Object)
$actual = @($files | ForEach-Object { $_.Name } | Sort-Object)
if (($allowed -join '|') -ne ($actual -join '|')) {
    throw 'Query inventory does not match manifest'
}
foreach ($entry in $manifest.queries) {
    if (-not $manifest.tables.Contains($entry.table)) {
        throw ('Unknown native source table: ' + $entry.table)
    }
    if ($entry.file -notmatch '^[a-z0-9-]+\.kql$') {
        throw ('Unsafe query filename: ' + $entry.file)
    }
    $file = Join-Path $directory $entry.file
    $query = Get-Content -Raw -Encoding UTF8 $file
    foreach ($required in $entry.required_fragments) {
        if (-not $query.Contains($required)) {
            throw ($entry.file + ': missing contract fragment: ' + $required)
        }
    }
    # Static vendor-symbol binding catches unknown table/field names and many
    # type mismatches. No runtime data or real workspace is used.
    $analyzed = [Kusto.Language.KustoCode]::ParseAndAnalyze($query, $globals)
    $diagnostics = @($analyzed.GetDiagnostics())
    $fatal = @($diagnostics | Where-Object {
        $_.Severity.ToString() -eq 'Error'
    })
    Write-Output ('[KQL STATIC] ' + $entry.file + ': ' +
                  $diagnostics.Count + ' diagnostics, ' + $fatal.Count +
                  ' errors (' + $entry.table + ')')
    foreach ($problem in $diagnostics) {
        Write-Output ('  ' + $problem.Severity + ': ' + $problem.Message)
    }
    if ($fatal.Count -gt 0) {
        $errors += $fatal.Count
    }
}
if ($errors -gt 0) {
    Write-Output ('[FAIL] Source-schema KQL check: ' + $errors + ' errors')
    exit 1
}
Write-Output ('[OK] Microsoft Kusto.Language ' + $package.version +
              ': ' + $files.Count +
              ' queries passed syntax AND curated-schema semantic analysis')
Write-Output '[SCOPE] No tenant query execution; no KQL/Python parity or production detection efficacy proven.'
