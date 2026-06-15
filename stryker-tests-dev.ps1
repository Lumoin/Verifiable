#!/usr/bin/env pwsh
#Requires -Version 7

<#
.SYNOPSIS
    Runs Stryker.NET mutation testing across all relevant Verifiable library projects.

.DESCRIPTION
    Stryker mutates one project per run, so this loops over every shippable library
    project (the same set as LIBRARY_PROJECTS in .github/workflows/main.yml) and runs
    the Verifiable.Tests suite against that project's mutants. Stryker auto-detects
    Verifiable.slnx in the repo root; --project selects which source project to mutate.
    Per-project HTML reports are written under StrykerOutput/<project> at the repo root.

    KNOWN BLOCKER — Stryker cannot run this suite yet:
    Verifiable.Tests uses Microsoft.Testing.Platform (the MSTest.Sdk default runner),
    which Stryker.NET 4.14.x does not support. Stryker discovers tests via VsTest, finds
    0 tests, and each project run fails with "No test result reported". Track upstream:
      https://github.com/stryker-mutator/stryker-net/issues/3094
    Until that is resolved upstream (or the test project additionally exposes a
    VsTest-compatible adapter), this script reports failures for every project. The
    project enumeration and invocation below are correct and ready for that day.
#>

$ErrorActionPreference = 'Stop'

#Shippable library projects to mutate — mirrors LIBRARY_PROJECTS in
#.github/workflows/main.yml. The CLI (Verifiable) is packaged and tested
#separately (native AOT), so it is intentionally not in this set.
$projects = @(
    'Verifiable.BouncyCastle',
    'Verifiable.Cbor',
    'Verifiable.Core',
    'Verifiable.Cryptography',
    'Verifiable.DecentralizedWebNode',
    'Verifiable.Foundation',
    'Verifiable.JCose',
    'Verifiable.Json',
    'Verifiable.JsonPointer',
    'Verifiable.Microsoft',
    'Verifiable.NSec',
    'Verifiable.OAuth',
    'Verifiable.Server',
    'Verifiable.Sidetree',
    'Verifiable.Tpm',
    'Verifiable.Vcalm'
)

$failed = @()
foreach($project in $projects)
{
    Write-Host "=== Stryker: mutating $project ===" -ForegroundColor Cyan
    dotnet stryker `
        --config-file stryker-config.json `
        --reporter progress `
        --reporter html `
        --project "$project.csproj" `
        --output "StrykerOutput/$project"

    if($LASTEXITCODE -ne 0)
    {
        Write-Warning "Stryker exited with code $LASTEXITCODE for $project. Continuing with remaining projects."
        $failed += $project
    }
}

if($failed.Count -gt 0)
{
    Write-Host "Stryker failed for: $($failed -join ', ')." -ForegroundColor Yellow
    exit 1
}
