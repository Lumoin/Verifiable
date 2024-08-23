param (
    [Parameter(Mandatory = $true)]
    [string]$libFuzzer,
    [Parameter(Mandatory = $true)]
    [string]$project,
    [Parameter(Mandatory = $true)]
    [string]$corpus,
    [string]$dict = $null,
    [int]$timeout = 10,
    [int]$fork = 0,
    [int]$ignore_crashes = 0,
    [string]$command = "sharpfuzz"
)

Set-StrictMode -Version Latest

$outputDir = "bin"

if (Test-Path $outputDir) {
    Remove-Item -Recurse -Force $outputDir
}

dotnet publish $project -c release -o $outputDir

$projectName = (Get-Item $project).BaseName
$projectDll = "$projectName.dll"
$project = Join-Path $outputDir $projectDll

$exclusions = @(
    "dnlib.dll",
    "SharpFuzz.dll",
    "SharpFuzz.Common.dll"
)

Write-Output "Exclusions: $($exclusions -join ', ')"

$allDlls = Get-ChildItem $outputDir -Filter *.dll
Write-Output "All DLLs: $($allDlls.Name -join ', ')"

$fuzzingTargets = $allDlls `
| Where-Object { $_.Name -notin $exclusions } `
| Where-Object { $_.Name -notlike "System.*.dll" }

Write-Output "Fuzzing Targets: $($fuzzingTargets.Name -join ', ')"

if (($fuzzingTargets | Measure-Object).Count -eq 0) {
    Write-Error "No fuzzing targets found"
    exit 1
}

foreach ($fuzzingTarget in $fuzzingTargets) {
    Write-Output "Instrumenting $fuzzingTarget"
    & $command $fuzzingTarget.FullName
    
    if ($LastExitCode -ne 0) {
        Write-Error "An error occurred while instrumenting $fuzzingTarget"
        exit 1
    }
}

# Construct the final command string
$finalCommand = "$libFuzzer --target_path=dotnet --target_arg=$project"

if ($dict) {
    $finalCommand += " -dict=$dict"
}

# Print the final command
Write-Output "Final Command: $finalCommand"

# Execute the final command
Invoke-Expression $finalCommand
