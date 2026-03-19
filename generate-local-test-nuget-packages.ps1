$projects = @(
    'Verifiable.BouncyCastle',
    'Verifiable.Cbor',
    'Verifiable.Core',
    'Verifiable.Cryptography',
    'Verifiable.DecentralizedWebNode',
    'Verifiable.JCose',
    'Verifiable.Json',
	'Verifiable.JsonPointer',
    'Verifiable.Microsoft',
    'Verifiable.NSec',
    'Verifiable.OAuth',
    'Verifiable.Sidetree',
    'Verifiable.Tpm'
)

$outputDir = './generated-nugets'
$baseVersion = '0.0.1'
$sha = git rev-parse --short HEAD 2>$null
$buildMetadata = ($sha) ? $sha : (Get-Date -Format 'yyyyMMddHHmmss')
$packageVersion = "$baseVersion-local"
$informationalVersion = "$baseVersion-local+$buildMetadata"

#Remove all existing packages before generating new ones so stale or malformed
#packages from previous runs do not accumulate in the output directory.
if(Test-Path $outputDir)
{
    Get-ChildItem -Path $outputDir -Filter '*.nupkg' | Remove-Item -Force
    Get-ChildItem -Path $outputDir -Filter '*.snupkg' | Remove-Item -Force
}
else
{
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

foreach($project in $projects)
{
    dotnet pack --verbosity normal `
        --configuration Release `
        --output $outputDir `
        --include-symbols `
        --include-source `
        --property:PackageVersion=$packageVersion `
        --property:InformationalVersion=$informationalVersion `
        "./src/$project/$project.csproj"

    if($LASTEXITCODE -ne 0)
    {
        Write-Error "Pack failed for $project."
        exit $LASTEXITCODE
    }
}

Write-Host "Generated packages in $outputDir with version $packageVersion."
