#Packs every Verifiable.* package a consumer pins from a local feed, at one version for the whole
#family, so a consumer never mixes assemblies of two builds.
#
#The version is 0.0.2-local.<publication>.<sha>.
#
#  0.0.2         The library's next release. A prerelease of it sorts below the release itself, so
#                the published 0.0.2 replaces every local build without a pin having to move down.
#  <publication> A four-digit integer, 1001 for the first local publication and the number a
#                consumer pins plus one for every later one. NuGet compares a purely numeric
#                prerelease label as a number and any other label as text, so this number alone
#                decides which build is newer: 1002 follows 1001, and with no leading zero allowed
#                the four digits keep that order up to 9999.
#  <sha>         The commit the packages were built from. It identifies the build and never orders
#                it: a hexadecimal commit id compares as text, so a later commit can sort below an
#                earlier one, which is why it stands after the publication number and never alone.
#
#The informational version carries the same version and the full commit id as build metadata.
#The sha must name exactly what was packed, so the packing is refused when git names no commit or
#when the sources or the build files differ from that commit.
param(
    [Parameter(Mandatory = $true)]
    [int]$Publication
)

$minimumPublication = 1001
$maximumPublication = 9999
if($Publication -lt $minimumPublication -or $Publication -gt $maximumPublication)
{
    Write-Error "The publication number $Publication is refused: it is a four-digit integer from $minimumPublication to $maximumPublication without a leading zero, $minimumPublication for the first publication and the pinned number plus one for every later one."
    exit 1
}

$repositoryRoot = $PSScriptRoot
$sha = git -C $repositoryRoot rev-parse --short HEAD 2>$null
$commitId = git -C $repositoryRoot rev-parse HEAD 2>$null
if([string]::IsNullOrWhiteSpace($sha) -or [string]::IsNullOrWhiteSpace($commitId))
{
    Write-Error "Packing is refused: git names no commit for $repositoryRoot, and the package version must carry the commit the packages are built from."
    exit 1
}

$changedBuildInputs = git -C $repositoryRoot status --porcelain -- src Directory.Build.props Directory.Build.targets Directory.Packages.props global.json NuGet.config
if(-not [string]::IsNullOrWhiteSpace(($changedBuildInputs -join '')))
{
    Write-Error "Packing is refused: the sources or the build files differ from commit $sha, so the version would name a commit that did not build these packages. Changed:`n$($changedBuildInputs -join "`n")"
    exit 1
}

$projects = @(
    'Verifiable.Acdc',
    'Verifiable.Apdu',
    'Verifiable.BouncyCastle',
    'Verifiable.Cbor',
    'Verifiable.Cesr',
    'Verifiable.Core',
    'Verifiable.Cryptography',
    'Verifiable.DidComm',
    'Verifiable.DidWebs',
    'Verifiable.Fido2',
    'Verifiable.Foundation',
    'Verifiable.JCose',
    'Verifiable.Json',
    'Verifiable.Keri',
    'Verifiable.Libsodium',
    'Verifiable.Microsoft',
    'Verifiable.OAuth',
    'Verifiable.Server',
    'Verifiable.Tpm',
    'Verifiable.Tpm.Spec',
    'Verifiable.Vcalm',
    'Verifiable.WebFinger'
)

$outputDir = Join-Path $repositoryRoot 'generated-nugets'
$baseVersion = '0.0.2'
$packageVersion = "$baseVersion-local.$Publication.$sha"
$informationalVersion = "$packageVersion+$commitId"

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
        (Join-Path $repositoryRoot "src/$project/$project.csproj")

    if($LASTEXITCODE -ne 0)
    {
        Write-Error "Pack failed for $project."
        exit $LASTEXITCODE
    }
}

Write-Host "Generated $($projects.Count) packages in $outputDir with version $packageVersion."
