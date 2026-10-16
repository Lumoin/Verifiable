#Packs every Verifiable.* package a consumer pins from a local feed, at one version for the whole
#family, so a consumer never mixes assemblies of two builds.
#
#The version is 0.0.2-local.<publication>.g<sha>.
#
#  0.0.2         The library's next release. A prerelease of it sorts below the release itself, so
#                the published 0.0.2 replaces every local build without a pin having to move down.
#  <publication> A four-digit integer, 1001 for the first local publication and the number a
#                consumer pins plus one for every later one. NuGet compares a purely numeric
#                prerelease label as a number and any other label as text, so this number alone
#                decides which build is newer: 1002 follows 1001, and with no leading zero allowed
#                the four digits keep that order up to 9999.
#  g<sha>        The commit the packages were built from, written as git describe writes it: the
#                letter g before the short commit id. The letter makes the label an alphanumeric
#                identifier for every commit, so a short id of digits alone with a leading zero,
#                which SemVer 2.0.0 section 9 forbids in a numeric identifier, is still a valid
#                version. It identifies the build and never orders it: an alphanumeric label
#                compares as text, so a later commit can sort below an earlier one, which is why it
#                stands after the publication number and never alone.
#
#The informational version carries the same version and the full commit id as build metadata.
#The sha must name exactly what was packed, so the packing is refused when any git command it asks
#fails, when git names no commit, when any file git tracks differs from that commit - this script,
#the sources, the build files and every file they bring into a package, such as the banned-symbol
#lists, the package logo and the README, among them - when any file git does not track stands in
#the tree, and when a file the ignore rules hide lies where the packing reads: the repository's root
#and the src and resources directories, outside the bin and obj directories the build writes.
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

#Runs one git command against the repository and answers the lines it wrote to its output. A command
#that fails answers nothing a verdict may rest on, so its exit code is read before its output and a
#failure refuses the packing: an empty answer from a git that could not read the tree is never taken
#for a clean one.
function Invoke-RepositoryGit
{
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Purpose
    )

    $written = & git -C $repositoryRoot @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $errors = @($written | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })

    if($exitCode -ne 0)
    {
        Write-Error "Packing is refused: git could not $Purpose in $repositoryRoot (git $($Arguments -join ' ') exited with $exitCode). $($errors -join ' ')"
        exit 1
    }

    return @($written | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
}

$sha = (Invoke-RepositoryGit -Arguments @('rev-parse', '--short', 'HEAD') -Purpose 'name the commit HEAD points at') -join ''
$commitId = (Invoke-RepositoryGit -Arguments @('rev-parse', 'HEAD') -Purpose 'name the commit HEAD points at') -join ''
if([string]::IsNullOrWhiteSpace($sha) -or [string]::IsNullOrWhiteSpace($commitId))
{
    Write-Error "Packing is refused: git names no commit for $repositoryRoot, and the package version must carry the commit the packages are built from."
    exit 1
}

#Every file git tracks, wherever it lies, is compared with the commit, and every file it does not
#track is listed one by one: the build reads files no list kept here could name ahead of time, from
#this script and the build files to whatever a project file brings into a package.
$changedFiles = Invoke-RepositoryGit -Arguments @('status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none') -Purpose 'read the state of the working tree'
if($changedFiles.Count -gt 0)
{
    Write-Error "Packing is refused: the working tree differs from commit $sha, so the version would name a commit that did not build these packages. Changed:`n$($changedFiles -join "`n")"
    exit 1
}

#The ignore rules hide what the build writes, and also files the build reads: MSBuild reads a
#Directory.Build.rsp and a project's .user file, which the rules hide as *.rsp and *.user. A hidden
#file is admitted only outside the places the packing reads - the repository's root, src and
#resources - or inside a bin or obj directory, which the build writes.
$packingReads = @('src', 'resources')
$buildWrites = @('bin', 'obj')
$hiddenEntries = (Invoke-RepositoryGit -Arguments @('ls-files', '-z', '--others', '--ignored', '--exclude-standard', '--directory') -Purpose 'list the files the ignore rules hide') -join ''
$hiddenInputs = @($hiddenEntries.Split([char]0, [System.StringSplitOptions]::RemoveEmptyEntries) | Where-Object {
    $segments = $_.TrimEnd('/').Split('/')
    $atRoot = $segments.Count -eq 1 -and -not $_.EndsWith('/')
    $whereRead = $packingReads -contains $segments[0]
    $whereWritten = @($segments | Where-Object { $buildWrites -contains $_ }).Count -gt 0
    $atRoot -or ($whereRead -and -not $whereWritten)
})
if($hiddenInputs.Count -gt 0)
{
    Write-Error "Packing is refused: files the ignore rules hide lie where the packing reads, so the packages could hold what commit $sha does not. Hidden:`n$($hiddenInputs -join "`n")"
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
$packageVersion = "$baseVersion-local.$Publication.g$sha"
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
