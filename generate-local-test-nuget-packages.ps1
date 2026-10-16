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
#
#The sha must name exactly what was packed, so the packing never reads the working tree. The
#commit HEAD names is fetched into a fresh repository in a new directory of its own, checked out
#there and restored and packed there: every source, build file and file a project brings into a
#package is the commit's, and every intermediate the build reads - the obj directories' restore
#outputs, which MSBuild imports while it evaluates a project, among them - is written by this run
#alone. Outside that directory the build reads only what the commit itself pins: the SDK its
#global.json names, the packages its lock files name by content hash, restored in locked mode
#through its own NuGet.config alone; a directory above the new one holding a file MSBuild or NuGet
#would read from an ancestor refuses the packing. The working tree is still held to the commit, so
#this script is the commit's own: any git command that fails, git naming no commit, a tracked file
#that differs from the commit, a file git does not track, and a file git has been told to stop
#comparing (assume-unchanged or skip-worktree, which status reads as unchanged whatever the file
#holds) each refuse the packing. Every package must name the commit as its repository commit.
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

#Runs one git command against a repository and answers the lines it wrote to its output. A command
#that fails answers nothing a verdict may rest on, so its exit code is read before its output and a
#failure refuses the packing: an empty answer from a git that could not read the tree is never taken
#for a clean one.
function Invoke-RepositoryGit
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Purpose
    )

    $written = & git -C $Repository @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $errors = @($written | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })

    if($exitCode -ne 0)
    {
        Write-Error "Packing is refused: git could not $Purpose in $Repository (git $($Arguments -join ' ') exited with $exitCode). $($errors -join ' ')"
        exit 1
    }

    return @($written | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
}

$sha = (Invoke-RepositoryGit -Repository $repositoryRoot -Arguments @('rev-parse', '--short', 'HEAD') -Purpose 'name the commit HEAD points at') -join ''
$commitId = (Invoke-RepositoryGit -Repository $repositoryRoot -Arguments @('rev-parse', 'HEAD') -Purpose 'name the commit HEAD points at') -join ''
if([string]::IsNullOrWhiteSpace($sha) -or [string]::IsNullOrWhiteSpace($commitId))
{
    Write-Error "Packing is refused: git names no commit for $repositoryRoot, and the package version must carry the commit the packages are built from."
    exit 1
}

#A file marked assume-unchanged or skip-worktree is one git status no longer compares with the
#commit, so status reads it as unchanged whatever it holds. git ls-files -v tags such a file with a
#lower-case letter (assume-unchanged) or with S (skip-worktree, lower-case s for both); any such
#file refuses the packing before status is asked.
$indexEntries = (Invoke-RepositoryGit -Repository $repositoryRoot -Arguments @('ls-files', '-v', '-z') -Purpose 'list the index entries and their tags') -join ''
$uncomparedFiles = @($indexEntries.Split([char]0, [System.StringSplitOptions]::RemoveEmptyEntries) | Where-Object {
    $tag = $_[0]
    [char]::IsLower($tag) -or $tag -ceq 'S'
})
if($uncomparedFiles.Count -gt 0)
{
    Write-Error "Packing is refused: git is told to stop comparing these files with commit $sha (assume-unchanged or skip-worktree), so the working tree cannot be shown to be that commit. Marked:`n$($uncomparedFiles -join "`n")"
    exit 1
}

#Every file git tracks, wherever it lies, is compared with the commit, and every file it does not
#track is listed one by one.
$changedFiles = Invoke-RepositoryGit -Repository $repositoryRoot -Arguments @('status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none') -Purpose 'read the state of the working tree'
if($changedFiles.Count -gt 0)
{
    Write-Error "Packing is refused: the working tree differs from commit $sha, so the version would name a commit that did not build these packages. Changed:`n$($changedFiles -join "`n")"
    exit 1
}

#The commit is packed in a directory created for this run alone. MSBuild reads a Directory.Build.rsp
#from every directory above a project until one holds it, and NuGet reads a NuGet.Config from every
#directory above it, so a directory above the new one holding a file either reads from an ancestor
#is an input the commit does not hold, and refuses the packing.
$exportRoot = Join-Path ([System.IO.Path]::GetTempPath()) "verifiable-pack-g$sha-$([Guid]::NewGuid().ToString('N'))"
$ancestorInputs = @('Directory.Build.props', 'Directory.Build.targets', 'Directory.Build.rsp', 'Directory.Packages.props', 'global.json', 'NuGet.Config')
$ancestorFound = @()
$ancestor = [System.IO.Directory]::GetParent($exportRoot)
while($null -ne $ancestor)
{
    foreach($name in $ancestorInputs)
    {
        $candidate = Join-Path $ancestor.FullName $name
        if(Test-Path -LiteralPath $candidate -PathType Leaf)
        {
            $ancestorFound += $candidate
        }
    }

    $ancestor = $ancestor.Parent
}

if($ancestorFound.Count -gt 0)
{
    Write-Error "Packing is refused: a directory above $exportRoot holds a file MSBuild or NuGet would read into the build, which commit $sha does not hold. Found:`n$($ancestorFound -join "`n")"
    exit 1
}

if(Test-Path -LiteralPath $exportRoot)
{
    Write-Error "Packing is refused: the directory $exportRoot already exists, and the packing reads only a directory this run creates."
    exit 1
}

New-Item -ItemType Directory -Path $exportRoot | Out-Null

#The commit alone is fetched into a fresh repository and checked out: no index, no configuration
#and no file of the working tree comes with it. The fresh repository names the working repository's
#origin as its own, so the source link the build writes into each package names the published
#repository, as a build of the working tree did.
$sourceUrl = ([Uri]$repositoryRoot).AbsoluteUri
$originUrl = (Invoke-RepositoryGit -Repository $repositoryRoot -Arguments @('remote', 'get-url', 'origin') -Purpose 'name the origin repository') -join ''
Invoke-RepositoryGit -Repository $exportRoot -Arguments @('init', '--quiet') -Purpose 'create the fresh repository' | Out-Null
Invoke-RepositoryGit -Repository $exportRoot -Arguments @('fetch', '--quiet', '--depth', '1', '--no-tags', $sourceUrl, $commitId) -Purpose "fetch commit $commitId" | Out-Null
Invoke-RepositoryGit -Repository $exportRoot -Arguments @('checkout', '--quiet', '--detach', $commitId) -Purpose "check out commit $commitId" | Out-Null
Invoke-RepositoryGit -Repository $exportRoot -Arguments @('remote', 'add', 'origin', $originUrl) -Purpose 'name the origin repository' | Out-Null

$exportedCommit = (Invoke-RepositoryGit -Repository $exportRoot -Arguments @('rev-parse', 'HEAD') -Purpose 'name the commit checked out') -join ''
$exportedState = Invoke-RepositoryGit -Repository $exportRoot -Arguments @('status', '--porcelain=v1', '--untracked-files=all', '--ignored') -Purpose 'read the state of the fresh tree'
if($exportedCommit -ne $commitId -or $exportedState.Count -gt 0)
{
    Write-Error "Packing is refused: the fresh tree in $exportRoot is not exactly commit $commitId (checked out $exportedCommit). State:`n$($exportedState -join "`n")"
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
$nugetConfig = Join-Path $exportRoot 'NuGet.config'

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
    $projectFile = Join-Path $exportRoot "src/$project/$project.csproj"

    #Restored in locked mode through the commit's NuGet.config alone: every package is the one the
    #commit's lock file names by its content hash, and no user or machine NuGet configuration is read.
    dotnet restore $projectFile `
        --configfile $nugetConfig `
        --locked-mode `
        --disable-build-servers `
        -nodeReuse:false

    if($LASTEXITCODE -ne 0)
    {
        Write-Error "Restore failed for $project in $exportRoot."
        exit $LASTEXITCODE
    }

    dotnet pack $projectFile --verbosity normal `
        --no-restore `
        --disable-build-servers `
        -nodeReuse:false `
        --configuration Release `
        --output $outputDir `
        --include-symbols `
        --include-source `
        --property:PackageVersion=$packageVersion `
        --property:InformationalVersion=$informationalVersion

    if($LASTEXITCODE -ne 0)
    {
        Write-Error "Pack failed for $project in $exportRoot."
        exit $LASTEXITCODE
    }
}

#Every package names the commit it was built from as its repository commit, which the build reads
#from the fresh repository's HEAD: a package naming any other was not built from this commit.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$misnamed = @()
foreach($project in $projects)
{
    $package = Join-Path $outputDir "$project.$packageVersion.nupkg"
    if(-not (Test-Path -LiteralPath $package))
    {
        $misnamed += "$project (no package $package)"
        continue
    }

    $archive = [System.IO.Compression.ZipFile]::OpenRead($package)
    try
    {
        $entry = $archive.Entries | Where-Object { $_.FullName -eq "$project.nuspec" } | Select-Object -First 1
        $reader = [System.IO.StreamReader]::new($entry.Open())
        try
        {
            [xml]$nuspec = $reader.ReadToEnd()
        }
        finally
        {
            $reader.Dispose()
        }
    }
    finally
    {
        $archive.Dispose()
    }

    $repositoryCommit = $nuspec.package.metadata.repository.commit
    if($repositoryCommit -ne $commitId)
    {
        $misnamed += "$project (repository commit '$repositoryCommit')"
    }
}

if($misnamed.Count -gt 0)
{
    Write-Error "Packing is refused: these packages do not name commit $commitId as their repository commit:`n$($misnamed -join "`n")"
    exit 1
}

Remove-Item -LiteralPath $exportRoot -Recurse -Force

Write-Host "Generated $($projects.Count) packages in $outputDir with version $packageVersion from commit $commitId, packed in a fresh checkout of that commit."
