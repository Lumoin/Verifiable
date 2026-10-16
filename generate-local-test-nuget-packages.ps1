#Packs every Verifiable.* package a consumer pins from a local feed, at one version for the whole
#family, so a consumer never mixes assemblies of two builds.
#
#The version is 0.0.2-local.<publication>.g<sha>.
#
#  0.0.2         The library's next release. A prerelease of it sorts below the release itself, so
#                the published 0.0.2 replaces every local build without a pin having to move down.
#  <publication> A four-digit integer without a leading zero, from 1001 to 9999. NuGet compares a
#                purely numeric prerelease label as a number and any other label as text, so this
#                number alone decides which build is newer, and a number is never cut twice: two
#                builds under one version would collide in every consumer's packages folder. The
#                record of the numbers used is the repository's local-publication/<number> tags,
#                each naming the commit that publication packed, together with the numbers the
#                consumer's pins carry in the package version file -ConsumerPins names. A number that
#                record names, or one not above every number it names, refuses the packing before
#                anything is packed, and the number is reserved by creating its tag, which git
#                refuses if the tag exists, only once the whole family is packed and checked.
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
#What the packing establishes itself, and what it trusts without establishing, are stated apart.
#
#Established by the packing:
#
#  The sources.  The commit HEAD names is fetched into a fresh repository in a directory created for
#                this run and checked out there by a git that reads no system, global or environment
#                configuration, no template and no hook, and that applies no attribute, filter or line
#                ending conversion. Every file of the checkout is then hashed as a git blob and held to
#                the commit's tree entry for its path: a file the tree does not hold, a tree entry with
#                no file and a file whose blob differs each refuse the packing.
#  The packages. Every package the lock files of the packed projects name is fetched as an archive
#                from the source the commit's NuGet.config maps it to - nuget.org for the most, and for
#                the local feed the commit's NuGet.config names in a directory the commit does not hold,
#                the directory -LocalFeedDirectory names - and its content hash is held to the hash the
#                lock files name before it is written to a private feed of verified archives. The
#                restore reads that feed alone, extracts into a packages directory created for this run
#                and never the shared global packages folder, and every restore output is held to
#                having read that configuration, that feed and that packages directory alone.
#  The build's   The SDK the CLI selects is the version the commit's global.json names, listed in the
#  selection.    installation the CLI runs from: the CLI is run from the checkout's root and its answer
#                checked there. Restore and pack run in an environment this script states in full:
#                nothing of the caller's environment is inherited, so no variable MSBuild or NuGet
#                would read as a property or a configuration reaches them, and the profile,
#                application data and temporary directories are the run's own. The SDK's imports of
#                user extension directories, and the fallback folder and library packs of its
#                installation it would add to the restore, are switched off by explicit properties. A
#                directory above the checkout holding a file MSBuild or NuGet reads from an ancestor
#                refuses the packing.
#  The family.   Every project is packed into a directory of the run's own, and the whole family is
#                checked there - every package and symbol package present under its name and nothing
#                else, each naming its project and this version, each package naming the commit as its
#                repository commit - before any of it reaches the output directory. The previous
#                family in the output directory is removed only once the new family stands there
#                complete, each archive held to the bytes that were checked.
#
#Trusted, not established, by the packing:
#
#  The tools.    git and dotnet are the first executables of those names the PATH of the publishing
#                process finds. The packing checks the SDK by the version the CLI answers and the
#                location it lists, nothing more: the bytes of git, of the dotnet host, of the SDK with
#                its compilers, MSBuild and NuGet, of the runtime and of the reference packs are not
#                authenticated, and NuGet's assemblies loaded from that SDK compute the content hashes
#                the archives are held to. PowerShell running this script is trusted alike.
#  The network.  Archives of a web source are fetched by the publishing PowerShell process through its
#                own networking configuration - its proxy, its name resolution and the operating
#                system's certificate store. Every location read, the service index, the package base
#                address it advertises and every redirect, must be https, and a location that is not
#                refuses the packing; what an archive holds is established by its content hash, not by
#                its transport.
#  The record.   The tags are this clone's: a tag another clone created and did not push is not seen.
#
#The working tree is still held to the commit, so this script is the commit's own: any git command
#that fails, git naming no commit, a tracked file that differs from the commit, a file git does not
#track, and a file git has been told to stop comparing (assume-unchanged or skip-worktree, which
#status reads as unchanged whatever the file holds) each refuse the packing.
#
#Every directory the run writes lies under one directory created for the run, which is removed when the
#run ends, whether it publishes or is refused, and whatever refused it: a check, a failed command, a
#process that could not start, an archive that could not be read or a network failure.
param(
    [Parameter(Mandatory = $true)]
    [int]$Publication,

    [Parameter(Mandatory = $true)]
    [string]$LocalFeedDirectory,

    [Parameter(Mandatory = $true)]
    [string]$ConsumerPins
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

#A refusal of the packing, carrying the reason it states.
class PackingRefusal : System.Exception
{
    PackingRefusal([string]$reason) : base("Packing is refused: $reason")
    {
    }
}

#Refuses the packing with the reason given; nothing after it runs but the run's own cleanup.
function Stop-Packing
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$Reason
    )

    throw [PackingRefusal]::new($Reason)
}

#The directory this run created for everything it writes, once it has created it; it is removed when the
#run ends, and never a directory the run did not create.
$createdRunRoot = $null

#The cancellation the run's own reads observe; it is cancelled by nothing but the end of the run.
$runCancellation = [System.Threading.CancellationTokenSource]::new()

#The client every web read of the run goes through. It follows no redirect itself, so every location a
#redirect names is held to https before it is read.
$httpHandler = [System.Net.Http.SocketsHttpHandler]::new()
$httpHandler.AllowAutoRedirect = $false
$httpClient = [System.Net.Http.HttpClient]::new($httpHandler, $true)

$exitCode = 1
try
{
    $minimumPublication = 1001
    $maximumPublication = 9999
    if($Publication -lt $minimumPublication -or $Publication -gt $maximumPublication)
    {
        Stop-Packing "the publication number $Publication is a four-digit integer from $minimumPublication to $maximumPublication without a leading zero."
    }

    $repositoryRoot = $PSScriptRoot

    $gitCommand = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $dotnetCommand = Get-Command dotnet -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if($null -eq $gitCommand -or $null -eq $dotnetCommand)
    {
        Stop-Packing 'git and dotnet must both be installed and found on the path.'
    }

    $gitExecutable = $gitCommand.Source
    $dotnetExecutable = $dotnetCommand.Source
    $dotnetRoot = Split-Path -Parent $dotnetExecutable

    if(-not (Test-Path -LiteralPath $LocalFeedDirectory -PathType Container))
    {
        Stop-Packing "the local feed directory $LocalFeedDirectory does not exist."
    }

    $localFeedRoot = (Resolve-Path -LiteralPath $LocalFeedDirectory).ProviderPath

    if(-not (Test-Path -LiteralPath $ConsumerPins -PathType Leaf))
    {
        Stop-Packing "the consumer's package version file $ConsumerPins does not exist, and the numbers its pins carry are part of the record of publications used."
    }

    $consumerPinsPath = (Resolve-Path -LiteralPath $ConsumerPins).ProviderPath

    #Every directory and file this run writes lies under one directory created for it alone: the checkout,
    #the verified archives, the packages extracted from them, the packed family, the profile and temporary
    #directories the build runs with, and the empty template, hook and configuration locations git is
    #pointed at.
    $runRoot = Join-Path ([System.IO.Path]::GetTempPath()) "vpack-$([Guid]::NewGuid().ToString('N'))"
    if(Test-Path -LiteralPath $runRoot)
    {
        Stop-Packing "the directory $runRoot already exists, and the packing reads only a directory this run creates."
    }

    New-Item -ItemType Directory -Path $runRoot | Out-Null
    $createdRunRoot = $runRoot
    Write-Host "Run directory: $runRoot"

    $exportRoot = Join-Path $runRoot 'checkout'
    $packagesRoot = Join-Path $runRoot 'packages'
    $archivesRoot = Join-Path $runRoot 'archives'
    $stagingRoot = Join-Path $runRoot 'family'
    $profileRoot = Join-Path $runRoot 'profile'
    $temporaryRoot = Join-Path $runRoot 'temp'
    $gitControlRoot = Join-Path $runRoot 'git'
    $emptyDirectory = Join-Path $gitControlRoot 'empty'
    $nugetControlRoot = Join-Path $runRoot 'nuget'
    foreach($directory in @($exportRoot, $packagesRoot, $archivesRoot, $stagingRoot, $profileRoot, $temporaryRoot, $gitControlRoot, $emptyDirectory, $nugetControlRoot,
        (Join-Path $profileRoot 'Roaming'), (Join-Path $profileRoot 'Local'), (Join-Path $profileRoot '.config')))
    {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }

    $emptyGitConfiguration = Join-Path $gitControlRoot 'empty-config'
    $emptyGitAttributes = Join-Path $gitControlRoot 'empty-attributes'
    [System.IO.File]::WriteAllBytes($emptyGitConfiguration, [byte[]]@())
    [System.IO.File]::WriteAllBytes($emptyGitAttributes, [byte[]]@())

    #MSBuild reads a Directory.Build.rsp from every directory above a project until one holds it, and
    #NuGet reads a NuGet.Config from every directory above it, so a directory above the checkout holding a
    #file either reads from an ancestor is an input the commit does not hold, and refuses the packing.
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
        Stop-Packing "a directory above $exportRoot holds a file MSBuild or NuGet would read into the build, which the commit does not hold. Found:`n$($ancestorFound -join "`n")"
    }

    $windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $systemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    $processorArchitecture = switch([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString())
    {
        'X64' { 'AMD64' }
        'Arm64' { 'ARM64' }
        'X86' { 'x86' }
        default { Stop-Packing "the operating system architecture $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) has no Windows processor architecture name this script states." }
    }

    #The environment every git command of this run sees, stated in full: the operating system's own
    #locations, and a profile, a temporary directory and a global configuration that are the run's own and
    #empty. No system configuration, no system attributes and no replacement objects are read, and git
    #never prompts or takes an optional lock on the working repository's index.
    $gitEnvironment = [ordered]@{
        'SystemRoot' = $windowsDirectory
        'windir' = $windowsDirectory
        'ComSpec' = Join-Path $systemDirectory 'cmd.exe'
        'PATHEXT' = '.COM;.EXE;.BAT;.CMD'
        'PATH' = "$systemDirectory;$windowsDirectory"
        'TEMP' = $temporaryRoot
        'TMP' = $temporaryRoot
        'HOME' = $profileRoot
        'USERPROFILE' = $profileRoot
        'XDG_CONFIG_HOME' = Join-Path $profileRoot '.config'
        'GIT_CONFIG_NOSYSTEM' = '1'
        'GIT_CONFIG_GLOBAL' = $emptyGitConfiguration
        'GIT_ATTR_NOSYSTEM' = '1'
        'GIT_NO_REPLACE_OBJECTS' = '1'
        'GIT_TERMINAL_PROMPT' = '0'
        'GIT_OPTIONAL_LOCKS' = '0'
    }

    #The configuration every git command of this run is given on its command line, above any a repository
    #holds: no hook runs, no attributes file outside the repository is read, and no line ending conversion,
    #symbolic link or file system monitor takes part.
    $gitIsolation = @(
        '-c', "core.hooksPath=$($emptyDirectory.Replace('\', '/'))",
        '-c', "core.attributesFile=$($emptyGitAttributes.Replace('\', '/'))",
        '-c', 'core.autocrlf=false',
        '-c', 'core.eol=lf',
        '-c', 'core.symlinks=false',
        '-c', 'core.fsmonitor=false',
        '-c', 'core.longpaths=true'
    )

    #Starts an executable with the arguments, working directory and environment given, the environment
    #cleared first so nothing of the caller's reaches it.
    function New-ControlledStartInfo
    {
        param(
            [Parameter(Mandatory = $true)]
            [string]$FilePath,

            [Parameter(Mandatory = $true)]
            [string[]]$Arguments,

            [Parameter(Mandatory = $true)]
            [string]$WorkingDirectory,

            [Parameter(Mandatory = $true)]
            [System.Collections.Specialized.OrderedDictionary]$Environment
        )

        $startInfo = [System.Diagnostics.ProcessStartInfo]::new($FilePath)
        foreach($argument in $Arguments)
        {
            $startInfo.ArgumentList.Add($argument)
        }

        $startInfo.WorkingDirectory = $WorkingDirectory
        $startInfo.UseShellExecute = $false
        $startInfo.Environment.Clear()
        foreach($name in $Environment.Keys)
        {
            $startInfo.Environment[$name] = $Environment[$name]
        }

        return $startInfo
    }

    #Ends a process this run started that is still running when its caller stops waiting for it, so no
    #process of the run outlives it or holds a file of its directory, and releases the process.
    function Close-ControlledProcess
    {
        param(
            [Parameter(Mandatory = $true)]
            [System.Diagnostics.Process]$Process
        )

        try
        {
            if(-not $Process.HasExited)
            {
                $Process.Kill($true)
                $Process.WaitForExit()
            }
        }
        finally
        {
            $Process.Dispose()
        }
    }

    #Runs an executable in a controlled environment and answers what it wrote to its output. A command that
    #fails answers nothing a verdict may rest on, so its exit code is read before its output is used and a
    #failure refuses the packing.
    function Invoke-ControlledCapture
    {
        param(
            [Parameter(Mandatory = $true)]
            [string]$FilePath,

            [Parameter(Mandatory = $true)]
            [string[]]$Arguments,

            [Parameter(Mandatory = $true)]
            [string]$WorkingDirectory,

            [Parameter(Mandatory = $true)]
            [System.Collections.Specialized.OrderedDictionary]$Environment,

            [Parameter(Mandatory = $true)]
            [string]$Purpose
        )

        $startInfo = New-ControlledStartInfo -FilePath $FilePath -Arguments $Arguments -WorkingDirectory $WorkingDirectory -Environment $Environment
        $startInfo.RedirectStandardOutput = $true
        $startInfo.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $process = [System.Diagnostics.Process]::Start($startInfo)
        try
        {
            $written = $process.StandardOutput.ReadToEnd()
            $process.WaitForExit()
            $processExitCode = $process.ExitCode
        }
        finally
        {
            Close-ControlledProcess -Process $process
        }

        if($processExitCode -ne 0)
        {
            Stop-Packing "could not $Purpose in $WorkingDirectory ($FilePath $($Arguments -join ' ') exited with $processExitCode)."
        }

        return $written
    }

    #Runs an executable in a controlled environment with its output written straight to this script's
    #output; a failure refuses the packing.
    function Invoke-ControlledStream
    {
        param(
            [Parameter(Mandatory = $true)]
            [string]$FilePath,

            [Parameter(Mandatory = $true)]
            [string[]]$Arguments,

            [Parameter(Mandatory = $true)]
            [string]$WorkingDirectory,

            [Parameter(Mandatory = $true)]
            [System.Collections.Specialized.OrderedDictionary]$Environment,

            [Parameter(Mandatory = $true)]
            [string]$Purpose
        )

        $startInfo = New-ControlledStartInfo -FilePath $FilePath -Arguments $Arguments -WorkingDirectory $WorkingDirectory -Environment $Environment
        $process = [System.Diagnostics.Process]::Start($startInfo)
        try
        {
            $process.WaitForExit()
            $processExitCode = $process.ExitCode
        }
        finally
        {
            Close-ControlledProcess -Process $process
        }

        if($processExitCode -ne 0)
        {
            Stop-Packing "could not $Purpose in $WorkingDirectory ($FilePath $($Arguments -join ' ') exited with $processExitCode)."
        }
    }

    #Runs one git command against a repository in the run's git environment and configuration and answers
    #the lines it wrote, split on the separator given.
    function Invoke-IsolatedGit
    {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Repository,

            [Parameter(Mandatory = $true)]
            [string[]]$Arguments,

            [Parameter(Mandatory = $true)]
            [string]$Purpose,

            [Parameter(Mandatory = $true)]
            [string]$Separator
        )

        $written = Invoke-ControlledCapture -FilePath $gitExecutable -Arguments (@('-C', $Repository) + $gitIsolation + $Arguments) -WorkingDirectory $Repository -Environment $gitEnvironment -Purpose "use git to $Purpose"

        return @($written.Split($Separator, [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.TrimEnd("`r") })
    }

    #Answers the paths git is told to stop comparing with the commit in a repository: git ls-files -v tags
    #such a file with a lower-case letter (assume-unchanged) or with S (skip-worktree, lower-case s for
    #both).
    function Get-UncomparedFiles
    {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Repository
        )

        $indexEntries = Invoke-IsolatedGit -Repository $Repository -Arguments @('ls-files', '-v', '-z') -Purpose 'list the index entries and their tags' -Separator ([string][char]0)

        return @($indexEntries | Where-Object {
            $tag = $_[0]
            [char]::IsLower($tag) -or $tag -ceq 'S'
        })
    }

    $baseVersion = '0.0.2'
    $publicationTagPrefix = 'refs/tags/local-publication/'

    #Answers every publication number already used, each with what names it: the repository's
    #local-publication/<number> tags, each naming the commit that publication packed, and the number every
    #Verifiable.* pin of the consumer's package version file carries in its version. A tag whose name is no
    #publication number refuses the packing, as does a package version file naming no Verifiable.* package,
    #since neither can then be read as the record.
    function Get-UsedPublications
    {
        $used = [System.Collections.Generic.SortedDictionary[int, string]]::new()
        $tags = Invoke-IsolatedGit -Repository $repositoryRoot -Arguments @('for-each-ref', '--format=%(refname) %(objectname)', $publicationTagPrefix) -Purpose 'list the publication tags' -Separator "`n"
        foreach($tag in $tags)
        {
            $match = [regex]::Match($tag, "^$([regex]::Escape($publicationTagPrefix))([1-9][0-9]{3}) ([0-9a-f]{40})$")
            if(-not $match.Success)
            {
                Stop-Packing "the repository holds the publication tag '$tag', which names no four-digit publication number and commit."
            }

            $used[[int]$match.Groups[1].Value] = "the tag local-publication/$($match.Groups[1].Value) of commit $($match.Groups[2].Value)"
        }

        [xml]$pinDocument = Get-Content -LiteralPath $consumerPinsPath -Raw
        $pinCount = 0
        foreach($pin in $pinDocument.SelectNodes("//*[local-name()='PackageVersion']"))
        {
            $include = $pin.GetAttribute('Include')
            if(-not $include.StartsWith('Verifiable.', [System.StringComparison]::Ordinal))
            {
                continue
            }

            $pinCount++
            $pinnedVersion = $pin.GetAttribute('Version')
            $match = [regex]::Match($pinnedVersion, "^$([regex]::Escape($baseVersion))-local\.([1-9][0-9]{3})\.")
            if($match.Success -and -not $used.ContainsKey([int]$match.Groups[1].Value))
            {
                $used[[int]$match.Groups[1].Value] = "the pin of $include at $pinnedVersion in $consumerPinsPath"
            }
        }

        if($pinCount -eq 0)
        {
            Stop-Packing "the consumer's package version file $consumerPinsPath names no Verifiable.* package, so it holds no pin of this family."
        }

        return ,$used
    }

    #Holds the publication number to the record of the numbers used: a number the record names is used, and
    #one below the highest it names would sort below a build already published.
    function Assert-PublicationForward
    {
        $used = Get-UsedPublications
        if($used.ContainsKey($Publication))
        {
            Stop-Packing "the publication number $Publication is used: $($used[$Publication]) names it, and a publication is never cut again under a number it has had."
        }

        if($used.Count -gt 0)
        {
            $highest = @($used.Keys)[-1]
            if($Publication -lt $highest)
            {
                Stop-Packing "the publication number $Publication is not forward of the highest used, $highest, which $($used[$highest]) names, and NuGet orders the family's builds by this number alone."
            }

            Write-Host "Publication $Publication is forward of every number used; the highest, $highest, is named by $($used[$highest])."
        }
    }

    Assert-PublicationForward

    $sha = (Invoke-IsolatedGit -Repository $repositoryRoot -Arguments @('rev-parse', '--short', 'HEAD') -Purpose 'name the commit HEAD points at' -Separator "`n") -join ''
    $commitId = (Invoke-IsolatedGit -Repository $repositoryRoot -Arguments @('rev-parse', 'HEAD') -Purpose 'name the commit HEAD points at' -Separator "`n") -join ''
    if([string]::IsNullOrWhiteSpace($sha) -or [string]::IsNullOrWhiteSpace($commitId))
    {
        Stop-Packing "git names no commit for $repositoryRoot, and the package version must carry the commit the packages are built from."
    }

    $objectFormat = (Invoke-IsolatedGit -Repository $repositoryRoot -Arguments @('rev-parse', '--show-object-format') -Purpose 'name the object format' -Separator "`n") -join ''
    if($objectFormat -ne 'sha1')
    {
        Stop-Packing "the repository's object format is $objectFormat, and this script establishes the checkout by SHA-1 blob ids."
    }

    #A file marked assume-unchanged or skip-worktree is one git status no longer compares with the commit,
    #so status reads it as unchanged whatever it holds; any such file refuses the packing before status is
    #asked.
    $uncomparedFiles = Get-UncomparedFiles -Repository $repositoryRoot
    if($uncomparedFiles.Count -gt 0)
    {
        Stop-Packing "git is told to stop comparing these files with commit $sha (assume-unchanged or skip-worktree), so the working tree cannot be shown to be that commit. Marked:`n$($uncomparedFiles -join "`n")"
    }

    #Every file git tracks, wherever it lies, is compared with the commit, and every file it does not track
    #is listed one by one.
    $changedFiles = Invoke-IsolatedGit -Repository $repositoryRoot -Arguments @('status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none') -Purpose 'read the state of the working tree' -Separator "`n"
    if($changedFiles.Count -gt 0)
    {
        Stop-Packing "the working tree differs from commit $sha, so the version would name a commit that did not build these packages. Changed:`n$($changedFiles -join "`n")"
    }

    #The commit alone is fetched into a fresh repository created from an empty template, so it holds no hook,
    #and checked out under an attributes file of its own that, above every .gitattributes the commit holds,
    #applies no line ending conversion, no filter, no identifier expansion and no working tree encoding:
    #each file is written as the commit's blob holds it. The fresh repository names the working
    #repository's origin as its own, so the source link the build writes into each package names the
    #published repository.
    $sourceUrl = ([Uri]$repositoryRoot).AbsoluteUri
    $originUrl = (Invoke-IsolatedGit -Repository $repositoryRoot -Arguments @('remote', 'get-url', 'origin') -Purpose 'name the origin repository' -Separator "`n") -join ''
    Invoke-IsolatedGit -Repository $exportRoot -Arguments @('init', '--quiet', "--template=$($emptyDirectory.Replace('\', '/'))") -Purpose 'create the fresh repository' -Separator "`n" | Out-Null

    $exportInformation = Join-Path $exportRoot '.git/info'
    New-Item -ItemType Directory -Path $exportInformation -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $exportInformation 'attributes'), "* -text !eol -filter -ident !working-tree-encoding`n", [System.Text.UTF8Encoding]::new($false))

    Invoke-IsolatedGit -Repository $exportRoot -Arguments @('fetch', '--quiet', '--depth', '1', '--no-tags', $sourceUrl, $commitId) -Purpose "fetch commit $commitId" -Separator "`n" | Out-Null
    Invoke-IsolatedGit -Repository $exportRoot -Arguments @('checkout', '--quiet', '--detach', $commitId) -Purpose "check out commit $commitId" -Separator "`n" | Out-Null
    Invoke-IsolatedGit -Repository $exportRoot -Arguments @('remote', 'add', 'origin', $originUrl) -Purpose 'name the origin repository' -Separator "`n" | Out-Null

    $exportedCommit = (Invoke-IsolatedGit -Repository $exportRoot -Arguments @('rev-parse', 'HEAD') -Purpose 'name the commit checked out' -Separator "`n") -join ''
    if($exportedCommit -ne $commitId)
    {
        Stop-Packing "the fresh repository in $exportRoot checked out $exportedCommit, not commit $commitId."
    }

    $exportUncompared = Get-UncomparedFiles -Repository $exportRoot
    if($exportUncompared.Count -gt 0)
    {
        Stop-Packing "the fresh repository's index tells git to stop comparing these files with commit ${sha}:`n$($exportUncompared -join "`n")"
    }

    #The checkout is established against the commit file by file. Every entry of the commit's tree is a
    #regular file's blob; every file the checkout holds outside its repository directory is hashed as git
    #hashes a blob - the header 'blob <length>' and a zero byte, then the bytes the file holds - and its id
    #held to the tree entry for its path. A file the tree does not hold, an entry with no file, a file whose
    #id differs and any link in the checkout refuse the packing.
    $treeEntries = Invoke-IsolatedGit -Repository $exportRoot -Arguments @('ls-tree', '-r', '-z', '--full-tree', $commitId) -Purpose "list the tree of commit $commitId" -Separator ([string][char]0)
    $expectedBlobs = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($treeEntry in $treeEntries)
    {
        $tab = $treeEntry.IndexOf("`t")
        $fields = $treeEntry.Substring(0, $tab).Split(' ')
        $path = $treeEntry.Substring($tab + 1)
        if($fields[1] -ne 'blob' -or ($fields[0] -ne '100644' -and $fields[0] -ne '100755'))
        {
            Stop-Packing "commit $sha holds $path as a $($fields[1]) of mode $($fields[0]), and only regular files are established against the commit."
        }

        if($expectedBlobs.ContainsKey($path))
        {
            Stop-Packing "commit $sha holds two paths that name the same file on this file system: $path."
        }

        $expectedBlobs[$path] = $fields[2]
    }

    $enumeration = [System.IO.EnumerationOptions]::new()
    $enumeration.AttributesToSkip = [System.IO.FileAttributes]0
    $enumeration.IgnoreInaccessible = $false
    $enumeration.RecurseSubdirectories = $false
    $enumeration.ReturnSpecialDirectories = $false

    $blobHeaderEncoding = [System.Text.Encoding]::ASCII
    $differing = [System.Collections.Generic.List[string]]::new()
    $establishedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pendingDirectories = [System.Collections.Generic.Stack[string]]::new()
    $pendingDirectories.Push($exportRoot)
    while($pendingDirectories.Count -gt 0)
    {
        $directory = $pendingDirectories.Pop()
        foreach($entry in [System.IO.DirectoryInfo]::new($directory).EnumerateFileSystemInfos('*', $enumeration))
        {
            $relativePath = [System.IO.Path]::GetRelativePath($exportRoot, $entry.FullName).Replace('\', '/')
            if(($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
            {
                Stop-Packing "the checkout holds a link at $relativePath, which no regular file of the commit is."
            }

            if($entry -is [System.IO.DirectoryInfo])
            {
                if($relativePath -ne '.git')
                {
                    $pendingDirectories.Push($entry.FullName)
                }

                continue
            }

            if(-not $expectedBlobs.ContainsKey($relativePath))
            {
                $differing.Add("$relativePath (no entry of the commit's tree)")
                continue
            }

            $content = [System.IO.File]::ReadAllBytes($entry.FullName)
            $hash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA1)
            try
            {
                $hash.AppendData($blobHeaderEncoding.GetBytes("blob $($content.Length)`0"))
                $hash.AppendData($content)
                $blobId = [System.Convert]::ToHexString($hash.GetHashAndReset()).ToLowerInvariant()
            }
            finally
            {
                $hash.Dispose()
            }

            if($blobId -ne $expectedBlobs[$relativePath])
            {
                $differing.Add("$relativePath (blob $blobId, the commit's $($expectedBlobs[$relativePath]))")
            }

            $establishedPaths.Add($relativePath) | Out-Null
        }
    }

    foreach($path in $expectedBlobs.Keys)
    {
        if(-not $establishedPaths.Contains($path))
        {
            $differing.Add("$path (the commit's tree entry has no file in the checkout)")
        }
    }

    if($differing.Count -gt 0)
    {
        Stop-Packing "the checkout in $exportRoot is not commit $commitId byte for byte:`n$($differing -join "`n")"
    }

    Write-Host "Established the checkout against commit $commitId file by file: $($establishedPaths.Count) files, each the blob its tree entry names."

    #The SDK is the one the commit's global.json names. A global.json naming SDK locations of its own would
    #let the SDK come from a directory this script does not even name.
    $globalJson = Get-Content -LiteralPath (Join-Path $exportRoot 'global.json') -Raw | ConvertFrom-Json -AsHashtable
    if($null -eq $globalJson['sdk'] -or [string]::IsNullOrWhiteSpace($globalJson['sdk']['version']))
    {
        Stop-Packing "the commit's global.json names no SDK version."
    }

    if($globalJson['sdk'].ContainsKey('paths'))
    {
        Stop-Packing "the commit's global.json names SDK locations of its own, and the SDK is taken only from the installation of $dotnetExecutable."
    }

    $sdkVersion = $globalJson['sdk']['version']
    $sdkDirectory = Join-Path $dotnetRoot "sdk/$sdkVersion"
    if(-not (Test-Path -LiteralPath $sdkDirectory -PathType Container))
    {
        Stop-Packing "the SDK $sdkVersion the commit's global.json names is not installed in $dotnetRoot."
    }

    #The environment restore and pack run in, stated in full. Of the operating system's variables only its
    #own locations are given; the profile, application data, temporary, NuGet and git configuration
    #locations are the run's own and empty; and the CLI's first-run, telemetry, workload and tool path
    #behaviours are switched off. Nothing of the caller's environment is inherited, so no MSBuild*,
    #DOTNET_*, NUGET_* or property-named variable such as DirectoryBuildPropsPath or
    #CustomBeforeDirectoryBuildProps reaches the build beyond these.
    $dotnetEnvironment = [ordered]@{
        'SystemRoot' = $windowsDirectory
        'windir' = $windowsDirectory
        'SystemDrive' = [System.IO.Path]::GetPathRoot($windowsDirectory).TrimEnd('\')
        'ComSpec' = Join-Path $systemDirectory 'cmd.exe'
        'PATHEXT' = '.COM;.EXE;.BAT;.CMD'
        'PATH' = "$dotnetRoot;$systemDirectory;$windowsDirectory"
        'ProgramFiles' = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
        'ProgramFiles(x86)' = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
        'ProgramW6432' = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
        'ProgramData' = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
        'OS' = 'Windows_NT'
        'PROCESSOR_ARCHITECTURE' = $processorArchitecture
        'NUMBER_OF_PROCESSORS' = [Environment]::ProcessorCount.ToString([System.Globalization.CultureInfo]::InvariantCulture)
        'TEMP' = $temporaryRoot
        'TMP' = $temporaryRoot
        'USERPROFILE' = $profileRoot
        'HOME' = $profileRoot
        'APPDATA' = Join-Path $profileRoot 'Roaming'
        'LOCALAPPDATA' = Join-Path $profileRoot 'Local'
        'XDG_CONFIG_HOME' = Join-Path $profileRoot '.config'
        'DOTNET_CLI_HOME' = $profileRoot
        'DOTNET_CLI_TELEMETRY_OPTOUT' = '1'
        'DOTNET_NOLOGO' = '1'
        'DOTNET_SKIP_FIRST_TIME_EXPERIENCE' = '1'
        'DOTNET_GENERATE_ASPNET_CERTIFICATE' = 'false'
        'DOTNET_ADD_GLOBAL_TOOLS_TO_PATH' = 'false'
        'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE' = 'true'
        'DOTNET_MULTILEVEL_LOOKUP' = '0'
        'NUGET_PACKAGES' = $packagesRoot
        'NUGET_HTTP_CACHE_PATH' = Join-Path $profileRoot 'nuget-http-cache'
        'NUGET_PLUGINS_CACHE_PATH' = Join-Path $profileRoot 'nuget-plugins-cache'
        'GIT_CONFIG_NOSYSTEM' = '1'
        'GIT_CONFIG_GLOBAL' = $emptyGitConfiguration
    }

    #The CLI selects its SDK from the global.json above its working directory, so it runs from the
    #checkout's root, and the selection is checked there: the version it answers is the one global.json
    #names, and the SDK it lists under that version lies in the installation the CLI runs from. Which bytes
    #that installation holds is trusted, not established.
    $selectedVersion = (Invoke-ControlledCapture -FilePath $dotnetExecutable -Arguments @('--version') -WorkingDirectory $exportRoot -Environment $dotnetEnvironment -Purpose 'name the SDK the CLI selects').Trim()
    if($selectedVersion -ne $sdkVersion)
    {
        Stop-Packing "the CLI run from $exportRoot selects SDK $selectedVersion, and the commit's global.json names $sdkVersion."
    }

    $listedSdks = Invoke-ControlledCapture -FilePath $dotnetExecutable -Arguments @('--list-sdks') -WorkingDirectory $exportRoot -Environment $dotnetEnvironment -Purpose 'list the installed SDKs'
    $listedSelection = @($listedSdks.Split("`n", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() } | Where-Object { $_.StartsWith("$sdkVersion [", [System.StringComparison]::Ordinal) })
    $expectedListing = "$sdkVersion [$(Join-Path $dotnetRoot 'sdk')]"
    if($listedSelection.Count -ne 1 -or $listedSelection[0] -ne $expectedListing)
    {
        Stop-Packing "the CLI lists SDK $sdkVersion as '$($listedSelection -join "', '")', not as '$expectedListing'."
    }

    Write-Host "SDK selection checked: dotnet --version run from $exportRoot answers '$selectedVersion'; the commit's global.json names sdk.version '$sdkVersion'; dotnet --list-sdks lists '$($listedSelection[0])'."

    #The content hash of a package is the one NuGet writes into a lock file, computed by the selected SDK's
    #own NuGet: for a signed package the archive with its signature left out, for any other the archive.
    foreach($assembly in @('NuGet.Common', 'NuGet.Frameworks', 'NuGet.Versioning', 'NuGet.Configuration', 'NuGet.Packaging'))
    {
        Add-Type -LiteralPath (Join-Path $sdkDirectory "$assembly.dll")
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

    #The packages the restore may extract are the ones the lock files of the packed projects, and of every
    #project they reference, name: each by its identifier, its resolved version and its content hash. Two
    #lock files naming one package with two hashes refuse the packing.
    $sourceDirectories = @{}
    foreach($directory in [System.IO.DirectoryInfo]::new((Join-Path $exportRoot 'src')).EnumerateDirectories('*', $enumeration))
    {
        $sourceDirectories[$directory.Name.ToLowerInvariant()] = $directory.FullName
    }

    $lockedPackages = [System.Collections.Generic.Dictionary[string, hashtable]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $visitedProjects = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pendingProjects = [System.Collections.Generic.Queue[string]]::new()
    foreach($project in $projects)
    {
        $pendingProjects.Enqueue($project)
    }

    while($pendingProjects.Count -gt 0)
    {
        $project = $pendingProjects.Dequeue()
        if(-not $visitedProjects.Add($project))
        {
            continue
        }

        $projectDirectory = $sourceDirectories[$project.ToLowerInvariant()]
        $lockFile = if($null -ne $projectDirectory) { Join-Path $projectDirectory 'packages.lock.json' } else { $null }
        if($null -eq $lockFile -or -not (Test-Path -LiteralPath $lockFile -PathType Leaf))
        {
            Stop-Packing "the project $project has no lock file in the commit, so the packages its restore reads cannot be held to content hashes."
        }

        $lock = Get-Content -LiteralPath $lockFile -Raw | ConvertFrom-Json -AsHashtable
        foreach($framework in $lock['dependencies'].Keys)
        {
            foreach($id in $lock['dependencies'][$framework].Keys)
            {
                $dependency = $lock['dependencies'][$framework][$id]
                if($dependency['type'] -eq 'Project')
                {
                    $pendingProjects.Enqueue($id)
                    continue
                }

                if([string]::IsNullOrWhiteSpace($dependency['resolved']) -or [string]::IsNullOrWhiteSpace($dependency['contentHash']))
                {
                    Stop-Packing "the lock file $lockFile names $id for $framework without a resolved version and a content hash."
                }

                $version = [NuGet.Versioning.NuGetVersion]::Parse($dependency['resolved'])
                $key = "$($id.ToLowerInvariant())/$($version.ToNormalizedString().ToLowerInvariant())"
                if($lockedPackages.ContainsKey($key))
                {
                    if($lockedPackages[$key]['ContentHash'] -cne $dependency['contentHash'])
                    {
                        Stop-Packing "two lock files name $id $($version.ToNormalizedString()) with two content hashes."
                    }

                    continue
                }

                $lockedPackages[$key] = @{
                    'Id' = $id
                    'Version' = $version
                    'ContentHash' = $dependency['contentHash']
                    'LockFile' = $lockFile
                }
            }
        }
    }

    #Every locked package is fetched from the source the commit's NuGet.config maps it to. A source on the
    #web is read through its package base address; the one local source the commit names in a directory it
    #does not hold is the directory -LocalFeedDirectory names. No other source is accepted.
    $commitNuGetConfig = Get-ChildItem -LiteralPath $exportRoot -File | Where-Object { $_.Name -ieq 'NuGet.config' } | Select-Object -First 1
    if($null -eq $commitNuGetConfig)
    {
        Stop-Packing 'the commit holds no NuGet.config at its root, so no package has a source this script can establish.'
    }

    [xml]$commitNuGet = Get-Content -LiteralPath $commitNuGetConfig.FullName -Raw
    $sources = @{}
    foreach($node in $commitNuGet.configuration.packageSources.ChildNodes)
    {
        if($node.NodeType -ne [System.Xml.XmlNodeType]::Element)
        {
            continue
        }

        switch($node.LocalName)
        {
            'clear' { $sources = @{} }
            'add' { $sources[$node.GetAttribute('key')] = $node.GetAttribute('value') }
            default { Stop-Packing "the commit's NuGet.config holds a package source element '$($node.LocalName)' this script does not read." }
        }
    }

    $sourceMapping = @{}
    foreach($node in $commitNuGet.configuration.packageSourceMapping.ChildNodes)
    {
        if($node.NodeType -ne [System.Xml.XmlNodeType]::Element -or $node.LocalName -ne 'packageSource')
        {
            continue
        }

        $sourceMapping[$node.GetAttribute('key')] = @($node.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element -and $_.LocalName -eq 'package' } | ForEach-Object { $_.GetAttribute('pattern') })
    }

    if($sources.Count -eq 0 -or $sourceMapping.Count -eq 0)
    {
        Stop-Packing "the commit's NuGet.config names no package source or no package source mapping, so no package has one source this script can establish."
    }

    #The status codes of an answer that names another location to read instead.
    $redirectStatuses = @(301, 302, 303, 307, 308)
    $maximumRedirections = 5

    #Answers the bytes an https location holds, read through the run's client. The location and every
    #location a redirect names are held to https before they are read, so no byte of a web source travels
    #over any other scheme; a location that is not https, an answer that is neither the content nor a
    #redirect, a redirect naming no location and a chain of more than the maximum redirections each refuse
    #the packing.
    function Get-HttpsContent
    {
        param(
            [Parameter(Mandatory = $true)]
            [Uri]$Location,

            [Parameter(Mandatory = $true)]
            [string]$Purpose
        )

        $current = $Location
        for($redirections = 0; $redirections -le $maximumRedirections; $redirections++)
        {
            if(-not $current.IsAbsoluteUri -or $current.Scheme -cne [Uri]::UriSchemeHttps)
            {
                Stop-Packing "to $Purpose the packing would read $current, which is not an https location, and every location of a web source, every redirect among them, is read over https alone."
            }

            $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $current)
            try
            {
                $response = $httpClient.Send($request, [System.Net.Http.HttpCompletionOption]::ResponseContentRead, $runCancellation.Token)
                try
                {
                    $status = [int]$response.StatusCode
                    if($redirectStatuses -contains $status)
                    {
                        $redirect = $response.Headers.Location
                        if($null -eq $redirect)
                        {
                            Stop-Packing "to $Purpose the packing read $current, which answered the redirect $status naming no location."
                        }

                        $current = if($redirect.IsAbsoluteUri) { $redirect } else { [Uri]::new($current, $redirect) }
                        continue
                    }

                    if($status -ne 200)
                    {
                        Stop-Packing "to $Purpose the packing read $current, which answered $status."
                    }

                    $buffer = [System.IO.MemoryStream]::new()
                    try
                    {
                        $stream = $response.Content.ReadAsStream($runCancellation.Token)
                        try
                        {
                            $stream.CopyTo($buffer)
                        }
                        finally
                        {
                            $stream.Dispose()
                        }

                        $content = $buffer.ToArray()
                    }
                    finally
                    {
                        $buffer.Dispose()
                    }

                    return ,$content
                }
                finally
                {
                    $response.Dispose()
                }
            }
            finally
            {
                $request.Dispose()
            }
        }

        Stop-Packing "to $Purpose the packing was redirected more than $maximumRedirections times from $Location."
    }

    $sourceKinds = @{}
    $absentLocalSources = @()
    foreach($key in $sources.Keys)
    {
        $value = $sources[$key]
        if($value.StartsWith('https://', [System.StringComparison]::OrdinalIgnoreCase))
        {
            $serviceIndexContent = Get-HttpsContent -Location ([Uri]$value) -Purpose "read the service index of the package source $key"
            $serviceIndex = [System.Text.Encoding]::UTF8.GetString($serviceIndexContent) | ConvertFrom-Json
            $baseAddress = @($serviceIndex.resources | Where-Object { $_.'@type' -eq 'PackageBaseAddress/3.0.0' } | ForEach-Object { $_.'@id' }) | Select-Object -First 1
            if([string]::IsNullOrWhiteSpace($baseAddress))
            {
                Stop-Packing "the package source $key ($value) names no package base address."
            }

            $baseLocation = $null
            if(-not [Uri]::TryCreate($baseAddress, [System.UriKind]::Absolute, [ref]$baseLocation) -or $baseLocation.Scheme -cne [Uri]::UriSchemeHttps)
            {
                Stop-Packing "the package source $key ($value) advertises the package base address $baseAddress, which is not an https location, and every location of a web source is read over https alone."
            }

            $sourceKinds[$key] = @{ 'Kind' = 'web'; 'Location' = $baseAddress.TrimEnd('/') + '/' }
            continue
        }

        if($value -match '^[a-zA-Z][a-zA-Z0-9+.-]*://')
        {
            Stop-Packing "the package source $key ($value) is neither a web source over https nor a directory."
        }

        $sourcePath = [System.IO.Path]::GetFullPath($value, $exportRoot)
        $insideCheckout = $sourcePath.StartsWith($exportRoot.TrimEnd('\') + '\', [System.StringComparison]::OrdinalIgnoreCase)
        if($insideCheckout -and (Test-Path -LiteralPath $sourcePath -PathType Container))
        {
            $sourceKinds[$key] = @{ 'Kind' = 'directory'; 'Location' = $sourcePath }
            continue
        }

        if(-not $insideCheckout)
        {
            Stop-Packing "the package source $key ($value) lies outside the checkout, and only a directory the commit holds or the local feed it names inside itself is accepted."
        }

        $sourceKinds[$key] = @{ 'Kind' = 'directory'; 'Location' = $localFeedRoot }
        $absentLocalSources += "$key ($value)"
    }

    if($absentLocalSources.Count -ne 1)
    {
        Stop-Packing "-LocalFeedDirectory stands for the one local feed the commit's NuGet.config names in a directory the commit does not hold, and it names $($absentLocalSources.Count): $($absentLocalSources -join ', ')."
    }

    #Answers the source key the commit's package source mapping maps a package to: the most specific
    #pattern wins, a full identifier above every prefix and a longer prefix above a shorter one.
    function Get-MappedSource
    {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Id
        )

        $bestKey = $null
        $bestRank = -1
        foreach($key in $sourceMapping.Keys)
        {
            foreach($pattern in $sourceMapping[$key])
            {
                $rank = -1
                if($pattern.EndsWith('*'))
                {
                    $prefix = $pattern.Substring(0, $pattern.Length - 1)
                    if($Id.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase))
                    {
                        $rank = $prefix.Length
                    }
                }
                elseif($Id -ieq $pattern)
                {
                    $rank = [int]::MaxValue
                }

                if($rank -gt $bestRank)
                {
                    $bestRank = $rank
                    $bestKey = $key
                }
            }
        }

        return $bestKey
    }

    foreach($package in $lockedPackages.Values)
    {
        $id = $package['Id']
        $version = $package['Version']
        $normalizedVersion = $version.ToNormalizedString()
        $sourceKey = Get-MappedSource -Id $id
        if($null -eq $sourceKey -or -not $sourceKinds.ContainsKey($sourceKey))
        {
            Stop-Packing "the commit's NuGet.config maps $id to no package source it names."
        }

        $source = $sourceKinds[$sourceKey]
        $archiveName = "$($id.ToLowerInvariant()).$($normalizedVersion.ToLowerInvariant()).nupkg"
        if($source['Kind'] -eq 'web')
        {
            $origin = "$($source['Location'])$($id.ToLowerInvariant())/$($normalizedVersion.ToLowerInvariant())/$archiveName"
            $archiveBytes = Get-HttpsContent -Location ([Uri]$origin) -Purpose "fetch $id $normalizedVersion"
        }
        else
        {
            $candidates = @(
                (Join-Path $source['Location'] "$id.$normalizedVersion.nupkg"),
                (Join-Path $source['Location'] "$($id.ToLowerInvariant())/$($normalizedVersion.ToLowerInvariant())/$archiveName")
            )
            $origin = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
            if($null -eq $origin)
            {
                Stop-Packing "the package source $sourceKey holds no archive of $id $normalizedVersion in $($source['Location'])."
            }

            $archiveBytes = [System.IO.File]::ReadAllBytes($origin)
        }

        #The archive is judged in memory, from the bytes that are then written, so what is extracted is
        #what was judged.
        $archiveStream = [System.IO.MemoryStream]::new($archiveBytes, $false)
        try
        {
            $reader = [NuGet.Packaging.PackageArchiveReader]::new($archiveStream)
            try
            {
                $identity = $reader.GetIdentity()
                $contentHash = $reader.GetContentHash($runCancellation.Token, $null)
            }
            finally
            {
                $reader.Dispose()
            }
        }
        finally
        {
            $archiveStream.Dispose()
        }

        if($identity.Id -ine $id -or -not $identity.Version.Equals($version))
        {
            Stop-Packing "the archive $origin is $($identity.Id) $($identity.Version), not $id $normalizedVersion."
        }

        if($contentHash -cne $package['ContentHash'])
        {
            Stop-Packing "the archive of $id $normalizedVersion from $origin has the content hash $contentHash, and the lock file $($package['LockFile']) names $($package['ContentHash'])."
        }

        [System.IO.File]::WriteAllBytes((Join-Path $archivesRoot $archiveName), $archiveBytes)
    }

    Write-Host "Verified $($lockedPackages.Count) package archives against the content hashes the lock files name, $($absentLocalSources[0]) read from $localFeedRoot."

    #The restore reads a configuration of this run's own: the commit's NuGet.config with its package sources
    #replaced by the one feed of verified archives, every package mapped to it, no fallback folder, and the
    #run's packages directory as the global packages folder. Its signature validation and trusted signers
    #are the commit's.
    $runNuGetConfig = Join-Path $nugetControlRoot 'NuGet.config'
    $configuration = $commitNuGet.configuration
    foreach($section in @('packageSources', 'packageSourceMapping', 'fallbackPackageFolders', 'disabledPackageSources', 'packageSourceCredentials'))
    {
        foreach($existing in @($configuration.SelectNodes($section)))
        {
            $configuration.RemoveChild($existing) | Out-Null
        }
    }

    $packageSourcesNode = $commitNuGet.CreateElement('packageSources')
    $packageSourcesNode.AppendChild($commitNuGet.CreateElement('clear')) | Out-Null
    $verifiedSource = $commitNuGet.CreateElement('add')
    $verifiedSource.SetAttribute('key', 'verified-archives')
    $verifiedSource.SetAttribute('value', $archivesRoot)
    $packageSourcesNode.AppendChild($verifiedSource) | Out-Null
    $configuration.PrependChild($packageSourcesNode) | Out-Null

    $mappingNode = $commitNuGet.CreateElement('packageSourceMapping')
    $mappingSource = $commitNuGet.CreateElement('packageSource')
    $mappingSource.SetAttribute('key', 'verified-archives')
    $mappingPattern = $commitNuGet.CreateElement('package')
    $mappingPattern.SetAttribute('pattern', '*')
    $mappingSource.AppendChild($mappingPattern) | Out-Null
    $mappingNode.AppendChild($mappingSource) | Out-Null
    $configuration.AppendChild($mappingNode) | Out-Null

    $fallbackNode = $commitNuGet.CreateElement('fallbackPackageFolders')
    $fallbackNode.AppendChild($commitNuGet.CreateElement('clear')) | Out-Null
    $configuration.AppendChild($fallbackNode) | Out-Null

    $configNode = $configuration.SelectSingleNode('config')
    if($null -eq $configNode)
    {
        $configNode = $commitNuGet.CreateElement('config')
        $configuration.AppendChild($configNode) | Out-Null
    }

    foreach($existing in @($configNode.SelectNodes("add[@key='globalPackagesFolder']")))
    {
        $configNode.RemoveChild($existing) | Out-Null
    }

    $globalPackagesFolder = $commitNuGet.CreateElement('add')
    $globalPackagesFolder.SetAttribute('key', 'globalPackagesFolder')
    $globalPackagesFolder.SetAttribute('value', $packagesRoot)
    $configNode.AppendChild($globalPackagesFolder) | Out-Null
    $commitNuGet.Save($runNuGetConfig)

    #The SDK's imports of the user's MSBuild extension directories, which lie outside the checkout, are
    #switched off for every kind of project file the SDK reads.
    $userExtensionImports = @()
    foreach($point in @('MicrosoftCommonProps', 'MicrosoftCommonTargets', 'MicrosoftCSharpTargets', 'MicrosoftVisualBasicTargets', 'MicrosoftNetFrameworkProps', 'MicrosoftNetFrameworkTargets'))
    {
        $userExtensionImports += "-p:ImportUserLocationsByWildcardBefore$point=false"
        $userExtensionImports += "-p:ImportUserLocationsByWildcardAfter$point=false"
    }

    #The SDK adds package locations of its installation to every restore it is not told to leave them out
    #of: its offline fallback folder as a fallback folder and its workload library packs as a source. Both
    #are switched off, so the feed of verified archives is the restore's one source and the run's packages
    #directory its one packages folder.
    $implicitPackageLocations = @(
        '-p:DisableImplicitNuGetFallbackFolder=true',
        '-p:DisableImplicitLibraryPacksFolder=true'
    )

    #Holds every restore output in the checkout to the run's configuration, its feed of verified archives
    #and its packages directory, and every package in that directory to a verified archive extracted with
    #the content hash the lock files name.
    function Assert-RestoreConfined
    {
        $expectedFolder = [System.IO.Path]::GetFullPath($packagesRoot).TrimEnd('\')
        $expectedSource = [System.IO.Path]::GetFullPath($archivesRoot).TrimEnd('\')
        $expectedConfig = [System.IO.Path]::GetFullPath($runNuGetConfig)
        $assetsFiles = @(Get-ChildItem -LiteralPath (Join-Path $exportRoot 'src') -Recurse -File -Filter 'project.assets.json')
        if($assetsFiles.Count -eq 0)
        {
            Stop-Packing "the restore wrote no restore output in $exportRoot."
        }

        foreach($assetsFile in $assetsFiles)
        {
            $assets = Get-Content -LiteralPath $assetsFile.FullName -Raw | ConvertFrom-Json -AsHashtable
            $folders = @($assets['packageFolders'].Keys | ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\') })
            $restore = $assets['project']['restore']
            $configs = @($restore['configFilePaths'] | ForEach-Object { [System.IO.Path]::GetFullPath($_) })
            $restoreSources = @($restore['sources'].Keys | ForEach-Object { [System.IO.Path]::GetFullPath($_).TrimEnd('\') })
            $fallbacks = @($restore['fallbackFolders'] | Where-Object { $null -ne $_ })
            if($folders.Count -ne 1 -or $folders[0] -ine $expectedFolder -or $configs.Count -ne 1 -or $configs[0] -ine $expectedConfig -or $restoreSources.Count -ne 1 -or $restoreSources[0] -ine $expectedSource -or $fallbacks.Count -ne 0)
            {
                Stop-Packing "the restore output $($assetsFile.FullName) read packages from '$($folders -join "', '")', configuration '$($configs -join "', '")', sources '$($restoreSources -join "', '")' and fallback folders '$($fallbacks -join "', '")', not the run's own alone."
            }
        }

        foreach($idDirectory in [System.IO.DirectoryInfo]::new($packagesRoot).EnumerateFileSystemInfos('*', $enumeration))
        {
            foreach($versionDirectory in [System.IO.DirectoryInfo]::new($idDirectory.FullName).EnumerateFileSystemInfos('*', $enumeration))
            {
                $key = "$($idDirectory.Name)/$($versionDirectory.Name)"
                if(-not $lockedPackages.ContainsKey($key))
                {
                    Stop-Packing "the packages directory $packagesRoot holds $key, which no lock file of the packed projects names."
                }

                $metadataFile = Join-Path $versionDirectory.FullName '.nupkg.metadata'
                $metadata = if(Test-Path -LiteralPath $metadataFile -PathType Leaf) { Get-Content -LiteralPath $metadataFile -Raw | ConvertFrom-Json -AsHashtable } else { @{} }
                $extractedFrom = if([string]::IsNullOrWhiteSpace($metadata['source'])) { '' } else { [System.IO.Path]::GetFullPath($metadata['source']).TrimEnd('\') }
                if($metadata['contentHash'] -cne $lockedPackages[$key]['ContentHash'] -or $extractedFrom -ine $expectedSource)
                {
                    Stop-Packing "the package $key in $packagesRoot was not extracted from the feed of verified archives with the content hash the lock files name."
                }
            }
        }
    }

    $packageVersion = "$baseVersion-local.$Publication.g$sha"
    $informationalVersion = "$packageVersion+$commitId"

    #Every project is packed into the run's own family directory, never the output directory, so a packing
    #refused at any later step leaves the output directory as it was.
    foreach($project in $projects)
    {
        $projectFile = "src/$project/$project.csproj"

        #Restored in locked mode from the feed of verified archives alone into the run's packages directory:
        #every package is the one the commit's lock file names by its content hash.
        Invoke-ControlledStream -FilePath $dotnetExecutable -WorkingDirectory $exportRoot -Environment $dotnetEnvironment -Purpose "restore $project" -Arguments (@(
            'restore', $projectFile,
            '--configfile', $runNuGetConfig,
            '--packages', $packagesRoot,
            '--locked-mode',
            '--disable-build-servers',
            '-nodeReuse:false') + $userExtensionImports + $implicitPackageLocations)

        Assert-RestoreConfined

        Invoke-ControlledStream -FilePath $dotnetExecutable -WorkingDirectory $exportRoot -Environment $dotnetEnvironment -Purpose "pack $project" -Arguments (@(
            'pack', $projectFile,
            '--verbosity', 'normal',
            '--no-restore',
            '--disable-build-servers',
            '-nodeReuse:false',
            '--configuration', 'Release',
            '--output', $stagingRoot,
            '--include-symbols',
            '--include-source',
            "--property:PackageVersion=$packageVersion",
            "--property:InformationalVersion=$informationalVersion") + $userExtensionImports + $implicitPackageLocations)
    }

    Assert-RestoreConfined

    #The whole family is checked where it was packed. The family directory holds exactly one package and one
    #symbol package of every project under its name and nothing else; each names its project and this
    #version, and each package names the commit as its repository commit, which the build reads from the
    #fresh repository's HEAD, so a package naming any other was not built from this commit. Every archive's
    #SHA-512 is taken here, and what is published is held to it.
    $expectedFamily = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
    foreach($project in $projects)
    {
        $expectedFamily["$project.$packageVersion.nupkg"] = $project
        $expectedFamily["$project.$packageVersion.snupkg"] = $project
    }

    $familyFaults = [System.Collections.Generic.List[string]]::new()
    $stagedNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach($entry in [System.IO.DirectoryInfo]::new($stagingRoot).EnumerateFileSystemInfos('*', $enumeration))
    {
        if($entry -isnot [System.IO.FileInfo] -or -not $expectedFamily.ContainsKey($entry.Name))
        {
            $familyFaults.Add("$($entry.Name) (no archive of the family)")
            continue
        }

        $stagedNames.Add($entry.Name) | Out-Null
    }

    foreach($name in $expectedFamily.Keys)
    {
        if(-not $stagedNames.Contains($name))
        {
            $familyFaults.Add("$name (not packed)")
        }
    }

    $stagedFamily = [System.Collections.Generic.List[hashtable]]::new()
    foreach($name in $stagedNames)
    {
        $stagedPath = Join-Path $stagingRoot $name
        $stagedReader = [NuGet.Packaging.PackageArchiveReader]::new($stagedPath)
        try
        {
            $stagedIdentity = $stagedReader.GetIdentity()
            $stagedCommit = $stagedReader.NuspecReader.GetRepositoryMetadata().Commit
        }
        finally
        {
            $stagedReader.Dispose()
        }

        if($stagedIdentity.Id -cne $expectedFamily[$name] -or $stagedIdentity.Version.ToNormalizedString() -cne $packageVersion)
        {
            $familyFaults.Add("$name (names $($stagedIdentity.Id) $($stagedIdentity.Version.ToNormalizedString()))")
        }

        if($name.EndsWith('.nupkg', [System.StringComparison]::Ordinal) -and $stagedCommit -cne $commitId)
        {
            $familyFaults.Add("$name (repository commit '$stagedCommit')")
        }

        $stagedFamily.Add(@{
            'Name' = $name
            'Path' = $stagedPath
            'Hash' = (Get-FileHash -LiteralPath $stagedPath -Algorithm SHA512).Hash
        })
    }

    if($familyFaults.Count -gt 0)
    {
        Stop-Packing "the family packed in $stagingRoot is not the $($expectedFamily.Count) archives of version $packageVersion from commit ${commitId}:`n$($familyFaults -join "`n")"
    }

    Write-Host "Checked the family in ${stagingRoot}: $($stagedFamily.Count) archives of version $packageVersion, each naming its project, the packages naming commit $commitId."

    #The number is reserved by creating its tag, which git refuses if the tag exists, after the record is
    #read once more, so a publication another run reserved since the first reading is never cut again.
    Assert-PublicationForward
    $absentObject = '0' * 40
    Invoke-IsolatedGit -Repository $repositoryRoot -Arguments @('update-ref', "$($publicationTagPrefix)$Publication", $commitId, $absentObject) -Purpose "reserve publication $Publication by creating its tag, which no publication may yet hold" -Separator "`n" | Out-Null
    Write-Host "Reserved publication ${Publication}: the tag local-publication/$Publication names commit $commitId."

    #The family is published into the output directory beside the previous one, each archive held to the
    #bytes checked, and only then is the previous family removed. A copy that fails removes every archive
    #this step wrote, so the output directory holds the previous family alone, as before the run.
    $outputDir = Join-Path $repositoryRoot 'generated-nugets'
    if(-not (Test-Path -LiteralPath $outputDir -PathType Container))
    {
        New-Item -ItemType Directory -Path $outputDir | Out-Null
    }

    $previousFamily = @(Get-ChildItem -LiteralPath $outputDir -File | Where-Object { $_.Extension -in @('.nupkg', '.snupkg') } | ForEach-Object { $_.FullName })
    $published = [System.Collections.Generic.List[string]]::new()
    try
    {
        foreach($staged in $stagedFamily)
        {
            $target = Join-Path $outputDir $staged['Name']
            if(Test-Path -LiteralPath $target)
            {
                Stop-Packing "the output directory already holds $target, which this run did not write."
            }

            $published.Add($target)
            [System.IO.File]::Copy($staged['Path'], $target, $false)
            if((Get-FileHash -LiteralPath $target -Algorithm SHA512).Hash -cne $staged['Hash'])
            {
                Stop-Packing "the archive published as $target is not the archive checked in $stagingRoot."
            }
        }
    }
    catch
    {
        foreach($written in $published)
        {
            if(Test-Path -LiteralPath $written)
            {
                Remove-Item -LiteralPath $written -Force
            }
        }

        throw
    }

    $remaining = [System.Collections.Generic.List[string]]::new()
    foreach($previous in $previousFamily)
    {
        try
        {
            Remove-Item -LiteralPath $previous -Force
        }
        catch
        {
            $remaining.Add("$previous ($($_.Exception.Message))")
        }
    }

    if($remaining.Count -gt 0)
    {
        Stop-Packing "the family of version $packageVersion stands complete in $outputDir, and these archives of the previous family could not be removed:`n$($remaining -join "`n")"
    }

    Write-Host "Generated $($projects.Count) packages in $outputDir with version $packageVersion from commit $commitId, packed in a checkout established against that commit file by file, restored from $($lockedPackages.Count) archives verified against the lock files' content hashes, with SDK $selectedVersion selected by the commit's global.json."
    $exitCode = 0
}
catch
{
    if($_.Exception -is [PackingRefusal])
    {
        $Host.UI.WriteErrorLine($_.Exception.Message)
    }
    else
    {
        $Host.UI.WriteErrorLine("Packing is refused: the run failed: $($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)")
    }
}
finally
{
    $httpClient.Dispose()
    $runCancellation.Dispose()
    if($null -ne $createdRunRoot -and (Test-Path -LiteralPath $createdRunRoot))
    {
        try
        {
            Remove-Item -LiteralPath $createdRunRoot -Recurse -Force
        }
        catch
        {
            $Host.UI.WriteErrorLine("The run directory $createdRunRoot could not be removed: $($_.Exception.Message)")
            $exitCode = 1
        }
    }
}

exit $exitCode
