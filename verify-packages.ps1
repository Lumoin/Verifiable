# Path to Directory.Packages.props
$packagesPropsPath = "./Directory.Packages.props"

Write-Host "Package props path: $packagesPropsPath"

# Read and parse the Directory.Packages.props file
[xml]$packagesProps = Get-Content $packagesPropsPath

# Initialize a flag to track if any verification fails
$verificationFailed = $false

foreach ($package in $packagesProps.Project.ItemGroup.PackageVersion) {
    $packageName = $package.Include
    $packageVersion = $package.Version

    # Construct the package path
    $packagePath = "$env:USERPROFILE\.nuget\packages\$packageName\$packageVersion\$packageName.$packageVersion.nupkg"

    # Print the package being verified
    Write-Output "Verifying package: $packageName, Version: $packageVersion"

    # Verification command string
    $command = "dotnet nuget verify --all --verbosity normal `"$packagePath`" --configfile NuGet.config"

    # Execute the command and capture the output
    try {
        Write-Output "Executing: $command"
        & dotnet nuget verify --all --verbosity normal "$packagePath" --configfile NuGet.config
    } catch {
        Write-Output "ERROR: Verification failed for $packageName, Version: $packageVersion"
        $verificationFailed = $true
    }
	
	# Also check the exit code explicitly if needed
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Verification failed for $packageName, Version: $packageVersion (Exit Code: $LASTEXITCODE)" -ForegroundColor Red
        $verificationFailed = $true
    }
}

# Check if any verifications failed
if ($verificationFailed) {
    Write-Host "One or more package verifications failed." -ForegroundColor Red
    exit 1
} else {
    Write-Host "All package verifications succeeded." -ForegroundColor Green
}
