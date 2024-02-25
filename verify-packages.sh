#!/bin/bash

packagesPropsPath="./Directory.Packages.props"

echo "Package props path: $packagesPropsPath"

# Prepare an XPath expression to extract PackageVersion attributes
xpathExpression="//Project/ItemGroup/PackageVersion"

# Read and parse each PackageVersion node from Directory.Packages.props
xmllint --xpath "${xpathExpression}" $packagesPropsPath 2>/dev/null | \
grep -oP 'Include="\K[^"]+' | \
while read packageName; do
    packageVersion=$(xmllint --xpath "string(//Project/ItemGroup/PackageVersion[@Include='$packageName']/@Version)" $packagesPropsPath 2>/dev/null)
    
    packagePath="$HOME/.nuget/packages/$packageName/$packageVersion/$packageName.$packageVersion.nupkg"
    echo "Verifying package: $packageName, Version: $packageVersion"
    command="dotnet nuget verify --all --verbosity normal '$packagePath' --configfile NuGet.config"
    echo "Executing: $command"
    if ! eval $command; then
        echo "ERROR: Verification failed for $packageName, Version: $packageVersion"
        verificationFailed=true
    fi
done

if [ "$verificationFailed" = true ]; then
    echo "One or more package verifications failed."
    exit 1
else
    echo "All package verifications succeeded."
fi
