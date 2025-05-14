$CoverageTargetDir = './generated-reports/coverage/'
$CoverageOutputFile = './generated-reports/coverage.cobertura.xml'

if (Test-Path $CoverageTargetDir) {
    Remove-Item -Recurse -Force $CoverageTargetDir
}

dotnet build Verifiable.sln
dotnet tool run dotnet-coverage collect --output $CoverageOutputFile --output-format cobertura test/Verifiable.Tests/bin/Debug/net10.0/Verifiable.Tests.exe --report-trx --report-trx-filename testresults.trx --results-directory $CoverageTargetDir
dotnet reportgenerator -filefilters:"-**\obj\**;-**\*.g.cs" -assemblyfilters:"+Verifiable*" -reports:$CoverageOutputFile -targetdir:$CoverageTargetDir -reporttypes:"HtmlInline"
