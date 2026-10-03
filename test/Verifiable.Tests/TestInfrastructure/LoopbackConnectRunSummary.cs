namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Holds the assembly-level cleanup that writes <see cref="LoopbackConnect"/>'s connect and retry
/// counts once, through <see cref="LoopbackKestrelDiagnostics.Provider"/>, when the test run ends. It
/// carries no test: the line it causes is read from the run's output, and no assertion rests on the
/// numbers.
/// </summary>
[TestClass]
internal static class LoopbackConnectRunSummary
{
    /// <summary>
    /// Writes the process's connect and retry counts once, after the last test of the assembly has run,
    /// and completes when the line has been written to the output, so the process does not end before it.
    /// </summary>
    /// <returns>A task that completes once the line has been written.</returns>
    [AssemblyCleanup]
    public static Task WriteSummaryAsync() => LoopbackConnect.WriteRunSummaryAsync(LoopbackKestrelDiagnostics.Provider);
}
