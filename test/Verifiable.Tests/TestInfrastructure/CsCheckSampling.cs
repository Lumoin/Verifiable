namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The thread count every CsCheck property test in the suite passes to <c>Sample</c>/<c>SampleAsync</c>.
/// </summary>
/// <remarks>
/// The suite already runs test classes in parallel across the machine's logical processors, so a property
/// test must not fan its own samples out again: doing so multiplies CPU-bound work onto the shared thread
/// pool and starves the continuations of unrelated tests that are queued behind it.
/// </remarks>
internal static class CsCheckSampling
{
    /// <summary>
    /// Gets the thread count passed as CsCheck's <c>threads</c> argument. Its value is 1, so each property
    /// test evaluates its samples one at a time.
    /// </summary>
    public static int Threads
    {
        get;
    } = 1;
}
