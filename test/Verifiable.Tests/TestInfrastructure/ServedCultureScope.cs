using System.Collections.Concurrent;
using System.Globalization;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Sets <see cref="CultureInfo.DefaultThreadCurrentCulture"/> and <see cref="CultureInfo.CurrentCulture"/>
/// to a named culture for the lifetime of a real-wire row and records, for every request the host
/// serves while it is active, the culture name the server's own code ran under, proving that a
/// case fold a row asserts was actually computed under that culture on the server's side, not merely
/// that the client sent an upper-case value. The wrapper is installed on
/// <see cref="ResolveCapabilitiesDelegate"/> through <see cref="TestHostShell.AlterAsync"/> because
/// that delegate is consulted exactly once per request
/// (<see cref="Verifiable.Server.Pipeline.EndpointChain.BuildForRequestAsync"/>), the one call site
/// every capability-bearing request always reaches. Setting the process-wide culture is a global
/// operation: every concurrently running test observes it while this scope is alive, so its rows
/// are marked <c>[DoNotParallelize]</c>, on the same reasoning
/// <see cref="TraceTreeCapture"/>'s remarks give for its own consumers (an <see cref="System.Diagnostics.ActivityListener"/>,
/// also process-wide).
/// </summary>
internal sealed class ServedCultureScope : IDisposable
{
    /// <summary>
    /// The default thread culture recorded before this scope changed it, <see langword="null"/> when
    /// none was set, restored exactly on disposal.
    /// </summary>
    private CultureInfo? OriginalDefaultThreadCulture { get; }

    /// <summary>The current culture recorded before this scope changed it, restored on disposal.</summary>
    private CultureInfo OriginalCurrentCulture { get; }

    /// <summary>
    /// The culture name recorded on every request the host served while this scope has been active,
    /// one entry per request, in service order.
    /// </summary>
    private ConcurrentQueue<string> ServedCultureNameQueue { get; } = new();

    /// <summary>
    /// Holds the two cultures read before this scope changes them; <see cref="CreateAsync"/> is the
    /// only way to obtain an instance, because installing the resolver wrapper must complete before
    /// the culture actually changes.
    /// </summary>
    /// <param name="originalDefaultThreadCulture">The default thread culture to restore on disposal, <see langword="null"/> when none was set.</param>
    /// <param name="originalCurrentCulture">The current culture to restore on disposal.</param>
    private ServedCultureScope(CultureInfo? originalDefaultThreadCulture, CultureInfo originalCurrentCulture)
    {
        OriginalDefaultThreadCulture = originalDefaultThreadCulture;
        OriginalCurrentCulture = originalCurrentCulture;
    }

    /// <summary>Every culture name recorded so far, one per request served while this scope has been active.</summary>
    internal IReadOnlyCollection<string> ServedCultureNames => [.. ServedCultureNameQueue];

    /// <summary>
    /// Installs a <see cref="ResolveCapabilitiesDelegate"/> wrapper on <paramref name="host"/> that
    /// appends <see cref="CultureInfo.CurrentCulture"/>'s name to <see cref="ServedCultureNames"/> and
    /// delegates to the resolver already wired, then sets <see cref="CultureInfo.DefaultThreadCurrentCulture"/>
    /// and <see cref="CultureInfo.CurrentCulture"/> to <paramref name="cultureName"/>. The wrapper is
    /// installed before the culture changes, so the very first request this scope serves is already
    /// recorded under it.
    /// </summary>
    /// <param name="host">The fixture whose serving is altered.</param>
    /// <param name="cultureName">The culture every request must be served under.</param>
    /// <param name="cancellationToken">Cancellation of the alteration wait.</param>
    /// <returns>The active scope; dispose it to restore both cultures.</returns>
    internal static async Task<ServedCultureScope> CreateAsync(TestHostShell host, string cultureName, CancellationToken cancellationToken)
    {
        ServedCultureScope scope = new(CultureInfo.DefaultThreadCurrentCulture, CultureInfo.CurrentCulture);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            ResolveCapabilitiesDelegate wrapped = candidateIntegration.ResolveCapabilitiesAsync!;
            candidateIntegration.ResolveCapabilitiesAsync = (registration, context, ct) =>
            {
                scope.ServedCultureNameQueue.Enqueue(CultureInfo.CurrentCulture.Name);

                return wrapped(registration, context, ct);
            };
        }).ConfigureAwait(false);

        CultureInfo namedCulture = new(cultureName);
        CultureInfo.DefaultThreadCurrentCulture = namedCulture;
        CultureInfo.CurrentCulture = namedCulture;

        return scope;
    }

    /// <summary>
    /// Asserts that <see cref="ServedCultureNames"/> holds at least <paramref name="atLeast"/>
    /// entries and that every one of them equals <paramref name="cultureName"/>; the proof that the
    /// server's own code, not merely the row's own request construction, ran under the named
    /// culture for every request the row made.
    /// </summary>
    /// <param name="cultureName">The culture every recorded request must have been served under.</param>
    /// <param name="atLeast">The minimum number of requests the scope must have observed.</param>
    internal void AssertEveryRequestWasServedUnder(string cultureName, int atLeast)
    {
        string[] names = [.. ServedCultureNameQueue];

        Assert.IsGreaterThanOrEqualTo(atLeast, names.Length,
            $"Expected at least {atLeast} request(s) recorded under '{cultureName}'; observed {names.Length}.");

        foreach(string name in names)
        {
            Assert.AreEqual(cultureName, name);
        }
    }

    /// <summary>
    /// Restores both cultures this scope changed, the default thread culture to exactly the value
    /// it found, <see langword="null"/> included.
    /// </summary>
    public void Dispose()
    {
        CultureInfo.DefaultThreadCurrentCulture = OriginalDefaultThreadCulture;
        CultureInfo.CurrentCulture = OriginalCurrentCulture;
    }
}
