using Verifiable.Core;
using Verifiable.Core.Outbound;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The shapes in which a dependency reports that its work was cancelled, shared by every test that proves a boundary
/// tells a cancellation from a failure of the dependency's own kind: <c>bare</c>, the
/// <see cref="OperationCanceledException"/> itself; <c>wrapped</c>, the cancellation as the inner exception of the
/// dependency's own exception; <c>aggregated</c>, the cancellation as the second inner exception of an
/// <see cref="AggregateException"/> whose first is an ordinary fault.
/// </summary>
/// <remarks>
/// Every message names <see cref="PrivateReason"/>, a private host and path standing for the dependency's own
/// diagnostic, which a response must never repeat.
/// </remarks>
internal static class CarriedCancellationFixtures
{
    /// <summary>The private host and path every carrier's message names, which no response may repeat.</summary>
    public static string PrivateReason { get; } = "private-policy-host/path";


    /// <summary>Creates the exception a dependency raises when its work is cancelled, in <paramref name="cancellationShape"/>.</summary>
    /// <param name="cancellationShape">The shape: <c>bare</c>, <c>wrapped</c> or <c>aggregated</c>.</param>
    /// <returns>The exception the dependency raises.</returns>
    public static Exception Create(string cancellationShape) => cancellationShape switch
    {
        "bare" => new OperationCanceledException(PrivateReason),
        "wrapped" => new IOException(PrivateReason, new OperationCanceledException(PrivateReason)),
        "aggregated" => new AggregateException(new IOException(PrivateReason), new OperationCanceledException(PrivateReason)),
        _ => throw new ArgumentOutOfRangeException(nameof(cancellationShape), cancellationShape, "Unknown cancellation shape.")
    };


    /// <summary>
    /// A single-hop transport that, once entered, cancels <paramref name="caller"/> when one is given, standing for a
    /// caller that abandons its request while the fetch runs, and then fails the fetch with the cancellation
    /// <see cref="Create"/> builds in <paramref name="cancellationShape"/>. Without a caller to cancel, the cancellation
    /// is the fetch's own budget running out while its caller still waits.
    /// </summary>
    /// <param name="cancellationShape">The shape the transport reports the cancellation in.</param>
    /// <param name="caller">The caller's token source, cancelled as the fetch starts, or <see langword="null"/> to leave it live.</param>
    /// <returns>The transport delegate.</returns>
    public static OutboundTransportDelegate CreateTransport(string cancellationShape, CancellationTokenSource? caller) =>
        async (request, context, readResponse, cancellationToken) =>
        {
            if(caller is not null)
            {
                await caller.CancelAsync().ConfigureAwait(false);
            }

            throw Create(cancellationShape);
        };


    /// <summary>
    /// Asserts that <paramref name="resolve"/> ends with the cancellation it met, never a result of its own: the
    /// <see cref="OperationCanceledException"/> itself, whatever wrapper carried it, which the caller classifies as its
    /// own when <paramref name="callerToken"/> was cancelled and as a dependency's own budget when it is still live
    /// (<see cref="WrappedCancellation.IsOwnBudgetCancellation"/>).
    /// </summary>
    /// <param name="resolve">The call under test.</param>
    /// <param name="isCallerCancelled">Whether the caller cancelled while the call ran.</param>
    /// <param name="callerToken">The caller's token the call ran under.</param>
    /// <returns>A task completing when the assertion has run.</returns>
    public static async Task AssertPropagatesAsTheCancellationAsync(Func<Task> resolve, bool isCallerCancelled, CancellationToken callerToken)
    {
        OperationCanceledException propagated = await Assert.ThrowsExactlyAsync<OperationCanceledException>(resolve).ConfigureAwait(false);

        Assert.AreEqual(isCallerCancelled, callerToken.IsCancellationRequested,
            "The caller's token is cancelled exactly when the caller abandoned the call.");
        Assert.AreEqual(!isCallerCancelled, WrappedCancellation.IsOwnBudgetCancellation(propagated, callerToken),
            "The caller classifies a cancellation met while its token is live as a dependency's own budget, and its own otherwise.");
    }
}
