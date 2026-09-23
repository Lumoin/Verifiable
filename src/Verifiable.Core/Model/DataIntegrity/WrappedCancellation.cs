using System.Runtime.ExceptionServices;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Classifies an exception that a verification dependency raised — a canonicalizer or the context loader it drives, a
/// DID resolver, a status list or schema resolver, a digest or signature function — by the cancellation it carries: an
/// <see cref="OperationCanceledException"/> the exception is, or carries among its inner exceptions, is that cancellation,
/// not a failure of the dependency's own kind.
/// </summary>
/// <remarks>
/// <para>
/// A JSON-LD processor, a transport or a task combinator commonly reports the cancellation of work it was doing wrapped in
/// an exception of its own: an <see cref="Exception.InnerException"/> chain, or an <see cref="AggregateException"/> whose
/// cancellation need not be its first inner exception. Reporting such a wrapper as the dependency's own failure would hide
/// the cancellation from the caller, which is the one that decides from a cancellation whether its own request was
/// abandoned or a dependency ended on its own budget.
/// </para>
/// <para>
/// Every verification boundary classifies through this one type: Core's canonicalization sites rethrow a carried
/// cancellation with <see cref="ThrowIfCarried"/>, and a boundary that turns a dependency's own-budget cancellation into a
/// verification result asks <see cref="IsOwnBudgetCancellation"/>, so a bare and a wrapped cancellation are one case
/// wherever they surface.
/// </para>
/// </remarks>
public static class WrappedCancellation
{
    /// <summary>
    /// Finds the <see cref="OperationCanceledException"/> that <paramref name="exception"/> is or carries: the exception
    /// itself, the exceptions of its <see cref="Exception.InnerException"/> chain, and every inner exception of an
    /// <see cref="AggregateException"/> met along the way, not only its first.
    /// </summary>
    /// <param name="exception">The exception to search, or <see langword="null"/> at the end of a chain.</param>
    /// <returns>The first cancellation found, or <see langword="null"/> when the exception carries none.</returns>
    public static OperationCanceledException? FindCancellation(Exception? exception) => exception switch
    {
        null => null,
        OperationCanceledException cancellation => cancellation,
        AggregateException aggregate => FindCancellationInAggregate(aggregate),
        _ => FindCancellation(exception.InnerException)
    };


    /// <summary>
    /// Whether <paramref name="exception"/> is, or carries, the cancellation of a dependency that ended on its own budget: a
    /// cancellation <see cref="FindCancellation"/> finds while <paramref name="callerToken"/>, the token of the caller the
    /// dependency served, has not been cancelled. A cancellation found after the caller cancelled is the caller's own and is
    /// not a dependency's budget.
    /// </summary>
    /// <param name="exception">The exception the dependency raised.</param>
    /// <param name="callerToken">The caller's own cancellation token.</param>
    /// <returns><see langword="true"/> when the exception is a dependency's own-budget cancellation, bare or wrapped.</returns>
    public static bool IsOwnBudgetCancellation(Exception exception, CancellationToken callerToken) =>
        !callerToken.IsCancellationRequested && FindCancellation(exception) is not null;


    /// <summary>
    /// Rethrows, with its original stack trace, the <see cref="OperationCanceledException"/> <paramref name="exception"/>
    /// carries (<see cref="FindCancellation"/>), and returns normally when it carries none.
    /// </summary>
    /// <param name="exception">The exception a dependency raised.</param>
    public static void ThrowIfCarried(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);

        if(FindCancellation(exception) is { } cancellation)
        {
            ExceptionDispatchInfo.Capture(cancellation).Throw();
        }
    }


    /// <summary>
    /// Finds the first cancellation any inner exception of <paramref name="aggregate"/> is or carries, in the order the
    /// aggregate holds them.
    /// </summary>
    /// <param name="aggregate">The aggregate to search.</param>
    /// <returns>The first cancellation found, or <see langword="null"/> when no inner exception carries one.</returns>
    private static OperationCanceledException? FindCancellationInAggregate(AggregateException aggregate)
    {
        foreach(Exception inner in aggregate.InnerExceptions)
        {
            if(FindCancellation(inner) is { } cancellation)
            {
                return cancellation;
            }
        }

        return null;
    }
}
