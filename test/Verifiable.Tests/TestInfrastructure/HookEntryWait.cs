namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The one body through which a test waits for the requests it has in flight to enter a hook it
/// installed (a store seam, a registration callback, an observer) before it releases them. The wait
/// races the barrier the hook sets against the requests that are to enter it, and nothing else: no
/// timer, no delay and no polling. The invariant: a test that waits for its requests to enter a hook
/// ends when they have entered or when one of them has ended without entering. A request that ends before
/// the barrier is set (faulted, cancelled, or completed) can never reach the hook it was to reach, so
/// the wait fails at once with that request's own outcome instead of waiting for a barrier nothing
/// will set; the only other end is the cancellation of the test's own token.
/// </summary>
internal static class HookEntryWait
{
    /// <summary>
    /// Waits until <paramref name="entered"/> is set, ending at once when <paramref name="request"/>
    /// ends first.
    /// </summary>
    /// <param name="entered">The task the hook completes when the request has entered it.</param>
    /// <param name="request">The in-flight request that is to enter the hook.</param>
    /// <param name="cancellationToken">The test's own token; its cancellation ends the wait.</param>
    /// <returns>A task that completes when <paramref name="entered"/> has completed.</returns>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled, or the request ended by cancellation.</exception>
    internal static Task WaitForEntryAsync(Task entered, Task request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        return WaitForEntryAsync(entered, [request], cancellationToken);
    }


    /// <summary>
    /// Waits until <paramref name="entered"/> is set, ending at once when any of
    /// <paramref name="requests"/> ends first. A request that faulted or was cancelled before the
    /// barrier was set throws its own exception as it is, not wrapped in another type; a request that
    /// ran to completion without the barrier being set fails an assertion that names the request by
    /// its position, its status, and its status code and body where the task carries them
    /// (<see cref="HttpResponseMessage"/>, <see cref="ServerHttpResponse"/>, a status and body pair, a
    /// string body). A request that ends after the barrier is set does not fail the wait.
    /// </summary>
    /// <param name="entered">The task the hook completes when every request that is to enter has entered.</param>
    /// <param name="requests">The in-flight requests that are to enter the hook.</param>
    /// <param name="cancellationToken">The test's own token; its cancellation ends the wait.</param>
    /// <returns>A task that completes when <paramref name="entered"/> has completed.</returns>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled, or a request ended by cancellation.</exception>
    internal static async Task WaitForEntryAsync(Task entered, IReadOnlyList<Task> requests, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entered);
        ArgumentNullException.ThrowIfNull(requests);

        Task[] pending = [.. requests];
        Task entry = entered.WaitAsync(cancellationToken);
        Task[] contenders = [entry, .. pending];
        Task first = await Task.WhenAny(contenders).ConfigureAwait(false);
        if(ReferenceEquals(first, entry) || entered.IsCompleted)
        {
            await entry.ConfigureAwait(false);

            return;
        }

        //The request ended with the barrier unset. A faulted or cancelled request throws its own
        //exception here; a completed one is reported below with what it carries.
        await first.ConfigureAwait(false);
        int index = Array.IndexOf(pending, first);
        string carried = await DescribeAsync(first, cancellationToken).ConfigureAwait(false);
        Assert.Fail($"Request {index} ended with status {first.Status} before it entered the hook; {carried}.");
    }


    /// <summary>
    /// Waits for a value a request in flight must produce before it can end (an observation the
    /// server writes ahead of its response), ending at once when any of <paramref name="requests"/> ends
    /// first, by the one race of
    /// <see cref="WaitForEntryAsync(Task, IReadOnlyList{Task}, CancellationToken)"/>, and hands back
    /// the value. The caller names a read this way only where the request cannot end before the code
    /// that produces the value has run.
    /// </summary>
    /// <typeparam name="T">The type of the value the read produces.</typeparam>
    /// <param name="produced">The read; it completes with the value when the server has produced it.</param>
    /// <param name="requests">The in-flight requests that produce the value.</param>
    /// <param name="cancellationToken">The test's own token; its cancellation ends the wait.</param>
    /// <returns>The value <paramref name="produced"/> completed with.</returns>
    /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled, or a request ended by cancellation.</exception>
    internal static async Task<T> WaitForValueAsync<T>(Task<T> produced, IReadOnlyList<Task> requests, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(produced);

        await WaitForEntryAsync(produced, requests, cancellationToken).ConfigureAwait(false);

        return await produced.ConfigureAwait(false);
    }


    /// <summary>
    /// Describes what a request that ran to completion carries: the status code and body of an HTTP
    /// response, or the text a task of the other recognised shapes holds.
    /// </summary>
    /// <param name="request">The completed request.</param>
    /// <param name="cancellationToken">Bounds reading a response body.</param>
    /// <returns>The description, naming the status code and body where the task carries them.</returns>
    private static async Task<string> DescribeAsync(Task request, CancellationToken cancellationToken) => request switch
    {
        Task<HttpResponseMessage> response => await DescribeResponseAsync(await response.ConfigureAwait(false), cancellationToken).ConfigureAwait(false),
        Task<ServerHttpResponse> response => Describe((await response.ConfigureAwait(false)).StatusCode, (await response.ConfigureAwait(false)).Body),
        Task<(int StatusCode, string Body)> pair => Describe((await pair.ConfigureAwait(false)).StatusCode, (await pair.ConfigureAwait(false)).Body),
        Task<(int Index, int Status, string Body)> triple => Describe((await triple.ConfigureAwait(false)).Status, (await triple.ConfigureAwait(false)).Body),
        Task<string> text => $"body '{await text.ConfigureAwait(false)}'",
        _ => "the task carries no status code or body"
    };


    /// <summary>Describes an HTTP response by its status code and the body its content holds.</summary>
    /// <param name="response">The response a completed request carried.</param>
    /// <param name="cancellationToken">Bounds reading the body.</param>
    /// <returns>The description naming the status code and body.</returns>
    private static async Task<string> DescribeResponseAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return Describe((int)response.StatusCode, body);
    }


    /// <summary>Formats a status code and a body the way the failure message names them.</summary>
    /// <param name="statusCode">The status code.</param>
    /// <param name="body">The body.</param>
    /// <returns>The formatted text.</returns>
    private static string Describe(int statusCode, string body) => $"status code {statusCode}, body '{body}'";
}
