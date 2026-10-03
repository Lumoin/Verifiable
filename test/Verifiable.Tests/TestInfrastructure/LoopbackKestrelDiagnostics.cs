using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The <see cref="ILoggerProvider"/> every loopback host bootstrap attaches via
/// <see cref="LoopbackKestrel.ConfigureLoopbackLogging"/> in place of the default providers
/// <c>Logging.ClearProviders()</c> removes on its own. Kestrel logs from its own connection threads, so
/// without a provider attached its own reason for closing a connection (a handshake timeout, a
/// request-headers timeout, the socket send loop completing) reaches no capture anywhere. This provider
/// formats every Warning-or-above log call into one line and writes it to <see cref="Console.Out"/>,
/// which the test runner's captured console output records for the run — a server-side abort therefore
/// names its reason in the run capture — and appends the line to <see cref="Captured"/>, the provider's
/// own testable observation surface. The console write runs on a thread-pool work item that does not
/// carry the caller's <see cref="ExecutionContext"/>: the runner keeps a line written inside a test's
/// own flow (a test client's connect, <see cref="LoopbackConnect"/>) in that test's captured output,
/// which it prints only for a failing test, while a line written outside any test's flow reaches the
/// run's output.
/// </summary>
internal sealed class LoopbackKestrelDiagnostics: ILoggerProvider
{
    /// <summary>The number of most-recent lines <see cref="Captured"/> retains; older lines are evicted.</summary>
    private const int CapturedCapacity = 256;

    /// <summary>
    /// The one instance every loopback host's logging pipeline attaches (<see cref="LoopbackKestrel.ConfigureLoopbackLogging"/>),
    /// so every host's Kestrel diagnostics land in the same <see cref="Captured"/> ring regardless of
    /// which host's listener emitted them.
    /// </summary>
    internal static LoopbackKestrelDiagnostics Provider { get; } = new(isConsoleWriteEnabled: true);

    /// <summary>The bounded ring buffer backing <see cref="Captured"/>.</summary>
    private ConcurrentQueue<string> CapturedLines { get; } = new();


    /// <summary>Whether a formatted line is also written to <see cref="Console.Out"/>; a line is always appended to <see cref="Captured"/>.</summary>
    private bool IsConsoleWriteEnabled { get; }


    /// <summary>Private: every caller reaches an instance through <see cref="Provider"/>, <see cref="CreateIsolated"/> or <see cref="CreateCapturingOnly"/>, never a public constructor.</summary>
    /// <param name="isConsoleWriteEnabled">Whether the instance writes each line to <see cref="Console.Out"/> as well as capturing it.</param>
    private LoopbackKestrelDiagnostics(bool isConsoleWriteEnabled)
    {
        IsConsoleWriteEnabled = isConsoleWriteEnabled;
    }


    /// <summary>
    /// Creates a fresh <see cref="LoopbackKestrelDiagnostics"/> distinct from <see cref="Provider"/> and
    /// from every other instance this method returns. A test that asserts on <see cref="Captured"/>
    /// probes an instance from here rather than <see cref="Provider"/>, so its assertions never share
    /// the process-wide ring with the concurrently running hosts <see cref="Provider"/> serves.
    /// </summary>
    internal static LoopbackKestrelDiagnostics CreateIsolated() => new(isConsoleWriteEnabled: true);


    /// <summary>
    /// Creates a fresh <see cref="LoopbackKestrelDiagnostics"/> as <see cref="CreateIsolated"/> does,
    /// whose lines are captured in <see cref="Captured"/> and never written to <see cref="Console.Out"/>,
    /// for a test that writes a line the run's output carries once, from its own owner, and must not add
    /// a second copy.
    /// </summary>
    internal static LoopbackKestrelDiagnostics CreateCapturingOnly() => new(isConsoleWriteEnabled: false);


    /// <summary>The last <see cref="CapturedCapacity"/> Warning-or-above lines this provider's loggers formatted, oldest first.</summary>
    public IReadOnlyList<string> Captured => [.. CapturedLines];


    /// <summary>Creates the per-category <see cref="ILogger"/> every logging pipeline this provider is attached to asks for.</summary>
    /// <param name="categoryName">The logging category, e.g. <c>Microsoft.AspNetCore.Server.Kestrel.Core.HttpsConnectionMiddleware</c>.</param>
    public ILogger CreateLogger(string categoryName) => new CapturingLogger(this, categoryName);


    /// <summary>
    /// A no-op: <see cref="Provider"/> is a process-wide singleton that outlives any one host's
    /// <c>WebApplication</c>, and that host's own logger factory disposes the providers it was given
    /// as if it owned them.
    /// </summary>
    public void Dispose()
    {
    }


    /// <summary>
    /// Writes one Warning-level line through this provider's own channel, the one every logger it hands
    /// out uses, and returns a task that completes when the console write has run: a caller that must
    /// see the line reach <see cref="Console.Out"/> before it returns (an assembly cleanup, after which
    /// the process ends) awaits it. The task is already complete when the instance writes no console line.
    /// </summary>
    /// <param name="categoryName">The logging category named in the line.</param>
    /// <param name="eventId">The event id named in the line.</param>
    /// <param name="message">The message the line carries.</param>
    /// <returns>A task that completes once the line has been written and captured.</returns>
    internal Task WriteAsync(string categoryName, EventId eventId, string message)
    {
        ArgumentNullException.ThrowIfNull(categoryName);
        ArgumentNullException.ThrowIfNull(message);

        return Deliver(FormatLine(categoryName, eventId, message, exception: null));
    }


    /// <summary>
    /// Formats the one line shape every log call of this provider produces:
    /// <c>[loopback-kestrel] {category}[{eventId}] {message}</c>, with a trailing
    /// <c>(ExceptionType: message)</c> when the call carried an exception.
    /// </summary>
    /// <param name="categoryName">The logging category.</param>
    /// <param name="eventId">The event id.</param>
    /// <param name="message">The formatted message.</param>
    /// <param name="exception">The exception the call carried, or <see langword="null"/>.</param>
    private static string FormatLine(string categoryName, EventId eventId, string message, Exception? exception)
    {
        string exceptionSummary = exception is null
            ? string.Empty
            : $" ({exception.GetType().Name}: {exception.Message})";

        return $"[loopback-kestrel] {categoryName}[{eventId}] {message}{exceptionSummary}";
    }


    /// <summary>
    /// Captures <paramref name="line"/> and, when console writes are enabled, writes it to
    /// <see cref="Console.Out"/> on a thread-pool work item that does not carry the caller's
    /// <see cref="ExecutionContext"/>, so the runner prints it in the run's output instead of keeping
    /// it in the captured output of the test that logged it, which the runner shows only when that test
    /// fails.
    /// </summary>
    /// <param name="line">The fully formatted diagnostic line.</param>
    /// <returns>
    /// A task that completes after the console write has returned, faults with the write's exception when the
    /// write throws, or completes at once when none is made.
    /// </returns>
    private Task Deliver(string line)
    {
        Append(line);
        if(!IsConsoleWriteEnabled)
        {

            return Task.CompletedTask;
        }

        TaskCompletionSource written = new(TaskCreationOptions.RunContinuationsAsynchronously);
        _ = ThreadPool.UnsafeQueueUserWorkItem(
            static state =>
            {
                try
                {
                    Console.Out.WriteLine(state.Line);
                    _ = state.Written.TrySetResult();
                }
                catch(Exception exception)
                {
                    _ = state.Written.TrySetException(exception);
                }
            },
            (Line: line, Written: written),
            preferLocal: false);

        return written.Task;
    }


    /// <summary>Appends <paramref name="line"/> to <see cref="Captured"/>, evicting the oldest line once the ring exceeds <see cref="CapturedCapacity"/>.</summary>
    /// <param name="line">The fully formatted diagnostic line.</param>
    private void Append(string line)
    {
        CapturedLines.Enqueue(line);
        while(CapturedLines.Count > CapturedCapacity && CapturedLines.TryDequeue(out _))
        {
        }
    }


    /// <summary>
    /// The <see cref="ILogger"/> <see cref="LoopbackKestrelDiagnostics"/> hands out per category. At
    /// <see cref="LogLevel.Warning"/> or above it formats one line —
    /// <c>[loopback-kestrel] {category}[{eventId}] {message}</c>, with a trailing
    /// <c>(ExceptionType: message)</c> when the log call carried an exception — writes it to
    /// <see cref="Console.Out"/>, and appends it to the owning provider's <see cref="Captured"/> ring.
    /// Below <see cref="LogLevel.Warning"/>, nothing is formatted, written, or captured.
    /// </summary>
    private sealed class CapturingLogger: ILogger
    {
        /// <summary>The provider whose <see cref="Captured"/> ring this logger appends to.</summary>
        private LoopbackKestrelDiagnostics Owner { get; }

        /// <summary>The logging category this logger was created for.</summary>
        private string CategoryName { get; }


        /// <summary>Binds this logger to the provider that owns its <see cref="Captured"/> ring and to its logging category.</summary>
        /// <param name="owner">The owning provider.</param>
        /// <param name="categoryName">The logging category.</param>
        public CapturingLogger(LoopbackKestrelDiagnostics owner, string categoryName)
        {
            this.Owner = owner;
            this.CategoryName = categoryName;
        }


        /// <summary>No scoped state is tracked by this logger; every call answers with no disposable scope.</summary>
        /// <typeparam name="TState">The scope state's type.</typeparam>
        /// <param name="state">The scope state.</param>
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;


        /// <summary>Only <see cref="LogLevel.Warning"/> and above are captured — the abort-naming Kestrel diagnostics, not routine request tracing.</summary>
        /// <param name="logLevel">The level of the pending log call.</param>
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;


        /// <summary>
        /// Formats, writes, and captures one log call at <see cref="LogLevel.Warning"/> or above;
        /// a call below that level is a no-op, per <see cref="IsEnabled"/>.
        /// </summary>
        /// <typeparam name="TState">The log call's state type.</typeparam>
        /// <param name="logLevel">The log call's level.</param>
        /// <param name="eventId">The log call's event id.</param>
        /// <param name="state">The log call's state.</param>
        /// <param name="exception">The exception the log call carried, or <see langword="null"/>.</param>
        /// <param name="formatter">Renders <paramref name="state"/> and <paramref name="exception"/> into the log message.</param>
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);

            if(!IsEnabled(logLevel))
            {
                return;
            }

            string message = formatter(state, exception);
            _ = Owner.Deliver(FormatLine(CategoryName, eventId, message, exception));
        }
    }
}
