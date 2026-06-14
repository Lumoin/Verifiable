using Verifiable.Cryptography.Text;


namespace Verifiable.Server.Diagnostics;

/// <summary>
/// Span event names emitted during protocol-neutral endpoint host dispatch operations.
/// </summary>
/// <remarks>
/// <para>
/// Events are points in time within a span. Host dispatch events capture the dispatch
/// loop milestones: flow creation, correlation resolution outcomes, and PDA state transitions.
/// </para>
/// </remarks>
public static class ServerEventNames
{
    /// <summary>The UTF-8 source literal of <see cref="StateTransition"/>.</summary>
    public static ReadOnlySpan<byte> StateTransitionUtf8 => "server.flow.state_transition"u8;

    /// <summary>
    /// The PDA transitioned to a new state.
    /// </summary>
    public static readonly string StateTransition = Utf8Constants.ToInternedString(StateTransitionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CorrelationResolved"/>.</summary>
    public static ReadOnlySpan<byte> CorrelationResolvedUtf8 => "server.correlation.resolved"u8;

    /// <summary>
    /// The correlation key was resolved from an external handle to the
    /// internal flow identifier.
    /// </summary>
    public static readonly string CorrelationResolved = Utf8Constants.ToInternedString(CorrelationResolvedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CorrelationNotFound"/>.</summary>
    public static ReadOnlySpan<byte> CorrelationNotFoundUtf8 => "server.correlation.not_found"u8;

    /// <summary>
    /// The correlation key could not be resolved — flow not found.
    /// </summary>
    public static readonly string CorrelationNotFound = Utf8Constants.ToInternedString(CorrelationNotFoundUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FlowCreated"/>.</summary>
    public static ReadOnlySpan<byte> FlowCreatedUtf8 => "server.flow.created"u8;

    /// <summary>
    /// A new flow was created with a fresh internal flow identifier.
    /// </summary>
    public static readonly string FlowCreated = Utf8Constants.ToInternedString(FlowCreatedUtf8);
}
