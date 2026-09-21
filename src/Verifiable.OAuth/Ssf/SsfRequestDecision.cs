using Verifiable.Core;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Ssf;

/// <summary>
/// Identifies which SSF 1.0 Stream Management API operation
/// <see cref="SsfRequestEvaluation"/> describes, so the application's
/// <see cref="AuthorizeSsfRequestDelegate"/> knows what is being asked without
/// inspecting the wire request itself.
/// </summary>
public enum SsfRequestOperation
{
    /// <summary>Create Stream. <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1">SSF 1.0 §8.1.1.1</see>.</summary>
    CreateStream = 0,

    /// <summary>Read Stream(s). <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.2">SSF 1.0 §8.1.1.2</see>.</summary>
    ReadStream,

    /// <summary>Update Stream (PATCH semantics). <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.3">SSF 1.0 §8.1.1.3</see>.</summary>
    UpdateStream,

    /// <summary>Replace Stream (PUT semantics). <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.4">SSF 1.0 §8.1.1.4</see>.</summary>
    ReplaceStream,

    /// <summary>Delete Stream. <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.5">SSF 1.0 §8.1.1.5</see>.</summary>
    DeleteStream,

    /// <summary>Read Stream Status. <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.1">SSF 1.0 §8.1.2.1</see>.</summary>
    ReadStatus,

    /// <summary>Update Stream Status. <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.2.2">SSF 1.0 §8.1.2.2</see>.</summary>
    UpdateStatus,

    /// <summary>Add Subject. <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3.2">SSF 1.0 §8.1.3.2</see>.</summary>
    AddSubject,

    /// <summary>Remove Subject. <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.3.3">SSF 1.0 §8.1.3.3</see>.</summary>
    RemoveSubject,

    /// <summary>Trigger Verification. <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.4.2">SSF 1.0 §8.1.4.2</see>.</summary>
    Verify
}


/// <summary>
/// The immutable snapshot of facts about one Stream Management API request, handed to
/// <see cref="AuthorizeSsfRequestDelegate"/> so the application can decide bearer validity,
/// tenant authority and stream-level access without re-deriving them from the wire request.
/// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8-3">SSF 1.0 §8</see>
/// requires this authorization to associate a Receiver with the stream IDs it may access.
/// </summary>
public sealed record SsfRequestEvaluation
{
    /// <summary>The management operation this request performs.</summary>
    public required SsfRequestOperation Operation { get; init; }

    /// <summary>The scope the operation requires (<c>ssf.read</c> or <c>ssf.manage</c>).</summary>
    public required string RequiredScope { get; init; }

    /// <summary>
    /// The tenant of the <see cref="ClientRecord"/> registration the request resolved to —
    /// the same tenant whose store the delegates receive. The application's
    /// <see cref="AuthorizeSsfRequestDelegate"/> decides the caller's authority on this value
    /// with its own policy; it must not decide on another source, such as the request's raw
    /// URL segment or a value it reads off <c>ExchangeContext</c> itself, because those can
    /// diverge from the registration the store touches (a host-preset registration, or a
    /// materializer that resolved a different tenant).
    /// </summary>
    public required TenantId TenantId { get; init; }

    /// <summary>
    /// The <c>stream_id</c> the request names: the query parameter for a read, delete or
    /// status read, or the value the endpoint already extracted from the parsed request body
    /// for an update, replace, status update, subject add, subject remove or verify — a
    /// malformed body answers its operation's existing 400 before this evaluation is ever
    /// built. <see langword="null"/> only for a create, which names no stream yet. Knowing
    /// this value here lets <see cref="AuthorizeSsfRequestDelegate"/> answer
    /// <see cref="SsfRequestDenialReason.StreamNotAvailableToReceiver"/> for every operation
    /// that names a stream, not only a read; a stream unknown even to the tenant is instead
    /// the store's own not-found outcome once the store runs.
    /// </summary>
    public string? StreamId { get; init; }

    /// <summary>The incoming request, carrying the Authorization header the application validates.</summary>
    public required IncomingRequest Request { get; init; }
}


/// <summary>
/// The reason a Stream Management API request was denied at the
/// <see cref="AuthorizeSsfRequestDelegate"/> seam. The library maps each reason to the
/// corresponding HTTP status per
/// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1">SSF 1.0 §8.1.1.1</see>'s
/// Create Stream Errors table (and the parallel tables for the other operations).
/// </summary>
public enum SsfRequestDenialReason
{
    /// <summary>The token is missing, invalid or expired.</summary>
    AuthenticationRequired = 0,

    /// <summary>The token is valid but its granted scope does not permit the operation.</summary>
    InsufficientScope,

    /// <summary>The caller has no authority on this tenant.</summary>
    NotAuthorizedForTenant,

    /// <summary>The stream exists on the tenant, but not for this caller.</summary>
    StreamNotAvailableToReceiver
}


/// <summary>
/// The host's own stable identifier for one authenticated Receiver, carried by a permitted
/// <see cref="SsfRequestDecision"/> to every store delegate so it can bind stream data to the
/// Receiver that reached it — <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8-3">SSF 1.0 §8</see>:
/// "This authorization MUST associate a Receiver with one or more stream IDs ... such that
/// only authorized Receivers are able to access or modify the details of the associated
/// Event Streams." The library never inspects <see cref="Id"/>; it is opaque, defined and
/// issued entirely by the application's own <see cref="AuthorizeSsfRequestDelegate"/>.
/// </summary>
public sealed record SsfReceiver
{
    /// <summary>
    /// The application's own stable identifier for the authenticated Receiver — non-empty,
    /// and stable across requests so a store can key stream ownership by it. The library
    /// refuses a permit whose <see cref="Id"/> is empty or whitespace, rather than let it
    /// reach a store.
    /// </summary>
    public required string Id { get; init; }
}


/// <summary>
/// An application's verdict on one Stream Management API request, returned from the
/// <see cref="AuthorizeSsfRequestDelegate"/> seam. A denial carries the
/// <see cref="DenialReason"/> the library maps to an HTTP status, plus an optional
/// human-readable <see cref="DenialDescription"/>: it never reaches the wire for any denial
/// reason — the endpoint always answers with a fixed, reason-specific description — and
/// instead rides the dispatch <see cref="System.Diagnostics.Activity"/> as an event tag,
/// recorded for every denial reason alike, so a deployment that wants the detail keeps it in
/// its own traces without <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8-3">SSF 1.0 §8</see>'s
/// Receiver-to-stream binding ever revealing which tenant, client or stream the caller
/// reached for.
/// </summary>
public sealed record SsfRequestDecision
{
    /// <summary>
    /// Whether the request is permitted to proceed to the store delegate.
    /// <see langword="false"/> fails the request with the status mapped from
    /// <see cref="DenialReason"/>.
    /// </summary>
    public required bool IsPermitted { get; init; }

    /// <summary>
    /// The Receiver <see cref="Permit(SsfReceiver)"/> bound the caller to. Non-null exactly
    /// when <see cref="IsPermitted"/> is <see langword="true"/> — the library passes it to
    /// every store delegate the request reaches, so the store can bind its stream data to
    /// this Receiver rather than to the tenant alone.
    /// </summary>
    public SsfReceiver? Receiver { get; init; }

    /// <summary>
    /// The reason a non-permitted request was denied. Ignored when
    /// <see cref="IsPermitted"/> is <see langword="true"/>; a denial with no reason set is
    /// treated as <see cref="SsfRequestDenialReason.NotAuthorizedForTenant"/>.
    /// </summary>
    public SsfRequestDenialReason? DenialReason { get; init; }

    /// <summary>
    /// An optional human-readable description of the denial. Never placed on the wire for any
    /// <see cref="SsfRequestDenialReason"/> — the endpoint carries a fixed, reason-specific
    /// description in the response body instead, and this value (when present) rides the
    /// dispatch <see cref="System.Diagnostics.Activity"/> as an event tag for the
    /// application's own traces, for every denial reason alike.
    /// </summary>
    public string? DenialDescription { get; init; }


    /// <summary>A permit verdict binding the caller to <paramref name="receiver"/>.</summary>
    /// <param name="receiver">The authenticated Receiver the caller is bound to.</param>
    /// <returns>A permitted <see cref="SsfRequestDecision"/> carrying <paramref name="receiver"/>.</returns>
    public static SsfRequestDecision Permit(SsfReceiver receiver)
    {
        ArgumentNullException.ThrowIfNull(receiver);

        return new SsfRequestDecision { IsPermitted = true, Receiver = receiver };
    }


    /// <summary>
    /// A deny verdict with the given <paramref name="reason"/> and optional
    /// <paramref name="description"/>.
    /// </summary>
    /// <param name="reason">The reason the request was denied.</param>
    /// <param name="description">An optional human-readable description for the application's own traces.</param>
    /// <returns>A non-permitted <see cref="SsfRequestDecision"/>.</returns>
    public static SsfRequestDecision Deny(SsfRequestDenialReason reason, string? description = null) =>
        new() { IsPermitted = false, DenialReason = reason, DenialDescription = description };
}


/// <summary>
/// Authorizes one Stream Management API request: validates the request's Bearer token,
/// decides the caller's authority on <see cref="SsfRequestEvaluation.TenantId"/> with the
/// application's own policy, and — on a permit — returns the <see cref="SsfReceiver"/> the
/// caller is bound to, via <see cref="SsfRequestDecision.Permit(SsfReceiver)"/>. The library
/// passes that Receiver to every store delegate the request reaches, so the store (not this
/// seam) associates it with the stream IDs it may access — <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8-3">SSF 1.0 §8</see>:
/// "This authorization MUST associate a Receiver with one or more stream IDs ... such that
/// only authorized Receivers are able to access or modify the details of the associated
/// Event Streams." The token-validation composition (<c>JwsAccessTokenValidator</c>,
/// introspection, RFC 9728 scope discovery) is the application's.
/// </summary>
/// <param name="evaluation">The immutable snapshot of the request's operation, scope, tenant and (when known) stream.</param>
/// <param name="registration">The <see cref="ClientRecord"/> serving the Transmitter endpoint — the tenant named by the URL.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<SsfRequestDecision> AuthorizeSsfRequestDelegate(
    SsfRequestEvaluation evaluation,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
