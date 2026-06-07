using System.Collections.Generic;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Routing;

namespace Verifiable.OAuth.Ssf;

/// <summary>
/// Parses a Create Stream request body (SSF 1.0 §8.1.1.1). Returns
/// <see langword="null"/> for a malformed body — the endpoint then responds 400.
/// </summary>
public delegate ValueTask<SsfStreamCreateRequest?> ParseSsfStreamCreateRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses an Update/Replace Stream request body (SSF 1.0 §8.1.1.3/§8.1.1.4).
/// Returns <see langword="null"/> for a malformed body — the endpoint then
/// responds 400.
/// </summary>
public delegate ValueTask<SsfStreamUpdateRequest?> ParseSsfStreamUpdateRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// How the Transmitter's stream store disposed of a write operation. The
/// endpoint maps the outcome to the SSF 1.0 §8.1.1 status codes; everything
/// behind the outcome (persistence, multi-stream policy, the
/// Transmitter-supplied property fill-in) is the application's.
/// </summary>
public enum SsfStreamWriteOutcome
{
    /// <summary>The operation succeeded; <see cref="SsfStreamWriteResult.Stream"/> carries the configuration.</summary>
    Success = 0,

    /// <summary>The update was accepted but not yet processed — 202 (§8.1.1.3).</summary>
    Accepted,

    /// <summary>An echoed Transmitter-supplied property did not match the expected value — 400.</summary>
    InvalidProperties,

    /// <summary>No stream with the given <c>stream_id</c> exists for this Receiver — 404.</summary>
    NotFound,

    /// <summary>The Receiver is not allowed to perform the operation — 403.</summary>
    Forbidden,

    /// <summary>The Transmitter does not support multiple streams per Receiver — 409 (§8.1.1.1).</summary>
    Conflict
}


/// <summary>The result of a stream-store write: an outcome plus, on success, the stream.</summary>
public sealed record SsfStreamWriteResult
{
    /// <summary>The store's disposition of the operation.</summary>
    public required SsfStreamWriteOutcome Outcome { get; init; }

    /// <summary>
    /// The full stream configuration on <see cref="SsfStreamWriteOutcome.Success"/>;
    /// otherwise <see langword="null"/>.
    /// </summary>
    public SsfStreamConfiguration? Stream { get; init; }


    /// <summary>Builds a success result carrying <paramref name="stream"/>.</summary>
    public static SsfStreamWriteResult Success(SsfStreamConfiguration stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        return new SsfStreamWriteResult { Outcome = SsfStreamWriteOutcome.Success, Stream = stream };
    }


    /// <summary>Builds a failure result carrying <paramref name="outcome"/>.</summary>
    public static SsfStreamWriteResult Failed(SsfStreamWriteOutcome outcome) =>
        new() { Outcome = outcome };
}


/// <summary>
/// Creates an Event Stream (SSF 1.0 §8.1.1.1). The store assigns
/// <c>stream_id</c>, fills the Transmitter-supplied properties (<c>iss</c>,
/// <c>aud</c>, <c>events_supported</c>, <c>events_delivered</c>), and — when the
/// request carried no <c>delivery</c> — applies the poll default and supplies
/// the polling <c>endpoint_url</c>.
/// </summary>
public delegate ValueTask<SsfStreamWriteResult> CreateSsfStreamDelegate(
    SsfStreamCreateRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Reads stream configurations (SSF 1.0 §8.1.1.2). With a
/// <paramref name="streamId"/>, returns a single-element list for the stream or
/// <see langword="null"/> when it does not exist (404). With
/// <paramref name="streamId"/> <see langword="null"/>, returns all streams for
/// this Receiver — possibly empty, never <see langword="null"/>.
/// </summary>
public delegate ValueTask<IReadOnlyList<SsfStreamConfiguration>?> ReadSsfStreamsDelegate(
    string? streamId,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Updates a stream with PATCH semantics (SSF 1.0 §8.1.1.3): present
/// Receiver-supplied properties are changed, absent ones are left untouched, and
/// echoed Transmitter-supplied properties must match.
/// </summary>
public delegate ValueTask<SsfStreamWriteResult> UpdateSsfStreamDelegate(
    SsfStreamUpdateRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Replaces a stream with PUT semantics (SSF 1.0 §8.1.1.4): the request carries
/// the full Receiver-supplied set and absent Receiver-supplied properties are
/// deleted; echoed Transmitter-supplied properties must match.
/// </summary>
public delegate ValueTask<SsfStreamWriteResult> ReplaceSsfStreamDelegate(
    SsfStreamUpdateRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Deletes a stream (SSF 1.0 §8.1.1.5). The endpoint maps
/// <see cref="SsfStreamWriteOutcome.Success"/> to 204,
/// <see cref="SsfStreamWriteOutcome.NotFound"/> to 404, and
/// <see cref="SsfStreamWriteOutcome.Forbidden"/> to 403.
/// </summary>
public delegate ValueTask<SsfStreamWriteOutcome> DeleteSsfStreamDelegate(
    string streamId,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a Stream Status update body (SSF 1.0 §8.1.2.2). Returns
/// <see langword="null"/> for a malformed or non-conformant body — the endpoint
/// then responds 400.
/// </summary>
public delegate ValueTask<SsfStreamStatus?> ParseSsfStreamStatusDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses an Add Subject request body (SSF 1.0 §8.1.3.2). Returns
/// <see langword="null"/> for a malformed body.
/// </summary>
public delegate ValueTask<SsfAddSubjectRequest?> ParseSsfAddSubjectRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a Remove Subject request body (SSF 1.0 §8.1.3.3). Returns
/// <see langword="null"/> for a malformed body.
/// </summary>
public delegate ValueTask<SsfRemoveSubjectRequest?> ParseSsfRemoveSubjectRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Parses a Trigger Verification request body (SSF 1.0 §8.1.4.2). Returns
/// <see langword="null"/> for a malformed body.
/// </summary>
public delegate ValueTask<SsfVerificationRequest?> ParseSsfVerificationRequestDelegate(
    string requestBody,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// How the Transmitter disposed of a stream-control operation (status update,
/// subject add/remove, verification trigger). The endpoints map outcomes to the
/// SSF §8.1.2–§8.1.4 status codes.
/// </summary>
public enum SsfStreamOperationOutcome
{
    /// <summary>The operation succeeded.</summary>
    Success = 0,

    /// <summary>The request was accepted but not yet processed — 202 (§8.1.2.2).</summary>
    Accepted,

    /// <summary>No stream with the given <c>stream_id</c> exists for this Receiver — 404.</summary>
    NotFound,

    /// <summary>The Receiver is not allowed to perform the operation — 403.</summary>
    Forbidden,

    /// <summary>The Receiver is sending too many requests — 429 (§8.1.3/§8.1.4, <c>min_verification_interval</c>).</summary>
    TooManyRequests
}


/// <summary>The result of a status read/update: an outcome plus, on success, the status.</summary>
public sealed record SsfStreamStatusResult
{
    /// <summary>The Transmitter's disposition of the operation.</summary>
    public required SsfStreamOperationOutcome Outcome { get; init; }

    /// <summary>
    /// The stream status on <see cref="SsfStreamOperationOutcome.Success"/>; otherwise
    /// <see langword="null"/>.
    /// </summary>
    public SsfStreamStatus? Status { get; init; }


    /// <summary>Builds a success result carrying <paramref name="status"/>.</summary>
    public static SsfStreamStatusResult Success(SsfStreamStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);

        return new SsfStreamStatusResult { Outcome = SsfStreamOperationOutcome.Success, Status = status };
    }


    /// <summary>Builds a failure result carrying <paramref name="outcome"/>.</summary>
    public static SsfStreamStatusResult Failed(SsfStreamOperationOutcome outcome) =>
        new() { Outcome = outcome };
}


/// <summary>
/// Reads a stream's status (SSF 1.0 §8.1.2.1). Returns <see langword="null"/>
/// when no stream with <paramref name="streamId"/> exists for this Receiver (404).
/// </summary>
public delegate ValueTask<SsfStreamStatus?> ReadSsfStreamStatusDelegate(
    string streamId,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Updates a stream's status (SSF 1.0 §8.1.2.2). A Transmitter that changes the
/// status MUST also send the <c>stream-updated</c> event when the change is
/// transmitter-visible (§8.1.5) — emission is the application's, behind this seam.
/// </summary>
public delegate ValueTask<SsfStreamStatusResult> UpdateSsfStreamStatusDelegate(
    SsfStreamStatus requestedStatus,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Adds a subject to a stream (SSF 1.0 §8.1.3.2). The endpoint maps
/// <see cref="SsfStreamOperationOutcome.Success"/> to an empty 200. A Transmitter
/// MAY silently accept a subject it will not act on (§8.1.3.2 privacy guidance).
/// </summary>
public delegate ValueTask<SsfStreamOperationOutcome> AddSsfSubjectDelegate(
    SsfAddSubjectRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Removes a subject from a stream (SSF 1.0 §8.1.3.3). The endpoint maps
/// <see cref="SsfStreamOperationOutcome.Success"/> to 204.
/// </summary>
public delegate ValueTask<SsfStreamOperationOutcome> RemoveSsfSubjectDelegate(
    SsfRemoveSubjectRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>
/// Requests a Verification Event over a stream (SSF 1.0 §8.1.4.2). The endpoint
/// maps <see cref="SsfStreamOperationOutcome.Success"/> to 204 — acceptance only;
/// the <c>verification</c> SET itself MAY be transmitted asynchronously by the
/// application, echoing the request's <c>state</c>.
/// </summary>
public delegate ValueTask<SsfStreamOperationOutcome> TriggerSsfVerificationDelegate(
    SsfVerificationRequest request,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);


/// <summary>The authorization disposition of one stream-management request.</summary>
public enum SsfRequestAuthorization
{
    /// <summary>The request carries a token granting the operation's required scope.</summary>
    Authorized = 0,

    /// <summary>Authorization failed or is missing — 401.</summary>
    Unauthorized,

    /// <summary>The token is valid but its scope does not permit the operation — 403.</summary>
    Forbidden
}


/// <summary>
/// Authorizes one stream-management request per CAEP Interoperability Profile
/// 1.0 §2.7.3: validate the request's Bearer token and check the granted scope
/// satisfies <paramref name="requiredScope"/> (read APIs accept
/// <c>ssf.read</c>, management APIs accept <c>ssf.manage</c>; coverage per
/// <c>WellKnownScopes.SsfScopeSatisfies</c>). The token-validation composition
/// (<c>JwsAccessTokenValidator</c>, introspection, RFC 9728 scope discovery) is
/// the application's. When this seam is unset, the endpoints enforce no
/// authorization.
/// </summary>
/// <param name="request">The incoming request, carrying the Authorization header.</param>
/// <param name="requiredScope">The scope the operation requires.</param>
/// <param name="registration">The <see cref="ClientRecord"/> serving the Transmitter endpoint.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<SsfRequestAuthorization> AuthorizeSsfRequestDelegate(
    IncomingRequest request,
    string requiredScope,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
