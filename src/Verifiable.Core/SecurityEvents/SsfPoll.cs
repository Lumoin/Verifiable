using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// A poll request body a SET Recipient (Receiver) sends to a Transmitter's
/// polling endpoint, per <see href="https://www.rfc-editor.org/rfc/rfc8936#section-2.2">RFC 8936 §2.2</see>.
/// Combines polling parameters with acknowledgement of previously received SETs.
/// </summary>
/// <remarks>
/// The three RFC 8936 variations fall out of the field combination: poll-only
/// (no <see cref="Acks"/>/<see cref="SetErrors"/>), acknowledge-only
/// (<see cref="MaxEvents"/> = 0 with acks), and combined acknowledge-and-poll.
/// </remarks>
public sealed record SsfPollRequest
{
    /// <summary>
    /// The OPTIONAL <c>maxEvents</c> — maximum unacknowledged SETs to return. <c>0</c> performs an
    /// acknowledge-only request; <see langword="null"/> places no limit.
    /// </summary>
    public int? MaxEvents { get; init; }

    /// <summary>
    /// The OPTIONAL <c>returnImmediately</c> — when <see langword="true"/>, short-poll (return even
    /// with no SETs). <see langword="null"/>/false means long-poll.
    /// </summary>
    public bool? ReturnImmediately { get; init; }

    /// <summary>The <c>ack</c> <c>jti</c> values of successfully received SETs. Never null; may be empty.</summary>
    public IReadOnlyList<string> Acks { get; init; } = [];

    /// <summary>
    /// The <c>setErrs</c> map of <c>jti</c> → error for invalid SETs received. Never null; may be empty.
    /// </summary>
    public IReadOnlyDictionary<string, SsfSetError> SetErrors { get; init; } =
        new Dictionary<string, SsfSetError>(System.StringComparer.Ordinal);
}


/// <summary>
/// A poll response body a Transmitter returns, per
/// <see href="https://www.rfc-editor.org/rfc/rfc8936#section-2.3">RFC 8936 §2.3</see>.
/// </summary>
public sealed record SsfPollResponse
{
    /// <summary>
    /// The <c>sets</c> map of <c>jti</c> → the corresponding compact SET (JWS) string. Never null;
    /// empty when no SETs are outstanding.
    /// </summary>
    public IReadOnlyDictionary<string, string> Sets { get; init; } =
        new Dictionary<string, string>(System.StringComparer.Ordinal);

    /// <summary>
    /// The <c>moreAvailable</c> flag — whether more unacknowledged SETs remain. Defaults to
    /// <see langword="false"/> (the meaning of an omitted member).
    /// </summary>
    public bool MoreAvailable { get; init; }
}


/// <summary>The member NAMES of poll request/response bodies (RFC 8936).</summary>
public static class SsfPollParameterNames
{
    /// <summary><c>maxEvents</c> — max SETs to return (request).</summary>
    public static readonly string MaxEvents = "maxEvents";

    /// <summary><c>returnImmediately</c> — short-poll flag (request).</summary>
    public static readonly string ReturnImmediately = "returnImmediately";

    /// <summary><c>ack</c> — array of acknowledged jti values (request).</summary>
    public static readonly string Ack = "ack";

    /// <summary><c>setErrs</c> — map of jti → error for invalid SETs (request).</summary>
    public static readonly string SetErrs = "setErrs";

    /// <summary><c>sets</c> — map of jti → compact SET string (response).</summary>
    public static readonly string Sets = "sets";

    /// <summary><c>moreAvailable</c> — whether more SETs remain (response).</summary>
    public static readonly string MoreAvailable = "moreAvailable";
}
