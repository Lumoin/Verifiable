namespace Verifiable.DidComm.ReturnRoute;

/// <summary>
/// Builds and resolves the <c>return_route</c> directive of the DIDComm Messaging Return-Route and Queue
/// Transport extension, per
/// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>.
/// </summary>
/// <remarks>
/// <para>
/// LIBRARY vs APPLICATION boundary: this surface models, validates, and serializes the
/// <see cref="DidCommMessage.ReturnRoute"/>/<see cref="DidCommMessage.ReturnRouteThread"/> headers on the way
/// out, and resolves the directive a received message carries on the way in. It does NOT hold anything open:
/// actually keeping an inbound HTTP request pending or a WebSocket connection alive so replies can flow back
/// over it, and the per-connection state that matches a queued reply to the connection it belongs to, is the
/// application's job — <c>Verifiable.DidComm.Transport.DidCommSendDelegate</c> is documented one-way by
/// design, and this project carries no transport of its own.
/// </para>
/// <para>
/// <see cref="DidCommMessage.ReturnRoute"/> is deliberately a plain string rather than an enum: DIDComm
/// Messaging v2.1 §Message Headers requires that software which does not understand a header MUST ignore it
/// and MUST NOT fail because of its inclusion, so an unrecognized directive value must survive a pack/unpack
/// round trip verbatim rather than be coerced or rejected. <see cref="ResolveReturnRoute"/> is where that
/// leniency is applied: any value other than the well-known ones — or a <c>thread</c> value with no
/// satisfiable companion — resolves to <see cref="WellKnownReturnRouteNames.None"/>. This consumer-side
/// leniency is asymmetric with the producer side: <see cref="WithReturnRoute"/> mints only the three
/// well-known, case-sensitive values, since a value this library invents off that set is a value no other
/// conformant implementation was ever going to understand either.
/// </para>
/// </remarks>
public static class DidCommReturnRouteExtensions
{
    /// <summary>
    /// Sets the <c>return_route</c> directive — and, for <c>thread</c>, its required
    /// <c>return_route_thread</c> companion — on <paramref name="message"/> (§Return Route Header).
    /// </summary>
    /// <param name="message">The message to set the directive on.</param>
    /// <param name="returnRoute">
    /// REQUIRED. The directive: exactly one of <see cref="WellKnownReturnRouteNames.None"/>,
    /// <see cref="WellKnownReturnRouteNames.All"/>, or <see cref="WellKnownReturnRouteNames.Thread"/>, compared
    /// case-sensitively (Ordinal). The value list is CLOSED for a producer: the wire is case-sensitive and a
    /// conformant peer honors only these three spellings (§Return Route Header), so minting anything else here
    /// would ship a directive no receiver understands. A receiver's tolerance for an unrecognized inbound value
    /// lives in <see cref="ResolveReturnRoute"/>, not here — that leniency is about not failing on OTHER
    /// software's messages, not about this library's own producer output.
    /// </param>
    /// <param name="returnRouteThread">
    /// REQUIRED (non-whitespace) when <paramref name="returnRoute"/> is
    /// <see cref="WellKnownReturnRouteNames.Thread"/>; otherwise MUST be <see langword="null"/>, empty, or
    /// whitespace-only. Correlation reuses <see cref="DidCommMessage.EffectiveThreadId"/> — this names the
    /// thread a peer replies against, not a new session/connection concept.
    /// </param>
    /// <returns><paramref name="message"/>, for chaining.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="returnRoute"/> is not exactly one of the three well-known directives; when
    /// <paramref name="returnRoute"/> is <c>thread</c> and <paramref name="returnRouteThread"/> is null, empty,
    /// or all-whitespace; or when <paramref name="returnRoute"/> is not <c>thread</c> and a non-whitespace
    /// <paramref name="returnRouteThread"/> is supplied anyway (§Return Route Header).
    /// </exception>
    public static DidCommMessage WithReturnRoute(this DidCommMessage message, string returnRoute, string? returnRouteThread = null)
    {
        ArgumentNullException.ThrowIfNull(message);
        ArgumentException.ThrowIfNullOrEmpty(returnRoute);

        bool isWellKnownDirective =
            string.Equals(returnRoute, WellKnownReturnRouteNames.None, StringComparison.Ordinal) ||
            string.Equals(returnRoute, WellKnownReturnRouteNames.All, StringComparison.Ordinal) ||
            string.Equals(returnRoute, WellKnownReturnRouteNames.Thread, StringComparison.Ordinal);

        if(!isWellKnownDirective)
        {
            throw new ArgumentException(
                $"return_route MUST be exactly one of '{WellKnownReturnRouteNames.None}', " +
                $"'{WellKnownReturnRouteNames.All}', or '{WellKnownReturnRouteNames.Thread}', case-sensitive " +
                "(DIDComm Messaging Return-Route and Queue Transport Extension §Return Route Header).",
                nameof(returnRoute));
        }

        bool isThread = string.Equals(returnRoute, WellKnownReturnRouteNames.Thread, StringComparison.Ordinal);
        if(isThread && string.IsNullOrWhiteSpace(returnRouteThread))
        {
            throw new ArgumentException(
                "The 'thread' return_route directive REQUIRES a non-whitespace return_route_thread " +
                "(DIDComm Messaging Return-Route and Queue Transport Extension §Return Route Header).",
                nameof(returnRouteThread));
        }

        if(!isThread && !string.IsNullOrWhiteSpace(returnRouteThread))
        {
            throw new ArgumentException(
                "return_route_thread MUST NOT be set unless return_route is 'thread' " +
                "(DIDComm Messaging Return-Route and Queue Transport Extension §Return Route Header).",
                nameof(returnRouteThread));
        }

        message.ReturnRoute = returnRoute;
        message.ReturnRouteThread = isThread ? returnRouteThread : null;

        return message;
    }


    /// <summary>
    /// Resolves the effective <c>return_route</c> directive of <paramref name="message"/>: its header value
    /// when that value is one of the well-known directives AND, for <c>thread</c>, satisfiable, and
    /// <see cref="WellKnownReturnRouteNames.None"/> otherwise (§Return Route Header: "none: Default. ... If
    /// return_route is omitted, this is the default value."). An absent header, an unrecognized value, or a
    /// <c>thread</c> directive with no non-whitespace <see cref="DidCommMessage.ReturnRouteThread"/> all
    /// resolve to <c>none</c> rather than throwing — the MUST-NOT-fail rule of DIDComm Messaging v2.1
    /// §Message Headers applies to resolution as much as to parsing.
    /// </summary>
    /// <remarks>
    /// The <c>thread</c> arm additionally requires the companion: §Return Route Header defines it as "Send
    /// all messages matching the DID and thread specified in the return_route_thread attribute" — without
    /// that attribute there is no thread to match against, so the directive is unsatisfiable. The producer
    /// seam (<see cref="WithReturnRoute"/>) itself refuses to mint that combination, but an inbound message is
    /// untrusted wire input and can carry it anyway; treating it as <c>none</c> rather than as <c>thread</c>
    /// is fail-safe — an unsatisfiable directive must not cause a connection hold or otherwise be acted on as
    /// if it could be honored.
    /// </remarks>
    /// <param name="message">The message to inspect.</param>
    /// <returns>
    /// One of <see cref="WellKnownReturnRouteNames.None"/>, <see cref="WellKnownReturnRouteNames.All"/>, or
    /// <see cref="WellKnownReturnRouteNames.Thread"/>.
    /// </returns>
    public static string ResolveReturnRoute(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return message.ReturnRoute switch
        {
            string value when string.Equals(value, WellKnownReturnRouteNames.All, StringComparison.Ordinal) => WellKnownReturnRouteNames.All,
            string value when string.Equals(value, WellKnownReturnRouteNames.Thread, StringComparison.Ordinal)
                && !string.IsNullOrWhiteSpace(message.ReturnRouteThread) => WellKnownReturnRouteNames.Thread,
            _ => WellKnownReturnRouteNames.None
        };
    }


    /// <summary>
    /// Whether <paramref name="message"/> directs that all messages for the DID be returned over the
    /// connection it arrived on — <see cref="ResolveReturnRoute"/> is <see cref="WellKnownReturnRouteNames.All"/>.
    /// The predicate a Message Pickup 3.0 / Coordinate Mediation 2.0 request builder asserts against before
    /// holding a connection open for replies.
    /// </summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the resolved directive is <c>all</c>.</returns>
    public static bool IsReturnRouteAll(this DidCommMessage message) =>
        string.Equals(message.ResolveReturnRoute(), WellKnownReturnRouteNames.All, StringComparison.Ordinal);
}
