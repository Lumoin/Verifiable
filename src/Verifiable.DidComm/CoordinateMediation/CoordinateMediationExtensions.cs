using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.DidComm.ReturnRoute;

namespace Verifiable.DidComm.CoordinateMediation;

/// <summary>
/// Build and interpret for the DIDComm Coordinate Mediation Protocol 2.0 — the seven message types a
/// recipient and mediator exchange to establish a routing relationship and keep the mediator's keylist in
/// sync, per
/// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// The <c>Create…</c> builders are producer-side and MAY throw on bad caller arguments; the
/// <c>TryRead…</c>/<c>Is…</c> members consume attacker-controlled wire input and are fail-closed — they
/// never throw (beyond a null-argument guard), returning <see langword="false"/> for any structurally
/// non-conformant message and leaving every <see langword="out"/> parameter zeroed/nulled on every failure
/// path. The dictionary <c>body</c> is only the wire intermediate; callers operate on
/// <see cref="KeylistUpdateEntry"/>/<see cref="KeylistUpdateResult"/>/<see cref="KeylistKey"/>/
/// <see cref="KeylistPaginate"/>/<see cref="KeylistPagination"/> or the individual <c>out</c> values.
/// </para>
/// <para>
/// Every RECIPIENT request builder (<see cref="CreateMediateRequest"/>, <see cref="CreateKeylistUpdate"/>,
/// <see cref="CreateKeylistQuery"/>) sets <c>return_route: all</c> via
/// <see cref="DidCommReturnRouteExtensions.WithReturnRoute"/> — §Requirements requires the recipient to
/// specify it for synchronous same-channel replies, and every request sample in the spec shows it. The
/// mediator-side response builders (<see cref="CreateMediateGrant"/>, <see cref="CreateMediateDeny"/>,
/// <see cref="CreateKeylistUpdateResponse"/>, <see cref="CreateKeylist"/>) never set it; instead they thread
/// <c>thid</c> to the request's <see cref="DidCommMessage.EffectiveThreadId"/> and validate that the
/// antecedent message really is the request they answer. The spec's own samples omit <c>thid</c> entirely,
/// but §States describes a request-response pattern, and DIDComm v2.1 §Threading treats a reply without
/// <c>thid</c> as starting a NEW thread — losing correlation — so every response builder sets it anyway.
/// </para>
/// <para>
/// <c>mediate-request</c> and <c>mediate-deny</c> carry NO <c>body</c> member at all — the wire shape their
/// samples show is <c>{id, type[, return_route]}</c>, not an empty <c>{}</c> object, so
/// <see cref="CreateMediateRequest"/> and <see cref="CreateMediateDeny"/> leave
/// <see cref="DidCommMessage.Body"/> <see langword="null"/>.
/// </para>
/// <para>
/// <c>action</c> and <c>result</c> are CLOSED producer sets
/// (<see cref="WellKnownCoordinateMediationNames.ActionAdd"/>/<see cref="WellKnownCoordinateMediationNames.ActionRemove"/>
/// and the four <c>Result*</c> values): a value this library invents off that set is a value no conformant
/// peer understands, so <see cref="CreateKeylistUpdate"/> and <see cref="CreateKeylistUpdateResponse"/>
/// refuse anything else. The readers are the asymmetric opposite: an inbound message may carry any string in
/// either member, and <see cref="TryReadKeylistUpdates"/>/<see cref="TryReadKeylistUpdateResults"/> return it
/// VERBATIM rather than failing, because an unrecognized value from another implementation is not this
/// library's malformation to reject.
/// </para>
/// <para>
/// Every numeric body member (<c>limit</c>, <c>offset</c>, <c>count</c>, <c>remaining</c>) is read through
/// <see cref="DidCommBodyNumbers"/>, the narrowing ladder shared with
/// <see cref="Verifiable.DidComm.MessagePickup.MessagePickupExtensions"/>.
/// </para>
/// </remarks>
public static class CoordinateMediationExtensions
{
    //The seven Coordinate Mediation 2.0 Message Type URIs, parsed once for semver-compatible handler dispatch
    //(pattern: Verifiable.DidComm.MessagePickup.MessagePickupExtensions).
    private static MessageTypeUri MediateRequestMessageType { get; } = MessageTypeUri.Parse(WellKnownCoordinateMediationNames.MediateRequestType);
    private static MessageTypeUri MediateDenyMessageType { get; } = MessageTypeUri.Parse(WellKnownCoordinateMediationNames.MediateDenyType);
    private static MessageTypeUri MediateGrantMessageType { get; } = MessageTypeUri.Parse(WellKnownCoordinateMediationNames.MediateGrantType);
    private static MessageTypeUri KeylistUpdateMessageType { get; } = MessageTypeUri.Parse(WellKnownCoordinateMediationNames.KeylistUpdateType);
    private static MessageTypeUri KeylistUpdateResponseMessageType { get; } = MessageTypeUri.Parse(WellKnownCoordinateMediationNames.KeylistUpdateResponseType);
    private static MessageTypeUri KeylistQueryMessageType { get; } = MessageTypeUri.Parse(WellKnownCoordinateMediationNames.KeylistQueryType);
    private static MessageTypeUri KeylistMessageType { get; } = MessageTypeUri.Parse(WellKnownCoordinateMediationNames.KeylistType);


    /// <summary>Whether <paramref name="message"/> is a <c>mediate-request</c> — its <c>type</c> names the mediate-request Message Type URI (§Mediate Request).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a mediate-request.</returns>
    public static bool IsMediateRequest(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(MediateRequestMessageType);
    }


    /// <summary>Whether <paramref name="message"/> is a <c>mediate-deny</c> — its <c>type</c> names the mediate-deny Message Type URI (§Mediate Deny).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a mediate-deny.</returns>
    public static bool IsMediateDeny(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(MediateDenyMessageType);
    }


    /// <summary>Whether <paramref name="message"/> is a <c>mediate-grant</c> — its <c>type</c> names the mediate-grant Message Type URI (§Mediate Grant).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a mediate-grant.</returns>
    public static bool IsMediateGrant(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(MediateGrantMessageType);
    }


    /// <summary>Whether <paramref name="message"/> is a <c>keylist-update</c> — its <c>type</c> names the keylist-update Message Type URI (§Keylist Update).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a keylist-update.</returns>
    public static bool IsKeylistUpdate(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(KeylistUpdateMessageType);
    }


    /// <summary>
    /// Whether <paramref name="message"/> is a <c>keylist-update-response</c> — its <c>type</c> names the
    /// keylist-update-response Message Type URI. TRAP: the spec section is titled "Keylist Response", but the
    /// wire type token is <c>keylist-update-response</c>, not <c>keylist-response</c> (§Keylist Response).
    /// </summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a keylist-update-response.</returns>
    public static bool IsKeylistUpdateResponse(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(KeylistUpdateResponseMessageType);
    }


    /// <summary>Whether <paramref name="message"/> is a <c>keylist-query</c> — its <c>type</c> names the keylist-query Message Type URI (§Keylist Query).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a keylist-query.</returns>
    public static bool IsKeylistQuery(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(KeylistQueryMessageType);
    }


    /// <summary>Whether <paramref name="message"/> is a <c>keylist</c> — its <c>type</c> names the keylist Message Type URI (§Keylist).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a keylist.</returns>
    public static bool IsKeylist(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(KeylistMessageType);
    }


    /// <summary>
    /// Builds a <c>mediate-request</c> message: <c>type</c> is the mediate-request Message Type URI, no
    /// <c>body</c> is emitted, and <c>return_route</c> is set to <c>all</c> (§Mediate Request, §Requirements).
    /// </summary>
    /// <param name="id">REQUIRED. The message id — its thread id is what a reply <c>mediate-grant</c> or <c>mediate-deny</c> correlates against.</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The mediate-request message, carrying <c>return_route: all</c> and no body.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null or empty.</exception>
    public static DidCommMessage CreateMediateRequest(string id, string? from = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        var message = new DidCommMessage
        {
            Id = id,
            Type = WellKnownCoordinateMediationNames.MediateRequestType,
            From = from
        };

        return message.WithReturnRoute(WellKnownReturnRouteNames.All);
    }


    /// <summary>
    /// Builds a <c>mediate-grant</c> message answering <paramref name="mediateRequest"/>: <c>type</c> is the
    /// mediate-grant Message Type URI, <c>thid</c> continues the request's thread, and <c>body.routing_did</c>
    /// carries <paramref name="routingDid"/> (§Mediate Grant).
    /// </summary>
    /// <param name="mediateRequest">REQUIRED. The mediate-request this grant answers.</param>
    /// <param name="id">REQUIRED. The grant message's own id.</param>
    /// <param name="routingDid">REQUIRED. The DID of the mediator where forwarded messages should be sent (§Mediate Grant).</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The mediate-grant message.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="mediateRequest"/> is not a mediate-request, carries no <c>id</c>/<c>thid</c>
    /// to correlate against, <paramref name="id"/> is null/empty, or <paramref name="routingDid"/> is
    /// null/whitespace.
    /// </exception>
    public static DidCommMessage CreateMediateGrant(this DidCommMessage mediateRequest, string id, string routingDid, string? from = null)
    {
        ArgumentNullException.ThrowIfNull(mediateRequest);
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(routingDid);

        if(!mediateRequest.IsMediateRequest())
        {
            throw new ArgumentException(
                "A mediate-grant MUST answer a mediate-request (DIDComm Coordinate Mediation Protocol 2.0 §Mediate Grant).",
                nameof(mediateRequest));
        }

        //The mediate-grant MUST continue the request's thread to correlate as its reply (DIDComm Coordinate
        //Mediation Protocol 2.0 §States (L41); DIDComm Messaging v2.1 §Threading) — an id-less antecedent has
        //no thread to continue, so building against one would silently start a NEW thread instead.
        if(mediateRequest.EffectiveThreadId is not { Length: > 0 } threadId)
        {
            throw new ArgumentException(
                "The mediate-request MUST carry an 'id' (or 'thid') so the mediate-grant can continue its thread (DIDComm Coordinate Mediation Protocol 2.0 §States (L41); DIDComm Messaging v2.1 §Threading).",
                nameof(mediateRequest));
        }

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownCoordinateMediationNames.MediateGrantType,
            From = from,
            ThreadId = threadId,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.RoutingDid] = routingDid }
        };
    }


    /// <summary>
    /// Builds a <c>mediate-deny</c> message answering <paramref name="mediateRequest"/>: <c>type</c> is the
    /// mediate-deny Message Type URI, <c>thid</c> continues the request's thread, and no <c>body</c> is
    /// emitted (§Mediate Deny).
    /// </summary>
    /// <param name="mediateRequest">REQUIRED. The mediate-request this denial answers.</param>
    /// <param name="id">REQUIRED. The deny message's own id.</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The mediate-deny message, carrying no body.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="mediateRequest"/> is not a mediate-request, carries no <c>id</c>/<c>thid</c>
    /// to correlate against, or <paramref name="id"/> is null/empty.
    /// </exception>
    public static DidCommMessage CreateMediateDeny(this DidCommMessage mediateRequest, string id, string? from = null)
    {
        ArgumentNullException.ThrowIfNull(mediateRequest);
        ArgumentException.ThrowIfNullOrEmpty(id);

        if(!mediateRequest.IsMediateRequest())
        {
            throw new ArgumentException(
                "A mediate-deny MUST answer a mediate-request (DIDComm Coordinate Mediation Protocol 2.0 §Mediate Deny).",
                nameof(mediateRequest));
        }

        //A mediate-deny answers THIS mediate-request specifically, so the antecedent type is validated exactly
        //as CreateMediateGrant does — and, symmetrically, it MUST continue the request's thread (DIDComm
        //Coordinate Mediation Protocol 2.0 §States (L41); DIDComm Messaging v2.1 §Threading).
        if(mediateRequest.EffectiveThreadId is not { Length: > 0 } threadId)
        {
            throw new ArgumentException(
                "The mediate-request MUST carry an 'id' (or 'thid') so the mediate-deny can continue its thread (DIDComm Coordinate Mediation Protocol 2.0 §States (L41); DIDComm Messaging v2.1 §Threading).",
                nameof(mediateRequest));
        }

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownCoordinateMediationNames.MediateDenyType,
            From = from,
            ThreadId = threadId
        };
    }


    /// <summary>
    /// Builds a <c>keylist-update</c> message: <c>type</c> is the keylist-update Message Type URI,
    /// <c>body.updates</c> carries <paramref name="updates"/>, and <c>return_route</c> is set to <c>all</c>
    /// (§Keylist Update, §Requirements).
    /// </summary>
    /// <param name="id">REQUIRED. The message id — its thread id is what a reply <c>keylist-update-response</c> correlates against.</param>
    /// <param name="updates">REQUIRED. The keys to register/deregister — at least one, no null entries, each with a non-whitespace <see cref="KeylistUpdateEntry.RecipientDid"/> and an <see cref="KeylistUpdateEntry.Action"/> of exactly <c>add</c> or <c>remove</c> (§Keylist Update).</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The keylist-update message, carrying <c>return_route: all</c>.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="id"/> is null/empty, <paramref name="updates"/> is empty, or an entry is
    /// null, has a null/whitespace <c>RecipientDid</c>, or an <c>Action</c> outside the closed <c>add</c>/<c>remove</c> set.
    /// </exception>
    public static DidCommMessage CreateKeylistUpdate(string id, IReadOnlyList<KeylistUpdateEntry> updates, string? from = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(updates);

        if(updates.Count == 0)
        {
            throw new ArgumentException(
                "A keylist-update MUST carry at least one update entry (DIDComm Coordinate Mediation Protocol 2.0 §Keylist Update).",
                nameof(updates));
        }

        var entries = new List<object>(updates.Count);
        foreach(KeylistUpdateEntry entry in updates)
        {
            ArgumentNullException.ThrowIfNull(entry);
            ArgumentException.ThrowIfNullOrWhiteSpace(entry.RecipientDid);

            if(!IsClosedActionValue(entry.Action))
            {
                throw new ArgumentException(
                    $"A keylist-update entry's action MUST be '{WellKnownCoordinateMediationNames.ActionAdd}' or " +
                    $"'{WellKnownCoordinateMediationNames.ActionRemove}' (DIDComm Coordinate Mediation Protocol 2.0 §Keylist Update).",
                    nameof(updates));
            }

            entries.Add(new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.RecipientDid] = entry.RecipientDid,
                [WellKnownCoordinateMediationNames.Action] = entry.Action
            });
        }

        var message = new DidCommMessage
        {
            Id = id,
            Type = WellKnownCoordinateMediationNames.KeylistUpdateType,
            From = from,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Updates] = entries }
        };

        return message.WithReturnRoute(WellKnownReturnRouteNames.All);
    }


    /// <summary>
    /// Builds a <c>keylist-update-response</c> message answering <paramref name="keylistUpdate"/>: <c>type</c>
    /// is the keylist-update-response Message Type URI, <c>thid</c> continues the request's thread, and
    /// <c>body.updated</c> carries <paramref name="updated"/> (§Keylist Response).
    /// </summary>
    /// <param name="keylistUpdate">REQUIRED. The keylist-update this response confirms.</param>
    /// <param name="id">REQUIRED. The response message's own id.</param>
    /// <param name="updated">
    /// REQUIRED. The per-key confirmations — at least one (a confirmation confirming nothing is producer
    /// nonsense), no null entries, each with a non-whitespace <see cref="KeylistUpdateResult.RecipientDid"/>,
    /// an <see cref="KeylistUpdateResult.Action"/> of exactly <c>add</c> or <c>remove</c>, and a
    /// <see cref="KeylistUpdateResult.Result"/> in the closed result set (§Keylist Response).
    /// </param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The keylist-update-response message.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="keylistUpdate"/> is not a keylist-update, carries no <c>id</c>/<c>thid</c>
    /// to correlate against, <paramref name="id"/> is null/empty, <paramref name="updated"/> is empty, or an
    /// entry is null, has a null/whitespace <c>RecipientDid</c>, an <c>Action</c> outside the closed
    /// <c>add</c>/<c>remove</c> set, or a <c>Result</c> outside the closed result set.
    /// </exception>
    public static DidCommMessage CreateKeylistUpdateResponse(this DidCommMessage keylistUpdate, string id, IReadOnlyList<KeylistUpdateResult> updated, string? from = null)
    {
        ArgumentNullException.ThrowIfNull(keylistUpdate);
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(updated);

        if(!keylistUpdate.IsKeylistUpdate())
        {
            throw new ArgumentException(
                "A keylist-update-response MUST answer a keylist-update (DIDComm Coordinate Mediation Protocol 2.0 §Keylist Response).",
                nameof(keylistUpdate));
        }

        //The keylist-update-response answers THIS keylist-update specifically, so it MUST continue the
        //update's thread (DIDComm Coordinate Mediation Protocol 2.0 §States (L41); DIDComm Messaging v2.1
        //§Threading).
        if(keylistUpdate.EffectiveThreadId is not { Length: > 0 } threadId)
        {
            throw new ArgumentException(
                "The keylist-update MUST carry an 'id' (or 'thid') so the keylist-update-response can continue its thread (DIDComm Coordinate Mediation Protocol 2.0 §States (L41); DIDComm Messaging v2.1 §Threading).",
                nameof(keylistUpdate));
        }

        if(updated.Count == 0)
        {
            throw new ArgumentException(
                "A keylist-update-response confirming zero entries confirms nothing (producer-side sanity guard) (DIDComm Coordinate Mediation Protocol 2.0 §Keylist Response).",
                nameof(updated));
        }

        var results = new List<object>(updated.Count);
        foreach(KeylistUpdateResult result in updated)
        {
            ArgumentNullException.ThrowIfNull(result);
            ArgumentException.ThrowIfNullOrWhiteSpace(result.RecipientDid);

            if(!IsClosedActionValue(result.Action))
            {
                throw new ArgumentException(
                    $"A keylist-update-response entry's action MUST be '{WellKnownCoordinateMediationNames.ActionAdd}' or " +
                    $"'{WellKnownCoordinateMediationNames.ActionRemove}' (DIDComm Coordinate Mediation Protocol 2.0 §Keylist Response).",
                    nameof(updated));
            }

            if(!IsClosedResultValue(result.Result))
            {
                throw new ArgumentException(
                    $"A keylist-update-response entry's result MUST be one of '{WellKnownCoordinateMediationNames.ResultClientError}', " +
                    $"'{WellKnownCoordinateMediationNames.ResultServerError}', '{WellKnownCoordinateMediationNames.ResultNoChange}', or " +
                    $"'{WellKnownCoordinateMediationNames.ResultSuccess}' (DIDComm Coordinate Mediation Protocol 2.0 §Keylist Response).",
                    nameof(updated));
            }

            results.Add(new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.RecipientDid] = result.RecipientDid,
                [WellKnownCoordinateMediationNames.Action] = result.Action,
                [WellKnownCoordinateMediationNames.Result] = result.Result
            });
        }

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownCoordinateMediationNames.KeylistUpdateResponseType,
            From = from,
            ThreadId = threadId,
            Body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Updated] = results }
        };
    }


    /// <summary>
    /// Builds a <c>keylist-query</c> message: <c>type</c> is the keylist-query Message Type URI, no
    /// <c>body</c> is emitted when <paramref name="paginate"/> is omitted, <c>body.paginate</c> carries
    /// <paramref name="paginate"/> when supplied, and <c>return_route</c> is set to <c>all</c> (§Keylist Query,
    /// §Requirements).
    /// </summary>
    /// <param name="id">REQUIRED. The message id — its thread id is what a reply <c>keylist</c> correlates against.</param>
    /// <param name="paginate">
    /// OPTIONAL. The pagination window. When supplied, <see cref="KeylistPaginate.Limit"/> MUST be positive —
    /// the spec is silent on <c>0</c>, but a zero-limit page can return nothing, so this producer-side sanity
    /// guard refuses it — and <see cref="KeylistPaginate.Offset"/> MUST NOT be negative (§Keylist Query).
    /// </param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The keylist-query message, carrying <c>return_route: all</c>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null/empty, <paramref name="paginate"/>.<see cref="KeylistPaginate.Limit"/> is not positive, or its <see cref="KeylistPaginate.Offset"/> is negative.</exception>
    public static DidCommMessage CreateKeylistQuery(string id, KeylistPaginate? paginate = null, string? from = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        Dictionary<string, object>? body = null;
        if(paginate is not null)
        {
            if(paginate.Limit <= 0)
            {
                throw new ArgumentException(
                    "A keylist-query's paginate.limit MUST be positive — a zero-limit page can return nothing " +
                    "(producer-side sanity guard) (DIDComm Coordinate Mediation Protocol 2.0 §Keylist Query).",
                    nameof(paginate));
            }

            if(paginate.Offset < 0)
            {
                throw new ArgumentException(
                    "A keylist-query's paginate.offset MUST NOT be negative (DIDComm Coordinate Mediation Protocol 2.0 §Keylist Query).",
                    nameof(paginate));
            }

            body = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Paginate] = new Dictionary<string, object>
                {
                    [WellKnownCoordinateMediationNames.Limit] = paginate.Limit,
                    [WellKnownCoordinateMediationNames.Offset] = paginate.Offset
                }
            };
        }

        var message = new DidCommMessage
        {
            Id = id,
            Type = WellKnownCoordinateMediationNames.KeylistQueryType,
            From = from,
            Body = body
        };

        return message.WithReturnRoute(WellKnownReturnRouteNames.All);
    }


    /// <summary>
    /// Builds a <c>keylist</c> message answering <paramref name="keylistQuery"/>: <c>type</c> is the keylist
    /// Message Type URI, <c>thid</c> continues the query's thread, <c>body.keys</c> carries
    /// <paramref name="keys"/>, and <c>body.pagination</c> carries <paramref name="pagination"/> when
    /// supplied (§Keylist).
    /// </summary>
    /// <param name="keylistQuery">REQUIRED. The keylist-query this keylist answers.</param>
    /// <param name="id">REQUIRED. The keylist message's own id.</param>
    /// <param name="keys">REQUIRED. The registered keys — non-null, MAY be empty (no keys registered is a legitimate answer), no null entries, each with a non-whitespace <see cref="KeylistKey.RecipientDid"/> (§Keylist).</param>
    /// <param name="pagination">OPTIONAL. The pagination window. When supplied, <see cref="KeylistPagination.Count"/>, <see cref="KeylistPagination.Offset"/>, and <see cref="KeylistPagination.Remaining"/> MUST NOT be negative (§Keylist).</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The keylist message.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="keylistQuery"/> is not a keylist-query, carries no <c>id</c>/<c>thid</c> to
    /// correlate against, <paramref name="id"/> is null/empty, a key is null or has a null/whitespace
    /// <c>RecipientDid</c>, or <paramref name="pagination"/> carries a negative member.
    /// </exception>
    public static DidCommMessage CreateKeylist(this DidCommMessage keylistQuery, string id, IReadOnlyList<KeylistKey> keys, KeylistPagination? pagination = null, string? from = null)
    {
        ArgumentNullException.ThrowIfNull(keylistQuery);
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(keys);

        if(!keylistQuery.IsKeylistQuery())
        {
            throw new ArgumentException(
                "A keylist MUST answer a keylist-query (DIDComm Coordinate Mediation Protocol 2.0 §Keylist).",
                nameof(keylistQuery));
        }

        //The keylist answers THIS keylist-query specifically, so it MUST continue the query's thread (DIDComm
        //Coordinate Mediation Protocol 2.0 §States (L41); DIDComm Messaging v2.1 §Threading).
        if(keylistQuery.EffectiveThreadId is not { Length: > 0 } threadId)
        {
            throw new ArgumentException(
                "The keylist-query MUST carry an 'id' (or 'thid') so the keylist can continue its thread (DIDComm Coordinate Mediation Protocol 2.0 §States (L41); DIDComm Messaging v2.1 §Threading).",
                nameof(keylistQuery));
        }

        var keyEntries = new List<object>(keys.Count);
        foreach(KeylistKey key in keys)
        {
            ArgumentNullException.ThrowIfNull(key);
            ArgumentException.ThrowIfNullOrWhiteSpace(key.RecipientDid);

            keyEntries.Add(new Dictionary<string, object> { [WellKnownCoordinateMediationNames.RecipientDid] = key.RecipientDid });
        }

        var body = new Dictionary<string, object> { [WellKnownCoordinateMediationNames.Keys] = keyEntries };

        if(pagination is not null)
        {
            if(pagination.Count < 0 || pagination.Offset < 0 || pagination.Remaining < 0)
            {
                throw new ArgumentException(
                    "A keylist's pagination.count/offset/remaining MUST NOT be negative (DIDComm Coordinate Mediation Protocol 2.0 §Keylist).",
                    nameof(pagination));
            }

            body[WellKnownCoordinateMediationNames.Pagination] = new Dictionary<string, object>
            {
                [WellKnownCoordinateMediationNames.Count] = pagination.Count,
                [WellKnownCoordinateMediationNames.Offset] = pagination.Offset,
                [WellKnownCoordinateMediationNames.Remaining] = pagination.Remaining
            };
        }

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownCoordinateMediationNames.KeylistType,
            From = from,
            ThreadId = threadId,
            Body = body
        };
    }


    /// <summary>
    /// Reads <paramref name="message"/> as a <c>mediate-grant</c>, recovering its <c>routing_did</c>. Fails
    /// closed — never throws — when the message is not a mediate-grant, or <c>routing_did</c> — the one
    /// member the message exists to carry — is missing, not a string, or whitespace-only (§Mediate Grant).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="routingDid">The recovered routing DID when interpretation succeeds; otherwise <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="message"/> is a conformant mediate-grant.</returns>
    public static bool TryReadMediateGrantRoutingDid(this DidCommMessage message, [NotNullWhen(true)] out string? routingDid)
    {
        ArgumentNullException.ThrowIfNull(message);

        routingDid = null;

        if(!message.IsMediateGrant() || message.Body is not { } body)
        {
            return false;
        }

        if(!body.TryGetValue(WellKnownCoordinateMediationNames.RoutingDid, out object? raw)
            || raw is not string text
            || string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        routingDid = text;

        return true;
    }


    /// <summary>
    /// Reads <paramref name="message"/> as a <c>keylist-update</c>, recovering its <c>updates</c> entries.
    /// Fails closed — never throws — when the message is not a keylist-update, or <c>body.updates</c> is
    /// missing, empty, not an array, or holds an entry missing a string <c>recipient_did</c> or <c>action</c>
    /// (§Keylist Update). <c>action</c> is returned VERBATIM — an unrecognized value does not fail the read.
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="updates">The recovered update entries, in wire order, when interpretation succeeds.</param>
    /// <returns><see langword="true"/> when <paramref name="message"/> is a conformant keylist-update.</returns>
    public static bool TryReadKeylistUpdates(this DidCommMessage message, [NotNullWhen(true)] out IReadOnlyList<KeylistUpdateEntry>? updates)
    {
        ArgumentNullException.ThrowIfNull(message);

        updates = null;

        if(!message.IsKeylistUpdate() || message.Body is not { } body)
        {
            return false;
        }

        if(!TryReadEntryArray(body, WellKnownCoordinateMediationNames.Updates, out IReadOnlyList<IDictionary<string, object>>? rawEntries))
        {
            return false;
        }

        var collected = new List<KeylistUpdateEntry>(rawEntries.Count);
        foreach(IDictionary<string, object> raw in rawEntries)
        {
            if(!TryReadEntryString(raw, WellKnownCoordinateMediationNames.RecipientDid, out string? recipientDid)
                || !TryReadEntryString(raw, WellKnownCoordinateMediationNames.Action, out string? action))
            {
                return false;
            }

            collected.Add(new KeylistUpdateEntry { RecipientDid = recipientDid, Action = action });
        }

        //A keylist-update MUST carry at least one update entry — the message exists to carry a change
        //(DIDComm Coordinate Mediation Protocol 2.0 §Keylist Update).
        if(collected.Count == 0)
        {
            return false;
        }

        updates = collected;

        return true;
    }


    /// <summary>
    /// Reads <paramref name="message"/> as a <c>keylist-update-response</c>, recovering its <c>updated</c>
    /// entries. Fails closed — never throws — when the message is not a keylist-update-response, or
    /// <c>body.updated</c> is missing, empty, not an array, or holds an entry missing a string
    /// <c>recipient_did</c>, <c>action</c>, or <c>result</c> (§Keylist Response). <c>action</c> and
    /// <c>result</c> are returned VERBATIM — an unrecognized value does not fail the read.
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="updated">The recovered confirmation entries, in wire order, when interpretation succeeds.</param>
    /// <returns><see langword="true"/> when <paramref name="message"/> is a conformant keylist-update-response.</returns>
    public static bool TryReadKeylistUpdateResults(this DidCommMessage message, [NotNullWhen(true)] out IReadOnlyList<KeylistUpdateResult>? updated)
    {
        ArgumentNullException.ThrowIfNull(message);

        updated = null;

        if(!message.IsKeylistUpdateResponse() || message.Body is not { } body)
        {
            return false;
        }

        if(!TryReadEntryArray(body, WellKnownCoordinateMediationNames.Updated, out IReadOnlyList<IDictionary<string, object>>? rawEntries))
        {
            return false;
        }

        var collected = new List<KeylistUpdateResult>(rawEntries.Count);
        foreach(IDictionary<string, object> raw in rawEntries)
        {
            if(!TryReadEntryString(raw, WellKnownCoordinateMediationNames.RecipientDid, out string? recipientDid)
                || !TryReadEntryString(raw, WellKnownCoordinateMediationNames.Action, out string? action)
                || !TryReadEntryString(raw, WellKnownCoordinateMediationNames.Result, out string? result))
            {
                return false;
            }

            collected.Add(new KeylistUpdateResult { RecipientDid = recipientDid, Action = action, Result = result });
        }

        //A keylist-update-response confirming zero entries confirms nothing (mirrors the producer guard in
        //CreateKeylistUpdateResponse) (DIDComm Coordinate Mediation Protocol 2.0 §Keylist Response).
        if(collected.Count == 0)
        {
            return false;
        }

        updated = collected;

        return true;
    }


    /// <summary>
    /// Reads <paramref name="message"/>'s <c>paginate</c> as a <c>keylist-query</c>, distinguishing "not a
    /// keylist-query" from "keylist-query naming no paginate" (§Keylist Query).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="paginate">
    /// The recovered pagination window, or <see langword="null"/> when the keylist-query carries none. Only
    /// meaningful when this method returns <see langword="true"/>.
    /// </param>
    /// <returns>
    /// <see langword="false"/> when <paramref name="message"/> is not a keylist-query, or names a
    /// <c>paginate</c> that is not an object, is missing/non-integral <c>limit</c>/<c>offset</c>, or narrows
    /// to a non-positive <c>limit</c> or a negative <c>offset</c> — consumer-side symmetry with
    /// <see cref="CreateKeylistQuery"/>'s producer guard, matching
    /// <see cref="Verifiable.DidComm.MessagePickup.MessagePickupExtensions.TryReadDeliveryRequest"/>: the
    /// spec is silent on the exact bound, but a non-positive limit cannot request a page, and a negative
    /// offset is malformation, not future vocabulary — the verbatim-reader leniency elsewhere in this class is
    /// scoped to the <c>action</c>/<c>result</c> tokens, not to numeric ranges a conformant producer would
    /// never emit; <see langword="true"/> for any conformant keylist-query, whether or not it names a paginate.
    /// </returns>
    public static bool TryReadKeylistQueryPaginate(this DidCommMessage message, out KeylistPaginate? paginate)
    {
        ArgumentNullException.ThrowIfNull(message);

        paginate = null;

        if(!message.IsKeylistQuery())
        {
            return false;
        }

        if(message.Body is not { } body
            || !body.TryGetValue(WellKnownCoordinateMediationNames.Paginate, out object? raw)
            || raw is null)
        {
            return true;
        }

        if(raw is not IDictionary<string, object> nested
            || !DidCommBodyNumbers.TryReadRequiredInteger(nested, WellKnownCoordinateMediationNames.Limit, out long limit)
            || !DidCommBodyNumbers.TryReadRequiredInteger(nested, WellKnownCoordinateMediationNames.Offset, out long offset)
            || limit <= 0
            || offset < 0)
        {
            return false;
        }

        paginate = new KeylistPaginate { Limit = limit, Offset = offset };

        return true;
    }


    /// <summary>
    /// Reads <paramref name="message"/> as a <c>keylist</c>, recovering its <c>keys</c> and OPTIONAL
    /// <c>pagination</c> (§Keylist).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="keys">The recovered registered keys, in wire order — an empty list is a legitimate "no keys registered" answer. Only meaningful when this method returns <see langword="true"/>.</param>
    /// <param name="pagination">The recovered pagination window, or <see langword="null"/> when the keylist carries none. Only meaningful when this method returns <see langword="true"/>.</param>
    /// <returns>
    /// <see langword="false"/> when <paramref name="message"/> is not a keylist, <c>body.keys</c> is
    /// missing/not an array/holds an entry missing a string <c>recipient_did</c>, or a present
    /// <c>pagination</c> is not an object, is missing/non-integral <c>count</c>/<c>offset</c>/<c>remaining</c>,
    /// or narrows to a negative <c>count</c>, <c>offset</c>, or <c>remaining</c> — consumer-side symmetry with
    /// <see cref="CreateKeylist"/>'s producer guard, matching
    /// <see cref="Verifiable.DidComm.MessagePickup.MessagePickupExtensions.TryReadDeliveryRequest"/>: the
    /// spec is silent on the exact bound, but a negative pagination value is malformation, not future
    /// vocabulary.
    /// </returns>
    public static bool TryReadKeylistKeys(this DidCommMessage message, [NotNullWhen(true)] out IReadOnlyList<KeylistKey>? keys, out KeylistPagination? pagination)
    {
        ArgumentNullException.ThrowIfNull(message);

        keys = null;
        pagination = null;

        if(!message.IsKeylist() || message.Body is not { } body)
        {
            return false;
        }

        if(!TryReadEntryArray(body, WellKnownCoordinateMediationNames.Keys, out IReadOnlyList<IDictionary<string, object>>? rawKeys))
        {
            return false;
        }

        var collected = new List<KeylistKey>(rawKeys.Count);
        foreach(IDictionary<string, object> raw in rawKeys)
        {
            if(!TryReadEntryString(raw, WellKnownCoordinateMediationNames.RecipientDid, out string? recipientDid))
            {
                return false;
            }

            collected.Add(new KeylistKey { RecipientDid = recipientDid });
        }

        if(body.TryGetValue(WellKnownCoordinateMediationNames.Pagination, out object? rawPagination) && rawPagination is not null)
        {
            if(rawPagination is not IDictionary<string, object> nested
                || !DidCommBodyNumbers.TryReadRequiredInteger(nested, WellKnownCoordinateMediationNames.Count, out long count)
                || !DidCommBodyNumbers.TryReadRequiredInteger(nested, WellKnownCoordinateMediationNames.Offset, out long offset)
                || !DidCommBodyNumbers.TryReadRequiredInteger(nested, WellKnownCoordinateMediationNames.Remaining, out long remaining)
                || count < 0
                || offset < 0
                || remaining < 0)
            {
                return false;
            }

            pagination = new KeylistPagination { Count = count, Offset = offset, Remaining = remaining };
        }

        keys = collected;

        return true;
    }


    //The action producer set is CLOSED — mirrors the CreateKeylistUpdate/CreateKeylistUpdateResponse guards.
    private static bool IsClosedActionValue(string action) =>
        string.Equals(action, WellKnownCoordinateMediationNames.ActionAdd, StringComparison.Ordinal)
        || string.Equals(action, WellKnownCoordinateMediationNames.ActionRemove, StringComparison.Ordinal);


    //The result producer set is CLOSED — mirrors the CreateKeylistUpdateResponse guard.
    private static bool IsClosedResultValue(string result) =>
        string.Equals(result, WellKnownCoordinateMediationNames.ResultClientError, StringComparison.Ordinal)
        || string.Equals(result, WellKnownCoordinateMediationNames.ResultServerError, StringComparison.Ordinal)
        || string.Equals(result, WellKnownCoordinateMediationNames.ResultNoChange, StringComparison.Ordinal)
        || string.Equals(result, WellKnownCoordinateMediationNames.ResultSuccess, StringComparison.Ordinal);


    //Reads a REQUIRED body member expected to be a JSON array of JSON objects (mirrors
    //DiscoverFeaturesExtensions.TryReadDescriptorArray). Missing, null, a string, a JSON object, a non-array,
    //or an element that is not an object fails closed; an empty array is a legal read — callers that require
    //at least one entry check the count themselves.
    private static bool TryReadEntryArray(IDictionary<string, object> body, string member, [NotNullWhen(true)] out IReadOnlyList<IDictionary<string, object>>? entries)
    {
        entries = null;
        if(!body.TryGetValue(member, out object? raw) || raw is null)
        {
            return false;
        }

        //A string is IEnumerable but is not a JSON array; reject it explicitly. Likewise a JSON object reads
        //back as a Dictionary<string, object>, which is ALSO IEnumerable (its KeyValuePair enumerator) — an
        //empty one, such as "keys": {}, would otherwise enumerate zero elements and read TRUE, contradicting
        //this method's own "false when … not an array" contract; reject it explicitly too.
        if(raw is string || raw is IDictionary<string, object> || raw is not IEnumerable elements)
        {
            return false;
        }

        var collected = new List<IDictionary<string, object>>();
        foreach(object? element in elements)
        {
            if(element is not IDictionary<string, object> entry)
            {
                return false;
            }

            collected.Add(entry);
        }

        entries = collected;

        return true;
    }


    //Reads a member expected to be a string, VERBATIM — no whitespace/emptiness enforcement and no closed-set
    //check, since an inbound message is untrusted wire input and this is the reader-side leniency half of the
    //action/result producer/reader asymmetry (see the class remarks). Missing, null, or non-string fails closed.
    private static bool TryReadEntryString(IDictionary<string, object> entry, string member, [NotNullWhen(true)] out string? value)
    {
        value = null;
        if(!entry.TryGetValue(member, out object? raw) || raw is not string text)
        {
            return false;
        }

        value = text;

        return true;
    }
}
