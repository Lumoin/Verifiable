using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.DidComm.ReturnRoute;

namespace Verifiable.DidComm.MessagePickup;

/// <summary>
/// Build and interpret for the DIDComm Message Pickup Protocol 3.0 — the six message types a recipient uses
/// to poll, retrieve, and acknowledge messages queued at a mediator, per
/// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// The <c>Create…</c> builders are producer-side and MAY throw on bad caller arguments; the
/// <c>TryRead…</c>/<c>Is…</c> members consume attacker-controlled wire input and are fail-closed — they
/// never throw (beyond a null-argument guard), returning <see langword="false"/> for any structurally
/// non-conformant message. The dictionary <c>body</c> is only the wire intermediate; callers operate on
/// <see cref="MessagePickupStatus"/> or the individual <c>out</c> values.
/// </para>
/// <para>
/// Every RECIPIENT request builder (<see cref="CreateStatusRequest"/>, <see cref="CreateDeliveryRequest"/>,
/// <see cref="CreateMessagesReceived"/>, <see cref="CreateLiveDeliveryChange"/>) sets <c>return_route: all</c>
/// via <see cref="DidCommReturnRouteExtensions.WithReturnRoute"/> — §States requires it "in all request
/// submitted by the recipient", so there is no parameter to opt out. The mediator-side builders
/// (<see cref="CreateStatus"/>, <see cref="CreateDelivery"/>) are replies, not requests, and never set it.
/// </para>
/// <para>
/// The mediator-only obligations this protocol states — replying to each request kind, deleting messages
/// only after acknowledgment, per-recipient independent queueing, and the Live Mode connection-state
/// machine — are queue/connection management this library holds no state for; those statements are proven
/// as composition tests showing the message shapes this surface produces are sufficient to build a
/// conformant mediator on top, with the library/application boundary stated at each site.
/// </para>
/// </remarks>
public static class MessagePickupExtensions
{
    //The six Message Pickup 3.0 Message Type URIs, parsed once for semver-compatible handler dispatch
    //(pattern: Verifiable.DidComm.TrustPing.TrustPingExtensions).
    private static MessageTypeUri StatusRequestMessageType { get; } = MessageTypeUri.Parse(WellKnownMessagePickupNames.StatusRequestType);
    private static MessageTypeUri StatusMessageType { get; } = MessageTypeUri.Parse(WellKnownMessagePickupNames.StatusType);
    private static MessageTypeUri DeliveryRequestMessageType { get; } = MessageTypeUri.Parse(WellKnownMessagePickupNames.DeliveryRequestType);
    private static MessageTypeUri DeliveryMessageType { get; } = MessageTypeUri.Parse(WellKnownMessagePickupNames.DeliveryType);
    private static MessageTypeUri MessagesReceivedMessageType { get; } = MessageTypeUri.Parse(WellKnownMessagePickupNames.MessagesReceivedType);
    private static MessageTypeUri LiveDeliveryChangeMessageType { get; } = MessageTypeUri.Parse(WellKnownMessagePickupNames.LiveDeliveryChangeType);


    /// <summary>Whether <paramref name="message"/> is a <c>status-request</c> — its <c>type</c> names the status-request Message Type URI (§Status Request).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a status-request.</returns>
    public static bool IsStatusRequest(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(StatusRequestMessageType);
    }


    /// <summary>Whether <paramref name="message"/> is a <c>status</c> — its <c>type</c> names the status Message Type URI (§Status).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a status.</returns>
    public static bool IsStatus(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(StatusMessageType);
    }


    /// <summary>Whether <paramref name="message"/> is a <c>delivery-request</c> — its <c>type</c> names the delivery-request Message Type URI (§Delivery Request).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a delivery-request.</returns>
    public static bool IsDeliveryRequest(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(DeliveryRequestMessageType);
    }


    /// <summary>
    /// Whether <paramref name="message"/> is a <c>delivery</c> — its <c>type</c> names the delivery Message
    /// Type URI. TRAP: the spec walkthrough calls this "the message-delivery message" in prose, but the
    /// actual wire type token is <c>delivery</c> (§Message Delivery).
    /// </summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a delivery.</returns>
    public static bool IsDelivery(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(DeliveryMessageType);
    }


    /// <summary>Whether <paramref name="message"/> is a <c>messages-received</c> — its <c>type</c> names the messages-received Message Type URI (§Messages Received).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a messages-received.</returns>
    public static bool IsMessagesReceived(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(MessagesReceivedMessageType);
    }


    /// <summary>Whether <paramref name="message"/> is a <c>live-delivery-change</c> — its <c>type</c> names the live-delivery-change Message Type URI (§Live Mode Change).</summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a live-delivery-change.</returns>
    public static bool IsLiveDeliveryChange(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(LiveDeliveryChangeMessageType);
    }


    /// <summary>
    /// Builds a <c>status-request</c> message: <c>type</c> is the status-request Message Type URI,
    /// <c>body.recipient_did</c> carries <paramref name="recipientDid"/> when supplied, and
    /// <c>return_route</c> is set to <c>all</c> (§Status Request, §States).
    /// </summary>
    /// <param name="id">REQUIRED. The message id.</param>
    /// <param name="recipientDid">OPTIONAL. Scopes the status to messages queued for this did (§Status Request).</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The status-request message, carrying <c>return_route: all</c>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null or empty.</exception>
    public static DidCommMessage CreateStatusRequest(string id, string? recipientDid = null, string? from = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        Dictionary<string, object>? body = recipientDid is null
            ? null
            : new Dictionary<string, object> { [WellKnownMessagePickupNames.RecipientDid] = recipientDid };

        var message = new DidCommMessage
        {
            Id = id,
            Type = WellKnownMessagePickupNames.StatusRequestType,
            From = from,
            Body = body
        };

        return message.WithReturnRoute(WellKnownReturnRouteNames.All);
    }


    /// <summary>
    /// Builds a <c>delivery-request</c> message: <c>type</c> is the delivery-request Message Type URI,
    /// <c>body.limit</c> carries the REQUIRED <paramref name="limit"/>, <c>body.recipient_did</c> carries
    /// <paramref name="recipientDid"/> when supplied, and <c>return_route</c> is set to <c>all</c>
    /// (§Delivery Request, §States).
    /// </summary>
    /// <param name="id">REQUIRED. The message id — its thread id is what a reply <c>delivery</c> or <c>status</c> correlates against.</param>
    /// <param name="limit">
    /// REQUIRED. The maximum number of messages the mediator should deliver. MUST be positive — the spec is
    /// silent on <c>0</c>, but a zero-limit delivery request can deliver nothing, so this producer-side
    /// sanity guard refuses it rather than shipping a request that can never do anything.
    /// </param>
    /// <param name="recipientDid">OPTIONAL. Scopes delivery to messages sent to this did (§Delivery Request).</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The delivery-request message, carrying <c>return_route: all</c>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null or empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="limit"/> is not positive.</exception>
    public static DidCommMessage CreateDeliveryRequest(string id, int limit, string? recipientDid = null, string? from = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(limit, 0);

        var body = new Dictionary<string, object> { [WellKnownMessagePickupNames.Limit] = limit };
        if(recipientDid is not null)
        {
            body[WellKnownMessagePickupNames.RecipientDid] = recipientDid;
        }

        var message = new DidCommMessage
        {
            Id = id,
            Type = WellKnownMessagePickupNames.DeliveryRequestType,
            From = from,
            Body = body
        };

        return message.WithReturnRoute(WellKnownReturnRouteNames.All);
    }


    /// <summary>
    /// Builds a <c>messages-received</c> message: <c>type</c> is the messages-received Message Type URI,
    /// <c>body.message_id_list</c> carries <paramref name="messageIdList"/> verbatim, and
    /// <c>return_route</c> is set to <c>all</c> (§Messages Received, §States).
    /// </summary>
    /// <param name="id">REQUIRED. The message id.</param>
    /// <param name="messageIdList">
    /// REQUIRED. The ids of the delivered attachments being acknowledged — non-null, non-empty (an empty ack
    /// acknowledges nothing, a producer-side sanity guard), and every entry non-null/non-whitespace. Pass
    /// the delivery attachment ids verbatim; the spec treats them as opaque (§Message Delivery).
    /// </param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The messages-received message, carrying <c>return_route: all</c>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null/empty, <paramref name="messageIdList"/> is null/empty, or any entry is null/whitespace.</exception>
    public static DidCommMessage CreateMessagesReceived(string id, IReadOnlyList<string> messageIdList, string? from = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(messageIdList);

        if(messageIdList.Count == 0)
        {
            throw new ArgumentException(
                "A messages-received acknowledging zero ids confirms nothing (producer-side sanity guard) (DIDComm Message Pickup Protocol 3.0 §Messages Received).",
                nameof(messageIdList));
        }

        var ids = new List<object>(messageIdList.Count);
        foreach(string messageId in messageIdList)
        {
            if(string.IsNullOrWhiteSpace(messageId))
            {
                throw new ArgumentException(
                    "Every acknowledged message id MUST be non-null and non-whitespace (DIDComm Message Pickup Protocol 3.0 §Messages Received).",
                    nameof(messageIdList));
            }

            ids.Add(messageId);
        }

        var message = new DidCommMessage
        {
            Id = id,
            Type = WellKnownMessagePickupNames.MessagesReceivedType,
            From = from,
            Body = new Dictionary<string, object> { [WellKnownMessagePickupNames.MessageIdList] = ids }
        };

        return message.WithReturnRoute(WellKnownReturnRouteNames.All);
    }


    /// <summary>
    /// Builds a <c>live-delivery-change</c> message: <c>type</c> is the live-delivery-change Message Type
    /// URI, <c>body.live_delivery</c> carries <paramref name="liveDelivery"/>, and <c>return_route</c> is set
    /// to <c>all</c> (§Live Mode Change, §States).
    /// </summary>
    /// <remarks>
    /// The spec's own <c>live-delivery-change</c> EXAMPLE (§Live Mode Change) omits <c>return_route</c>
    /// entirely, but §States requires it "in all request submitted by the recipient" — a
    /// live-delivery-change IS a recipient request (it gets a <c>status</c> or problem-report reply), so
    /// this builder sets <c>return_route: all</c> anyway. This is a deliberate divergence from the spec's
    /// own worked example, not an oversight.
    /// </remarks>
    /// <param name="id">REQUIRED. The message id.</param>
    /// <param name="liveDelivery">The requested Live Mode state: <see langword="true"/> to activate, <see langword="false"/> to deactivate.</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The live-delivery-change message, carrying <c>return_route: all</c>.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null or empty.</exception>
    public static DidCommMessage CreateLiveDeliveryChange(string id, bool liveDelivery, string? from = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        var message = new DidCommMessage
        {
            Id = id,
            Type = WellKnownMessagePickupNames.LiveDeliveryChangeType,
            From = from,
            Body = new Dictionary<string, object> { [WellKnownMessagePickupNames.LiveDelivery] = liveDelivery }
        };

        return message.WithReturnRoute(WellKnownReturnRouteNames.All);
    }


    /// <summary>
    /// Builds a <c>status</c> message answering <paramref name="inResponseTo"/> (or a proactive, unsolicited
    /// status when omitted): <c>type</c> is the status Message Type URI, <c>thid</c> continues the request's
    /// thread, and the body carries every populated member of <paramref name="status"/> (§Status).
    /// </summary>
    /// <remarks>
    /// When <paramref name="inResponseTo"/> is a <c>status-request</c> or <c>delivery-request</c> that named
    /// a <c>recipient_did</c>, the spec requires that "the matching value MUST be specified in the
    /// recipient_did attribute of the status message" — enforced here by throwing when
    /// <paramref name="status"/>.<see cref="MessagePickupStatus.RecipientDid"/> disagrees. A
    /// <c>messages-received</c> or <c>live-delivery-change</c> carries no <c>recipient_did</c> of its own, so
    /// answering one imposes no such constraint.
    /// </remarks>
    /// <param name="id">REQUIRED. The status message's own id.</param>
    /// <param name="status">The queue state to report.</param>
    /// <param name="inResponseTo">
    /// OPTIONAL. The request this status answers — a <c>status-request</c>, an empty-queue
    /// <c>delivery-request</c> (§Delivery Request: "If no messages are available to be sent, a status
    /// message MUST be sent immediately"), a <c>messages-received</c> follow-up, or a
    /// <c>live-delivery-change</c>. <see langword="null"/> for a proactive, unsolicited status.
    /// </param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The status message.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="id"/> is null or empty, or <paramref name="inResponseTo"/> named a
    /// <c>recipient_did</c> that <paramref name="status"/> does not echo.
    /// </exception>
    public static DidCommMessage CreateStatus(string id, MessagePickupStatus status, DidCommMessage? inResponseTo = null, string? from = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentNullException.ThrowIfNull(status);

        if(inResponseTo is not null
            && TryGetNamedRecipientDid(inResponseTo, out string? requestedRecipientDid)
            && !string.Equals(requestedRecipientDid, status.RecipientDid, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The status MUST echo the matching recipient_did '{requestedRecipientDid}' the request named " +
                "(DIDComm Message Pickup Protocol 3.0 §Status).",
                nameof(status));
        }

        var body = new Dictionary<string, object> { [WellKnownMessagePickupNames.MessageCount] = status.MessageCount };
        if(status.RecipientDid is not null)
        {
            body[WellKnownMessagePickupNames.RecipientDid] = status.RecipientDid;
        }

        if(status.LongestWaitedSeconds is { } longestWaited)
        {
            body[WellKnownMessagePickupNames.LongestWaitedSeconds] = longestWaited;
        }

        if(status.NewestReceivedTime is { } newestReceived)
        {
            body[WellKnownMessagePickupNames.NewestReceivedTime] = newestReceived;
        }

        if(status.OldestReceivedTime is { } oldestReceived)
        {
            body[WellKnownMessagePickupNames.OldestReceivedTime] = oldestReceived;
        }

        if(status.TotalBytes is { } totalBytes)
        {
            body[WellKnownMessagePickupNames.TotalBytes] = totalBytes;
        }

        if(status.LiveDelivery is { } liveDelivery)
        {
            body[WellKnownMessagePickupNames.LiveDelivery] = liveDelivery;
        }

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownMessagePickupNames.StatusType,
            From = from,
            ThreadId = inResponseTo?.EffectiveThreadId,
            Body = body
        };
    }


    /// <summary>
    /// Builds a <c>delivery</c> message answering the delivery-request whose thread id is
    /// <paramref name="deliveryRequestThreadId"/>: <c>type</c> is the delivery Message Type URI, <c>thid</c>
    /// is REQUIRED to be that thread id, <c>body.recipient_did</c> carries <paramref name="recipientDid"/>
    /// when supplied, and <paramref name="messages"/> become the delivery's attachments (§Message Delivery).
    /// </summary>
    /// <remarks>
    /// The ONLY valid attachment for a delivery is a DIDComm v2 message in encrypted form — this builder
    /// cannot verify that an attachment's <c>data.base64</c> actually holds ciphertext (that is the caller's
    /// obligation), but it enforces the SHAPE the spec requires: a non-empty <see cref="Attachment.Id"/> (the
    /// id a subsequent <c>messages-received</c> uses to confirm receipt) and a <see cref="AttachmentData.Base64"/>
    /// value with no <see cref="AttachmentData.Json"/>/<see cref="AttachmentData.Links"/> alternative.
    /// </remarks>
    /// <param name="id">REQUIRED. The delivery message's own id.</param>
    /// <param name="deliveryRequestThreadId">REQUIRED. The delivery-request's message id — becomes this delivery's <c>thid</c> (§Message Delivery).</param>
    /// <param name="messages">REQUIRED. The queued messages to deliver as attachments — at least one (an empty queue is answered with <see cref="CreateStatus"/>, never an empty delivery).</param>
    /// <param name="recipientDid">OPTIONAL. Set ONLY when the delivery-request that is being answered indicated a <c>recipient_did</c> — a caller obligation this builder does not itself verify (§Message Delivery).</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <returns>The delivery message.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="id"/> or <paramref name="deliveryRequestThreadId"/> is null/empty,
    /// <paramref name="messages"/> is empty, any attachment lacks a non-empty <c>id</c> or a base64-by-value
    /// <c>data</c>, or two attachments in the batch repeat the same <c>id</c>.
    /// </exception>
    public static DidCommMessage CreateDelivery(
        string id,
        string deliveryRequestThreadId,
        IReadOnlyList<Attachment> messages,
        string? recipientDid = null,
        string? from = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentException.ThrowIfNullOrEmpty(deliveryRequestThreadId);
        ArgumentNullException.ThrowIfNull(messages);

        if(messages.Count == 0)
        {
            throw new ArgumentException(
                "A delivery MUST carry at least one message attachment — an empty queue is answered with a status message instead (DIDComm Message Pickup Protocol 3.0 §Delivery Request).",
                nameof(messages));
        }

        var seenAttachmentIds = new HashSet<string>(StringComparer.Ordinal);
        foreach(Attachment attachment in messages)
        {
            ArgumentNullException.ThrowIfNull(attachment);

            if(string.IsNullOrEmpty(attachment.Id))
            {
                throw new ArgumentException(
                    "Every delivered attachment MUST carry a non-empty id — it is how the recipient confirms receipt (DIDComm Message Pickup Protocol 3.0 §Message Delivery).",
                    nameof(messages));
            }

            if(!seenAttachmentIds.Add(attachment.Id))
            {
                throw new ArgumentException(
                    "Every delivered attachment id MUST be unique within the batch — the id is how the recipient confirms receipt and is unique to the mediator, so a duplicate makes acknowledgment ambiguous (DIDComm Message Pickup Protocol 3.0 §Message Delivery).",
                    nameof(messages));
            }

            if(attachment.Data is not AttachmentData data
                || data.Base64 is not { Length: > 0 }
                || data.Json is not null
                || data.Links is { Count: > 0 })
            {
                throw new ArgumentException(
                    "The ONLY valid attachment type for a delivery is a DIDComm v2 message in encrypted form, carried as base64-by-value data with no json/links alternative (DIDComm Message Pickup Protocol 3.0 §Message Delivery).",
                    nameof(messages));
            }
        }

        Dictionary<string, object>? body = recipientDid is null
            ? null
            : new Dictionary<string, object> { [WellKnownMessagePickupNames.RecipientDid] = recipientDid };

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownMessagePickupNames.DeliveryType,
            From = from,
            ThreadId = deliveryRequestThreadId,
            Body = body,
            Attachments = [.. messages]
        };
    }


    /// <summary>
    /// Reads <paramref name="message"/> as a <c>status</c>, recovering its <see cref="MessagePickupStatus"/>.
    /// Fails closed — never throws — when the message is not a status, or <c>body.message_count</c> — the
    /// only REQUIRED attribute — is missing or not an integral number (§Status).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="status">The recovered status when interpretation succeeds.</param>
    /// <returns><see langword="true"/> when <paramref name="message"/> is a conformant status.</returns>
    public static bool TryReadStatus(this DidCommMessage message, [NotNullWhen(true)] out MessagePickupStatus? status)
    {
        ArgumentNullException.ThrowIfNull(message);

        status = null;

        if(!message.IsStatus() || message.Body is not { } body)
        {
            return false;
        }

        if(!DidCommBodyNumbers.TryReadRequiredInteger(body, WellKnownMessagePickupNames.MessageCount, out long messageCount))
        {
            return false;
        }

        if(!TryReadOptionalString(body, WellKnownMessagePickupNames.RecipientDid, out string? recipientDid)
            || !DidCommBodyNumbers.TryReadOptionalInteger(body, WellKnownMessagePickupNames.LongestWaitedSeconds, out long? longestWaited)
            || !DidCommBodyNumbers.TryReadOptionalInteger(body, WellKnownMessagePickupNames.NewestReceivedTime, out long? newestReceived)
            || !DidCommBodyNumbers.TryReadOptionalInteger(body, WellKnownMessagePickupNames.OldestReceivedTime, out long? oldestReceived)
            || !DidCommBodyNumbers.TryReadOptionalInteger(body, WellKnownMessagePickupNames.TotalBytes, out long? totalBytes)
            || !TryReadOptionalBoolean(body, WellKnownMessagePickupNames.LiveDelivery, out bool? liveDelivery))
        {
            return false;
        }

        status = new MessagePickupStatus
        {
            RecipientDid = recipientDid,
            MessageCount = messageCount,
            LongestWaitedSeconds = longestWaited,
            NewestReceivedTime = newestReceived,
            OldestReceivedTime = oldestReceived,
            TotalBytes = totalBytes,
            LiveDelivery = liveDelivery
        };

        return true;
    }


    /// <summary>
    /// Reads <paramref name="message"/> as a <c>delivery-request</c>, recovering its REQUIRED <c>limit</c>
    /// and OPTIONAL <c>recipient_did</c>. Fails closed — never throws — when the message is not a
    /// delivery-request, <c>limit</c> is missing, not an integral number, or not positive (consumer-side
    /// symmetry with <see cref="CreateDeliveryRequest"/>'s producer guard: the spec is silent on <c>0</c>, but
    /// a non-positive limit cannot request a delivery of anything), or a present <c>recipient_did</c> is not a
    /// string (§Delivery Request).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="limit">The requested delivery limit when interpretation succeeds; otherwise <c>0</c>.</param>
    /// <param name="recipientDid">
    /// The requested recipient scope when interpretation succeeds — <see langword="null"/> when none was
    /// named; also <see langword="null"/>, never a partially-read value, when interpretation fails.
    /// </param>
    /// <returns><see langword="true"/> when <paramref name="message"/> is a conformant delivery-request carrying a positive limit.</returns>
    public static bool TryReadDeliveryRequest(this DidCommMessage message, out long limit, out string? recipientDid)
    {
        ArgumentNullException.ThrowIfNull(message);

        limit = 0;
        recipientDid = null;

        if(!message.IsDeliveryRequest() || message.Body is not { } body)
        {
            return false;
        }

        if(!DidCommBodyNumbers.TryReadRequiredInteger(body, WellKnownMessagePickupNames.Limit, out long parsedLimit) || parsedLimit <= 0)
        {
            return false;
        }

        if(!TryReadOptionalString(body, WellKnownMessagePickupNames.RecipientDid, out string? parsedRecipientDid))
        {
            return false;
        }

        limit = parsedLimit;
        recipientDid = parsedRecipientDid;

        return true;
    }


    /// <summary>
    /// Reads <paramref name="message"/> as a <c>messages-received</c>, recovering its
    /// <c>message_id_list</c> verbatim. Fails closed — never throws — when the message is not a
    /// messages-received, or <c>message_id_list</c> is missing, not an array, or holds a non-string element
    /// (§Messages Received).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="messageIds">The acknowledged message ids, in wire order, when interpretation succeeds.</param>
    /// <returns><see langword="true"/> when <paramref name="message"/> is a conformant messages-received.</returns>
    public static bool TryReadMessagesReceivedIds(this DidCommMessage message, [NotNullWhen(true)] out IReadOnlyList<string>? messageIds)
    {
        ArgumentNullException.ThrowIfNull(message);

        messageIds = null;

        if(!message.IsMessagesReceived() || message.Body is not { } body)
        {
            return false;
        }

        if(!body.TryGetValue(WellKnownMessagePickupNames.MessageIdList, out object? raw) || raw is null)
        {
            return false;
        }

        //A string is IEnumerable but is not a JSON array; reject it explicitly (mirrors DiscoverFeaturesExtensions).
        if(raw is string || raw is not IEnumerable elements)
        {
            return false;
        }

        var collected = new List<string>();
        foreach(object? element in elements)
        {
            if(element is not string text)
            {
                return false;
            }

            collected.Add(text);
        }

        messageIds = collected;

        return true;
    }


    /// <summary>
    /// Reads <paramref name="message"/> as a <c>live-delivery-change</c>, recovering its
    /// <c>live_delivery</c> state. Fails closed — never throws — when the message is not a
    /// live-delivery-change, or <c>live_delivery</c> is missing or not a boolean (§Live Mode Change).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="liveDelivery">The requested Live Mode state when interpretation succeeds; otherwise <see langword="false"/>.</param>
    /// <returns><see langword="true"/> when <paramref name="message"/> is a conformant live-delivery-change.</returns>
    public static bool TryReadLiveDeliveryChange(this DidCommMessage message, out bool liveDelivery)
    {
        ArgumentNullException.ThrowIfNull(message);

        liveDelivery = false;

        if(!message.IsLiveDeliveryChange()
            || message.Body is not { } body
            || !body.TryGetValue(WellKnownMessagePickupNames.LiveDelivery, out object? raw)
            || raw is not bool value)
        {
            return false;
        }

        liveDelivery = value;

        return true;
    }


    /// <summary>
    /// Reads <paramref name="message"/>'s <c>recipient_did</c> as a <c>status-request</c>, distinguishing
    /// "not a status-request" from "status-request naming no did" (§Status Request).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="recipientDid">
    /// The named recipient did, or <see langword="null"/> when the status-request carries none. Only
    /// meaningful when this method returns <see langword="true"/>.
    /// </param>
    /// <returns>
    /// <see langword="false"/> when <paramref name="message"/> is not a status-request (or names a
    /// non-string <c>recipient_did</c>); <see langword="true"/> for any conformant status-request, whether or
    /// not it names a did.
    /// </returns>
    public static bool TryReadStatusRequestRecipientDid(this DidCommMessage message, out string? recipientDid)
    {
        ArgumentNullException.ThrowIfNull(message);

        recipientDid = null;

        if(!message.IsStatusRequest())
        {
            return false;
        }

        if(message.Body is not { } body)
        {
            return true;
        }

        return TryReadOptionalString(body, WellKnownMessagePickupNames.RecipientDid, out recipientDid);
    }


    //Reads the recipient_did a status-request or delivery-request named, for CreateStatus's echo check. A
    //messages-received/live-delivery-change carries no recipient_did member, so nothing is returned for them.
    private static bool TryGetNamedRecipientDid(DidCommMessage inResponseTo, [NotNullWhen(true)] out string? recipientDid)
    {
        recipientDid = null;

        if((inResponseTo.IsStatusRequest() || inResponseTo.IsDeliveryRequest())
            && inResponseTo.Body is { } body
            && body.TryGetValue(WellKnownMessagePickupNames.RecipientDid, out object? raw)
            && raw is string text)
        {
            recipientDid = text;

            return true;
        }

        return false;
    }


    //Reads an OPTIONAL boolean body member: absent or JSON-null yields null with success; a present
    //non-boolean value is a malformation and fails closed.
    private static bool TryReadOptionalBoolean(IDictionary<string, object> body, string member, out bool? value)
    {
        value = null;
        if(!body.TryGetValue(member, out object? raw) || raw is null)
        {
            return true;
        }

        if(raw is not bool parsed)
        {
            return false;
        }

        value = parsed;

        return true;
    }


    //Reads an OPTIONAL string body member: absent or JSON-null yields null with success; a present
    //non-string value is a malformation and fails closed (mirrors DiscoverFeaturesExtensions/DidCommProblemReportExtensions).
    private static bool TryReadOptionalString(IDictionary<string, object> body, string member, out string? value)
    {
        value = null;
        if(!body.TryGetValue(member, out object? raw) || raw is null)
        {
            return true;
        }

        if(raw is string text)
        {
            value = text;

            return true;
        }

        return false;
    }
}
