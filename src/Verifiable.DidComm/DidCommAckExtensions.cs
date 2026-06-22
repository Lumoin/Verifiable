using System.Collections.Generic;

namespace Verifiable.DidComm;

/// <summary>
/// Acknowledgment helpers for DIDComm plaintext messages — reading the <c>please_ack</c> and <c>ack</c>
/// headers and building the messages that honor an acknowledgment request, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#acks">DIDComm Messaging v2.1 §ACKs</see>.
/// </summary>
/// <remarks>
/// <para>
/// A sender MAY request acknowledgment with the <c>please_ack</c> header — an array of message ids, where
/// the empty string <c>""</c> stands for the current message. The request creates no obligation; a
/// cooperating recipient SHOULD include an <c>ack</c> header on a subsequent message naming the
/// acknowledged ids, oldest to most recent. A message carrying an <c>ack</c> header is an explicit ACK
/// regardless of its type, and a pure ACK with no other content SHOULD be the Empty Message with an
/// <c>ack</c> header (DIDComm v2.1 §ACKs, §The Empty Message).
/// </para>
/// <para>
/// The anti-loop rules of §ACKs (never honor a request more than once; never send a pure ACK that itself
/// requests an ACK; never honor a pure ACK's request that arrives in reply to your own request) depend on
/// per-protocol runtime state the library does not hold, so they are the application's responsibility.
/// This surface supplies the building blocks: it never sets <c>please_ack</c> on a pure acknowledgment
/// (<see cref="CreateAcknowledgment"/>), and it leaves request bookkeeping to the caller.
/// </para>
/// </remarks>
public static class DidCommAckExtensions
{
    /// <summary>
    /// Whether <paramref name="message"/> is an explicit ACK — it carries an <c>ack</c> header with at
    /// least one acknowledged id, regardless of its message type (DIDComm v2.1 §ACKs).
    /// </summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the <c>ack</c> header is present and non-empty.</returns>
    public static bool IsExplicitAck(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return message.Ack is { Count: > 0 };
    }


    /// <summary>
    /// Whether <paramref name="message"/> requests acknowledgment — it carries a <c>please_ack</c> header
    /// with at least one entry (DIDComm v2.1 §ACKs). The request creates no obligation on the recipient.
    /// </summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the <c>please_ack</c> header is present and non-empty.</returns>
    public static bool RequestsAcknowledgment(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return message.PleaseAck is { Count: > 0 };
    }


    /// <summary>
    /// Resolves the concrete message ids whose acknowledgment <paramref name="message"/> requests — each
    /// <c>please_ack</c> entry with the empty string <c>""</c> expanded to the message's own
    /// <see cref="DidCommMessage.Id"/> (DIDComm v2.1 §ACKs: <c>""</c> means "the current message").
    /// </summary>
    /// <param name="message">The message whose <c>please_ack</c> header is read.</param>
    /// <returns>
    /// The requested ids in header order, with <c>""</c> resolved to the current id. An absent
    /// <c>please_ack</c> yields an empty list; an <c>""</c> entry is dropped when the message has no id
    /// (a malformed message cannot identify "the current message").
    /// </returns>
    public static IReadOnlyList<string> ResolveRequestedAcks(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        if(message.PleaseAck is not { Count: > 0 } requested)
        {
            return [];
        }

        var resolved = new List<string>(requested.Count);
        foreach(string entry in requested)
        {
            if(entry is null)
            {
                continue;
            }

            if(entry.Length == 0)
            {
                if(!string.IsNullOrEmpty(message.Id))
                {
                    resolved.Add(message.Id);
                }

                continue;
            }

            resolved.Add(entry);
        }

        return resolved;
    }


    /// <summary>
    /// Builds an Empty Message — a message whose <c>type</c> is the empty Message Type URI and whose
    /// <c>body</c> is the empty object <c>{}</c> (DIDComm v2.1 §The Empty Message). The empty message has
    /// no semantic meaning; it exists to carry headers when there is no body content.
    /// </summary>
    /// <param name="id">REQUIRED. The message id, unique to the sender (DIDComm v2.1 §Message Headers).</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <param name="threadId">OPTIONAL. The thread this message continues.</param>
    /// <param name="parentThreadId">OPTIONAL. The parent thread, when this message is a child of another.</param>
    /// <returns>The empty message.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null or empty.</exception>
    public static DidCommMessage CreateEmptyMessage(string id, string? from = null, string? threadId = null, string? parentThreadId = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(id);

        return new DidCommMessage
        {
            Id = id,
            Type = WellKnownEmptyMessageNames.EmptyType,
            From = from,
            ThreadId = threadId,
            ParentThreadId = parentThreadId,
            Body = new Dictionary<string, object>()
        };
    }


    /// <summary>
    /// Builds a pure acknowledgment — an Empty Message carrying an <c>ack</c> header naming
    /// <paramref name="acknowledgedMessageIds"/> (DIDComm v2.1 §ACKs: "the empty message with an
    /// <c>ack</c> header"). The message continues the acknowledged thread via <paramref name="threadId"/>,
    /// as any message that continues a protocol MUST (DIDComm v2.1 §Threads).
    /// </summary>
    /// <param name="acknowledgedMessageIds">
    /// REQUIRED. The ids being acknowledged, in the order received — oldest to most recent (DIDComm v2.1 §ACKs).
    /// </param>
    /// <param name="id">REQUIRED. The acknowledgment message's own id, unique to the sender.</param>
    /// <param name="threadId">REQUIRED. The thread the acknowledged messages belong to.</param>
    /// <param name="from">OPTIONAL. The acknowledger's identifier.</param>
    /// <returns>The pure acknowledgment message. It never requests an acknowledgment in turn (DIDComm v2.1 §ACKs anti-loop rules).</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> or <paramref name="threadId"/> is null or empty, or <paramref name="acknowledgedMessageIds"/> is empty or contains a null or empty id.</exception>
    public static DidCommMessage CreateAcknowledgment(IReadOnlyList<string> acknowledgedMessageIds, string id, string threadId, string? from = null)
    {
        ArgumentNullException.ThrowIfNull(acknowledgedMessageIds);
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentException.ThrowIfNullOrEmpty(threadId);

        if(acknowledgedMessageIds.Count == 0)
        {
            throw new ArgumentException(
                "An acknowledgment MUST name at least one acknowledged message id (DIDComm v2.1 §ACKs).",
                nameof(acknowledgedMessageIds));
        }

        foreach(string acknowledgedId in acknowledgedMessageIds)
        {
            if(string.IsNullOrEmpty(acknowledgedId))
            {
                throw new ArgumentException(
                    "An acknowledged message id MUST NOT be null or empty (DIDComm v2.1 §ACKs).",
                    nameof(acknowledgedMessageIds));
            }
        }

        DidCommMessage acknowledgment = CreateEmptyMessage(id, from, threadId);

        //A pure ACK is an explicit ACK (it carries the ack header) but MUST NOT itself request an ACK —
        //never send a pure ACK that requests an ACK (DIDComm v2.1 §ACKs anti-loop rules). PleaseAck is
        //left unset by construction.
        acknowledgment.Ack = [.. acknowledgedMessageIds];

        return acknowledgment;
    }
}
