using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.DidComm.BasicMessage;

/// <summary>
/// Build and interpret for the DIDComm Basic Message Protocol 2.0 — turning a semantic
/// <see cref="BasicMessage"/> into a wire <see cref="DidCommMessage"/> and recovering one from a received
/// message, per
/// <see href="https://didcomm.org/basicmessage/2.0/">DIDComm Basic Message Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// Basic Message is a didcomm.org companion protocol, NOT part of the DIDComm Messaging v2.1 core
/// specification. <see cref="CreateBasicMessage"/> is producer-side and MAY throw on bad caller arguments;
/// <see cref="TryInterpretBasicMessage"/> reads an (already envelope-authenticated) message and is
/// fail-closed — it never throws, returning <see langword="false"/> for any non-conformant message. The
/// dictionary <c>body</c> is only the wire intermediate; callers operate on the typed
/// <see cref="BasicMessage"/>. The protocol expects the message to be encrypted in transit and repudiable
/// (didcomm.org/basicmessage/2.0 §Basics); this layer only shapes the plaintext, leaving the envelope —
/// normally anoncrypt or authcrypt, both repudiable — to the caller.
/// </para>
/// <para>
/// <see cref="IsBasicMessage"/> uses the spec-mandated MTURI dispatch match
/// (<see cref="MessageTypeUri.IsSameMessageType(MessageTypeUri?)"/>): protocol and message names ignoring
/// case and punctuation, same major version, under the same documentation URI — so a future
/// <c>basicmessage/2.x</c> message still dispatches.
/// </para>
/// </remarks>
public static class BasicMessageExtensions
{
    //The basic-message Message Type URI, parsed once for semver-compatible handler dispatch.
    private static readonly MessageTypeUri BasicMessageMessageType = MessageTypeUri.Parse(WellKnownBasicMessageNames.MessageType);


    /// <summary>
    /// Builds a Basic Message from <paramref name="basicMessage"/>: <c>type</c> is the message Message Type
    /// URI, <c>body.content</c> carries the text, the optional <c>lang</c> header carries its language, and
    /// the standard <c>created_time</c> header carries when it was sent (didcomm.org/basicmessage/2.0
    /// §message).
    /// </summary>
    /// <param name="basicMessage">The semantic basic message; its <see cref="BasicMessage.Content"/> is REQUIRED.</param>
    /// <param name="id">REQUIRED. The message id, unique to the sender (DIDComm v2.1 §Message Headers).</param>
    /// <param name="createdTime">REQUIRED. When the message was sent, in UTC epoch seconds — the <c>created_time</c> header. Basic Message MUST carry the send time (didcomm.org/basicmessage/2.0 §message: "the time the message is sent must be included"); the library holds no clock, so the caller supplies it.</param>
    /// <param name="from">OPTIONAL. The sender identifier.</param>
    /// <param name="to">OPTIONAL. The recipient identifiers, conveyed in the plaintext <c>to</c> header.</param>
    /// <returns>The basic message.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="id"/> is null or empty.</exception>
    public static DidCommMessage CreateBasicMessage(
        this BasicMessage basicMessage,
        string id,
        long createdTime,
        string? from = null,
        IList<string>? to = null)
    {
        ArgumentNullException.ThrowIfNull(basicMessage);
        ArgumentNullException.ThrowIfNull(basicMessage.Content);
        ArgumentException.ThrowIfNullOrEmpty(id);

        var message = new DidCommMessage
        {
            Id = id,
            Type = WellKnownBasicMessageNames.MessageType,
            From = from,
            To = to,
            CreatedTime = createdTime,
            Body = new Dictionary<string, object> { [WellKnownBasicMessageNames.Content] = basicMessage.Content }
        };

        //lang is a top-level header (a sibling of body), so it rides in the extension-header bag rather than
        //the body (didcomm.org/basicmessage/2.0 §message).
        if(basicMessage.Lang is not null)
        {
            message.AdditionalHeaders = new Dictionary<string, object> { [WellKnownBasicMessageNames.Lang] = basicMessage.Lang };
        }

        return message;
    }


    /// <summary>
    /// Whether <paramref name="message"/> is a Basic Message — its <c>type</c> names the message Message Type
    /// URI (didcomm.org/basicmessage/2.0 §message).
    /// </summary>
    /// <param name="message">The message to inspect.</param>
    /// <returns><see langword="true"/> when the message is a basic message.</returns>
    public static bool IsBasicMessage(this DidCommMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);

        return MessageTypeUri.TryParse(message.Type, out MessageTypeUri? messageType)
            && messageType.IsSameMessageType(BasicMessageMessageType);
    }


    /// <summary>
    /// Interprets <paramref name="message"/> as a Basic Message, recovering its semantic
    /// <see cref="BasicMessage"/> — fail-closed: returns <see langword="false"/> without throwing for any
    /// message that is not a conformant basic message (didcomm.org/basicmessage/2.0 §message).
    /// </summary>
    /// <param name="message">The received message to interpret.</param>
    /// <param name="basicMessage">The recovered basic message when interpretation succeeds.</param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="message"/> is a basic message whose <c>body.content</c> is
    /// a string; otherwise <see langword="false"/>. A present-but-non-string <c>lang</c> header is a
    /// malformation that fails closed.
    /// </returns>
    public static bool TryInterpretBasicMessage(this DidCommMessage message, [NotNullWhen(true)] out BasicMessage? basicMessage)
    {
        ArgumentNullException.ThrowIfNull(message);

        basicMessage = null;

        if(!message.IsBasicMessage())
        {
            return false;
        }

        //content is REQUIRED and a string (an empty string is a valid, if unusual, content).
        if(message.Body is not { } body
            || !body.TryGetValue(WellKnownBasicMessageNames.Content, out object? contentValue)
            || contentValue is not string content)
        {
            return false;
        }

        //lang is an OPTIONAL top-level header carried in AdditionalHeaders; a present-but-non-string lang is a
        //malformation and fails closed, mirroring the other interpreters' wire-type discipline.
        string? lang = null;
        if(message.AdditionalHeaders is { } headers && headers.TryGetValue(WellKnownBasicMessageNames.Lang, out object? langValue))
        {
            if(langValue is not string langText)
            {
                return false;
            }

            lang = langText;
        }

        basicMessage = new BasicMessage { Content = content, Lang = lang };

        return true;
    }
}
