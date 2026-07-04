using System;
using System.Collections.Generic;

namespace Verifiable.Cesr.Streaming;

/// <summary>
/// A message read from a message-oriented CESR stream together with the attachment groups that immediately
/// follow it: an interleaved non-native (JSON/CBOR/MGPK) serialization and the zero or more count-code groups the
/// stream frames after it. For a KERI Key Event Log this is one key event followed by its controller-signature
/// group and any witness-signature or receipt groups. The message and every attachment hold pooled memory this
/// instance owns; disposing it returns all of those buffers to their pools.
/// </summary>
public sealed class CesrMessage: IDisposable
{
    /// <summary>Whether the pooled buffers have already been returned, so a second dispose is a no-op.</summary>
    private bool disposed;

    /// <summary>
    /// Initializes a new instance of the <see cref="CesrMessage"/> class, taking ownership of the message token
    /// and every attachment token.
    /// </summary>
    /// <param name="message">The message serialization token (a <see cref="CesrTokenKind.NonNative"/> item).</param>
    /// <param name="attachments">The attachment count-code groups that follow the message, in stream order.</param>
    internal CesrMessage(CesrToken message, IReadOnlyList<CesrToken> attachments)
    {
        Message = message;
        Attachments = attachments;
    }


    /// <summary>The message serialization token: an interleaved non-native (JSON/CBOR/MGPK) item.</summary>
    public CesrToken Message { get; }

    /// <summary>
    /// The attachment count-code groups that follow the message, in stream order (empty when the message carries
    /// no attachments). Each is a <see cref="CesrTokenKind.CountGroup"/> whose body a semantics-aware reader
    /// descends into (for a KERI event, the <c>-K</c> controller-signature group).
    /// </summary>
    public IReadOnlyList<CesrToken> Attachments { get; }


    /// <summary>
    /// Returns the message's and every attachment's pooled buffers to their pools. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;
        Message.Dispose();
        foreach(CesrToken attachment in Attachments)
        {
            attachment.Dispose();
        }
    }
}
