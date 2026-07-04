using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Threading;

namespace Verifiable.Cesr.Streaming;

/// <summary>
/// Groups the top-level items of a message-oriented CESR stream into messages with their attachments — each
/// interleaved non-native (JSON/CBOR/MGPK) serialization and the count-code groups that follow it, up to the next
/// message — layered over the top-level <see cref="CesrStreamReader"/>. This is the framing a KERI Key Event Log
/// stream uses: a key event serialization followed by its controller-signature (and any witness-signature or
/// receipt) groups.
/// </summary>
/// <remarks>
/// <para>
/// A genus/version code delimits the stream but is not itself a message; it is consumed and does not appear in
/// the output. A count-code group that appears before any message is a framing error — an attachment with nothing
/// to attach to.
/// </para>
/// <para>
/// A native-CESR-framed message (a field-map count group rather than an interleaved serialization) is not grouped
/// here: telling a message group apart from an attachment group in that form needs the stream's genus semantics,
/// which belong to the protocol layer, so this reader groups the interleaved-serialization form KERI event
/// streams use. A protocol layer that needs native-framed messages walks <see cref="CesrStreamReader"/> directly.
/// </para>
/// </remarks>
public static class CesrMessageReader
{
    /// <summary>
    /// Reads the text-domain (qb64) messages of a message-oriented CESR stream, each with its attachment groups.
    /// </summary>
    /// <param name="reader">The pipe to read from. The caller owns its lifetime and completes it.</param>
    /// <param name="pool">The memory pool the message and attachment bodies are rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The messages in order. Each <see cref="CesrMessage"/> MUST be disposed by the consumer to return its buffers to the pool.</returns>
    /// <exception cref="CesrFormatException">The stream is malformed, truncated, or carries an attachment group before any message.</exception>
    public static IAsyncEnumerable<CesrMessage> ReadTextAsync(
        PipeReader reader,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(pool);

        return GroupMessagesAsync(CesrStreamReader.ReadTextAsync(reader, pool, cancellationToken), cancellationToken);
    }


    /// <summary>
    /// Reads the binary-domain (qb2) messages of a message-oriented CESR stream, each with its attachment groups.
    /// </summary>
    /// <param name="reader">The pipe to read from. The caller owns its lifetime and completes it.</param>
    /// <param name="pool">The memory pool the message and attachment bodies are rented from.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The messages in order. Each <see cref="CesrMessage"/> MUST be disposed by the consumer to return its buffers to the pool.</returns>
    /// <exception cref="CesrFormatException">The stream is malformed, truncated, or carries an attachment group before any message.</exception>
    public static IAsyncEnumerable<CesrMessage> ReadBinaryAsync(
        PipeReader reader,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(pool);

        return GroupMessagesAsync(CesrStreamReader.ReadBinaryAsync(reader, pool, cancellationToken), cancellationToken);
    }


    /// <summary>
    /// Folds the flat top-level token stream into messages-with-attachments. A non-native item starts a new
    /// message and flushes the previous one; a count group attaches to the current message; a genus/version code
    /// is consumed. Ownership of a pooled token is transferred to the emitted <see cref="CesrMessage"/> before it
    /// is yielded, and the <c>finally</c> disposes any tokens not yet handed to the consumer, so an abandoned
    /// enumeration (an early break) or a malformed stream never leaks a rented buffer.
    /// </summary>
    /// <param name="tokens">The top-level token stream from <see cref="CesrStreamReader"/>.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The grouped messages in order.</returns>
    private static async IAsyncEnumerable<CesrMessage> GroupMessagesAsync(
        IAsyncEnumerable<CesrToken> tokens,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        CesrToken? pendingMessage = null;
        List<CesrToken>? pendingAttachments = null;
        try
        {
            await foreach(CesrToken token in tokens.WithCancellation(cancellationToken).ConfigureAwait(false))
            {
                switch(token.Kind)
                {
                    case CesrTokenKind.NonNative:
                        //A new message flushes the previous one. The new token is tracked as pending, and the
                        //flushed message's attachment list is detached, BEFORE the flushed message is yielded, so
                        //the yielded message owns those tokens and an early break disposes only what is still
                        //pending — never leaking and never double-disposing.
                        if(pendingMessage is { } previousMessage)
                        {
                            IReadOnlyList<CesrToken> attachments = (IReadOnlyList<CesrToken>?)pendingAttachments ?? [];
                            pendingMessage = token;
                            pendingAttachments = null;
                            yield return new CesrMessage(previousMessage, attachments);
                        }
                        else
                        {
                            pendingMessage = token;
                        }

                        break;

                    case CesrTokenKind.CountGroup:
                        if(pendingMessage is null)
                        {
                            token.Dispose();
                            throw new CesrFormatException("A CESR attachment group appeared before any message in the stream.");
                        }

                        (pendingAttachments ??= []).Add(token);
                        break;

                    case CesrTokenKind.GenusVersion:
                        //A genus/version code delimits the stream but is not a message and carries no body.
                        token.Dispose();
                        break;

                    default:
                        token.Dispose();
                        throw new CesrFormatException($"Unexpected CESR token kind '{token.Kind}' in the message stream.");
                }
            }

            if(pendingMessage is { } finalMessage)
            {
                IReadOnlyList<CesrToken> attachments = (IReadOnlyList<CesrToken>?)pendingAttachments ?? [];
                pendingMessage = null;
                pendingAttachments = null;
                yield return new CesrMessage(finalMessage, attachments);
            }
        }
        finally
        {
            pendingMessage?.Dispose();
            if(pendingAttachments is not null)
            {
                foreach(CesrToken attachment in pendingAttachments)
                {
                    attachment.Dispose();
                }
            }
        }
    }
}
