using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Foundation;

namespace Verifiable.DidComm;

/// <summary>
/// The serialized wire form of a DIDComm signed message — a JWS over a plaintext JWM, carried as
/// <c>application/didcomm-signed+json</c> (DIDComm Messaging v2.1 §DIDComm Signed Messages).
/// </summary>
/// <remarks>
/// <para>
/// A distinct named type rather than a bare buffer: it owns its pooled bytes with deterministic
/// disposal, names the artifact at API boundaries (so a signed message cannot be passed where a
/// plaintext <see cref="DidCommPlaintextMessage"/> or, later, an encrypted message is expected), and
/// gives the signed-message operations a home as extension methods
/// (<see cref="DidCommSignedExtensions"/>). It extends <see cref="SensitiveMemory"/> not because a
/// signed message is secret — it is transmitted in the clear — but because disciplined, pooled
/// memory handling and clear lifetimes apply uniformly to every byte buffer the library mints.
/// </para>
/// <para>
/// The in-memory, structural counterpart is JCose's <c>JwsMessage</c> (pack) /
/// <c>UnverifiedJwsMessage</c> (parse); this type is the transmittable serialized artifact those
/// produce and consume.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class DidCommSignedMessage: SensitiveMemory, IEquatable<DidCommSignedMessage>
{
    /// <summary>
    /// Initializes a new <see cref="DidCommSignedMessage"/> from owned wire bytes.
    /// </summary>
    /// <param name="wireBytes">The owned <c>application/didcomm-signed+json</c> bytes. Ownership transfers to this instance.</param>
    /// <param name="tag">Metadata describing the buffer (e.g. its <see cref="BufferKind"/> and provenance).</param>
    /// <param name="lifetime">
    /// Optional OTel activity spanning this message's lifetime. Stopped on
    /// <see cref="SensitiveMemory.Dispose()"/>. Pass <see langword="null"/> when no OTel listener is active.
    /// </param>
    public DidCommSignedMessage(IMemoryOwner<byte> wireBytes, Tag tag, Activity? lifetime = null): base(wireBytes, tag, lifetime)
    {
    }


    /// <summary>The length of the serialized message in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>
    /// The IANA media type of this artifact, <c>application/didcomm-signed+json</c> — both the HTTP
    /// <c>Content-Type</c> and the JOSE <c>typ</c> value for the signed form.
    /// </summary>
    public static string MediaType => DidCommMediaTypes.Signed;


    /// <summary>
    /// Copies <paramref name="wireBytes"/> into a buffer rented from <paramref name="pool"/> and wraps
    /// it as a <see cref="DidCommSignedMessage"/> that owns the rented buffer.
    /// </summary>
    /// <param name="wireBytes">The serialized <c>application/didcomm-signed+json</c> bytes to take ownership of.</param>
    /// <param name="tag">Metadata describing the buffer.</param>
    /// <param name="pool">The pool the owning buffer is drawn from.</param>
    /// <param name="lifetime">Optional OTel activity bracketing this message's lifetime.</param>
    /// <returns>A new <see cref="DidCommSignedMessage"/> owning a pooled copy of <paramref name="wireBytes"/>.</returns>
    public static DidCommSignedMessage Create(ReadOnlySpan<byte> wireBytes, Tag tag, MemoryPool<byte> pool, Activity? lifetime = null)
    {
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        //Mirrors Salt.Generate / DigestValue.Compute: the pool is an exact-size pool
        //(BaseMemoryPool / ExactSizeMemoryPool), so Rent returns a buffer of the requested
        //length and the owned Memory is exactly the message bytes.
        IMemoryOwner<byte> owner = pool.Rent(wireBytes.Length);
        Debug.Assert(owner.Memory.Length == wireBytes.Length, "Pool must return exact-size allocations.");
        wireBytes.CopyTo(owner.Memory.Span);

        return new DidCommSignedMessage(owner, tag, lifetime);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] DidCommSignedMessage? other)
    {
        return other is not null
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj switch
        {
            DidCommSignedMessage m => Equals(m),
            SensitiveMemory sm => base.Equals(sm),
            _ => false
        };
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => base.GetHashCode();


    /// <summary>Determines whether two <see cref="DidCommSignedMessage"/> instances contain identical bytes.</summary>
    public static bool operator ==(DidCommSignedMessage? left, DidCommSignedMessage? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>Determines whether two <see cref="DidCommSignedMessage"/> instances differ.</summary>
    public static bool operator !=(DidCommSignedMessage? left, DidCommSignedMessage? right) => !(left == right);


    /// <inheritdoc/>
    public override string ToString() => DebuggerDisplay;


    private string DebuggerDisplay => $"DidCommSignedMessage({Length} bytes, {MediaType})";
}
