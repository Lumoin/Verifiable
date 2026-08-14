using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Semantic carrier for the wire bytes of one version 2 countersignature value — the CBOR
/// encoding of either a <see cref="CounterSignatureV2"/> or a <see cref="CounterSignature0V2"/>,
/// as written by <c>CoseSerialization.WriteCounterSignatureV2</c>/
/// <c>WriteCounterSignature0V2</c> in <c>Verifiable.Cbor</c>. Owns its underlying pool-rented
/// memory; disposing the carrier returns the buffer.
/// </summary>
/// <remarks>
/// Never carries a CBOR tag 19 prefix: the writer emits untagged —
/// the tagged form is read-tolerated only, never
/// produced. The caller is responsible for placing these bytes as a header-parameter value
/// (label 11 or 12); this carrier holds only the value bytes.
/// </remarks>
[DebuggerDisplay("EncodedCoseCounterSignature({Length} bytes)")]
public sealed class EncodedCoseCounterSignature(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
    : SensitiveMemory(sensitiveMemory, tag, lifetime)
{
    /// <summary>Gets the length of the encoded value in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Rents pool memory of <paramref name="bytes"/>'s length, copies the bytes in, and wraps
    /// the buffer in an <see cref="EncodedCoseCounterSignature"/> carrying
    /// <see cref="CryptoTags.CoseEncodedCounterSignature"/>. Caller takes ownership of the
    /// returned carrier.
    /// </summary>
    public static EncodedCoseCounterSignature FromBytes(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new EncodedCoseCounterSignature(owner, CryptoTags.CoseEncodedCounterSignature);
    }
}
