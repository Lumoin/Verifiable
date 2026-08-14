using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Semantic carrier for the wire bytes of a complete <c>COSE_Sign</c> message per
/// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-4.1">RFC 9052 §4.1</see> — the
/// CBOR tag(98)-wrapped 4-array carrying body-layer protected header, body-layer
/// unprotected header, payload, and the <c>signatures</c> array. Owns its underlying
/// pool-rented memory; disposing the carrier returns the buffer.
/// </summary>
/// <remarks>
/// Mirrors <see cref="EncodedCoseSign1"/>'s shape — sealed, <see cref="SensitiveMemory"/>-
/// derived, carries <see cref="CryptoTags.CoseEncodedSign"/> for CBOM/OTel provenance. The
/// multi-signer counterpart of <see cref="EncodedCoseSign1"/>.
/// </remarks>
[DebuggerDisplay("EncodedCoseSign({Length} bytes)")]
public sealed class EncodedCoseSign(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
    : SensitiveMemory(sensitiveMemory, tag, lifetime)
{
    /// <summary>Gets the length of the encoded message in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Rents pool memory of <paramref name="bytes"/>'s length, copies the bytes in, and
    /// wraps the buffer in an <see cref="EncodedCoseSign"/> carrying
    /// <see cref="CryptoTags.CoseEncodedSign"/>. Caller takes ownership of the returned
    /// carrier.
    /// </summary>
    public static EncodedCoseSign FromBytes(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new EncodedCoseSign(owner, CryptoTags.CoseEncodedSign);
    }
}
