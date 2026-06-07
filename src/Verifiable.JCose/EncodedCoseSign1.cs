using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Semantic carrier for the wire bytes of a complete <c>COSE_Sign1</c>
/// message per
/// <see href="https://www.rfc-editor.org/rfc/rfc9052">RFC 9052</see> —
/// the CBOR tag(18)-wrapped 4-array carrying protected header,
/// unprotected header, payload, and signature. Owns its underlying
/// pool-rented memory; disposing the carrier returns the buffer.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="Signature"/>'s shape — sealed,
/// <see cref="SensitiveMemory"/>-derived, carries
/// <see cref="CryptoTags.CoseEncodedSign1"/> for CBOM/OTel provenance.
/// Used as the storage type for credential-side fields that hold a
/// COSE_Sign1 wire form (e.g. mdoc's
/// <c>MdocIssuerAuth.EncodedCoseSign1</c>,
/// <c>MdocDeviceSignature.EncodedCoseSign1</c>).
/// </para>
/// </remarks>
[DebuggerDisplay("EncodedCoseSign1({Length} bytes)")]
public sealed class EncodedCoseSign1(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
    : SensitiveMemory(sensitiveMemory, tag, lifetime)
{
    /// <summary>Gets the length of the encoded message in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Rents pool memory of <paramref name="bytes"/>'s length, copies the
    /// bytes in, and wraps the buffer in an <see cref="EncodedCoseSign1"/>
    /// carrying <see cref="CryptoTags.CoseEncodedSign1"/>. Caller takes
    /// ownership of the returned carrier.
    /// </summary>
    public static EncodedCoseSign1 FromBytes(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new EncodedCoseSign1(owner, CryptoTags.CoseEncodedSign1);
    }
}
