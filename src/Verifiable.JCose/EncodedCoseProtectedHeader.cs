using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.JCose;

/// <summary>
/// Semantic carrier for the CBOR-encoded <c>protected</c> header bytes of
/// a <c>COSE_Sign1</c> message per
/// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-3">RFC 9052 §3</see>.
/// Owns its underlying pool-rented memory; disposing the carrier returns
/// the buffer.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="Signature"/>'s shape — sealed,
/// <see cref="SensitiveMemory"/>-derived, carries
/// <see cref="CryptoTags.CoseEncodedProtectedHeader"/> for CBOM/OTel
/// provenance. The encoded bytes are the exact byte sequence the
/// Sig_structure (RFC 9052 §4.4) embeds as <c>body_protected</c>; the
/// verifier must use the same bytes, which is why this carrier preserves
/// the original encoding rather than re-encoding from a decoded dict.
/// </para>
/// </remarks>
[DebuggerDisplay("EncodedCoseProtectedHeader({Length} bytes)")]
public sealed class EncodedCoseProtectedHeader(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
    : SensitiveMemory(sensitiveMemory, tag, lifetime)
{
    /// <summary>Gets the length of the encoded header in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Rents pool memory of <paramref name="bytes"/>'s length, copies the
    /// bytes in, and wraps the buffer in an
    /// <see cref="EncodedCoseProtectedHeader"/> carrying
    /// <see cref="CryptoTags.CoseEncodedProtectedHeader"/>. Caller takes
    /// ownership of the returned carrier.
    /// </summary>
    public static EncodedCoseProtectedHeader FromBytes(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new EncodedCoseProtectedHeader(owner, CryptoTags.CoseEncodedProtectedHeader);
    }
}
