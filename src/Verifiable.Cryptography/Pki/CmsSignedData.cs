using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Semantic carrier for the DER wire bytes of a CMS SignedData structure per
/// <see href="https://www.rfc-editor.org/rfc/rfc5652">RFC 5652</see> — the signature-envelope
/// substrate of eMRTD Passive Authentication (the EF.SOD content) and the CAdES family of EU
/// advanced electronic signatures. Owns its underlying pool-rented memory; disposing the carrier
/// returns the buffer.
/// </summary>
/// <remarks>
/// <para>
/// The CMS analog of <see cref="Verifiable.JCose"/>'s <c>EncodedCoseSign1</c>: sealed,
/// <see cref="SensitiveMemory"/>-derived, carrying <see cref="CryptoTags.CmsEncodedSignedData"/>
/// for CBOM/OTel provenance. This is the input to <see cref="VerifyCmsSignedDataDelegate"/>; the
/// verified result is a <see cref="CmsVerifiedContent"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("CmsSignedData({Length} bytes)")]
public sealed class CmsSignedData(IMemoryOwner<byte> sensitiveMemory, Tag tag, Activity? lifetime = null)
    : SensitiveMemory(sensitiveMemory, tag, lifetime)
{
    /// <summary>Gets the length of the encoded CMS SignedData in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;


    /// <summary>
    /// Rents pool memory of <paramref name="bytes"/>'s length, copies the bytes in, and wraps the
    /// buffer in a <see cref="CmsSignedData"/> carrying <see cref="CryptoTags.CmsEncodedSignedData"/>.
    /// The caller takes ownership of the returned carrier.
    /// </summary>
    public static CmsSignedData FromBytes(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new CmsSignedData(owner, CryptoTags.CmsEncodedSignedData);
    }
}
