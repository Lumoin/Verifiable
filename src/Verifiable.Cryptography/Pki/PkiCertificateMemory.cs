using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A DER-encoded PKI object held in pooled memory with a <see cref="PkiObjectKind"/>
/// discriminator carried in the <see cref="Tag"/>.
/// </summary>
/// <remarks>
/// <para>
/// Covers the four PKI object types used across the library:
/// </para>
/// <list type="bullet">
///   <item><description>
///     X.509 v3 certificates — in <c>x5c</c> JOSE headers for JAR signature
///     verification, in TPM EK/AK certificate chains, and in AdES signatures.
///   </description></item>
///   <item><description>
///     Certificate Revocation Lists — for offline revocation checking in AdES
///     long-term validation.
///   </description></item>
///   <item><description>
///     OCSP responses — for online revocation checking.
///   </description></item>
///   <item><description>
///     RFC 3161 timestamp tokens — for AdES time assertion.
///   </description></item>
/// </list>
/// <para>
/// The <see cref="Tag"/> on every instance carries a <see cref="PkiObjectKind"/>
/// discriminator. Use <see cref="IsX509Certificate"/>, <see cref="IsCrl"/>,
/// <see cref="IsOcspResponse"/>, and <see cref="IsTimestampToken"/> to branch
/// without reading raw bytes.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PkiCertificateMemory: SensitiveMemory, IEquatable<PkiCertificateMemory>
{
    /// <summary>
    /// The number of bytes in the DER-encoded object.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>
    /// Returns <see langword="true"/> when this object is an X.509 v3 certificate.
    /// </summary>
    public bool IsX509Certificate =>
        Tag.Get<PkiObjectKind>() == PkiObjectKind.X509Certificate;

    /// <summary>
    /// Returns <see langword="true"/> when this object is a Certificate Revocation List.
    /// </summary>
    public bool IsCrl =>
        Tag.Get<PkiObjectKind>() == PkiObjectKind.X509Crl;

    /// <summary>
    /// Returns <see langword="true"/> when this object is an OCSP response.
    /// </summary>
    public bool IsOcspResponse =>
        Tag.Get<PkiObjectKind>() == PkiObjectKind.OcspResponse;

    /// <summary>
    /// Returns <see langword="true"/> when this object is an RFC 3161 timestamp token.
    /// </summary>
    public bool IsTimestampToken =>
        Tag.Get<PkiObjectKind>() == PkiObjectKind.TimestampToken;


    /// <summary>
    /// Creates a new <see cref="PkiCertificateMemory"/> from owned DER-encoded bytes.
    /// </summary>
    /// <param name="derBytes">
    /// The DER-encoded PKI object. Ownership transfers to this instance.
    /// </param>
    /// <param name="tag">
    /// A tag carrying a <see cref="PkiObjectKind"/> discriminator. Use one of the
    /// pre-built tags from <see cref="PkiCertificateTags"/>.
    /// </param>
    public PkiCertificateMemory(IMemoryOwner<byte> derBytes, Tag tag) : base(derBytes, tag)
    {
    }


    private string DebuggerDisplay
    {
        get
        {
            PkiObjectKind kind = Tag.Get<PkiObjectKind>();
            return $"PkiCertificateMemory[{kind}, {Length} bytes]";
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals([NotNullWhen(true)] PkiCertificateMemory? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Tag.Equals(other.Tag)
            && MemoryOwner.Memory.Span.SequenceEqual(other.MemoryOwner.Memory.Span);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is PkiCertificateMemory other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Tag);
        hash.AddBytes(MemoryOwner.Memory.Span);
        return hash.ToHashCode();
    }
}
