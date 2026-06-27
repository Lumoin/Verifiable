using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A single signed attribute of a CMS SignerInfo (RFC 5652 §5.3): its type object identifier and its
/// DER-encoded value. The signer's signature covers these attributes, so they are authenticated; a format
/// layered on the CMS core reads them to apply its own rules — for example CAdES (ETSI EN 319 122) checks
/// the signing-certificate-v2 attribute (ESS, RFC 5035) binds the signer certificate.
/// </summary>
/// <remarks>
/// A tracked carrier rather than a naked buffer: it owns its pooled memory, carries
/// <see cref="CryptoTags.CmsSignedAttributeValue"/> for provenance, and pairs the value with its
/// <see cref="AttributeType"/> object identifier. A signed attribute may carry several values; this carrier
/// holds the first, which is the single-valued case the CAdES attributes use.
/// </remarks>
[DebuggerDisplay("CmsSignedAttribute({AttributeType}, {Length} bytes)")]
public sealed class CmsSignedAttribute: SensitiveMemory
{
    /// <summary>
    /// Initialises a new <see cref="CmsSignedAttribute"/> from owned value bytes.
    /// </summary>
    /// <param name="attributeType">The attribute type object identifier (dotted form).</param>
    /// <param name="value">The owned DER-encoded attribute value bytes. Ownership transfers to this instance.</param>
    public CmsSignedAttribute(string attributeType, IMemoryOwner<byte> value)
        : base(value, CryptoTags.CmsSignedAttributeValue)
    {
        ArgumentNullException.ThrowIfNull(attributeType);
        ArgumentNullException.ThrowIfNull(value);

        AttributeType = attributeType;
    }


    /// <summary>Gets the attribute type object identifier (dotted form, for example <c>1.2.840.113549.1.9.16.2.47</c> for signing-certificate-v2).</summary>
    public string AttributeType { get; }

    /// <summary>Gets the length of the DER-encoded attribute value in bytes.</summary>
    public int Length => MemoryOwner.Memory.Length;
}
