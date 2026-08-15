using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for the pooled carriers the octets of an
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see> Evidence Record ride in.
/// </summary>
/// <remarks>
/// Each tag carries an <see cref="XmlEvidenceRecordObjectKind"/> discriminator together with
/// <see cref="EncodingScheme.Raw"/>, because these octets are an XML serialisation rather than DER or any other
/// structured encoding this library names. The pattern mirrors <see cref="AsicTags"/> exactly.
/// </remarks>
public static class XmlEvidenceRecordTags
{
    /// <summary>Tag for the serialised octets of one whole <c>EvidenceRecord</c> document.</summary>
    public static Tag EvidenceRecord { get; } = Tag.Create(XmlEvidenceRecordObjectKind.EvidenceRecord).With(EncodingScheme.Raw);

    /// <summary>Tag for the canonical binary representation of one XML element, as the canonicalization seam produced it.</summary>
    public static Tag CanonicalizedElement { get; } = Tag.Create(XmlEvidenceRecordObjectKind.CanonicalizedElement).With(EncodingScheme.Raw);

    /// <summary>Tag for the octets of one <c>CryptographicInformation</c> element's content.</summary>
    public static Tag CryptographicInformation { get; } = Tag.Create(XmlEvidenceRecordObjectKind.CryptographicInformation).With(EncodingScheme.Raw);

    /// <summary>Tag for the serialised octets of one <c>Attribute</c> or <c>SupportingInformation</c> element.</summary>
    public static Tag OpaqueInformation { get; } = Tag.Create(XmlEvidenceRecordObjectKind.OpaqueInformation).With(EncodingScheme.Raw);
}
