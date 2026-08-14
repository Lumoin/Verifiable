using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for the pooled carriers an Information Package's metadata documents ride
/// in.
/// </summary>
/// <remarks>
/// Each tag carries an <see cref="EArkObjectKind"/> discriminator together with the encoding its octets really
/// are. A metadata document's octets are <see cref="EncodingScheme.Raw"/>, because they are neither DER nor any
/// other structured encoding this library names — they are whatever the serialisation seam produced; the one
/// value this library encodes itself is tagged for what it is. The pattern mirrors <see cref="AsicTags"/>, which
/// does the same job for container octets.
/// </remarks>
public static class EArkTags
{
    /// <summary>Tag for the serialised octets of one METS document.</summary>
    public static Tag MetsDocument { get; } = Tag.Create(EArkObjectKind.MetsDocument).With(EncodingScheme.Raw);

    /// <summary>Tag for the serialised octets of one preservation-metadata document.</summary>
    public static Tag PremisDocument { get; } = Tag.Create(EArkObjectKind.PremisDocument).With(EncodingScheme.Raw);

    /// <summary>Tag for the octets of one entry of an Information Package, as the package handed them over.</summary>
    public static Tag PackageEntry { get; } = Tag.Create(EArkObjectKind.PackageEntry).With(EncodingScheme.Raw);

    /// <summary>
    /// Tag for the canonical encoding of one evidence self-description. Unlike the three above it is
    /// <see cref="EncodingScheme.Der"/>, because this value's canonical form is a DER structure this library
    /// defines rather than whatever a serialisation seam produced.
    /// </summary>
    public static Tag EvidenceSelfDescription { get; } =
        Tag.Create(EArkObjectKind.EvidenceSelfDescription).With(EncodingScheme.Der);
}
