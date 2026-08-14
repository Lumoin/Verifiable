using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for the pooled carriers Associated Signature Container octets ride in.
/// </summary>
/// <remarks>
/// Each tag carries an <see cref="AsicObjectKind"/> discriminator together with
/// <see cref="EncodingScheme.Raw"/>, because container and entry octets are neither DER nor any other structured
/// encoding this library names — a container is a ZIP archive and an entry is whatever octets its producer put
/// there. The pattern mirrors <see cref="PkiCertificateTags"/>, which does the same job for DER objects.
/// </remarks>
public static class AsicTags
{
    /// <summary>Tag for the octets of a whole container.</summary>
    public static Tag Container { get; } = Tag.Create(AsicObjectKind.Container).With(EncodingScheme.Raw);

    /// <summary>Tag for the decompressed octets of one container entry.</summary>
    public static Tag ContainerEntry { get; } = Tag.Create(AsicObjectKind.ContainerEntry).With(EncodingScheme.Raw);

    /// <summary>Tag for the serialised octets of one manifest document.</summary>
    public static Tag Manifest { get; } = Tag.Create(AsicObjectKind.Manifest).With(EncodingScheme.Raw);

    /// <summary>Tag for the serialised octets of one manifest <c>Extension</c> element.</summary>
    public static Tag ManifestExtension { get; } = Tag.Create(AsicObjectKind.ManifestExtension).With(EncodingScheme.Raw);
}
