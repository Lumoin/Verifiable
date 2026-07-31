namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Discriminates what a pooled carrier holding Associated Signature Container octets holds.
/// </summary>
/// <remarks>
/// <para>
/// Used as a <see cref="Tag"/> component so a block of container octets can be routed and reported on without
/// re-parsing it, the same job <see cref="PkiObjectKind"/> does for the DER objects
/// <see cref="PkiCertificateMemory"/> carries. It is a separate enumeration rather than two more members of that
/// one because a container is a ZIP archive rather than a DER-encoded PKI object, and
/// <see cref="PkiObjectKind"/> is documented as the discriminator of what
/// <see cref="PkiCertificateMemory"/> holds — widening it would make that statement false.
/// </para>
/// <para>
/// <see cref="None"/> occupies zero so a default-initialised tag component never reads as a container.
/// </para>
/// </remarks>
public enum AsicObjectKind
{
    /// <summary>No container object kind specified. The value of an unset component, by design.</summary>
    None = 0,

    /// <summary>
    /// The octets of a whole container: the ZIP archive an
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
    /// ETSI EN 319 162-1 V1.1.1</see> clause 4.2 container is.
    /// </summary>
    Container = 1,

    /// <summary>The octets of one entry of a container, after decompression.</summary>
    ContainerEntry = 2,

    /// <summary>
    /// The serialised octets of one manifest document — an <c>ASiCManifest</c> element instance conformant to
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
    /// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2, in whichever of its three roles. Distinct from
    /// <see cref="ContainerEntry"/> because a manifest is produced and consumed by the serialisation seams
    /// before it is ever an entry, and because the octets are what a time-stamp token or a detached signature
    /// commits to.
    /// </summary>
    Manifest = 3,

    /// <summary>
    /// The serialised octets of one <c>Extension</c> element of a manifest (Annex A.4.2's <c>ExtensionType</c>),
    /// whose content this library carries verbatim rather than interpreting.
    /// </summary>
    ManifestExtension = 4
}
