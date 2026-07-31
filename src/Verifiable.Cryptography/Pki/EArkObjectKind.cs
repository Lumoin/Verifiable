namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Discriminates what a pooled carrier holding the octets of an Information Package's metadata holds.
/// </summary>
/// <remarks>
/// <para>
/// Used as a <see cref="Tag"/> component so a block of package-metadata octets can be routed and reported on
/// without re-parsing it, the same job <see cref="AsicObjectKind"/> does for container octets. It is a separate
/// enumeration rather than more members of that one because an Information Package is a folder tree with XML
/// manifests rather than a container format, and <see cref="AsicObjectKind"/> is documented as the discriminator
/// of what an Associated Signature Container carries — widening it would make that statement false.
/// </para>
/// <para>
/// <see cref="None"/> occupies zero so a default-initialised tag component never reads as package metadata.
/// </para>
/// </remarks>
public enum EArkObjectKind
{
    /// <summary>No package object kind specified. The value of an unset component, by design.</summary>
    None = 0,

    /// <summary>
    /// The serialised octets of one METS document — the package-level or representation-level <c>METS.xml</c> the
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause
    /// 4.1</see> requirement <c>CSIPSTR4</c> puts at the root of an Information Package.
    /// </summary>
    MetsDocument = 1,

    /// <summary>
    /// The serialised octets of one preservation-metadata document — the <c>premis</c> element instance the
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> clause 5.1.1 table binds
    /// into a METS document through <c>amdSec/digiprovMD/mdRef[@MDTYPE='PREMIS']</c>.
    /// </summary>
    PremisDocument = 2,

    /// <summary>
    /// The octets of one entry of an Information Package as it was handed over — a data file, a metadata
    /// document, a schema, a piece of documentation, or the manifest itself. The kind says where the octets came
    /// from and nothing about what they are: the position an entry holds in the layout
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause
    /// 4.1</see> fixes is stated by the package facts, not by the carrier's tag.
    /// </summary>
    PackageEntry = 3,

    /// <summary>
    /// The canonical encoding of one evidence self-description — the value naming the preservation service, the
    /// preservation evidence policy and the preservation profile an evidential artifact was produced under, which
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
    /// ETSI TS 119 511 V1.2.1</see> requirements <c>OVR-6.5-09</c> and <c>OVR-9.2-04</c> ask an evidence to
    /// carry and for which no format the specification names has a field.
    /// </summary>
    EvidenceSelfDescription = 4
}
