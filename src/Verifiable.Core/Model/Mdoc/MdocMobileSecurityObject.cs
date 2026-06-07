namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// The Mobile Security Object (MSO) per ISO/IEC 18013-5 §9.1.2.4 — the
/// CBOR map carried as the payload of the <c>issuerAuth</c> COSE_Sign1.
/// </summary>
/// <remarks>
/// <para>
/// The MSO is where the credential's cryptographic substance lives. It
/// commits to four things the issuer wants the verifier to trust:
/// </para>
/// <list type="number">
///   <item><description>
///     The exact set of namespaced claim items (via the
///     <see cref="ValueDigests"/> map — namespace → digestID → digest).
///   </description></item>
///   <item><description>
///     The wallet's public key (via <see cref="DeviceKeyInfo"/>) so that
///     <c>DeviceAuth</c> structures can be authenticated as originating from
///     the credential's intended holder.
///   </description></item>
///   <item><description>
///     The document type (<see cref="DocType"/>) — protects against the
///     verifier being tricked into accepting a credential of the wrong
///     class.
///   </description></item>
///   <item><description>
///     The temporal bounds (via <see cref="ValidityInfo"/>) — when the
///     credential is valid for presentation.
///   </description></item>
/// </list>
/// <para>
/// The MSO ITSELF is not signed inside this carrier; the signing happens
/// in the enclosing COSE_Sign1 (M.3). This carrier is the parsed view —
/// <see cref="MdocIssuerAuth"/> holds both this and the original COSE_Sign1
/// wire bytes so verification (M.3) and digest binding (M.4) can both
/// proceed.
/// </para>
/// </remarks>
public sealed class MdocMobileSecurityObject
{
    /// <summary>
    /// Initializes an MSO view from caller-supplied parts.
    /// </summary>
    /// <param name="version">
    /// The protocol version string — currently always
    /// <see cref="MdocMsoWellKnownKeys.Version10"/>.
    /// </param>
    /// <param name="digestAlgorithm">
    /// The IANA hash-algorithm name applied to each <c>IssuerSignedItem</c>
    /// wire bytes to produce the <see cref="ValueDigests"/> commitments —
    /// one of <see cref="MdocMsoWellKnownKeys.DigestAlgorithmSha256"/>,
    /// <c>SHA-384</c>, or <c>SHA-512</c>.
    /// </param>
    /// <param name="valueDigests">
    /// The <c>namespace → digestID → digest-bytes</c> commitment map.
    /// </param>
    /// <param name="deviceKeyInfo">The wallet-side key the MSO binds to.</param>
    /// <param name="docType">
    /// The document type URI; matches the enclosing document's
    /// <see cref="MdocDocument.DocType"/>.
    /// </param>
    /// <param name="validityInfo">The temporal bounds.</param>
    public MdocMobileSecurityObject(
        string version,
        string digestAlgorithm,
        IReadOnlyDictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>> valueDigests,
        MdocDeviceKeyInfo deviceKeyInfo,
        string docType,
        MdocValidityInfo validityInfo)
    {
        ArgumentException.ThrowIfNullOrEmpty(version);
        ArgumentException.ThrowIfNullOrEmpty(digestAlgorithm);
        ArgumentNullException.ThrowIfNull(valueDigests);
        ArgumentNullException.ThrowIfNull(deviceKeyInfo);
        ArgumentException.ThrowIfNullOrEmpty(docType);
        ArgumentNullException.ThrowIfNull(validityInfo);

        Version = version;
        DigestAlgorithm = digestAlgorithm;
        ValueDigests = valueDigests;
        DeviceKeyInfo = deviceKeyInfo;
        DocType = docType;
        ValidityInfo = validityInfo;
    }


    /// <summary>The MSO protocol version string — currently always <c>"1.0"</c>.</summary>
    public string Version { get; }

    /// <summary>
    /// The IANA hash-algorithm name (e.g. <c>SHA-256</c>) applied to each
    /// <c>IssuerSignedItem</c> wire bytes for the <see cref="ValueDigests"/>
    /// commitments.
    /// </summary>
    public string DigestAlgorithm { get; }

    /// <summary>
    /// The <c>namespace → digestID → digest-bytes</c> commitment map. Each
    /// digest is the hash of the corresponding <c>IssuerSignedItem</c>'s
    /// Tag-24 wire bytes under <see cref="DigestAlgorithm"/>.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>> ValueDigests { get; }

    /// <summary>The wallet-side key the MSO binds to.</summary>
    public MdocDeviceKeyInfo DeviceKeyInfo { get; }

    /// <summary>
    /// The document type URI; matches the enclosing document's
    /// <see cref="MdocDocument.DocType"/>.
    /// </summary>
    public string DocType { get; }

    /// <summary>The temporal bounds for the credential.</summary>
    public MdocValidityInfo ValidityInfo { get; }
}
