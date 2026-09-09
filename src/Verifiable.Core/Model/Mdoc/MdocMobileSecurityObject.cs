using Verifiable.Core.StatusList;

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
/// <para>
/// <see cref="Version"/>, <see cref="DigestAlgorithm"/>, <see cref="ValueDigests"/>,
/// <see cref="DeviceKeyInfo"/>, <see cref="DocType"/>, and <see cref="ValidityInfo"/>
/// are the six members ISO/IEC 18013-5:2021 §9.1.2.4 requires. <see cref="Status"/>
/// is an optional seventh member specified by the second edition of ISO/IEC
/// 18013-5, under ballot as a DIS (expected publication 2026-11-30) — carrying
/// the credential's Token Status List status claim.
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
    /// <param name="status">
    /// The optional <see cref="MdocMsoWellKnownKeys.Status"/> member — the
    /// Token Status List status claim, specified by the second
    /// edition of ISO/IEC 18013-5 (under ballot as a DIS). Absent from
    /// ISO/IEC 18013-5:2021 MSOs.
    /// </param>
    public MdocMobileSecurityObject(
        string version,
        string digestAlgorithm,
        IReadOnlyDictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>> valueDigests,
        MdocDeviceKeyInfo deviceKeyInfo,
        string docType,
        MdocValidityInfo validityInfo,
        StatusClaim? status = null)
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
        Status = status;
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

    /// <summary>
    /// The optional <see cref="MdocMsoWellKnownKeys.Status"/> member — the
    /// Token Status List status claim — or <see langword="null"/>
    /// when the MSO carries no <c>status</c> member (every ISO/IEC
    /// 18013-5:2021 MSO, and any second-edition MSO that opts out of a
    /// revocation mechanism).
    /// </summary>
    /// <remarks>
    /// Placement inside the Mobile Security Object is specified by the second
    /// edition of ISO/IEC 18013-5, under ballot as a DIS (ISO/IEC DIS 18013-5;
    /// expected publication 2026-11-30) — the published ISO/IEC 18013-5:2021
    /// carries no <c>status</c> member. The placement is witnessed by the draft
    /// EU implementing act amending the EAA implementing regulations: "its
    /// MobileSecurityObject (MSO) shall contain the status structure ... which
    /// contains MSO revocation information." The Status structure's own shape —
    /// <see cref="StatusClaim"/>'s members — is normative in Token Status List
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.3">
    /// Section 6.3</see>.
    /// </remarks>
    public StatusClaim? Status { get; }
}
