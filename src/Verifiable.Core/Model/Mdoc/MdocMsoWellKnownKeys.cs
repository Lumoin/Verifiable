namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Map-key string constants for the Mobile Security Object (MSO) wire
/// shapes per ISO/IEC 18013-5 §9.1.2.4 — <c>MobileSecurityObject</c>,
/// <c>DeviceKeyInfo</c>, and <c>ValidityInfo</c>.
/// </summary>
/// <remarks>
/// <para>
/// The MSO is the payload carried inside the <c>issuerAuth</c> COSE_Sign1.
/// Unlike COSE header maps (integer-keyed per RFC 9052), the MSO and its
/// nested structures use text-string keys per ISO 18013-5's CDDL. Encoders
/// and decoders MUST round-trip these strings verbatim — the issuer commits
/// to byte patterns that depend on map insertion order plus exact key
/// spellings.
/// </para>
/// <para>
/// Constants here describe the data model only and carry no serialization-
/// format dependency. The CBOR reader in <c>Verifiable.Cbor.Mdoc</c>
/// consumes them when walking the wire bytes.
/// </para>
/// </remarks>
public static class MdocMsoWellKnownKeys
{
    //MobileSecurityObject map keys (ISO/IEC 18013-5 §9.1.2.4).

    /// <summary>The <c>version</c> key in the MSO; currently always <c>"1.0"</c>.</summary>
    public const string Version = "version";

    /// <summary>
    /// The <c>digestAlgorithm</c> key in the MSO; the IANA hash-algorithm name
    /// applied to each <c>IssuerSignedItem</c> wire bytes to produce the
    /// <c>valueDigests</c> commitments.
    /// </summary>
    public const string DigestAlgorithm = "digestAlgorithm";

    /// <summary>The <c>valueDigests</c> key in the MSO; the <c>NameSpace → DigestID → Digest</c> map.</summary>
    public const string ValueDigests = "valueDigests";

    /// <summary>The <c>deviceKeyInfo</c> key in the MSO; the wallet-side key bound to this credential.</summary>
    public const string DeviceKeyInfo = "deviceKeyInfo";

    /// <summary>The <c>docType</c> key in the MSO; mirrors <see cref="MdocWellKnownKeys.DocType"/> on the outer document.</summary>
    public const string DocType = "docType";

    /// <summary>The <c>validityInfo</c> key in the MSO; the temporal bounds the issuer commits to.</summary>
    public const string ValidityInfo = "validityInfo";


    //DeviceKeyInfo map keys (ISO/IEC 18013-5 §9.1.2.4).

    /// <summary>The <c>deviceKey</c> key in <c>DeviceKeyInfo</c>; carries the COSE_Key per RFC 9052.</summary>
    public const string DeviceKey = "deviceKey";

    /// <summary>
    /// The <c>keyAuthorizations</c> key in <c>DeviceKeyInfo</c>; per-namespace and
    /// per-data-element authorization bounds on what the device key may sign over.
    /// </summary>
    public const string KeyAuthorizations = "keyAuthorizations";

    /// <summary>
    /// The <c>keyInfo</c> key in <c>DeviceKeyInfo</c>; reserved for additional
    /// integer-keyed key metadata (e.g. device attestation parameters).
    /// </summary>
    public const string KeyInfo = "keyInfo";


    //KeyAuthorizations sub-keys (ISO/IEC 18013-5 §9.1.2.4 KeyAuthorizations).

    /// <summary>The <c>nameSpaces</c> key in <c>KeyAuthorizations</c>; namespaces the device key may present in full.</summary>
    public const string AuthorizedNameSpaces = "nameSpaces";

    /// <summary>
    /// The <c>dataElements</c> key in <c>KeyAuthorizations</c>; namespaces → data
    /// element identifiers the device key may present individually.
    /// </summary>
    public const string AuthorizedDataElements = "dataElements";


    //ValidityInfo map keys (ISO/IEC 18013-5 §9.1.2.4 ValidityInfo).

    /// <summary>The <c>signed</c> key in <c>ValidityInfo</c>; tdate of MSO signature creation.</summary>
    public const string Signed = "signed";

    /// <summary>The <c>validFrom</c> key in <c>ValidityInfo</c>; tdate from which the MSO is valid.</summary>
    public const string ValidFrom = "validFrom";

    /// <summary>The <c>validUntil</c> key in <c>ValidityInfo</c>; tdate after which the MSO is invalid.</summary>
    public const string ValidUntil = "validUntil";

    /// <summary>The <c>expectedUpdate</c> key in <c>ValidityInfo</c>; optional tdate when the issuer plans to issue a fresh MSO.</summary>
    public const string ExpectedUpdate = "expectedUpdate";


    //Version sentinels.

    /// <summary>The current MSO version string (<c>"1.0"</c>).</summary>
    public const string Version10 = "1.0";


    //Digest algorithm identifiers per ISO/IEC 18013-5 §9.1.2.5; restricted to
    //the IANA hash-algorithm registry names accepted by the spec.

    /// <summary>The <c>SHA-256</c> digest-algorithm identifier (ISO 18013-5 §9.1.2.5).</summary>
    public const string DigestAlgorithmSha256 = "SHA-256";

    /// <summary>The <c>SHA-384</c> digest-algorithm identifier (ISO 18013-5 §9.1.2.5).</summary>
    public const string DigestAlgorithmSha384 = "SHA-384";

    /// <summary>The <c>SHA-512</c> digest-algorithm identifier (ISO 18013-5 §9.1.2.5).</summary>
    public const string DigestAlgorithmSha512 = "SHA-512";
}
