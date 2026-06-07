namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Map-key string constants for the ISO/IEC 18013-5 mdoc wire shapes —
/// <c>DeviceResponse</c>, <c>Document</c>, <c>IssuerSigned</c>, and
/// <c>IssuerSignedItem</c> — as well as the version and status sentinels.
/// </summary>
/// <remarks>
/// <para>
/// Unlike COSE structures (which key maps by integer per RFC 9052), the mdoc
/// CDDL in ISO/IEC 18013-5 §8.3.2 specifies <em>text-string</em> map keys for
/// every wire-shape map. The strings are case-sensitive and exactly the
/// identifiers below; encoders and decoders MUST round-trip them verbatim.
/// </para>
/// <para>
/// These constants are pure protocol vocabulary — they describe the data model
/// only and carry no serialization-format dependency.
/// </para>
/// </remarks>
public static class MdocWellKnownKeys
{
    //DeviceResponse map keys (ISO/IEC 18013-5 §8.3.2.1.1).

    /// <summary>The <c>version</c> key in <c>DeviceResponse</c>; carries the protocol version string.</summary>
    public const string Version = "version";

    /// <summary>The <c>documents</c> key in <c>DeviceResponse</c>; carries the array of mdoc documents.</summary>
    public const string Documents = "documents";

    /// <summary>The <c>documentErrors</c> key in <c>DeviceResponse</c>; carries per-document error info.</summary>
    public const string DocumentErrors = "documentErrors";

    /// <summary>The <c>status</c> key in <c>DeviceResponse</c>; carries the unsigned-integer status code.</summary>
    public const string Status = "status";


    //Document map keys (§8.3.2.1).

    /// <summary>The <c>docType</c> key in a <c>Document</c>; carries the credential doctype URI (e.g. <c>org.iso.18013.5.1.mDL</c>).</summary>
    public const string DocType = "docType";

    /// <summary>The <c>issuerSigned</c> key in a <c>Document</c>; carries the <c>IssuerSigned</c> structure.</summary>
    public const string IssuerSigned = "issuerSigned";

    /// <summary>The <c>deviceSigned</c> key in a <c>Document</c>; carries the holder-signed presentation half. Optional on issuance, required on presentation.</summary>
    public const string DeviceSigned = "deviceSigned";

    /// <summary>The <c>errors</c> key in a <c>Document</c>; carries per-namespace per-element error info.</summary>
    public const string Errors = "errors";


    //IssuerSigned map keys (§8.3.2.1.2).

    /// <summary>The <c>nameSpaces</c> key in <c>IssuerSigned</c>; carries the namespace-to-items map.</summary>
    public const string NameSpaces = "nameSpaces";

    /// <summary>The <c>issuerAuth</c> key in <c>IssuerSigned</c>; carries the COSE_Sign1 with the MSO payload.</summary>
    public const string IssuerAuth = "issuerAuth";


    //IssuerSignedItem map keys (§8.3.2.1.2.2).

    /// <summary>The <c>digestID</c> key in <c>IssuerSignedItem</c>; unique within its namespace, referenced by MSO valueDigests.</summary>
    public const string DigestId = "digestID";

    /// <summary>
    /// The <c>random</c> key in <c>IssuerSignedItem</c>; the per-item salt that
    /// prevents precomputation of the issuer-side digest across credentials.
    /// Length MUST be at least 16 bytes per §9.1.2.5.
    /// </summary>
    public const string Random = "random";

    /// <summary>The <c>elementIdentifier</c> key in <c>IssuerSignedItem</c>; the claim name within the namespace.</summary>
    public const string ElementIdentifier = "elementIdentifier";

    /// <summary>The <c>elementValue</c> key in <c>IssuerSignedItem</c>; the claim value, as an arbitrary CBOR item.</summary>
    public const string ElementValue = "elementValue";


    //Status code sentinels (§8.3.2.1.1.2 Table 8).

    /// <summary>Status code 0: OK.</summary>
    public const uint StatusOk = 0;

    /// <summary>Status code 10: general error.</summary>
    public const uint StatusGeneralError = 10;

    /// <summary>Status code 11: CBOR decoding error.</summary>
    public const uint StatusCborDecodingError = 11;

    /// <summary>Status code 12: CBOR validation error.</summary>
    public const uint StatusCborValidationError = 12;


    //Protocol version sentinels (§8.3.2.1.1.1).

    /// <summary>The current DeviceResponse version string (<c>"1.0"</c>).</summary>
    public const string Version10 = "1.0";


    //Minimum-length sentinels surfaced for the data-model layer that builders
    //and validators key off of; the digest commitment in the MSO depends on
    //the random meeting at least this lower bound.

    /// <summary>The ISO/IEC 18013-5 §9.1.2.5 minimum length for the per-item random salt (16 bytes).</summary>
    public const int IssuerSignedItemRandomMinimumLength = 16;


    //DeviceAuth map keys (ISO/IEC 18013-5 §9.1.3.4). DeviceAuth carries
    //exactly one of these: a COSE_Sign1 (deviceSignature) when the device
    //key signs the DeviceAuthentication directly, or a COSE_Mac0 (deviceMac)
    //when the device key is used for ECDH-based MAC derivation.

    /// <summary>The <c>deviceAuth</c> key in <c>DeviceSigned</c>; carries the inner <c>DeviceAuth</c> map.</summary>
    public const string DeviceAuth = "deviceAuth";

    /// <summary>The <c>deviceSignature</c> key in <c>DeviceAuth</c>; carries the COSE_Sign1.</summary>
    public const string DeviceSignature = "deviceSignature";

    /// <summary>The <c>deviceMac</c> key in <c>DeviceAuth</c>; carries the COSE_Mac0.</summary>
    public const string DeviceMac = "deviceMac";


    //DeviceAuthentication context string (ISO/IEC 18013-5 §9.1.3.4).
    //The first element of the DeviceAuthentication array — the canonical
    //domain separator that distinguishes a device-signed assertion from any
    //other signed payload the device key could be misled into producing.

    /// <summary>The leading context string for the DeviceAuthentication array (<c>"DeviceAuthentication"</c>).</summary>
    public const string DeviceAuthenticationContext = "DeviceAuthentication";
}
