namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Discriminates the type of a PKI object held in <see cref="PkiCertificateMemory"/>.
/// </summary>
/// <remarks>
/// Used as a <see cref="Tag"/> component to identify what a block of DER-encoded
/// bytes represents, enabling correct routing and processing without inspecting
/// the raw bytes.
/// </remarks>
public enum PkiObjectKind
{
    /// <summary>
    /// No PKI object kind specified. Default value for uninitialized instances.
    /// </summary>
    None = 0,

    /// <summary>An X.509 v3 certificate per RFC 5280.</summary>
    X509Certificate = 1,

    /// <summary>A Certificate Revocation List per RFC 5280.</summary>
    X509Crl = 2,

    /// <summary>An OCSP response per RFC 6960.</summary>
    OcspResponse = 3,

    /// <summary>An RFC 3161 timestamp token.</summary>
    TimestampToken = 4,

    /// <summary>A DER-encoded OCSP request per RFC 6960.</summary>
    OcspRequest = 5,

    /// <summary>A DER-encoded RFC 3161 <c>TimeStampReq</c>.</summary>
    TimestampRequest = 6,

    /// <summary>A DER-encoded RFC 3161 <c>TimeStampResp</c> (the status envelope a Time-Stamping Authority returns, before the embedded token is extracted).</summary>
    TimestampResponse = 7
}
