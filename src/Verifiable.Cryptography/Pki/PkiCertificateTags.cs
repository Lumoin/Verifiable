namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Pre-built <see cref="Tag"/> instances for PKI objects carried in
/// <see cref="PkiCertificateMemory"/>.
/// </summary>
/// <remarks>
/// Each tag encodes a <see cref="PkiObjectKind"/> discriminator that identifies
/// what the DER-encoded bytes represent. This allows routing and processing code
/// to distinguish certificates from CRLs, OCSP responses, and timestamp tokens
/// without inspecting the raw content.
/// </remarks>
public static class PkiCertificateTags
{
    /// <summary>Tag for a DER-encoded X.509 v3 certificate per RFC 5280.</summary>
    public static Tag X509Certificate { get; } = Tag.Create((typeof(PkiObjectKind), PkiObjectKind.X509Certificate));

    /// <summary>Tag for a DER-encoded Certificate Revocation List per RFC 5280.</summary>
    public static Tag X509Crl { get; } = Tag.Create((typeof(PkiObjectKind), PkiObjectKind.X509Crl));

    /// <summary>Tag for a DER-encoded OCSP response per RFC 6960.</summary>
    public static Tag OcspResponse { get; } = Tag.Create((typeof(PkiObjectKind), PkiObjectKind.OcspResponse));

    /// <summary>Tag for a DER-encoded RFC 3161 timestamp token.</summary>
    public static Tag TimestampToken { get; } = Tag.Create((typeof(PkiObjectKind), PkiObjectKind.TimestampToken));
}
