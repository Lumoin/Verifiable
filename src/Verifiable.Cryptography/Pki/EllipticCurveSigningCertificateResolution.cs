using System;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Resolves the elliptic-curve verification inputs (the registry-resolution algorithm plus the raw public-key
/// point) a caller needs to verify a signature under an X.509 certificate's own public key, without that caller
/// needing to depend on a certificate-parsing library of its own.
/// </summary>
/// <remarks>
/// This exists so a format binding living OUTSIDE this assembly (for example a CB-AdES/COSE binding in
/// <c>Verifiable.JCose</c>) can obtain a <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>-resolvable
/// algorithm and the raw public-key material from a DER-encoded X.509 certificate without a project reference to
/// a certificate library — <see cref="ManagedCertificate"/> is <see langword="internal"/> to this assembly and
/// stays that way; this is the narrow, purpose-built public seam onto it (never reimplementing certificate
/// parsing at the caller's own layer — reuse over reinvention).
/// </remarks>
public static class EllipticCurveSigningCertificateResolution
{
    /// <summary>
    /// Attempts to resolve the <see cref="CryptoAlgorithm"/> and raw public-key point of a DER-encoded X.509
    /// certificate carrying an elliptic-curve public key.
    /// </summary>
    /// <param name="certificate">The DER-encoded certificate.</param>
    /// <param name="algorithm">The resolved algorithm, valid only when this method returns <see langword="true"/>.</param>
    /// <param name="publicKeyPoint">The uncompressed SEC1 public-key point (<c>0x04 || X || Y</c>), valid only when this method returns <see langword="true"/>.</param>
    /// <returns>
    /// <see langword="true"/> when <paramref name="certificate"/> parses as a well-formed X.509 certificate whose
    /// subject public key is one of the curves this library names a <see cref="CryptoAlgorithm"/> for
    /// (P-256/P-384/P-521/secp256k1); <see langword="false"/> otherwise — a malformed certificate, an RSA/ML-DSA
    /// key, or an elliptic curve this library has no <see cref="CryptoAlgorithm"/> identity for.
    /// </returns>
    public static bool TryResolve(PkiCertificateMemory certificate, out CryptoAlgorithm algorithm, out ReadOnlyMemory<byte> publicKeyPoint)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        ManagedCertificate parsed;
        try
        {
            parsed = ManagedCertificate.Parse(certificate.AsReadOnlyMemory());
        }
        catch(Exception ex) when(ex is System.Formats.Asn1.AsnContentException or ArgumentException or OverflowException)
        {
            algorithm = default;
            publicKeyPoint = default;

            return false;
        }

        switch(parsed.EllipticCurve)
        {
            case EllipticCurveTypes.P256:
                algorithm = CryptoAlgorithm.P256;
                publicKeyPoint = parsed.PublicPoint;

                return true;

            case EllipticCurveTypes.P384:
                algorithm = CryptoAlgorithm.P384;
                publicKeyPoint = parsed.PublicPoint;

                return true;

            case EllipticCurveTypes.P521:
                algorithm = CryptoAlgorithm.P521;
                publicKeyPoint = parsed.PublicPoint;

                return true;

            case EllipticCurveTypes.Secp256k1:
                algorithm = CryptoAlgorithm.Secp256k1;
                publicKeyPoint = parsed.PublicPoint;

                return true;

            default:
                algorithm = default;
                publicKeyPoint = default;

                return false;
        }
    }
}
