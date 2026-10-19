using System.Buffers.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Real DER X.509 certificates (RFC 5280) for the keys a JWK's <c>x5c</c> rows carry (RFC 7517 section 4.7): each certificate's
/// subject public key is the P-256 key whose coordinates the row's JWK states, issued under a key of its own, so a row's chain is
/// one a certificate parser reads as a certificate and its first certificate's key is the JWK's key, or another's where the row
/// says so.
/// </summary>
internal static class JwkCertificateFixtures
{
    /// <summary>
    /// The base64 text (RFC 4648 section 4, not base64url) of a DER certificate whose subject public key is the P-256 key of the
    /// base64url coordinates given, issued under a fresh key of its own.
    /// </summary>
    /// <param name="x">The key's x coordinate, base64url.</param>
    /// <param name="y">The key's y coordinate, base64url.</param>
    /// <param name="notBefore">The first instant the certificate is valid at.</param>
    /// <returns>The certificate's base64 text.</returns>
    public static string CertificateOfP256Key(string x, string y, DateTimeOffset notBefore)
    {
        using var subjectKey = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = Base64Url.DecodeFromChars(x), Y = Base64Url.DecodeFromChars(y) }
        });
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var request = new CertificateRequest("CN=jwk-certificate-fixture", subjectKey, HashAlgorithmName.SHA256);
        using var certificate = request.Create(
            new X500DistinguishedName("CN=jwk-certificate-fixture-issuer"),
            X509SignatureGenerator.CreateForECDsa(issuerKey),
            notBefore,
            notBefore.AddDays(1),
            [0x01]);

        return Convert.ToBase64String(certificate.RawData);
    }


    /// <summary>
    /// The base64 text of a DER certificate whose subject public key is a fresh P-256 key, no key a row's JWK states: the first
    /// certificate of a chain that names another key than its JWK's.
    /// </summary>
    /// <param name="notBefore">The first instant the certificate is valid at.</param>
    /// <returns>The certificate's base64 text.</returns>
    public static string CertificateOfAnotherP256Key(DateTimeOffset notBefore)
    {
        using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = otherKey.ExportParameters(includePrivateParameters: false).Q;
        var x = point.X ?? throw new InvalidOperationException("An exported P-256 key carries its x coordinate.");
        var y = point.Y ?? throw new InvalidOperationException("An exported P-256 key carries its y coordinate.");

        return CertificateOfP256Key(Base64Url.EncodeToString(x), Base64Url.EncodeToString(y), notBefore);
    }
}
