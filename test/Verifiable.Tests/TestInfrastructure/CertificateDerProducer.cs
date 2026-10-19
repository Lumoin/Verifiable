using System.Formats.Asn1;
using Verifiable.Cryptography;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The shape of a DER X.509 certificate (RFC 5280 section 4.1) <see cref="CertificateDerProducer"/> writes: the subject public
/// key's algorithm, its parameters and its key, and the deviations from RFC 5280 a row asks for, each written by the producer
/// before the certificate is encoded, so the bytes a row judges are the first and only bytes the producer wrote.
/// </summary>
internal sealed record CertificateDerShape
{
    /// <summary>The object identifier of the subject public key's algorithm.</summary>
    public required string KeyAlgorithmOid { get; init; }

    /// <summary>Writes the algorithm's parameters after its identifier, or <see langword="null"/> for parameters absent.</summary>
    public required Action<AsnWriter>? WriteKeyParameters { get; init; }

    /// <summary>The <c>subjectPublicKey</c> BIT STRING's octets.</summary>
    public required byte[] SubjectPublicKey { get; init; }

    /// <summary>
    /// Writes a field after the <c>subjectPublicKey</c> inside the <c>SubjectPublicKeyInfo</c>, which RFC 5280 section 4.1.2.7
    /// does not admit, or <see langword="null"/> for the two fields alone.
    /// </summary>
    public Action<AsnWriter>? WriteFieldAfterSubjectPublicKey { get; init; }

    /// <summary>
    /// Whether the issuer <c>Name</c>'s attribute stands directly in the <c>RDNSequence</c> rather than in a
    /// <c>RelativeDistinguishedName</c> SET (RFC 5280 section 4.1.2.4).
    /// </summary>
    public bool IssuerAttributeOutsideASet { get; init; }

    /// <summary>
    /// The object identifier of the outer <c>signatureAlgorithm</c>, which RFC 5280 section 4.1.1.2 has equal the
    /// <c>tbsCertificate.signature</c>'s, <c>ecdsa-with-SHA256</c>.
    /// </summary>
    public string OuterSignatureAlgorithmOid { get; init; } = CertificateDerProducer.EcdsaWithSha256Oid;
}


/// <summary>
/// Writes DER X.509 certificates (RFC 5280 section 4.1) of a shape a row states, with the <c>System.Formats.Asn1</c> writer:
/// a version 3 certificate whose <c>tbsCertificate.signature</c> is <c>ecdsa-with-SHA256</c>, whose issuer and subject are
/// one common name each, valid over a fixed day, and whose subject public key is the one the shape states. The signature value
/// is no signature: a judgement of a JWK's <c>x5c</c> (RFC 7517 section 4.7) reads a certificate structurally and compares its
/// key, and the certification of a certificate is the trust step's, which no row here reaches.
/// </summary>
internal static class CertificateDerProducer
{
    /// <summary>The <c>ecdsa-with-SHA256</c> signature algorithm identifier (RFC 5758 section 3.2).</summary>
    public const string EcdsaWithSha256Oid = "1.2.840.10045.4.3.2";

    /// <summary>The <c>ecdsa-with-SHA384</c> signature algorithm identifier (RFC 5758 section 3.2).</summary>
    public const string EcdsaWithSha384Oid = "1.2.840.10045.4.3.3";

    /// <summary>The common-name attribute type (RFC 5280 section 4.1.2.4).</summary>
    private const string CommonNameOid = "2.5.4.3";

    /// <summary>The first instant of the certificate's validity.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch;


    /// <summary>The DER encoding of a certificate of the shape given.</summary>
    /// <param name="shape">The shape.</param>
    /// <returns>The certificate's DER bytes.</returns>
    public static byte[] Der(CertificateDerShape shape)
    {
        ArgumentNullException.ThrowIfNull(shape);

        var writer = new AsnWriter(AsnEncodingRules.DER);

        using(writer.PushSequence())
        {
            using(writer.PushSequence())
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    writer.WriteInteger(2);
                }

                writer.WriteInteger(1);
                WriteAlgorithmIdentifier(writer, EcdsaWithSha256Oid);
                WriteName(writer, "x5c-producer-issuer", shape.IssuerAttributeOutsideASet);

                using(writer.PushSequence())
                {
                    writer.WriteUtcTime(NotBefore);
                    writer.WriteUtcTime(NotBefore.AddDays(1));
                }

                WriteName(writer, "x5c-producer-subject", attributeOutsideASet: false);

                using(writer.PushSequence())
                {
                    using(writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(shape.KeyAlgorithmOid);
                        shape.WriteKeyParameters?.Invoke(writer);
                    }

                    writer.WriteBitString(shape.SubjectPublicKey);
                    shape.WriteFieldAfterSubjectPublicKey?.Invoke(writer);
                }
            }

            WriteAlgorithmIdentifier(writer, shape.OuterSignatureAlgorithmOid);
            writer.WriteBitString(new byte[64]);
        }

        return writer.Encode();
    }


    /// <summary>The base64 text (RFC 4648 section 4) of a certificate of the shape given, as an <c>x5c</c> element carries it.</summary>
    /// <param name="shape">The shape.</param>
    /// <returns>The base64 text.</returns>
    public static string Base64(CertificateDerShape shape) => Convert.ToBase64String(Der(shape));


    /// <summary>
    /// The shape of a certificate whose subject public key is the elliptic-curve point given (RFC 5480 section 2): an
    /// <c>id-ecPublicKey</c> on the named curve, the point <c>0x04 || x || y</c>.
    /// </summary>
    /// <param name="curveOid">The named curve's object identifier.</param>
    /// <param name="x">The point's x coordinate.</param>
    /// <param name="y">The point's y coordinate.</param>
    /// <returns>The shape.</returns>
    public static CertificateDerShape EllipticCurveKey(string curveOid, byte[] x, byte[] y) => new()
    {
        KeyAlgorithmOid = WellKnownOids.EcPublicKey,
        WriteKeyParameters = writer => writer.WriteObjectIdentifier(curveOid),
        SubjectPublicKey = [EllipticCurveUtilities.UncompressedCoordinateFormat, .. x, .. y]
    };


    /// <summary>The shape of a certificate whose subject public key is the Ed25519 key given, parameters absent (RFC 8410 section 3).</summary>
    /// <param name="publicKey">The 32-octet public key.</param>
    /// <returns>The shape.</returns>
    public static CertificateDerShape Ed25519Key(byte[] publicKey) => new()
    {
        KeyAlgorithmOid = WellKnownOids.EdDSA25519,
        WriteKeyParameters = null,
        SubjectPublicKey = publicKey
    };


    /// <summary>The shape of a certificate whose subject public key is the ML-DSA key of the parameter set given, parameters absent.</summary>
    /// <param name="parameterSetOid">The ML-DSA parameter set's object identifier.</param>
    /// <param name="publicKey">The raw public key.</param>
    /// <returns>The shape.</returns>
    public static CertificateDerShape MlDsaKey(string parameterSetOid, byte[] publicKey) => new()
    {
        KeyAlgorithmOid = parameterSetOid,
        WriteKeyParameters = null,
        SubjectPublicKey = publicKey
    };


    /// <summary>
    /// The shape of a certificate whose subject public key is the RSA key given (RFC 3279 section 2.3.1): <c>rsaEncryption</c>
    /// with <c>NULL</c> parameters, the key the PKCS #1 <c>RSAPublicKey</c> encoding of the modulus and exponent.
    /// </summary>
    /// <param name="modulus">The modulus, unsigned big-endian.</param>
    /// <param name="exponent">The public exponent, unsigned big-endian.</param>
    /// <returns>The shape.</returns>
    public static CertificateDerShape RsaKey(byte[] modulus, byte[] exponent) => new()
    {
        KeyAlgorithmOid = WellKnownOids.RsaEncryption,
        WriteKeyParameters = static writer => writer.WriteNull(),
        SubjectPublicKey = RsaPublicKeyEncoding.Encode(modulus, exponent)
    };


    /// <summary>Writes an <c>AlgorithmIdentifier</c> whose parameters are absent.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="algorithmOid">The algorithm's object identifier.</param>
    private static void WriteAlgorithmIdentifier(AsnWriter writer, string algorithmOid)
    {
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(algorithmOid);
        }
    }


    /// <summary>
    /// Writes a <c>Name</c> of one common-name attribute: an <c>RDNSequence</c> of one <c>RelativeDistinguishedName</c> SET
    /// holding it, or, where the row asks for it, the attribute standing directly in the <c>RDNSequence</c>.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <param name="commonName">The common name.</param>
    /// <param name="attributeOutsideASet">Whether the attribute stands outside a SET.</param>
    private static void WriteName(AsnWriter writer, string commonName, bool attributeOutsideASet)
    {
        using(writer.PushSequence())
        {
            if(attributeOutsideASet)
            {
                WriteCommonName(writer, commonName);

                return;
            }

            using(writer.PushSetOf())
            {
                WriteCommonName(writer, commonName);
            }
        }
    }


    /// <summary>Writes one common-name <c>AttributeTypeAndValue</c>.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="commonName">The common name.</param>
    private static void WriteCommonName(AsnWriter writer, string commonName)
    {
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(CommonNameOid);
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, commonName);
        }
    }
}
