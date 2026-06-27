using System;
using System.Formats.Asn1;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A partial managed parse of an X.509 certificate (RFC 5280) — only the fields the managed CMS verifier
/// needs: the issuer and serial number (for matching a signer identifier), the elliptic-curve public key
/// (for verifying the signature), and the subject key identifier (the alternative signer-identifier match).
/// It is not a full certificate model; the encoded bytes are retained for the verified-content output and the
/// separate certificate-chain trust step.
/// </summary>
/// <remarks>
/// Parsed with <see cref="System.Formats.Asn1"/> only, no platform certificate type, so the managed CMS
/// verifier carries no dependency on a certificate library. RSA public keys are recognised (the curve is
/// <see cref="EllipticCurveTypes.None"/> and the point empty) but not used until the
/// RSA signer slice.
/// </remarks>
internal sealed class ManagedCertificate
{
    /// <summary>The id-ecPublicKey key type (RFC 5480).</summary>
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";

    /// <summary>The rsaEncryption key type (RFC 8017).</summary>
    private const string RsaEncryptionOid = "1.2.840.113549.1.1.1";

    /// <summary>The subject key identifier extension (RFC 5280 §4.2.1.2).</summary>
    private const string SubjectKeyIdentifierOid = "2.5.29.14";


    private ManagedCertificate(
        ReadOnlyMemory<byte> encoded,
        ReadOnlyMemory<byte> issuerDer,
        ReadOnlyMemory<byte> serialNumber,
        EllipticCurveTypes ellipticCurve,
        ReadOnlyMemory<byte> publicPoint,
        ReadOnlyMemory<byte> rsaModulus,
        ReadOnlyMemory<byte> rsaExponent,
        ReadOnlyMemory<byte> subjectKeyIdentifier)
    {
        Encoded = encoded;
        IssuerDer = issuerDer;
        SerialNumber = serialNumber;
        EllipticCurve = ellipticCurve;
        PublicPoint = publicPoint;
        RsaModulus = rsaModulus;
        RsaExponent = rsaExponent;
        SubjectKeyIdentifier = subjectKeyIdentifier;
    }


    /// <summary>Gets the full DER encoding of the certificate.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>Gets the issuer distinguished name as raw DER (for issuer-and-serial-number matching).</summary>
    public ReadOnlyMemory<byte> IssuerDer { get; }

    /// <summary>Gets the certificate serial number as its DER INTEGER content bytes.</summary>
    public ReadOnlyMemory<byte> SerialNumber { get; }

    /// <summary>Gets the elliptic curve of the subject public key, or <see cref="EllipticCurveTypes.None"/> when the key is not a recognised elliptic-curve key.</summary>
    public EllipticCurveTypes EllipticCurve { get; }

    /// <summary>Gets the subject public key as an uncompressed SEC1 point (<c>0x04 || X || Y</c>); empty when the key is not elliptic-curve.</summary>
    public ReadOnlyMemory<byte> PublicPoint { get; }

    /// <summary>Gets the RSA public modulus as unsigned big-endian bytes; empty when the key is not RSA.</summary>
    public ReadOnlyMemory<byte> RsaModulus { get; }

    /// <summary>Gets the RSA public exponent as unsigned big-endian bytes; empty when the key is not RSA.</summary>
    public ReadOnlyMemory<byte> RsaExponent { get; }

    /// <summary>Gets the subject key identifier from the certificate extension; empty when absent.</summary>
    public ReadOnlyMemory<byte> SubjectKeyIdentifier { get; }


    /// <summary>
    /// Parses the fields the CMS verifier needs from an encoded certificate.
    /// </summary>
    /// <param name="encoded">The DER-encoded certificate.</param>
    /// <returns>The parsed certificate.</returns>
    public static ManagedCertificate Parse(ReadOnlyMemory<byte> encoded)
    {
        var certificate = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader tbs = certificate.ReadSequence().ReadSequence();

        //version [0] EXPLICIT INTEGER DEFAULT v1, present in practically every certificate.
        if(tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            _ = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        ReadOnlyMemory<byte> serialNumber = tbs.ReadIntegerBytes();
        _ = tbs.ReadSequence();                                        //signature AlgorithmIdentifier
        ReadOnlyMemory<byte> issuer = tbs.ReadEncodedValue();          //issuer Name (raw DER)
        _ = tbs.ReadSequence();                                        //validity
        _ = tbs.ReadEncodedValue();                                    //subject Name

        ParsedPublicKey publicKey = ParseSubjectPublicKeyInfo(tbs.ReadSequence());

        ReadOnlyMemory<byte> subjectKeyIdentifier = ParseSubjectKeyIdentifier(tbs);

        return new ManagedCertificate(
            encoded, issuer, serialNumber, publicKey.Curve, publicKey.Point, publicKey.RsaModulus, publicKey.RsaExponent, subjectKeyIdentifier);
    }


    /// <summary>
    /// Parses the subject public key info: for an elliptic-curve key, the curve and the uncompressed public
    /// point; for an RSA key, the modulus and exponent; otherwise an unsupported key.
    /// </summary>
    private static ParsedPublicKey ParseSubjectPublicKeyInfo(AsnReader subjectPublicKeyInfo)
    {
        AsnReader algorithm = subjectPublicKeyInfo.ReadSequence();
        string algorithmOid = algorithm.ReadObjectIdentifier();

        if(string.Equals(algorithmOid, EcPublicKeyOid, StringComparison.Ordinal))
        {
            string curveOid = algorithm.ReadObjectIdentifier();
            byte[] point = subjectPublicKeyInfo.ReadBitString(out _);

            return new ParsedPublicKey(CurveFromOid(curveOid), point, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty);
        }

        if(string.Equals(algorithmOid, RsaEncryptionOid, StringComparison.Ordinal))
        {
            //The subjectPublicKey BIT STRING wraps RSAPublicKey ::= SEQUENCE { modulus, publicExponent }.
            byte[] rsaPublicKey = subjectPublicKeyInfo.ReadBitString(out _);
            var rsa = new AsnReader(rsaPublicKey, AsnEncodingRules.DER).ReadSequence();
            ReadOnlyMemory<byte> modulus = StripLeadingZero(rsa.ReadIntegerBytes());
            ReadOnlyMemory<byte> exponent = StripLeadingZero(rsa.ReadIntegerBytes());

            return new ParsedPublicKey(EllipticCurveTypes.None, ReadOnlyMemory<byte>.Empty, modulus, exponent);
        }

        return new ParsedPublicKey(EllipticCurveTypes.None, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty);
    }


    /// <summary>
    /// Strips a single leading <c>0x00</c> sign octet from a DER INTEGER's two's-complement encoding.
    /// </summary>
    private static ReadOnlyMemory<byte> StripLeadingZero(ReadOnlyMemory<byte> integer) =>
        integer.Length > 1 && integer.Span[0] == 0x00 ? integer[1..] : integer;


    /// <summary>
    /// Walks the optional unique identifiers and the extensions to the subject-key-identifier extension,
    /// returning its key identifier, or <see langword="null"/> when absent.
    /// </summary>
    private static ReadOnlyMemory<byte> ParseSubjectKeyIdentifier(AsnReader tbs)
    {
        //issuerUniqueID [1] IMPLICIT and subjectUniqueID [2] IMPLICIT are obsolete but allowed before extensions.
        if(tbs.HasData && tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
        {
            _ = tbs.ReadEncodedValue();
        }

        if(tbs.HasData && tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true))
        {
            _ = tbs.ReadEncodedValue();
        }

        if(!tbs.HasData || tbs.PeekTag() != new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true))
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        AsnReader extensions = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3)).ReadSequence();
        while(extensions.HasData)
        {
            AsnReader extension = extensions.ReadSequence();
            string extensionId = extension.ReadObjectIdentifier();
            if(extension.PeekTag() == new Asn1Tag(UniversalTagNumber.Boolean))
            {
                _ = extension.ReadBoolean();
            }

            byte[] extensionValue = extension.ReadOctetString();
            if(string.Equals(extensionId, SubjectKeyIdentifierOid, StringComparison.Ordinal))
            {
                //The extension value wraps a KeyIdentifier ::= OCTET STRING.
                return new AsnReader(extensionValue, AsnEncodingRules.DER).ReadOctetString();
            }
        }

        return ReadOnlyMemory<byte>.Empty;
    }


    /// <summary>
    /// Maps a named-curve object identifier to its <see cref="EllipticCurveTypes"/>.
    /// </summary>
    private static EllipticCurveTypes CurveFromOid(string curveOid) => curveOid switch
    {
        WellKnownOids.EcP256 => EllipticCurveTypes.P256,
        WellKnownOids.EcP384 => EllipticCurveTypes.P384,
        WellKnownOids.EcP521 => EllipticCurveTypes.P521,
        WellKnownOids.EcSecp256k1 => EllipticCurveTypes.Secp256k1,
        WellKnownOids.EcBrainpoolP224r1 => EllipticCurveTypes.BrainpoolP224r1,
        WellKnownOids.EcBrainpoolP256r1 => EllipticCurveTypes.BrainpoolP256r1,
        WellKnownOids.EcBrainpoolP320r1 => EllipticCurveTypes.BrainpoolP320r1,
        WellKnownOids.EcBrainpoolP384r1 => EllipticCurveTypes.BrainpoolP384r1,
        WellKnownOids.EcBrainpoolP512r1 => EllipticCurveTypes.BrainpoolP512r1,
        _ => EllipticCurveTypes.None
    };


    /// <summary>A parsed subject public key: an elliptic-curve point, or RSA modulus and exponent.</summary>
    private readonly record struct ParsedPublicKey(
        EllipticCurveTypes Curve,
        ReadOnlyMemory<byte> Point,
        ReadOnlyMemory<byte> RsaModulus,
        ReadOnlyMemory<byte> RsaExponent);
}
