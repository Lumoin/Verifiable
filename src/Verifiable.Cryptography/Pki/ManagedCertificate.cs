using System;
using System.Collections.Generic;
using System.Formats.Asn1;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A partial managed parse of an X.509 certificate (RFC 5280) — the fields the managed CMS verifier and
/// the managed OCSP response verifier need: the issuer, subject, and validity fields (for name matching and
/// the certificate's own validity window), the raw <c>subjectPublicKey</c> BIT STRING content and its typed
/// decomposition (elliptic-curve point, or RSA modulus/exponent — for verifying a signature under the key and
/// for hashing the raw key material), the subject key identifier (an alternative signer-identifier match), the
/// Extended Key Usage key purpose identifiers (for an OCSP-signing delegation check), and the raw
/// <c>tbsCertificate</c> bytes together with the outer <c>signatureAlgorithm</c>/<c>signatureValue</c> (for
/// verifying that this certificate was itself issued by a candidate issuer). It is not a full certificate
/// model; the encoded bytes are retained for the verified-content output and the separate certificate-chain
/// trust step.
/// </summary>
/// <remarks>
/// Parsed with <see cref="System.Formats.Asn1"/> only, no platform certificate type, so the managed
/// verifiers carry no dependency on a certificate library. RSA public keys are recognised (the curve is
/// <see cref="EllipticCurveTypes.None"/> and the point empty) but used only by the RSA signer slice.
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
        ReadOnlyMemory<byte> tbsCertificateDer,
        ReadOnlyMemory<byte> issuerDer,
        ReadOnlyMemory<byte> serialNumber,
        ReadOnlyMemory<byte> subjectDer,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        EllipticCurveTypes ellipticCurve,
        ReadOnlyMemory<byte> publicPoint,
        ReadOnlyMemory<byte> rsaModulus,
        ReadOnlyMemory<byte> rsaExponent,
        ReadOnlyMemory<byte> subjectPublicKeyBitStringContent,
        ReadOnlyMemory<byte> subjectKeyIdentifier,
        IReadOnlyList<string> extendedKeyUsageOids,
        string signatureAlgorithmOid,
        ReadOnlyMemory<byte> signatureValue)
    {
        Encoded = encoded;
        TbsCertificateDer = tbsCertificateDer;
        IssuerDer = issuerDer;
        SerialNumber = serialNumber;
        SubjectDer = subjectDer;
        NotBefore = notBefore;
        NotAfter = notAfter;
        EllipticCurve = ellipticCurve;
        PublicPoint = publicPoint;
        RsaModulus = rsaModulus;
        RsaExponent = rsaExponent;
        SubjectPublicKeyBitStringContent = subjectPublicKeyBitStringContent;
        SubjectKeyIdentifier = subjectKeyIdentifier;
        ExtendedKeyUsageOids = extendedKeyUsageOids;
        SignatureAlgorithmOid = signatureAlgorithmOid;
        SignatureValue = signatureValue;
    }


    /// <summary>Gets the full DER encoding of the certificate.</summary>
    public ReadOnlyMemory<byte> Encoded { get; }

    /// <summary>Gets the raw DER encoding of the <c>tbsCertificate</c> (tag and length included), for verifying this certificate's own signature.</summary>
    public ReadOnlyMemory<byte> TbsCertificateDer { get; }

    /// <summary>Gets the issuer distinguished name as raw DER (for issuer-and-serial-number matching, and for matching a candidate issuer's subject).</summary>
    public ReadOnlyMemory<byte> IssuerDer { get; }

    /// <summary>Gets the certificate serial number as its DER INTEGER content bytes.</summary>
    public ReadOnlyMemory<byte> SerialNumber { get; }

    /// <summary>Gets the subject distinguished name as raw DER (RFC 5280 §4.1.2.4), tag and length included.</summary>
    public ReadOnlyMemory<byte> SubjectDer { get; }

    /// <summary>Gets the <c>notBefore</c> validity instant (RFC 5280 §4.1.2.5).</summary>
    public DateTimeOffset NotBefore { get; }

    /// <summary>Gets the <c>notAfter</c> validity instant (RFC 5280 §4.1.2.5).</summary>
    public DateTimeOffset NotAfter { get; }

    /// <summary>Gets the elliptic curve of the subject public key, or <see cref="EllipticCurveTypes.None"/> when the key is not a recognised elliptic-curve key.</summary>
    public EllipticCurveTypes EllipticCurve { get; }

    /// <summary>Gets the subject public key as an uncompressed SEC1 point (<c>0x04 || X || Y</c>); empty when the key is not elliptic-curve.</summary>
    public ReadOnlyMemory<byte> PublicPoint { get; }

    /// <summary>Gets the RSA public modulus as unsigned big-endian bytes; empty when the key is not RSA.</summary>
    public ReadOnlyMemory<byte> RsaModulus { get; }

    /// <summary>Gets the RSA public exponent as unsigned big-endian bytes; empty when the key is not RSA.</summary>
    public ReadOnlyMemory<byte> RsaExponent { get; }

    /// <summary>
    /// Gets the <c>subjectPublicKey</c> BIT STRING content bytes exactly as encoded — excluding the BIT
    /// STRING tag, length, and unused-bits count octet — regardless of the key algorithm. This is the input
    /// an RFC 6960 §4.2.1 <c>KeyHash</c> (SHA-1 over the responder public key) is computed from, independent
    /// of whether <see cref="PublicPoint"/> or <see cref="RsaModulus"/>/<see cref="RsaExponent"/> apply.
    /// </summary>
    public ReadOnlyMemory<byte> SubjectPublicKeyBitStringContent { get; }

    /// <summary>Gets the subject key identifier from the certificate extension; empty when absent.</summary>
    public ReadOnlyMemory<byte> SubjectKeyIdentifier { get; }

    /// <summary>Gets the ExtendedKeyUsage key purpose identifiers (RFC 5280 §4.2.1.12), in certificate order; empty when the extension is absent.</summary>
    public IReadOnlyList<string> ExtendedKeyUsageOids { get; }

    /// <summary>Gets the certificate's own <c>signatureAlgorithm</c> object identifier (RFC 5280 §4.1.1.2).</summary>
    public string SignatureAlgorithmOid { get; }

    /// <summary>Gets the certificate's own <c>signatureValue</c> BIT STRING content bytes (RFC 5280 §4.1.1.3).</summary>
    public ReadOnlyMemory<byte> SignatureValue { get; }


    /// <summary>
    /// Parses the fields the managed CMS and OCSP verifiers need from an encoded certificate.
    /// </summary>
    /// <param name="encoded">The DER-encoded certificate.</param>
    /// <returns>The parsed certificate.</returns>
    public static ManagedCertificate Parse(ReadOnlyMemory<byte> encoded)
    {
        var certificateReader = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader certificateSequence = certificateReader.ReadSequence();
        certificateReader.ThrowIfNotEmpty();

        //The exact tbsCertificate bytes (tag and length included) are captured before descending, so a
        //candidate issuer's key can later verify this certificate's own signature over them.
        ReadOnlyMemory<byte> tbsCertificateDer = certificateSequence.ReadEncodedValue();
        AsnReader tbs = new AsnReader(tbsCertificateDer, AsnEncodingRules.DER).ReadSequence();

        //version [0] EXPLICIT INTEGER DEFAULT v1, present in practically every certificate.
        if(tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            _ = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        ReadOnlyMemory<byte> serialNumber = tbs.ReadIntegerBytes();
        _ = tbs.ReadSequence();                                        //signature AlgorithmIdentifier
        ReadOnlyMemory<byte> issuer = tbs.ReadEncodedValue();          //issuer Name (raw DER)
        AsnReader validity = tbs.ReadSequence();
        DateTimeOffset notBefore = ReadTime(validity);
        DateTimeOffset notAfter = ReadTime(validity);
        validity.ThrowIfNotEmpty();
        ReadOnlyMemory<byte> subject = tbs.ReadEncodedValue();         //subject Name (raw DER)

        ParsedPublicKey publicKey = ParseSubjectPublicKeyInfo(tbs.ReadSequence());

        (ReadOnlyMemory<byte> subjectKeyIdentifier, IReadOnlyList<string> extendedKeyUsageOids) = ParseExtensions(tbs);
        tbs.ThrowIfNotEmpty();

        AsnReader signatureAlgorithm = certificateSequence.ReadSequence();
        string signatureAlgorithmOid = signatureAlgorithm.ReadObjectIdentifier();
        if(!certificateSequence.TryReadPrimitiveBitString(out _, out ReadOnlyMemory<byte> signatureValue))
        {
            throw new AsnContentException("A Certificate must close with its signatureValue BIT STRING (RFC 5280 §4.1.1).");
        }

        certificateSequence.ThrowIfNotEmpty();

        return new ManagedCertificate(
            encoded, tbsCertificateDer, issuer, serialNumber, subject, notBefore, notAfter,
            publicKey.Curve, publicKey.Point, publicKey.RsaModulus, publicKey.RsaExponent, publicKey.RawBitStringContent,
            subjectKeyIdentifier, extendedKeyUsageOids, signatureAlgorithmOid, signatureValue);
    }


    /// <summary>
    /// Reads a <c>Validity</c> time (RFC 5280 §4.1.2.5): a <c>UTCTime</c> for dates through 2049, or a
    /// <c>GeneralizedTime</c> from 2050 on.
    /// </summary>
    private static DateTimeOffset ReadTime(AsnReader validity)
    {
        Asn1Tag tag = validity.PeekTag();
        if(tag.TagClass != TagClass.Universal)
        {
            throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5).");
        }

        return (UniversalTagNumber)tag.TagValue switch
        {
            UniversalTagNumber.UtcTime => validity.ReadUtcTime(),
            UniversalTagNumber.GeneralizedTime => validity.ReadGeneralizedTime(),
            _ => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5).")
        };
    }


    /// <summary>
    /// Parses the subject public key info: for an elliptic-curve key, the curve and the uncompressed public
    /// point; for an RSA key, the modulus and exponent; the raw BIT STRING content is captured regardless of
    /// the key algorithm.
    /// </summary>
    private static ParsedPublicKey ParseSubjectPublicKeyInfo(AsnReader subjectPublicKeyInfo)
    {
        AsnReader algorithm = subjectPublicKeyInfo.ReadSequence();
        string algorithmOid = algorithm.ReadObjectIdentifier();

        if(string.Equals(algorithmOid, EcPublicKeyOid, StringComparison.Ordinal))
        {
            string curveOid = algorithm.ReadObjectIdentifier();
            byte[] point = subjectPublicKeyInfo.ReadBitString(out _);

            return new ParsedPublicKey(CurveFromOid(curveOid), point, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, point);
        }

        if(string.Equals(algorithmOid, RsaEncryptionOid, StringComparison.Ordinal))
        {
            //The subjectPublicKey BIT STRING wraps RSAPublicKey ::= SEQUENCE { modulus, publicExponent }.
            byte[] rsaPublicKey = subjectPublicKeyInfo.ReadBitString(out _);
            var rsa = new AsnReader(rsaPublicKey, AsnEncodingRules.DER).ReadSequence();
            ReadOnlyMemory<byte> modulus = StripLeadingZero(rsa.ReadIntegerBytes());
            ReadOnlyMemory<byte> exponent = StripLeadingZero(rsa.ReadIntegerBytes());

            return new ParsedPublicKey(EllipticCurveTypes.None, ReadOnlyMemory<byte>.Empty, modulus, exponent, rsaPublicKey);
        }

        byte[] unrecognisedKeyBits = subjectPublicKeyInfo.ReadBitString(out _);

        return new ParsedPublicKey(EllipticCurveTypes.None, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, unrecognisedKeyBits);
    }


    /// <summary>
    /// Strips a single leading <c>0x00</c> sign octet from a DER INTEGER's two's-complement encoding.
    /// </summary>
    private static ReadOnlyMemory<byte> StripLeadingZero(ReadOnlyMemory<byte> integer) =>
        integer.Length > 1 && integer.Span[0] == 0x00 ? integer[1..] : integer;


    /// <summary>
    /// Walks the optional unique identifiers and the extensions to the subject-key-identifier (RFC 5280
    /// §4.2.1.2) and ExtendedKeyUsage (RFC 5280 §4.2.1.12) extensions, reading the first occurrence of each.
    /// </summary>
    private static (ReadOnlyMemory<byte> SubjectKeyIdentifier, IReadOnlyList<string> ExtendedKeyUsageOids) ParseExtensions(AsnReader tbs)
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

        ReadOnlyMemory<byte> subjectKeyIdentifier = ReadOnlyMemory<byte>.Empty;
        bool subjectKeyIdentifierSeen = false;
        List<string>? extendedKeyUsageOids = null;

        if(tbs.HasData && tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true))
        {
            AsnReader extensionsWrapper = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            AsnReader extensions = extensionsWrapper.ReadSequence();
            while(extensions.HasData)
            {
                AsnReader extension = extensions.ReadSequence();
                string extensionId = extension.ReadObjectIdentifier();
                if(extension.PeekTag() == new Asn1Tag(UniversalTagNumber.Boolean))
                {
                    _ = extension.ReadBoolean();
                }

                byte[] extensionValue = extension.ReadOctetString();
                if(string.Equals(extensionId, SubjectKeyIdentifierOid, StringComparison.Ordinal) && !subjectKeyIdentifierSeen)
                {
                    //The extension value wraps a KeyIdentifier ::= OCTET STRING. A bool sentinel (not an
                    //emptiness check on subjectKeyIdentifier) marks "first occurrence read" — a legal DER
                    //KeyIdentifier can itself be zero-length, and an emptiness check would then let a second,
                    //attacker-controlled occurrence silently override it.
                    subjectKeyIdentifierSeen = true;
                    subjectKeyIdentifier = new AsnReader(extensionValue, AsnEncodingRules.DER).ReadOctetString();
                }
                else if(string.Equals(extensionId, WellKnownOids.ExtendedKeyUsageExtension, StringComparison.Ordinal) && extendedKeyUsageOids is null)
                {
                    extendedKeyUsageOids = [];
                    AsnReader keyPurposes = new AsnReader(extensionValue, AsnEncodingRules.DER).ReadSequence();
                    while(keyPurposes.HasData)
                    {
                        extendedKeyUsageOids.Add(keyPurposes.ReadObjectIdentifier());
                    }
                }

                extension.ThrowIfNotEmpty();
            }

            extensionsWrapper.ThrowIfNotEmpty();
        }

        return (subjectKeyIdentifier, extendedKeyUsageOids ?? []);
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


    /// <summary>A parsed subject public key: an elliptic-curve point, or RSA modulus and exponent, plus the raw BIT STRING content.</summary>
    private readonly record struct ParsedPublicKey(
        EllipticCurveTypes Curve,
        ReadOnlyMemory<byte> Point,
        ReadOnlyMemory<byte> RsaModulus,
        ReadOnlyMemory<byte> RsaExponent,
        ReadOnlyMemory<byte> RawBitStringContent);
}
