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
    private const string RsaEncryptionOid = WellKnownOids.RsaEncryption;

    /// <summary>The subject key identifier extension (RFC 5280 §4.2.1.2).</summary>
    private const string SubjectKeyIdentifierOid = WellKnownOids.SubjectKeyIdentifierExtension;

    /// <summary>The octet length of an Ed25519 public key (RFC 8032 section 5.1.5).</summary>
    private const int Ed25519PublicKeyOctetCount = 32;


    /// <summary>Creates the parse of a certificate from the fields <see cref="Parse"/> read.</summary>
    /// <param name="encoded">The full DER encoding.</param>
    /// <param name="tbsCertificateDer">The raw DER encoding of the <c>tbsCertificate</c>.</param>
    /// <param name="issuerDer">The issuer name as raw DER.</param>
    /// <param name="serialNumber">The serial number's INTEGER content bytes.</param>
    /// <param name="subjectDer">The subject name as raw DER.</param>
    /// <param name="notBefore">The <c>notBefore</c> instant.</param>
    /// <param name="notAfter">The <c>notAfter</c> instant.</param>
    /// <param name="subjectPublicKeyAlgorithmOid">The subject public key's algorithm identifier.</param>
    /// <param name="ellipticCurve">The elliptic curve of the subject public key, or none.</param>
    /// <param name="publicPoint">The SEC1 point of an elliptic-curve key as encoded, or empty.</param>
    /// <param name="rsaModulus">The modulus of an RSA key, or empty.</param>
    /// <param name="rsaExponent">The public exponent of an RSA key, or empty.</param>
    /// <param name="mlDsaAlgorithmOid">The ML-DSA parameter-set identifier, or the empty string.</param>
    /// <param name="mlDsaPublicKey">The raw ML-DSA public key, or empty.</param>
    /// <param name="subjectPublicKeyBitStringContent">The <c>subjectPublicKey</c> BIT STRING content bytes.</param>
    /// <param name="subjectKeyIdentifier">The subject key identifier, or empty.</param>
    /// <param name="extendedKeyUsageOids">The ExtendedKeyUsage key purpose identifiers.</param>
    /// <param name="signatureAlgorithmOid">The certificate's own signature algorithm identifier.</param>
    /// <param name="signatureValue">The certificate's own signature value.</param>
    private ManagedCertificate(
        ReadOnlyMemory<byte> encoded,
        ReadOnlyMemory<byte> tbsCertificateDer,
        ReadOnlyMemory<byte> issuerDer,
        ReadOnlyMemory<byte> serialNumber,
        ReadOnlyMemory<byte> subjectDer,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        string subjectPublicKeyAlgorithmOid,
        EllipticCurveTypes ellipticCurve,
        ReadOnlyMemory<byte> publicPoint,
        ReadOnlyMemory<byte> rsaModulus,
        ReadOnlyMemory<byte> rsaExponent,
        string mlDsaAlgorithmOid,
        ReadOnlyMemory<byte> mlDsaPublicKey,
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
        SubjectPublicKeyAlgorithmOid = subjectPublicKeyAlgorithmOid;
        EllipticCurve = ellipticCurve;
        PublicPoint = publicPoint;
        RsaModulus = rsaModulus;
        RsaExponent = rsaExponent;
        MlDsaAlgorithmOid = mlDsaAlgorithmOid;
        MlDsaPublicKey = mlDsaPublicKey;
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

    /// <summary>
    /// Gets the object identifier of the subject public key's algorithm (RFC 5280 §4.1.2.7, the <c>SubjectPublicKeyInfo</c>'s
    /// <c>AlgorithmIdentifier</c>), whatever the key algorithm, recognised by this parse or not.
    /// </summary>
    public string SubjectPublicKeyAlgorithmOid { get; }

    /// <summary>Gets the elliptic curve of the subject public key, or <see cref="EllipticCurveTypes.None"/> when the key is not a recognised elliptic-curve key.</summary>
    public EllipticCurveTypes EllipticCurve { get; }

    /// <summary>
    /// Gets the subject public key as the SEC1 point the certificate encodes it as (SEC 1 section 2.3.3): uncompressed
    /// (<c>0x04 || X || Y</c>) or compressed (<c>0x02</c> or <c>0x03 || X</c>), each coordinate the full width of the curve's
    /// coordinate and the point one of the curve, for a key on a curve this parse recognises; as encoded for a key on another
    /// curve; empty when the key is not elliptic-curve.
    /// </summary>
    public ReadOnlyMemory<byte> PublicPoint { get; }

    /// <summary>Gets the RSA public modulus as unsigned big-endian bytes; empty when the key is not RSA.</summary>
    public ReadOnlyMemory<byte> RsaModulus { get; }

    /// <summary>Gets the RSA public exponent as unsigned big-endian bytes; empty when the key is not RSA.</summary>
    public ReadOnlyMemory<byte> RsaExponent { get; }

    /// <summary>
    /// Gets the ML-DSA parameter-set object identifier the <c>SubjectPublicKeyInfo</c> names
    /// (<see cref="WellKnownOids.MlDsa44"/>, <see cref="WellKnownOids.MlDsa65"/> or
    /// <see cref="WellKnownOids.MlDsa87"/>), or the empty string when the key is not ML-DSA. In X.509 the one
    /// identifier binds the key to its parameter set, so a signature stated under a different set is a
    /// substitution rather than a variant.
    /// </summary>
    public string MlDsaAlgorithmOid { get; }

    /// <summary>Gets the raw ML-DSA public key bytes (FIPS 204 encoding, the <c>subjectPublicKey</c> BIT STRING content); empty when the key is not ML-DSA.</summary>
    public ReadOnlyMemory<byte> MlDsaPublicKey { get; }

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
    /// Gets the size in bits of the subject public key — the RSA modulus length, or the named curve's field
    /// size — or <see langword="null"/> when the key algorithm is not one this parse recognises. This is the
    /// "size of the key, if applicable, used with that algorithm" a cryptographic constraint is stated about
    /// (ETSI EN 319 102-1 V1.4.1 clause 5.1.4.3).
    /// </summary>
    public int? SubjectPublicKeySizeBits => RsaModulus.IsEmpty
        ? EllipticCurve switch
        {
            EllipticCurveTypes.P256 => 256,
            EllipticCurveTypes.P384 => 384,
            EllipticCurveTypes.P521 => 521,
            EllipticCurveTypes.Secp256k1 => 256,
            EllipticCurveTypes.BrainpoolP224r1 => 224,
            EllipticCurveTypes.BrainpoolP256r1 => 256,
            EllipticCurveTypes.BrainpoolP320r1 => 320,
            EllipticCurveTypes.BrainpoolP384r1 => 384,
            EllipticCurveTypes.BrainpoolP512r1 => 512,
            EllipticCurveTypes.None => null,
            EllipticCurveTypes.Curve25519 => null,
            EllipticCurveTypes.NistCurves => null,
            EllipticCurveTypes.BrainpoolCurves => null,
            _ => null
        }
        : RsaModulus.Length * 8;


    /// <summary>
    /// Parses the fields the managed CMS and OCSP verifiers need from an encoded certificate, rejecting shapes
    /// RFC 5280 section 4.1 does not admit for every field this parse walks (no new field is extracted by these
    /// checks — they only tighten fields already read): a present <c>[0]</c> EXPLICIT version wrapper must contain
    /// exactly one INTEGER valued 0, 1, or 2 (§4.1.2.1); each <c>AlgorithmIdentifier</c> is an OBJECT IDENTIFIER
    /// followed by at most one parameters value (§4.1.1.2), and the outer <c>signatureAlgorithm</c> is the very
    /// <c>tbsCertificate.signature</c> (§4.1.1.2: "MUST contain the same algorithm identifier"); the issuer and
    /// subject <c>Name</c> fields are each an <c>RDNSequence</c> of non-empty <c>SET OF AttributeTypeAndValue</c>, each
    /// an OBJECT IDENTIFIER and one value (§4.1.2.4), the issuer's non-empty ("The issuer field MUST contain a non-empty
    /// distinguished name (DN)") and the subject's possibly empty (§4.1.2.6); the optional <c>issuerUniqueID</c> and
    /// <c>subjectUniqueID</c> are each the primitive, implicitly tagged BIT STRING a <c>UniqueIdentifier</c> is (§4.1,
    /// §4.1.2.8); and the <c>SubjectPublicKeyInfo</c> is exactly an
    /// <c>AlgorithmIdentifier</c> and a BIT STRING (§4.1.2.7), with no field after them, its parameters those of its
    /// algorithm: a named curve for an elliptic-curve key (RFC 5480 section 2.1.1), <c>NULL</c> for an RSA key (RFC 3279
    /// section 2.3.1), absent for an Ed25519 key (RFC 8410 section 3: "the parameters MUST be absent") and for an ML-DSA
    /// key, and the key's BIT STRING whole octets for each of those: an elliptic-curve key on a curve this parse recognises an
    /// uncompressed or compressed SEC1 point of the curve's coordinate width naming a point of the curve (SEC 1 section 2.3.4,
    /// RFC 5480 section 2.2), an ML-DSA key the length its parameter set has (FIPS 204 table 2: 1,312, 1,952 and 2,592 octets).
    /// </summary>
    /// <param name="encoded">The DER-encoded certificate.</param>
    /// <returns>The parsed certificate.</returns>
    /// <exception cref="AsnContentException">The encoding is no DER certificate of the shape RFC 5280 section 4.1 admits.</exception>
    public static ManagedCertificate Parse(ReadOnlyMemory<byte> encoded)
    {
        var certificateReader = new AsnReader(encoded, AsnEncodingRules.DER);
        AsnReader certificateSequence = certificateReader.ReadSequence();
        certificateReader.ThrowIfNotEmpty();

        //The exact tbsCertificate bytes (tag and length included) are captured before descending, so a
        //candidate issuer's key can later verify this certificate's own signature over them.
        ReadOnlyMemory<byte> tbsCertificateDer = certificateSequence.ReadEncodedValue();
        AsnReader tbs = new AsnReader(tbsCertificateDer, AsnEncodingRules.DER).ReadSequence();

        //version [0] EXPLICIT INTEGER DEFAULT v1, present in practically every certificate; when present, its
        //content is exactly one INTEGER valued 0 (v1), 1 (v2), or 2 (v3) (RFC 5280 §4.1.2.1).
        if(tbs.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
        {
            AsnReader version = tbs.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            if(!version.TryReadInt32(out int versionNumber) || versionNumber is < 0 or > 2)
            {
                throw new AsnContentException("The [0] EXPLICIT version wrapper contains a single INTEGER valued 0 (v1), 1 (v2), or 2 (v3) (RFC 5280 §4.1.2.1).");
            }

            version.ThrowIfNotEmpty();
        }

        ReadOnlyMemory<byte> serialNumber = tbs.ReadIntegerBytes();

        //signature AlgorithmIdentifier (RFC 5280 §4.1.2.3), its encoding kept for the outer signatureAlgorithm to equal.
        var tbsSignatureAlgorithm = tbs.ReadEncodedValue();
        _ = ReadAlgorithmIdentifier(new AsnReader(tbsSignatureAlgorithm, AsnEncodingRules.DER));
        ReadOnlyMemory<byte> issuer = ReadNameOrThrow(tbs);            //issuer Name (raw DER, RFC 5280 §4.1.2.4)

        //RFC 5280 §4.1.2.4: "The issuer field MUST contain a non-empty distinguished name (DN)." An empty subject is permitted
        //(§4.1.2.6), so the emptiness is judged for the issuer alone.
        if(!new AsnReader(issuer, AsnEncodingRules.DER).ReadSequence().HasData)
        {
            throw new AsnContentException("The issuer field contains a non-empty distinguished name (RFC 5280 §4.1.2.4).");
        }

        AsnReader validity = tbs.ReadSequence();
        DateTimeOffset notBefore = ReadTime(validity);
        DateTimeOffset notAfter = ReadTime(validity);
        validity.ThrowIfNotEmpty();
        ReadOnlyMemory<byte> subject = ReadNameOrThrow(tbs);           //subject Name (raw DER, RFC 5280 §4.1.2.4)

        ParsedPublicKey publicKey = ParseSubjectPublicKeyInfo(tbs.ReadSequence());

        var extensions = ParseExtensions(tbs);
        tbs.ThrowIfNotEmpty();

        //RFC 5280 §4.1.1.2: "This field MUST contain the same algorithm identifier as the signature field in the sequence
        //tbsCertificate", compared as the DER encodings they are.
        var signatureAlgorithm = certificateSequence.ReadEncodedValue();
        if(!signatureAlgorithm.Span.SequenceEqual(tbsSignatureAlgorithm.Span))
        {
            throw new AsnContentException("The signatureAlgorithm is the tbsCertificate's signature algorithm identifier (RFC 5280 §4.1.1.2).");
        }

        var signatureAlgorithmOid = ReadAlgorithmIdentifier(new AsnReader(signatureAlgorithm, AsnEncodingRules.DER));
        if(!certificateSequence.TryReadPrimitiveBitString(out _, out ReadOnlyMemory<byte> signatureValue))
        {
            throw new AsnContentException("A Certificate must close with its signatureValue BIT STRING (RFC 5280 §4.1.1).");
        }

        certificateSequence.ThrowIfNotEmpty();

        return new ManagedCertificate(
            encoded, tbsCertificateDer, issuer, serialNumber, subject, notBefore, notAfter,
            publicKey.AlgorithmOid, publicKey.Curve, publicKey.Point, publicKey.RsaModulus, publicKey.RsaExponent,
            publicKey.MlDsaAlgorithmOid, publicKey.MlDsaPublicKey, publicKey.RawBitStringContent,
            extensions.SubjectKeyIdentifier, extensions.ExtendedKeyUsageOids, signatureAlgorithmOid, signatureValue);
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
            UniversalTagNumber.EndOfContents => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Boolean => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Integer => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.BitString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.OctetString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Null => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.ObjectIdentifier => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.ObjectDescriptor => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.External => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Real => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Enumerated => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Embedded => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.UTF8String => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.RelativeObjectIdentifier => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Time => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Sequence => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Set => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.NumericString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.PrintableString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.TeletexString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.VideotexString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.IA5String => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.GraphicString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.VisibleString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.GeneralString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.UniversalString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.UnrestrictedCharacterString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.BMPString => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Date => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.TimeOfDay => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.DateTime => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.Duration => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.ObjectIdentifierIRI => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            UniversalTagNumber.RelativeObjectIdentifierIRI => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5)."),
            _ => throw new AsnContentException("A Validity time must be a UTCTime or a GeneralizedTime (RFC 5280 §4.1.2.5).")
        };
    }


    /// <summary>
    /// Reads an RFC 5280 §4.1.2.4 <c>Name</c> as its raw encoded DER, having walked it whole: an <c>RDNSequence</c>, a
    /// SEQUENCE OF <c>RelativeDistinguishedName</c>, each a non-empty <c>SET OF AttributeTypeAndValue</c> in DER order, each
    /// a SEQUENCE of an attribute type OBJECT IDENTIFIER and exactly one value, rejecting any other shape.
    /// </summary>
    /// <param name="tbs">The reader positioned at the <c>Name</c> field.</param>
    /// <returns>The <c>Name</c>'s raw DER encoding (tag and length included).</returns>
    private static ReadOnlyMemory<byte> ReadNameOrThrow(AsnReader tbs)
    {
        if(tbs.PeekTag() != Asn1Tag.Sequence)
        {
            throw new AsnContentException("A Name is an RDNSequence, encoded as a SEQUENCE (RFC 5280 §4.1.2.4).");
        }

        var name = tbs.ReadEncodedValue();
        var relativeDistinguishedNames = new AsnReader(name, AsnEncodingRules.DER).ReadSequence();

        while(relativeDistinguishedNames.HasData)
        {
            var attributes = relativeDistinguishedNames.ReadSetOf();

            if(!attributes.HasData)
            {
                throw new AsnContentException("A RelativeDistinguishedName is a SET SIZE (1..MAX) OF AttributeTypeAndValue (RFC 5280 §4.1.2.4).");
            }

            while(attributes.HasData)
            {
                var attribute = attributes.ReadSequence();
                _ = attribute.ReadObjectIdentifier();
                _ = attribute.ReadEncodedValue();
                attribute.ThrowIfNotEmpty();
            }
        }

        return name;
    }


    /// <summary>
    /// Reads an <c>AlgorithmIdentifier</c> (RFC 5280 §4.1.1.2: <c>SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY
    /// DEFINED BY algorithm OPTIONAL }</c>) whose parameters this parse does not interpret: the identifier, then at most one
    /// parameters value, and nothing after it.
    /// </summary>
    /// <param name="reader">The reader positioned at the <c>AlgorithmIdentifier</c>.</param>
    /// <returns>The algorithm's object identifier.</returns>
    private static string ReadAlgorithmIdentifier(AsnReader reader)
    {
        var algorithm = reader.ReadSequence();
        reader.ThrowIfNotEmpty();
        var algorithmOid = algorithm.ReadObjectIdentifier();

        if(algorithm.HasData)
        {
            _ = algorithm.ReadEncodedValue();
        }

        algorithm.ThrowIfNotEmpty();

        return algorithmOid;
    }


    /// <summary>
    /// Reads a subject public key's BIT STRING as the whole octets its key algorithm's encoding is, refusing one with unused
    /// bits.
    /// </summary>
    /// <param name="subjectPublicKeyInfo">The reader positioned at the <c>subjectPublicKey</c>.</param>
    /// <returns>The key's octets.</returns>
    private static byte[] ReadWholeOctetKey(AsnReader subjectPublicKeyInfo)
    {
        var key = subjectPublicKeyInfo.ReadBitString(out var unusedBitCount);

        if(unusedBitCount != 0)
        {
            throw new AsnContentException("A subject public key of this algorithm is whole octets: its BIT STRING carries no unused bits.");
        }

        return key;
    }


    /// <summary>
    /// Parses the subject public key info (RFC 5280 §4.1.2.7), exactly an <c>AlgorithmIdentifier</c> and the
    /// <c>subjectPublicKey</c> BIT STRING, with no field after them: for an elliptic-curve key, the named curve
    /// (RFC 5480 section 2.1.1) and the public point; for an RSA key, <c>NULL</c> parameters (RFC 3279 section 2.3.1) and the
    /// modulus and exponent; for an Ed25519 key, absent parameters (RFC 8410 section 3) and the 32-octet key; for an ML-DSA key,
    /// absent parameters and the raw key; for another algorithm, at most one parameters value this parse does not interpret.
    /// The raw BIT STRING content is captured regardless of the key algorithm.
    /// </summary>
    /// <param name="subjectPublicKeyInfo">The reader of the <c>SubjectPublicKeyInfo</c> SEQUENCE's content.</param>
    /// <returns>The parsed key.</returns>
    private static ParsedPublicKey ParseSubjectPublicKeyInfo(AsnReader subjectPublicKeyInfo)
    {
        AsnReader algorithm = subjectPublicKeyInfo.ReadSequence();
        string algorithmOid = algorithm.ReadObjectIdentifier();
        ParsedPublicKey parsed;

        if(string.Equals(algorithmOid, EcPublicKeyOid, StringComparison.Ordinal))
        {
            string curveOid = algorithm.ReadObjectIdentifier();
            algorithm.ThrowIfNotEmpty();
            var point = ReadWholeOctetKey(subjectPublicKeyInfo);
            var curve = CurveFromOid(curveOid);

            if(curve != EllipticCurveTypes.None && !IsPointOfTheCurve(point, curve))
            {
                throw new AsnContentException(
                    "An elliptic-curve subject public key is an uncompressed or compressed SEC1 point of the curve's coordinate width naming a point of the curve (SEC 1 section 2.3.4, RFC 5480 section 2.2).");
            }

            parsed = new ParsedPublicKey(algorithmOid, curve, point, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, string.Empty, ReadOnlyMemory<byte>.Empty, point);
        }
        else if(string.Equals(algorithmOid, RsaEncryptionOid, StringComparison.Ordinal))
        {
            algorithm.ReadNull();
            algorithm.ThrowIfNotEmpty();

            //The subjectPublicKey BIT STRING wraps RSAPublicKey ::= SEQUENCE { modulus, publicExponent }.
            var rsaPublicKey = ReadWholeOctetKey(subjectPublicKeyInfo);
            (byte[] modulus, byte[] exponent) = RsaPublicKeyEncoding.Decode(rsaPublicKey);

            parsed = new ParsedPublicKey(algorithmOid, EllipticCurveTypes.None, ReadOnlyMemory<byte>.Empty, modulus, exponent, string.Empty, ReadOnlyMemory<byte>.Empty, rsaPublicKey);
        }
        else if(string.Equals(algorithmOid, WellKnownOids.EdDSA25519, StringComparison.Ordinal))
        {
            //RFC 8410 section 3: "For all of the OIDs, the parameters MUST be absent." Section 4: the key is the 32-octet
            //encoding of RFC 8032.
            algorithm.ThrowIfNotEmpty();
            var ed25519PublicKey = ReadWholeOctetKey(subjectPublicKeyInfo);

            if(ed25519PublicKey.Length != Ed25519PublicKeyOctetCount)
            {
                throw new AsnContentException("An Ed25519 subject public key is 32 octets (RFC 8410 section 4, RFC 8032 section 5.1.5).");
            }

            parsed = new ParsedPublicKey(algorithmOid, EllipticCurveTypes.None, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, string.Empty, ReadOnlyMemory<byte>.Empty, ed25519PublicKey);
        }
        else if(IsMlDsaOid(algorithmOid))
        {
            //An ML-DSA SubjectPublicKeyInfo carries the raw FIPS 204 public key directly in the BIT STRING,
            //with absent AlgorithmIdentifier parameters; the identifier itself pins the parameter set.
            algorithm.ThrowIfNotEmpty();
            var mlDsaPublicKey = ReadWholeOctetKey(subjectPublicKeyInfo);

            if(mlDsaPublicKey.Length != MlDsaPublicKeyOctetCount(algorithmOid))
            {
                throw new AsnContentException("An ML-DSA subject public key is the length its parameter set has: 1,312, 1,952 or 2,592 octets (FIPS 204 table 2).");
            }

            parsed = new ParsedPublicKey(algorithmOid, EllipticCurveTypes.None, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, algorithmOid, mlDsaPublicKey, mlDsaPublicKey);
        }
        else
        {
            if(algorithm.HasData)
            {
                _ = algorithm.ReadEncodedValue();
            }

            algorithm.ThrowIfNotEmpty();
            var unrecognisedKeyBits = subjectPublicKeyInfo.ReadBitString(out _);

            parsed = new ParsedPublicKey(algorithmOid, EllipticCurveTypes.None, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, string.Empty, ReadOnlyMemory<byte>.Empty, unrecognisedKeyBits);
        }

        //RFC 5280 §4.1.2.7: SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }.
        subjectPublicKeyInfo.ThrowIfNotEmpty();

        return parsed;
    }


    /// <summary>Reports whether an object identifier names one of the three ML-DSA parameter sets.</summary>
    /// <param name="algorithmOid">The dotted-decimal identifier to classify.</param>
    /// <returns><see langword="true"/> when it is an ML-DSA identifier.</returns>
    private static bool IsMlDsaOid(string algorithmOid) =>
        string.Equals(algorithmOid, WellKnownOids.MlDsa44, StringComparison.Ordinal)
        || string.Equals(algorithmOid, WellKnownOids.MlDsa65, StringComparison.Ordinal)
        || string.Equals(algorithmOid, WellKnownOids.MlDsa87, StringComparison.Ordinal);


    /// <summary>
    /// Walks the optional unique identifiers and the extensions to the subject-key-identifier (RFC 5280
    /// §4.2.1.2) and ExtendedKeyUsage (RFC 5280 §4.2.1.12) extensions, reading the first occurrence of each.
    /// </summary>
    /// <param name="tbs">The reader of the <c>tbsCertificate</c>, positioned after the <c>SubjectPublicKeyInfo</c>.</param>
    /// <returns>The subject key identifier and the extended key usage purposes.</returns>
    private static ParsedExtensions ParseExtensions(AsnReader tbs)
    {
        //issuerUniqueID [1] IMPLICIT UniqueIdentifier OPTIONAL and subjectUniqueID [2] IMPLICIT UniqueIdentifier OPTIONAL, with
        //UniqueIdentifier ::= BIT STRING (RFC 5280 §4.1): each present one is read whole as the BIT STRING it is.
        ReadUniqueIdentifier(tbs, 1);
        ReadUniqueIdentifier(tbs, 2);

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

        return new ParsedExtensions(subjectKeyIdentifier, extendedKeyUsageOids ?? []);
    }


    /// <summary>
    /// Reads an optional unique identifier of the context-specific tag number given (RFC 5280 §4.1: <c>[1] IMPLICIT
    /// UniqueIdentifier</c> for the issuer, <c>[2]</c> for the subject), a <c>UniqueIdentifier</c> being a BIT STRING, so the
    /// field is a primitive BIT STRING under the implicit tag, its unused-bits octet and content judged as DER has them; a
    /// constructed field of the tag is refused. Nothing is read when the next field carries another tag.
    /// </summary>
    /// <param name="tbs">The reader of the <c>tbsCertificate</c>.</param>
    /// <param name="tagNumber">The context-specific tag number of the identifier.</param>
    private static void ReadUniqueIdentifier(AsnReader tbs, int tagNumber)
    {
        if(!tbs.HasData || tbs.PeekTag() is not { TagClass: TagClass.ContextSpecific } tag || tag.TagValue != tagNumber)
        {
            return;
        }

        if(tag.IsConstructed)
        {
            throw new AsnContentException("A unique identifier is a primitive, implicitly tagged BIT STRING (RFC 5280 §4.1).");
        }

        _ = tbs.ReadBitString(out _, new Asn1Tag(TagClass.ContextSpecific, tagNumber));
    }


    /// <summary>
    /// Whether a SEC1 point (SEC 1 section 2.3.4) is a point of the curve: uncompressed, <c>0x04</c> and two coordinates of the
    /// curve's width naming a point of it, or compressed, <c>0x02</c> or <c>0x03</c> and an x of the curve's width from which the
    /// curve's equation recovers a y naming a point of it (NIST SP 800-186 appendix D.1.1.1).
    /// </summary>
    /// <param name="point">The point as encoded.</param>
    /// <param name="curve">The curve, one this parse recognises.</param>
    /// <returns><see langword="true"/> for a point of the curve.</returns>
    private static bool IsPointOfTheCurve(ReadOnlySpan<byte> point, EllipticCurveTypes curve)
    {
        var width = CoordinateOctetCount(curve);

        if(point.Length == 1 + (2 * width) && point[0] == EllipticCurveUtilities.UncompressedCoordinateFormat)
        {
            return EllipticCurveUtilities.CheckPointOnCurve(point.Slice(1, width), point[(1 + width)..], curve);
        }

        return point.Length == 1 + width
            && (point[0] == EllipticCurveUtilities.EvenYCoordinate || point[0] == EllipticCurveUtilities.OddYCoordinate)
            && EllipticCurveUtilities.CheckPointOnCurve(point[1..], EllipticCurveUtilities.Decompress(point, curve), curve);
    }


    /// <summary>The octet width of a coordinate of a curve this parse recognises (SEC 1 section 2.3.5).</summary>
    /// <param name="curve">The curve.</param>
    /// <returns>The width.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The curve is none this parse recognises.</exception>
    private static int CoordinateOctetCount(EllipticCurveTypes curve) => curve switch
    {
        EllipticCurveTypes.P256 => EllipticCurveConstants.P256.PointArrayLength,
        EllipticCurveTypes.P384 => EllipticCurveConstants.P384.PointArrayLength,
        EllipticCurveTypes.P521 => EllipticCurveConstants.P521.PointArrayLength,
        EllipticCurveTypes.Secp256k1 => EllipticCurveConstants.Secp256k1.PointArrayLength,
        EllipticCurveTypes.BrainpoolP224r1 => EllipticCurveConstants.BrainpoolP224r1.PointArrayLength,
        EllipticCurveTypes.BrainpoolP256r1 => EllipticCurveConstants.BrainpoolP256r1.PointArrayLength,
        EllipticCurveTypes.BrainpoolP320r1 => EllipticCurveConstants.BrainpoolP320r1.PointArrayLength,
        EllipticCurveTypes.BrainpoolP384r1 => EllipticCurveConstants.BrainpoolP384r1.PointArrayLength,
        EllipticCurveTypes.BrainpoolP512r1 => EllipticCurveConstants.BrainpoolP512r1.PointArrayLength,
        EllipticCurveTypes.None => throw new ArgumentOutOfRangeException(nameof(curve), curve, "No coordinate width is known for no curve."),
        EllipticCurveTypes.NistCurves => throw new ArgumentOutOfRangeException(nameof(curve), curve, "A family of curves has no one coordinate width."),
        EllipticCurveTypes.Curve25519 => throw new ArgumentOutOfRangeException(nameof(curve), curve, "Curve25519 keys carry no SEC1 point."),
        EllipticCurveTypes.BrainpoolCurves => throw new ArgumentOutOfRangeException(nameof(curve), curve, "A family of curves has no one coordinate width."),
        _ => throw new ArgumentOutOfRangeException(nameof(curve), curve, "No coordinate width is known for the curve.")
    };


    /// <summary>The octet length of the public key of an ML-DSA parameter set (FIPS 204 table 2).</summary>
    /// <param name="parameterSetOid">The parameter set's object identifier, one of the three ML-DSA identifiers.</param>
    /// <returns>1,312 for ML-DSA-44, 1,952 for ML-DSA-65, 2,592 for ML-DSA-87.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The identifier names no ML-DSA parameter set.</exception>
    private static int MlDsaPublicKeyOctetCount(string parameterSetOid) => parameterSetOid switch
    {
        WellKnownOids.MlDsa44 => 1312,
        WellKnownOids.MlDsa65 => 1952,
        WellKnownOids.MlDsa87 => 2592,
        _ => throw new ArgumentOutOfRangeException(nameof(parameterSetOid), parameterSetOid, "The identifier names no ML-DSA parameter set.")
    };


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


    /// <summary>A parsed subject public key: its algorithm identifier, an elliptic-curve point, RSA modulus and exponent, or an ML-DSA parameter-set identifier and raw key, plus the raw BIT STRING content.</summary>
    /// <param name="AlgorithmOid">The key's algorithm identifier.</param>
    /// <param name="Curve">The elliptic curve, or none.</param>
    /// <param name="Point">The SEC1 point as encoded, or empty.</param>
    /// <param name="RsaModulus">The RSA modulus, or empty.</param>
    /// <param name="RsaExponent">The RSA public exponent, or empty.</param>
    /// <param name="MlDsaAlgorithmOid">The ML-DSA parameter-set identifier, or the empty string.</param>
    /// <param name="MlDsaPublicKey">The raw ML-DSA public key, or empty.</param>
    /// <param name="RawBitStringContent">The BIT STRING content bytes.</param>
    private readonly record struct ParsedPublicKey(
        string AlgorithmOid,
        EllipticCurveTypes Curve,
        ReadOnlyMemory<byte> Point,
        ReadOnlyMemory<byte> RsaModulus,
        ReadOnlyMemory<byte> RsaExponent,
        string MlDsaAlgorithmOid,
        ReadOnlyMemory<byte> MlDsaPublicKey,
        ReadOnlyMemory<byte> RawBitStringContent);


    /// <summary>The extensions a certificate's parse reads.</summary>
    /// <param name="SubjectKeyIdentifier">The subject key identifier, or empty.</param>
    /// <param name="ExtendedKeyUsageOids">The ExtendedKeyUsage key purpose identifiers, in certificate order.</param>
    private sealed record ParsedExtensions(ReadOnlyMemory<byte> SubjectKeyIdentifier, IReadOnlyList<string> ExtendedKeyUsageOids);
}
