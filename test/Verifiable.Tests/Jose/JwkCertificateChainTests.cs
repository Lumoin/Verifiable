using System.Buffers.Text;
using System.Formats.Asn1;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests the judgement of a JWK's <c>x5c</c> (RFC 7517 section 4.7, <see cref="JwkCertificateChain.DefectOf"/>) over
/// certificates the rows write with the ASN.1 producer (<see cref="CertificateDerProducer"/>): the base64 alphabet of each
/// element (RFC 4648 sections 3.3 and 4), the structure of each certificate (RFC 5280 section 4.1, RFC 8410 section 3), and
/// the first certificate's key against the key the JWK states, for every key type the judgement compares - EC on each curve it
/// names, its coordinates of the curve's width and naming a point of it, RSA, Ed25519 and ML-DSA - matching, another key, and the
/// matching certificate standing second.
/// </summary>
[TestClass]
internal sealed class JwkCertificateChainTests
{
    /// <summary>
    /// RFC 4648 section 3.3: "Implementations MUST reject the encoded data if it contains characters outside the base alphabet
    /// when interpreting base-encoded data, unless the specification referring to this document explicitly states otherwise";
    /// RFC 7517 section 4.7 states no such allowance for <c>x5c</c>, so a space, a tab, a carriage return or a line feed inside an
    /// element's base64 text refuses the chain as no base64 text, where the same element written whole matches the key.
    /// </summary>
    /// <param name="whitespace">The character written into the element.</param>
    [TestMethod]
    [DataRow(32, DisplayName = "A space")]
    [DataRow(9, DisplayName = "A tab")]
    [DataRow(13, DisplayName = "A carriage return")]
    [DataRow(10, DisplayName = "A line feed")]
    public void AnElementCarryingWhitespaceIsNoBase64Text(int whitespace)
    {
        var key = EllipticCurveKeyOf("P-256");
        var element = CertificateDerProducer.Base64(key.Shape);
        var withWhitespace = string.Concat(element.AsSpan(0, 8), ((char)whitespace).ToString(), element.AsSpan(8));

        Assert.IsNull(JwkCertificateChain.DefectOf([element], key.Members), "The control: the element written whole matches the key.");
        Assert.AreEqual(JwkCertificateChainDefect.NotBase64Text, JwkCertificateChain.DefectOf([withWhitespace], key.Members));
    }


    /// <summary>
    /// RFC 5280 section 4.1 and RFC 8410 section 3: a certificate whose structure the standards do not admit is no certificate,
    /// whatever key it carries - a field after the <c>subjectPublicKey</c> in its <c>SubjectPublicKeyInfo</c>, a second
    /// parameter after an EC key's named curve, parameters for an Ed25519 key ("the parameters MUST be absent") or for an ML-DSA
    /// key, an RSA key without its <c>NULL</c> parameters, an issuer attribute outside a <c>RelativeDistinguishedName</c> SET,
    /// and an outer <c>signatureAlgorithm</c> other than the <c>tbsCertificate</c>'s. Each certificate carries the very key the
    /// JWK states, so only its structure refuses it; the control, each key's certificate written as the standards shape it,
    /// matches.
    /// </summary>
    /// <param name="deviation">The deviation the producer writes.</param>
    [TestMethod]
    [DataRow("field-after-the-subject-public-key", DisplayName = "A field after the subjectPublicKey")]
    [DataRow("second-ec-parameter", DisplayName = "A second parameter after the named curve")]
    [DataRow("ed25519-parameters", DisplayName = "Ed25519 parameters present")]
    [DataRow("ml-dsa-parameters", DisplayName = "ML-DSA parameters present")]
    [DataRow("rsa-without-null", DisplayName = "RSA parameters absent")]
    [DataRow("attribute-outside-a-set", DisplayName = "An issuer attribute outside a SET")]
    [DataRow("outer-algorithm-differs", DisplayName = "An outer signatureAlgorithm other than the tbsCertificate's")]
    public void ACertificateOfAShapeTheStandardsDoNotAdmitIsNoCertificate(string deviation)
    {
        var (key, deviated) = deviation switch
        {
            "field-after-the-subject-public-key" => WithShape(EllipticCurveKeyOf("P-256"), shape => shape with { WriteFieldAfterSubjectPublicKey = static writer => writer.WriteNull() }),
            "second-ec-parameter" => WithShape(EllipticCurveKeyOf("P-256"), shape => shape with
            {
                WriteKeyParameters = static writer =>
                {
                    writer.WriteObjectIdentifier(WellKnownOids.EcP256);
                    writer.WriteNull();
                }
            }),
            "ed25519-parameters" => WithShape(Ed25519KeyOf(1), shape => shape with { WriteKeyParameters = static writer => writer.WriteNull() }),
            "ml-dsa-parameters" => WithShape(MlDsaKeyOf("ML-DSA-44", 1), shape => shape with { WriteKeyParameters = static writer => writer.WriteNull() }),
            "rsa-without-null" => WithShape(RsaKeyOf(), shape => shape with { WriteKeyParameters = null }),
            "attribute-outside-a-set" => WithShape(EllipticCurveKeyOf("P-256"), shape => shape with { IssuerAttributeOutsideASet = true }),
            "outer-algorithm-differs" => WithShape(EllipticCurveKeyOf("P-256"), shape => shape with { OuterSignatureAlgorithmOid = CertificateDerProducer.EcdsaWithSha384Oid }),
            _ => throw new ArgumentOutOfRangeException(nameof(deviation), deviation, "No deviation is named so.")
        };

        Assert.IsNull(JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(key.Shape)], key.Members), "The control: the well-formed certificate of the key matches it.");
        Assert.AreEqual(JwkCertificateChainDefect.NotACertificate, JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(deviated)], key.Members), deviation);
    }


    /// <summary>
    /// RFC 7517 section 4.7: "The key in the first certificate MUST match the public key represented by other members of the
    /// JWK." For each curve the judgement names an EC key on (RFC 7518 section 6.2.1.1, RFC 5639) - the certificate of the key
    /// matches it, the certificate of another key on the same curve does not, and neither does a chain whose first certificate is
    /// the other key's though the matching one stands second.
    /// </summary>
    /// <param name="crv">The curve's JWK name.</param>
    [TestMethod]
    [DataRow("P-256")]
    [DataRow("P-384")]
    [DataRow("P-521")]
    [DataRow("secp256k1")]
    [DataRow("brainpoolP224r1")]
    [DataRow("brainpoolP256r1")]
    [DataRow("brainpoolP320r1")]
    [DataRow("brainpoolP384r1")]
    [DataRow("brainpoolP512r1")]
    public void TheFirstCertificateOfAnEllipticCurveKeyMatchesOnlyThatKey(string crv)
    {
        AssertMatchesOnlyItsKey(EllipticCurveKeyOf(crv), EllipticCurveKeyOf(crv));
    }


    /// <summary>
    /// RFC 7518 section 6.3.1 and RFC 7517 section 4.7 for an RSA key: the certificate carrying the modulus and exponent the JWK
    /// states matches it, another RSA key's does not, and neither does a chain whose matching certificate stands second.
    /// </summary>
    [TestMethod]
    public void TheFirstCertificateOfAnRsaKeyMatchesOnlyThatKey()
    {
        AssertMatchesOnlyItsKey(RsaKeyOf(), RsaKeyOf());
    }


    /// <summary>
    /// RFC 8037 section 2, RFC 8410 section 4 and RFC 7517 section 4.7 for an Ed25519 key: the certificate carrying the public
    /// key the JWK's <c>x</c> states matches it, another key's does not, and neither does a chain whose matching certificate
    /// stands second.
    /// </summary>
    [TestMethod]
    public void TheFirstCertificateOfAnEd25519KeyMatchesOnlyThatKey()
    {
        AssertMatchesOnlyItsKey(Ed25519KeyOf(1), Ed25519KeyOf(2));
    }


    /// <summary>
    /// RFC 7517 section 4.7 for an AKP key of each ML-DSA parameter set: the certificate carrying the parameter set the JWK's
    /// <c>alg</c> names and the public key its <c>pub</c> carries matches it, another key of the set does not, and neither does a
    /// chain whose matching certificate stands second.
    /// </summary>
    /// <param name="alg">The ML-DSA parameter set's JWK algorithm name.</param>
    [TestMethod]
    [DataRow("ML-DSA-44")]
    [DataRow("ML-DSA-65")]
    [DataRow("ML-DSA-87")]
    public void TheFirstCertificateOfAnMlDsaKeyMatchesOnlyThatKey(string alg)
    {
        AssertMatchesOnlyItsKey(MlDsaKeyOf(alg, 1), MlDsaKeyOf(alg, 2));
    }


    /// <summary>
    /// The identifier binds an ML-DSA key to its parameter set (draft-ietf-lamps-dilithium-certificates): a valid ML-DSA-65
    /// certificate, its 1,952-octet key opening with the ML-DSA-44 JWK's 1,312 octets, is not the key the JWK states.
    /// </summary>
    [TestMethod]
    public void AnMlDsaCertificateOfAnotherParameterSetIsNotTheKey()
    {
        var key = MlDsaKeyOf("ML-DSA-44", 1);
        var otherSetKey = Base64Url.DecodeFromChars(key.Members["pub"]).Concat(OctetsOf(1952 - 1312, 5)).ToArray();
        var otherSet = CertificateDerProducer.MlDsaKey(WellKnownOids.MlDsa65, otherSetKey);

        Assert.AreEqual(WellKnownOids.MlDsa65, ManagedCertificate.Parse(CertificateDerProducer.Der(otherSet)).MlDsaAlgorithmOid, "The other parameter set's certificate is well formed.");
        Assert.AreEqual(JwkCertificateChainDefect.FirstCertificateNotOfTheKey, JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(otherSet)], key.Members));
    }


    /// <summary>
    /// FIPS 204 table 2: the public key of ML-DSA-44, ML-DSA-65 and ML-DSA-87 is 1,312, 1,952 and 2,592 octets. A certificate
    /// carrying a key of another length under a parameter set's identifier is no certificate of that set, whatever octets a JWK
    /// states beside it - the ML-DSA-44 key's 1,312 octets under ML-DSA-65's identifier, and short keys the JWK states the very
    /// same octets of, which would otherwise compare as one key; the control, each set's key of its own length, matches.
    /// </summary>
    /// <param name="alg">The parameter set's JWK algorithm name.</param>
    /// <param name="length">The octet length of the key the certificate carries.</param>
    [TestMethod]
    [DataRow("ML-DSA-65", 1312, DisplayName = "ML-DSA-65 carrying 1,312 octets")]
    [DataRow("ML-DSA-44", 1311, DisplayName = "ML-DSA-44 carrying 1,311 octets")]
    [DataRow("ML-DSA-87", 32, DisplayName = "ML-DSA-87 carrying 32 octets")]
    public void AnMlDsaCertificateOfAKeyLengthItsSetDoesNotHaveIsNoCertificate(string alg, int length)
    {
        var control = MlDsaKeyOf(alg, 1);
        var shortKey = OctetsOf(length, 3);
        var members = new Dictionary<string, string>(control.Members, StringComparer.Ordinal) { ["pub"] = Base64Url.EncodeToString(shortKey) };
        var certificate = CertificateDerProducer.MlDsaKey(control.Shape.KeyAlgorithmOid, shortKey);

        Assert.IsNull(JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(control.Shape)], control.Members), "The control: the set's key of its own length matches.");
        Assert.AreEqual(JwkCertificateChainDefect.NotACertificate, JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(certificate)], members), alg);
    }


    /// <summary>
    /// SEC 1 section 2.3.3 and RFC 5480 section 2.2: an elliptic-curve subject public key is the curve's point, uncompressed or
    /// compressed. For each curve the judgement names, a certificate carrying the JWK's point in its compressed form is the key
    /// the JWK states, never a mismatch, and a certificate carrying another key's compressed point is not.
    /// </summary>
    /// <param name="crv">The curve's JWK name.</param>
    [TestMethod]
    [DataRow("P-256")]
    [DataRow("P-384")]
    [DataRow("P-521")]
    [DataRow("secp256k1")]
    [DataRow("brainpoolP224r1")]
    [DataRow("brainpoolP256r1")]
    [DataRow("brainpoolP320r1")]
    [DataRow("brainpoolP384r1")]
    [DataRow("brainpoolP512r1")]
    public void ACompressedPointOfTheKeyIsTheKey(string crv)
    {
        var key = EllipticCurveKeyOf(crv);
        var other = EllipticCurveKeyOf(crv);

        Assert.IsNull(JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(CompressedShapeOf(key))], key.Members), "The compressed point of the key is the key.");
        Assert.AreEqual(JwkCertificateChainDefect.FirstCertificateNotOfTheKey, JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(CompressedShapeOf(other))], key.Members), "Another key's compressed point is not.");
    }


    /// <summary>
    /// SEC 1 section 2.3.4: an elliptic-curve point is <c>0x04</c> and two coordinates of the curve's width, or <c>0x02</c> or
    /// <c>0x03</c> and one, naming a point of the curve. A certificate whose key is another encoding - a hybrid <c>0x06</c> form,
    /// an uncompressed point with an octet after it, coordinates naming no point of the curve, a compressed x naming none - is no
    /// certificate the parse reads; the control, the uncompressed point of the key, is read.
    /// </summary>
    /// <param name="encoding">The encoding the producer writes.</param>
    [TestMethod]
    [DataRow("hybrid", DisplayName = "A hybrid 0x06 point")]
    [DataRow("trailing-octet", DisplayName = "An uncompressed point with an octet after it")]
    [DataRow("off-curve", DisplayName = "Coordinates naming no point of the curve")]
    [DataRow("compressed-off-curve", DisplayName = "A compressed x naming no point of the curve")]
    public void AnEllipticCurveKeyOfAnotherEncodingIsNoCertificate(string encoding)
    {
        var key = EllipticCurveKeyOf("P-256");
        var x = Base64Url.DecodeFromChars(key.Members["x"]);
        var y = Base64Url.DecodeFromChars(key.Members["y"]);
        var offCurveY = (byte[])y.Clone();
        offCurveY[^1] ^= 0x01;

        byte[] point = encoding switch
        {
            "hybrid" => [0x06, .. x, .. y],
            "trailing-octet" => [EllipticCurveUtilities.UncompressedCoordinateFormat, .. x, .. y, 0x00],
            "off-curve" => [EllipticCurveUtilities.UncompressedCoordinateFormat, .. x, .. offCurveY],
            "compressed-off-curve" => [EllipticCurveUtilities.EvenYCoordinate, .. NoCurveX()],
            _ => throw new ArgumentOutOfRangeException(nameof(encoding), encoding, "No encoding is named so.")
        };

        var parsed = ManagedCertificate.Parse(CertificateDerProducer.Der(key.Shape));

        Assert.IsTrue(parsed.PublicPoint.Span.SequenceEqual(key.Shape.SubjectPublicKey), "The control: the uncompressed point of the key is read.");
        _ = Assert.ThrowsExactly<AsnContentException>(() => ManagedCertificate.Parse(CertificateDerProducer.Der(key.Shape with { SubjectPublicKey = point })), encoding);
    }


    /// <summary>
    /// RFC 5280 section 4.1.2.4: "The issuer field MUST contain a non-empty distinguished name (DN)", while section 4.1.2.6 admits
    /// an empty subject. A certificate whose issuer is an empty <c>RDNSequence</c> is no certificate; one whose subject is, the
    /// control, is read and matches the key it carries.
    /// </summary>
    [TestMethod]
    public void AnEmptyIssuerIsNoCertificateAndAnEmptySubjectIs()
    {
        var key = EllipticCurveKeyOf("P-256");

        Assert.IsNull(JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(key.Shape with { SubjectEmpty = true })], key.Members), "The control: an empty subject is admitted.");
        Assert.AreEqual(JwkCertificateChainDefect.NotACertificate, JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(key.Shape with { IssuerEmpty = true })], key.Members));
    }


    /// <summary>
    /// RFC 5280 section 4.1: <c>issuerUniqueID [1] IMPLICIT UniqueIdentifier</c> and <c>subjectUniqueID [2] IMPLICIT
    /// UniqueIdentifier</c>, <c>UniqueIdentifier ::= BIT STRING</c> - each a primitive BIT STRING under its implicit tag. A
    /// certificate carrying either or both so is read; one carrying an identifier as a constructed wrapper, or a primitive one
    /// whose BIT STRING content is no BIT STRING - no unused-bits octet, or eight unused bits - is no certificate.
    /// </summary>
    /// <param name="identifiers">The unique identifiers the producer writes.</param>
    /// <param name="isACertificate">Whether the certificate is one the parse reads.</param>
    [TestMethod]
    [DataRow("issuer", true, DisplayName = "An issuer unique identifier")]
    [DataRow("subject", true, DisplayName = "A subject unique identifier")]
    [DataRow("both", true, DisplayName = "Both unique identifiers")]
    [DataRow("constructed-issuer", false, DisplayName = "An issuer unique identifier as a constructed wrapper")]
    [DataRow("constructed-subject", false, DisplayName = "A subject unique identifier as a constructed wrapper")]
    [DataRow("no-unused-bits-octet", false, DisplayName = "An issuer unique identifier with no unused-bits octet")]
    [DataRow("eight-unused-bits", false, DisplayName = "An issuer unique identifier claiming eight unused bits")]
    public void AUniqueIdentifierIsReadAsTheBitStringItIs(string identifiers, bool isACertificate)
    {
        var key = EllipticCurveKeyOf("P-256");
        var issuerTag = new Asn1Tag(TagClass.ContextSpecific, 1);
        var subjectTag = new Asn1Tag(TagClass.ContextSpecific, 2);
        Action<AsnWriter> write = identifiers switch
        {
            "issuer" => writer => writer.WriteBitString([0x5A, 0xA5], 0, issuerTag),
            "subject" => writer => writer.WriteBitString([0x01], 0, subjectTag),
            "both" => writer => WriteBothUniqueIdentifiers(writer, issuerTag, subjectTag),
            "constructed-issuer" => static writer => WriteConstructedUniqueIdentifier(writer, 1),
            "constructed-subject" => static writer => WriteConstructedUniqueIdentifier(writer, 2),
            "no-unused-bits-octet" => static writer => writer.WriteEncodedValue([0x81, 0x00]),
            "eight-unused-bits" => static writer => writer.WriteEncodedValue([0x81, 0x02, 0x08, 0x00]),
            _ => throw new ArgumentOutOfRangeException(nameof(identifiers), identifiers, "No identifiers are named so.")
        };

        var defect = JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(key.Shape with { WriteUniqueIdentifiers = write })], key.Members);

        Assert.AreEqual(isACertificate ? null : JwkCertificateChainDefect.NotACertificate, defect, identifiers);
    }


    /// <summary>Writes both unique identifiers as the primitive, implicitly tagged BIT STRINGs RFC 5280 section 4.1 defines.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="issuerTag">The issuer identifier's tag, <c>[1]</c>.</param>
    /// <param name="subjectTag">The subject identifier's tag, <c>[2]</c>.</param>
    private static void WriteBothUniqueIdentifiers(AsnWriter writer, Asn1Tag issuerTag, Asn1Tag subjectTag)
    {
        writer.WriteBitString([0x5A, 0xA5], 0, issuerTag);
        writer.WriteBitString([0x80], 7, subjectTag);
    }


    /// <summary>Writes a unique identifier of the tag number given as a constructed wrapper around a BIT STRING, which RFC 5280 does not admit.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="tagNumber">The identifier's context-specific tag number.</param>
    private static void WriteConstructedUniqueIdentifier(AsnWriter writer, int tagNumber)
    {
        using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, tagNumber, isConstructed: true)))
        {
            writer.WriteBitString([0x5A]);
        }
    }


    /// <summary>The shape of the certificate of a key, its point written compressed.</summary>
    /// <param name="key">The key.</param>
    /// <returns>The shape.</returns>
    private static CertificateDerShape CompressedShapeOf(CertificateKey key) =>
        CertificateDerProducer.CompressedEllipticCurveKey(
            CurveOidOf(key.Members["crv"]), Base64Url.DecodeFromChars(key.Members["x"]), Base64Url.DecodeFromChars(key.Members["y"]));


    /// <summary>
    /// A P-256 x coordinate naming no point of the curve: x³ - 3x + b is no square modulo p for x = 1, so the curve's equation
    /// recovers no y of it.
    /// </summary>
    /// <returns>The coordinate.</returns>
    private static byte[] NoCurveX()
    {
        var x = new byte[32];
        x[^1] = 1;

        return x;
    }


    /// <summary>
    /// RFC 7518 sections 6.2.1.2 and 6.2.1.3: an EC key's <c>x</c> and <c>y</c> are each the full width of the curve's
    /// coordinate. A JWK splitting a P-256 point's sixty-four octets as thirty-three and thirty-one states no point of the
    /// curve, so the certificate of that point is not its key, though the two coordinates concatenate to the certificate's
    /// point.
    /// </summary>
    [TestMethod]
    public void AJwkWhoseCoordinatesAreNotOfTheCurvesWidthIsNotTheCertificatesKey()
    {
        var key = EllipticCurveKeyOf("P-256");
        var point = Base64Url.DecodeFromChars(key.Members["x"]).Concat(Base64Url.DecodeFromChars(key.Members["y"])).ToArray();
        var split = new Dictionary<string, string>(key.Members, StringComparer.Ordinal)
        {
            ["x"] = Base64Url.EncodeToString(point.AsSpan(0, 33)),
            ["y"] = Base64Url.EncodeToString(point.AsSpan(33))
        };

        Assert.AreEqual(JwkCertificateChainDefect.FirstCertificateNotOfTheKey, JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(key.Shape)], split));
    }


    /// <summary>
    /// NIST SP 800-186 appendix D.1.1.1: coordinates of the curve's width that do not satisfy its equation name no point of it.
    /// A JWK stating such coordinates states no EC public key, so the certificate of the real point whose x it shares is not its
    /// key; a certificate whose point the producer wrote with the JWK's very octets names no point either, and is no certificate.
    /// </summary>
    [TestMethod]
    public void AJwkWhoseCoordinatesNameNoPointOfTheCurveIsNotTheCertificatesKey()
    {
        var key = EllipticCurveKeyOf("P-256");
        var x = Base64Url.DecodeFromChars(key.Members["x"]);
        var y = Base64Url.DecodeFromChars(key.Members["y"]);
        y[^1] ^= 0x01;

        var offCurve = new Dictionary<string, string>(key.Members, StringComparer.Ordinal) { ["y"] = Base64Url.EncodeToString(y) };
        var sameOctets = CertificateDerProducer.EllipticCurveKey(WellKnownOids.EcP256, x, y);

        Assert.IsFalse(EllipticCurveUtilities.CheckPointOnCurve(x, y, EllipticCurveTypes.P256), "The coordinates name no point of P-256.");
        Assert.AreEqual(JwkCertificateChainDefect.FirstCertificateNotOfTheKey, JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(key.Shape)], offCurve));
        Assert.AreEqual(JwkCertificateChainDefect.NotACertificate, JwkCertificateChain.DefectOf([CertificateDerProducer.Base64(sameOctets)], offCurve));
    }


    /// <summary>
    /// The certificate parser's own rows (RFC 5280 section 4.1.2.7, RFC 8410 section 3): an Ed25519 key's parameters and a field
    /// after the <c>subjectPublicKey</c> are each refused by <see cref="ManagedCertificate.Parse"/> as an encoding of no
    /// certificate, and the well-formed certificate of the same key is read with its key.
    /// </summary>
    [TestMethod]
    public void TheParserRefusesASubjectPublicKeyInfoCarryingMoreThanItsTwoFields()
    {
        var key = Ed25519KeyOf(3);
        var withParameters = key.Shape with { WriteKeyParameters = static writer => writer.WriteNull() };
        var withTrailingField = key.Shape with { WriteFieldAfterSubjectPublicKey = static writer => writer.WriteInteger(0) };

        var parsed = ManagedCertificate.Parse(CertificateDerProducer.Der(key.Shape));

        Assert.AreEqual(WellKnownOids.EdDSA25519, parsed.SubjectPublicKeyAlgorithmOid);
        Assert.IsTrue(parsed.SubjectPublicKeyBitStringContent.Span.SequenceEqual(key.Shape.SubjectPublicKey), "The well-formed certificate's key is read.");
        _ = Assert.ThrowsExactly<AsnContentException>(() => ManagedCertificate.Parse(CertificateDerProducer.Der(withParameters)));
        _ = Assert.ThrowsExactly<AsnContentException>(() => ManagedCertificate.Parse(CertificateDerProducer.Der(withTrailingField)));
    }


    /// <summary>
    /// Asserts the three rows of RFC 7517 section 4.7's first-certificate rule: the certificate of the key matches it, the
    /// certificate of another key does not, and a chain whose first certificate is the other key's does not though the matching
    /// certificate stands second.
    /// </summary>
    /// <param name="key">The key the JWK states and its certificate.</param>
    /// <param name="other">Another key of the same type and its certificate.</param>
    private static void AssertMatchesOnlyItsKey(CertificateKey key, CertificateKey other)
    {
        var ofTheKey = CertificateDerProducer.Base64(key.Shape);
        var ofAnotherKey = CertificateDerProducer.Base64(other.Shape);

        Assert.IsNull(JwkCertificateChain.DefectOf([ofTheKey], key.Members), "The certificate of the key matches it.");
        Assert.AreEqual(JwkCertificateChainDefect.FirstCertificateNotOfTheKey, JwkCertificateChain.DefectOf([ofAnotherKey], key.Members), "Another key's certificate does not.");
        Assert.AreEqual(JwkCertificateChainDefect.FirstCertificateNotOfTheKey, JwkCertificateChain.DefectOf([ofAnotherKey, ofTheKey], key.Members), "The first certificate is the one judged.");
    }


    /// <summary>A key with the deviated shape of its certificate.</summary>
    /// <param name="key">The key.</param>
    /// <param name="deviate">Writes the deviation into the key's certificate shape.</param>
    /// <returns>The key and the deviated shape.</returns>
    private static DeviatedCertificateKey WithShape(CertificateKey key, Func<CertificateDerShape, CertificateDerShape> deviate) => new(key, deviate(key.Shape));


    /// <summary>A fresh EC key on the curve the JWK name names, its JWK members and its certificate's shape.</summary>
    /// <param name="crv">The curve's JWK name.</param>
    /// <returns>The key.</returns>
    private static CertificateKey EllipticCurveKeyOf(string crv)
    {
        var curveOid = CurveOidOf(crv);

        //The curve is named by its object identifier (RFC 5480 section 2.1.1.1), the one name every platform's EC key knows it by.
        using var ecKey = ECDsa.Create(ECCurve.CreateFromValue(curveOid));
        var point = ecKey.ExportParameters(includePrivateParameters: false).Q;
        var x = point.X ?? throw new InvalidOperationException("An exported EC key carries its x coordinate.");
        var y = point.Y ?? throw new InvalidOperationException("An exported EC key carries its y coordinate.");

        return new CertificateKey(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["kty"] = "EC",
                ["crv"] = crv,
                ["x"] = Base64Url.EncodeToString(x),
                ["y"] = Base64Url.EncodeToString(y)
            },
            CertificateDerProducer.EllipticCurveKey(curveOid, x, y));
    }


    /// <summary>The object identifier of the curve a JWK name names (RFC 5480 section 2.1.1.1, RFC 5639).</summary>
    /// <param name="crv">The curve's JWK name.</param>
    /// <returns>The identifier.</returns>
    private static string CurveOidOf(string crv) => crv switch
    {
        "P-256" => WellKnownOids.EcP256,
        "P-384" => WellKnownOids.EcP384,
        "P-521" => WellKnownOids.EcP521,
        "secp256k1" => WellKnownOids.EcSecp256k1,
        "brainpoolP224r1" => WellKnownOids.EcBrainpoolP224r1,
        "brainpoolP256r1" => WellKnownOids.EcBrainpoolP256r1,
        "brainpoolP320r1" => WellKnownOids.EcBrainpoolP320r1,
        "brainpoolP384r1" => WellKnownOids.EcBrainpoolP384r1,
        "brainpoolP512r1" => WellKnownOids.EcBrainpoolP512r1,
        _ => throw new ArgumentOutOfRangeException(nameof(crv), crv, "No curve is named so.")
    };


    /// <summary>A fresh 2048-bit RSA key, its JWK members and its certificate's shape.</summary>
    /// <returns>The key.</returns>
    private static CertificateKey RsaKeyOf()
    {
        using var rsa = RSA.Create(2048);
        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        var modulus = parameters.Modulus ?? throw new InvalidOperationException("An exported RSA key carries its modulus.");
        var exponent = parameters.Exponent ?? throw new InvalidOperationException("An exported RSA key carries its exponent.");

        return new CertificateKey(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["kty"] = "RSA",
                ["n"] = Base64Url.EncodeToString(modulus),
                ["e"] = Base64Url.EncodeToString(exponent)
            },
            CertificateDerProducer.RsaKey(modulus, exponent));
    }


    /// <summary>An Ed25519 public key of octets the seed spells, its JWK members and its certificate's shape.</summary>
    /// <param name="seed">The value every octet of the key is derived from, so two seeds give two keys.</param>
    /// <returns>The key.</returns>
    private static CertificateKey Ed25519KeyOf(int seed)
    {
        var publicKey = OctetsOf(32, seed);

        return new CertificateKey(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["kty"] = "OKP",
                ["crv"] = "Ed25519",
                ["x"] = Base64Url.EncodeToString(publicKey)
            },
            CertificateDerProducer.Ed25519Key(publicKey));
    }


    /// <summary>An ML-DSA public key of the parameter set and length FIPS 204 gives it, of octets the seed spells.</summary>
    /// <param name="alg">The parameter set's JWK algorithm name.</param>
    /// <param name="seed">The value every octet of the key is derived from.</param>
    /// <returns>The key.</returns>
    private static CertificateKey MlDsaKeyOf(string alg, int seed)
    {
        var oid = alg switch
        {
            "ML-DSA-44" => WellKnownOids.MlDsa44,
            "ML-DSA-65" => WellKnownOids.MlDsa65,
            "ML-DSA-87" => WellKnownOids.MlDsa87,
            _ => throw new ArgumentOutOfRangeException(nameof(alg), alg, "No ML-DSA parameter set is named so.")
        };

        //FIPS 204 table 2: the public key of ML-DSA-44, ML-DSA-65 and ML-DSA-87 is 1312, 1952 and 2592 octets.
        var length = alg switch
        {
            "ML-DSA-44" => 1312,
            "ML-DSA-65" => 1952,
            _ => 2592
        };

        var publicKey = OctetsOf(length, seed);

        return new CertificateKey(
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["kty"] = "AKP",
                ["alg"] = alg,
                ["pub"] = Base64Url.EncodeToString(publicKey)
            },
            CertificateDerProducer.MlDsaKey(oid, publicKey));
    }


    /// <summary>Octets of the length given, each derived from its index and the seed.</summary>
    /// <param name="length">The length.</param>
    /// <param name="seed">The seed.</param>
    /// <returns>The octets.</returns>
    private static byte[] OctetsOf(int length, int seed) => [.. Enumerable.Range(0, length).Select(index => (byte)((index * 31) + (seed * 7)))];

}


/// <summary>A key a JWK states, as its members, and the shape of the certificate carrying it.</summary>
/// <param name="Members">The JWK's string members.</param>
/// <param name="Shape">The certificate's shape.</param>
internal sealed record CertificateKey(IReadOnlyDictionary<string, string> Members, CertificateDerShape Shape);


/// <summary>A key and the shape of a certificate carrying it with a deviation the standards do not admit.</summary>
/// <param name="Key">The key and its well-formed certificate's shape.</param>
/// <param name="Deviated">The deviated shape.</param>
internal sealed record DeviatedCertificateKey(CertificateKey Key, CertificateDerShape Deviated);
