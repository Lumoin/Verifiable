using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// The three reference-processing shapes <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML
/// Signature Syntax and Processing (Second Edition)</see> section 4.3.3.2 admits, over which of the
/// <see cref="XmlSignatureInteropCorpusGenerator"/> corpus's cases distributes.
/// </summary>
internal enum XmlSignatureInteropShape
{
    /// <summary>The <c>ds:Signature</c> is a descendant of the referenced content (<c>URI=""</c>, whole document, enveloped-signature transform present).</summary>
    Enveloped,

    /// <summary>The referenced content is a descendant of the <c>ds:Signature</c> (a <c>ds:Object</c> child), per section 4.5.</summary>
    Enveloping,

    /// <summary>The <c>ds:Signature</c> and the referenced content are siblings within the same document, neither containing the other.</summary>
    DetachedSameDocument
}


/// <summary>One minted interop corpus case: the signed document octets and the shape they exercise.</summary>
/// <param name="Name">A stable, descriptive case name for failure messages.</param>
/// <param name="Document">The complete signed XML document, UTF-8 encoded.</param>
/// <param name="Shape">Which of the three reference-processing shapes this case is.</param>
/// <param name="KeyTag">
/// The house verification <see cref="Tag"/> of the framework key this case's signature was minted with —
/// this generator's own record of which algorithm signed, independent of the document's own
/// <c>SignatureMethod</c> URI. This dispatch idiom resolves verification from this, the KEY's own
/// tag, never from the URI.
/// </param>
/// <param name="IsPlatformVerifiable">
/// Whether <see cref="SignedXml.LoadXml(System.Xml.XmlElement)"/>/<see cref="SignedXml.CheckSignature()"/>
/// can independently re-verify this case — <see langword="false"/> only for the one case whose
/// <c>CanonicalizationMethod</c> is Canonical XML 1.1, which the platform ships no transform for at all (see
/// the type remarks).
/// </param>
internal sealed record XmlSignatureInteropCase(string Name, byte[] Document, XmlSignatureInteropShape Shape, Tag KeyTag, bool IsPlatformVerifiable = true);


/// <summary>
/// The RSA PKCS#1 v1.5 SHA-256 <see cref="SignatureDescription"/> <see cref="XmlSignatureInteropCorpusGenerator"/>
/// registers with <see cref="CryptoConfig"/> under <see cref="XmlSignatureWellKnown.RsaSha256SignatureUri"/>.
/// </summary>
/// <remarks>
/// The platform's own <see cref="CryptoConfig"/> table carries no built-in entry for this — or any —
/// RSA-SHAnnn or ECDSA-SHAnnn XMLDSIG signature-method identifier beyond the original 1.0 <c>rsa-sha1</c>,
/// so <see cref="SignedXml.ComputeSignature()"/> cannot resolve one without a caller registering it first —
/// the documented .NET pattern this type and <see cref="EcdsaSha256SignatureDescription"/> follow. Public,
/// rather than the usual internal visibility this test project's own types take, because
/// <see cref="CryptoConfig.AddAlgorithm(Type, string[])"/> refuses a type it cannot see from outside its
/// declaring assembly.
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1515:Consider making public types internal",
    Justification = "CryptoConfig.AddAlgorithm requires a type visible from outside its declaring assembly (confirmed at runtime: 'Algorithms added to CryptoConfig must be accessible from outside their assembly'); nothing else in this project references the type by name.")]
public sealed class RsaPkcs1Sha256SignatureDescription: SignatureDescription
{
    /// <summary>Creates the description with the RSA/SHA-256/PKCS#1 formatter and deformatter algorithm names <see cref="CreateFormatter"/>/<see cref="CreateDeformatter"/> instantiate.</summary>
    public RsaPkcs1Sha256SignatureDescription()
    {
        KeyAlgorithm = typeof(RSA).AssemblyQualifiedName!;
        DigestAlgorithm = typeof(SHA256).AssemblyQualifiedName!;
        FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).AssemblyQualifiedName!;
        DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).AssemblyQualifiedName!;
    }


    /// <summary>
    /// Returns a fresh <see cref="SHA256"/> instance directly, bypassing the base implementation's
    /// <see cref="CryptoConfig.CreateFromName(string)"/> resolution of <see cref="DigestAlgorithm"/> — that
    /// resolution instantiates the named type via reflection, which fails for the abstract
    /// <see cref="SHA256"/> class itself; <see cref="SHA256.Create()"/> is the concrete factory every other
    /// digest computation in this library's own test infrastructure already goes through.
    /// </summary>
    public override HashAlgorithm CreateDigest() => SHA256.Create();


    /// <inheritdoc />
    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
    {
        var deformatter = new RSAPKCS1SignatureDeformatter(key);
        deformatter.SetHashAlgorithm(nameof(SHA256));

        return deformatter;
    }


    /// <inheritdoc />
    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
        var formatter = new RSAPKCS1SignatureFormatter(key);
        formatter.SetHashAlgorithm(nameof(SHA256));

        return formatter;
    }
}


/// <summary>
/// The ECDSA-SHA256 <see cref="SignatureDescription"/> <see cref="XmlSignatureInteropCorpusGenerator"/>
/// registers with <see cref="CryptoConfig"/> under <see cref="XmlSignatureWellKnown.EcdsaSha256SignatureUri"/>.
/// </summary>
/// <remarks>
/// Unlike RSA and DSA, the BCL ships no <see cref="AsymmetricSignatureFormatter"/>/<see cref="AsymmetricSignatureDeformatter"/>
/// pair for ECDSA at all — <see cref="CreateFormatter"/>/<see cref="CreateDeformatter"/> below wrap
/// <see cref="ECDsa.SignHash(byte[])"/>/<see cref="ECDsa.VerifyHash(byte[],byte[])"/> directly, over an
/// already-computed hash, exactly matching the two other <see cref="AsymmetricSignatureFormatter"/>
/// implementations' contract (they receive the digest, not the original data). The signature these produce
/// is the fixed-width IEEE P1363 <c>r‖s</c> encoding both <see cref="ECDsa.SignHash(byte[])"/> and this
/// library's own registered ECDSA verification seam use — see <see cref="EllipticCurveUtilities"/>'s remarks
/// on the P1363/DER distinction — so no conversion is needed anywhere in this corpus.
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1515:Consider making public types internal",
    Justification = "CryptoConfig.AddAlgorithm requires a type visible from outside its declaring assembly (confirmed at runtime: 'Algorithms added to CryptoConfig must be accessible from outside their assembly'); nothing else in this project references the type by name.")]
public sealed class EcdsaSha256SignatureDescription: SignatureDescription
{
    /// <summary>Creates the description, setting <see cref="SignatureDescription.KeyAlgorithm"/> so <see cref="SignedXml.CheckSignature()"/>'s own key-type check succeeds.</summary>
    public EcdsaSha256SignatureDescription()
    {
        KeyAlgorithm = typeof(ECDsa).AssemblyQualifiedName!;
        DigestAlgorithm = typeof(SHA256).AssemblyQualifiedName!;
    }


    /// <inheritdoc cref="RsaPkcs1Sha256SignatureDescription.CreateDigest"/>
    public override HashAlgorithm CreateDigest() => SHA256.Create();


    /// <inheritdoc />
    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
    {
        var deformatter = new EcdsaRawSignatureDeformatter();
        deformatter.SetKey(key);

        return deformatter;
    }


    /// <inheritdoc />
    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
    {
        var formatter = new EcdsaRawSignatureFormatter();
        formatter.SetKey(key);

        return formatter;
    }
}


/// <summary>The <see cref="ECDsa.SignHash(byte[])"/>-backed formatter <see cref="EcdsaSha256SignatureDescription"/> uses.</summary>
internal sealed class EcdsaRawSignatureFormatter: AsymmetricSignatureFormatter
{
    private ECDsa? key;

    /// <inheritdoc />
    public override void SetKey(AsymmetricAlgorithm key) => this.key = (ECDsa)key;

    /// <inheritdoc />
    public override void SetHashAlgorithm(string strName)
    {
        //ECDsa.SignHash has no separate hash-algorithm parameter — CreateDigest already fixed it to SHA-256.
    }

    /// <inheritdoc />
    public override byte[] CreateSignature(byte[] rgbHash) => key!.SignHash(rgbHash);
}


/// <summary>The <see cref="ECDsa.VerifyHash(byte[],byte[])"/>-backed deformatter <see cref="EcdsaSha256SignatureDescription"/> uses.</summary>
internal sealed class EcdsaRawSignatureDeformatter: AsymmetricSignatureDeformatter
{
    private ECDsa? key;

    /// <inheritdoc />
    public override void SetKey(AsymmetricAlgorithm key) => this.key = (ECDsa)key;

    /// <inheritdoc />
    public override void SetHashAlgorithm(string strName)
    {
        //ECDsa.VerifyHash has no separate hash-algorithm parameter — CreateDigest already fixed it to SHA-256.
    }

    /// <inheritdoc />
    public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature) => key!.VerifyHash(rgbHash, rgbSignature);
}


/// <summary>
/// Mints a deterministic corpus of REAL signed XML documents for the interop oracle: enveloped, enveloping
/// and detached-same-document shapes; RSA-SHA256 and ECDSA-P256-SHA256 <c>SignatureMethod</c>s; Canonical
/// XML 1.0, Canonical XML 1.1 and Exclusive XML Canonicalization <c>CanonicalizationMethod</c>s; a
/// multi-reference signature (a <c>ds:Object</c> target and a bare-name-<c>Id</c> target); <c>KeyInfo</c>
/// as <c>X509Data</c> and as <c>KeyValue</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Cert-factory carve-out</strong> (the <c>TestCertificateChainProvider</c> precedent,
/// <c>test/Verifiable.Tests/TestDataProviders/TestCertificateChainProvider.cs</c>): six of the seven cases
/// mint their signature through <see cref="SignedXml.ComputeSignature()"/>, which requires a framework
/// <see cref="RSA"/>/<see cref="ECDsa"/> as <see cref="SignedXml.SigningKey"/> and, for the <c>X509Data</c>
/// cases, a framework <see cref="X509Certificate2"/> built over that same key via
/// <see cref="CertificateRequest"/>. These keys/certificates are minted fresh per case, used only to drive
/// the platform's own signing, and never converted to this library's key-material carriers. Signing with
/// RSA-SHA256/ECDSA-SHA256 additionally needs the two <see cref="SignatureDescription"/>s registered above —
/// the platform's <see cref="CryptoConfig"/> table carries neither by default.
/// </para>
/// <para>
/// <strong>Canonical XML 1.1 has no platform transform</strong> — confirmed by this same test project's differential harness (<c>XmlCanonicalizationDifferentialTests</c>'s own type doc comment: "Canonical XML 1.1
/// is deliberately absent: the platform ships no transform for it"). <see cref="SignedXml.ComputeSignature"/> therefore cannot mint a document whose <c>CanonicalizationMethod</c> is <see
/// cref="XmlSignatureWellKnown.CanonicalXml11Uri"/>. The seventh case, <c>HandAssembledC14N11SignedInfo</c>, supplies this algorithm instead: its <c>Reference</c> digest is computed through the house digest seam
/// (<see cref="CryptographicKeyEvents.ComputeDigestAsync(System.ReadOnlyMemory{byte},int,Tag,BaseMemoryPool,System.Collections.Frozen.FrozenDictionary{string,object}?,string?,System.Threading.CancellationToken)"/>)
/// over a namespace-free, already-canonical <c>Data</c> element (so no namespace-axis rendering needs deriving by hand), its <c>SignedInfo</c> canonical octets are produced by THIS library's own <see
/// cref="XmlCanonicalization"/> — a legitimate fixture-construction use, not the surface <c>XmlSignatureInteropOracleTests</c> exercises — and the <c>SignatureValue</c> is a genuine framework <see
/// cref="RSA.SignData(byte[],HashAlgorithmName,RSASignaturePadding)"/> call over those exact octets, so the cryptographic-verification proof stays non-circular even though one canonicalization step used this
/// library as a tool rather than the platform.
/// </para>
/// </remarks>
internal static class XmlSignatureInteropCorpusGenerator
{
    private const string Sha256DigestUri = "http://www.w3.org/2001/04/xmlenc#sha256";


    /// <summary>
    /// Registers <see cref="RsaPkcs1Sha256SignatureDescription"/> and <see cref="EcdsaSha256SignatureDescription"/>
    /// with <see cref="CryptoConfig"/> once per process, before any case that signs runs.
    /// </summary>
    static XmlSignatureInteropCorpusGenerator()
    {
        CryptoConfig.AddAlgorithm(typeof(RsaPkcs1Sha256SignatureDescription), XmlSignatureWellKnown.RsaSha256SignatureUri);
        CryptoConfig.AddAlgorithm(typeof(EcdsaSha256SignatureDescription), XmlSignatureWellKnown.EcdsaSha256SignatureUri);
    }


    /// <summary>Mints the whole deterministic corpus.</summary>
    /// <param name="pool">The pool the one house-digest-seam call (the C14N 1.1 case) rents from.</param>
    /// <returns>The seven corpus cases, in a fixed order.</returns>
    public static IReadOnlyList<XmlSignatureInteropCase> Generate(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return
        [
            CreateEnvelopedCase(
                "EnvelopedRsaSha256C14N10X509Data",
                XmlSignatureWellKnown.RsaSha256SignatureUri,
                SignedXml.XmlDsigC14NTransformUrl,
                useExclusive: false),
            CreateEnvelopedCase(
                "EnvelopedEcdsaSha256ExclusiveX509Data",
                XmlSignatureWellKnown.EcdsaSha256SignatureUri,
                SignedXml.XmlDsigExcC14NTransformUrl,
                useExclusive: true),
            CreateEnvelopingSingleReferenceCase(),
            CreateEnvelopingMultiReferenceCase(),
            CreateDetachedSameDocumentCase(
                "DetachedSameDocumentRsaSha256ExclusiveX509Data",
                XmlSignatureWellKnown.RsaSha256SignatureUri,
                SignedXml.XmlDsigExcC14NTransformUrl,
                useExclusive: true),
            CreateDetachedSameDocumentCase(
                "DetachedSameDocumentEcdsaSha256C14N10X509Data",
                XmlSignatureWellKnown.EcdsaSha256SignatureUri,
                SignedXml.XmlDsigC14NTransformUrl,
                useExclusive: false),
            CreateHandAssembledC14N11Case(pool)
        ];
    }


    /// <summary>
    /// Mints an enveloped-signature case: a whole-document <c>URI=""</c> Reference under
    /// <c>[enveloped-signature, canonicalization]</c> transforms, <c>KeyInfo</c> as <c>X509Data</c>.
    /// </summary>
    private static XmlSignatureInteropCase CreateEnvelopedCase(string name, string signatureMethodUri, string canonicalizationUri, bool useExclusive)
    {
        using AsymmetricAlgorithm key = CreateSigningKey(signatureMethodUri, out X509Certificate2 certificate);
        using(certificate)
        {
            XmlDocument document = new() { PreserveWhitespace = true };
            document.LoadXml("<Root><Payload>enveloped interop payload</Payload></Root>");

            SignedXml signedXml = new(document) { SigningKey = key };
            signedXml.SignedInfo!.CanonicalizationMethod = canonicalizationUri;
            signedXml.SignedInfo.SignatureMethod = signatureMethodUri;

            Reference reference = new(string.Empty) { DigestMethod = Sha256DigestUri };
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(useExclusive ? new XmlDsigExcC14NTransform() : new XmlDsigC14NTransform());
            signedXml.AddReference(reference);

            signedXml.KeyInfo!.AddClause(new KeyInfoX509Data(certificate));

            signedXml.ComputeSignature();
            document.DocumentElement!.AppendChild(document.ImportNode(signedXml.GetXml(), deep: true));

            return new XmlSignatureInteropCase(name, Encoding.UTF8.GetBytes(document.OuterXml), XmlSignatureInteropShape.Enveloped, KeyTagFor(signatureMethodUri));
        }
    }


    /// <summary>
    /// Mints an enveloping-signature case with a single <c>ds:Object</c>-targeted Reference and <c>KeyInfo</c>
    /// as <c>KeyValue</c> (<c>RSAKeyValue</c>).
    /// </summary>
    private static XmlSignatureInteropCase CreateEnvelopingSingleReferenceCase()
    {
        using RSA rsaKey = RSA.Create(2048);

        XmlDocument document = new();
        SignedXml signedXml = new(document) { SigningKey = rsaKey };
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = XmlSignatureWellKnown.RsaSha256SignatureUri;

        XmlDocument contentDocument = new();
        XmlElement dataElement = contentDocument.CreateElement("Data");
        dataElement.InnerText = "enveloping interop payload";
        signedXml.AddObject(new DataObject("obj1", string.Empty, string.Empty, dataElement));

        Reference reference = new("#obj1") { DigestMethod = Sha256DigestUri };
        reference.AddTransform(new XmlDsigC14NTransform());
        signedXml.AddReference(reference);

        signedXml.KeyInfo!.AddClause(new RSAKeyValue(rsaKey));

        signedXml.ComputeSignature();

        XmlDocument outputDocument = new();
        outputDocument.AppendChild(outputDocument.ImportNode(signedXml.GetXml(), deep: true));

        return new XmlSignatureInteropCase(
            "EnvelopingRsaSha256C14N10KeyValue", Encoding.UTF8.GetBytes(outputDocument.OuterXml), XmlSignatureInteropShape.Enveloping, CryptoTags.RsaSha256Pkcs1Signature);
    }


    /// <summary>
    /// Mints an enveloping-signature case with two references: a <c>ds:Object</c> target (<c>URI="#obj1"</c>)
    /// and a second <c>ds:Object</c> reached only through its own <c>Id</c> attribute as a bare-name XPointer
    /// target (<c>URI="#target2"</c>) — the multi-reference shape the interop oracle requires.
    /// </summary>
    private static XmlSignatureInteropCase CreateEnvelopingMultiReferenceCase()
    {
        using ECDsa ecdsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 certificate = CreateSelfSignedEcdsaCertificate(ecdsaKey);

        XmlDocument document = new();
        SignedXml signedXml = new(document) { SigningKey = ecdsaKey };
        signedXml.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigC14NTransformUrl;
        signedXml.SignedInfo.SignatureMethod = XmlSignatureWellKnown.EcdsaSha256SignatureUri;

        XmlDocument contentDocument = new();
        XmlElement firstElement = contentDocument.CreateElement("ObjectPayload");
        firstElement.InnerText = "multi-reference object target";
        signedXml.AddObject(new DataObject("obj1", string.Empty, string.Empty, firstElement));

        XmlElement secondElement = contentDocument.CreateElement("BareNamePayload");
        secondElement.InnerText = "multi-reference bare-name target";
        signedXml.AddObject(new DataObject("target2", string.Empty, string.Empty, secondElement));

        Reference objectReference = new("#obj1") { DigestMethod = Sha256DigestUri };
        objectReference.AddTransform(new XmlDsigC14NTransform());
        signedXml.AddReference(objectReference);

        Reference bareNameReference = new("#target2") { DigestMethod = Sha256DigestUri };
        bareNameReference.AddTransform(new XmlDsigC14NTransform());
        signedXml.AddReference(bareNameReference);

        signedXml.KeyInfo!.AddClause(new KeyInfoX509Data(certificate));

        signedXml.ComputeSignature();

        XmlDocument outputDocument = new();
        outputDocument.AppendChild(outputDocument.ImportNode(signedXml.GetXml(), deep: true));

        return new XmlSignatureInteropCase(
            "EnvelopingEcdsaSha256C14N10MultiReferenceX509Data", Encoding.UTF8.GetBytes(outputDocument.OuterXml), XmlSignatureInteropShape.Enveloping, CryptoTags.P256Signature);
    }


    /// <summary>
    /// Mints a detached-same-document case: the <c>ds:Signature</c> and the referenced <c>Data</c> element
    /// are siblings under the same document element, neither containing the other, the Reference reaching
    /// its target through a bare-name <c>Id</c> XPointer.
    /// </summary>
    private static XmlSignatureInteropCase CreateDetachedSameDocumentCase(string name, string signatureMethodUri, string canonicalizationUri, bool useExclusive)
    {
        using AsymmetricAlgorithm key = CreateSigningKey(signatureMethodUri, out X509Certificate2 certificate);
        using(certificate)
        {
            XmlDocument document = new() { PreserveWhitespace = true };
            document.LoadXml("<Root><Data Id=\"payload\">detached interop payload</Data></Root>");

            SignedXml signedXml = new(document) { SigningKey = key };
            signedXml.SignedInfo!.CanonicalizationMethod = canonicalizationUri;
            signedXml.SignedInfo.SignatureMethod = signatureMethodUri;

            Reference reference = new("#payload") { DigestMethod = Sha256DigestUri };
            reference.AddTransform(useExclusive ? new XmlDsigExcC14NTransform() : new XmlDsigC14NTransform());
            signedXml.AddReference(reference);

            signedXml.KeyInfo!.AddClause(new KeyInfoX509Data(certificate));

            signedXml.ComputeSignature();
            document.DocumentElement!.AppendChild(document.ImportNode(signedXml.GetXml(), deep: true));

            return new XmlSignatureInteropCase(name, Encoding.UTF8.GetBytes(document.OuterXml), XmlSignatureInteropShape.DetachedSameDocument, KeyTagFor(signatureMethodUri));
        }
    }


    /// <summary>
    /// Mints the Canonical XML 1.1 case by hand — see the type remarks for why
    /// <see cref="SignedXml.ComputeSignature()"/> cannot produce this <c>CanonicalizationMethod</c> and what
    /// each of the three pieces (Reference digest, <c>SignedInfo</c> canonicalization, <c>SignatureValue</c>)
    /// is computed with.
    /// </summary>
    private static XmlSignatureInteropCase CreateHandAssembledC14N11Case(BaseMemoryPool pool)
    {
        const string dataElement = "<Data Id=\"payload\">c14n11 interop payload</Data>";

        using DigestValue referenceDigest = CryptographicKeyEvents.ComputeDigestAsync(
            Encoding.UTF8.GetBytes(dataElement), 32, CryptoTags.Sha256Digest, pool).AsTask().GetAwaiter().GetResult();
        string referenceDigestBase64 = Convert.ToBase64String(referenceDigest.AsReadOnlySpan());

        string signedInfoXml =
            "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">" +
            $"<CanonicalizationMethod Algorithm=\"{XmlSignatureWellKnown.CanonicalXml11Uri}\"/>" +
            $"<SignatureMethod Algorithm=\"{XmlSignatureWellKnown.RsaSha256SignatureUri}\"/>" +
            "<Reference URI=\"#payload\">" +
            $"<DigestMethod Algorithm=\"{Sha256DigestUri}\"/>" +
            $"<DigestValue>{referenceDigestBase64}</DigestValue>" +
            "</Reference>" +
            "</SignedInfo>";

        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(signedInfoXml), pool, out XmlNodeTable? signedInfoTable, out XmlReadError parseError);
        if(!isParsed || signedInfoTable is null)
        {
            throw new InvalidOperationException($"The hand-built SignedInfo fixture must parse, but failed with {parseError.Failure}.");
        }

        byte[] signedInfoCanonicalOctets;
        using(signedInfoTable)
        {
            bool isCanonicalized = XmlCanonicalization.TryCanonicalize(
                signedInfoTable, XmlNodeSet.WholeDocument(signedInfoTable), XmlCanonicalizationAlgorithm.CanonicalXml11, pool,
                out PooledMemory? canonicalOctets, out XmlCanonicalizationError canonicalizationError);
            if(!isCanonicalized || canonicalOctets is null)
            {
                throw new InvalidOperationException($"The hand-built SignedInfo fixture must canonicalize, but failed with {canonicalizationError.Failure}.");
            }

            using(canonicalOctets)
            {
                signedInfoCanonicalOctets = canonicalOctets.AsReadOnlySpan().ToArray();
            }
        }

        using RSA rsaKey = RSA.Create(2048);
        using X509Certificate2 certificate = CreateSelfSignedRsaCertificate(rsaKey);
        byte[] signatureValue = rsaKey.SignData(signedInfoCanonicalOctets, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        string certificateBase64 = Convert.ToBase64String(certificate.RawData);

        //SignedInfo's inner content (everything between its own opening and closing tag) is spliced,
        //unchanged, into an embedded <SignedInfo> that relies on Signature's xmlns instead of redeclaring
        //it — both forms canonicalize identically (see the type remarks), so this keeps the embedded
        //document's SignedInfo byte-for-byte the same element content the standalone parse canonicalized.
        const string signedInfoOpenTag = "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
        const string signedInfoCloseTag = "</SignedInfo>";
        string signedInfoInnerContent = signedInfoXml[signedInfoOpenTag.Length..^signedInfoCloseTag.Length];

        string documentXml = "<Root>" + dataElement +
            "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo>" +
            signedInfoInnerContent +
            "</SignedInfo>" +
            $"<SignatureValue>{Convert.ToBase64String(signatureValue)}</SignatureValue>" +
            $"<KeyInfo><X509Data><X509Certificate>{certificateBase64}</X509Certificate></X509Data></KeyInfo>" +
            "</Signature></Root>";

        return new XmlSignatureInteropCase(
            "HandAssembledRsaSha256C14N11SignedInfo", Encoding.UTF8.GetBytes(documentXml), XmlSignatureInteropShape.DetachedSameDocument, CryptoTags.RsaSha256Pkcs1Signature, IsPlatformVerifiable: false);
    }


    /// <summary>Creates the framework signing key <see cref="SignedXml"/> needs for <paramref name="signatureMethodUri"/> and a matching self-signed certificate.</summary>
    private static AsymmetricAlgorithm CreateSigningKey(string signatureMethodUri, out X509Certificate2 certificate)
    {
        if(XmlSignatureWellKnown.IsEcdsaSha256SignatureUri(signatureMethodUri))
        {
            ECDsa ecdsaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            certificate = CreateSelfSignedEcdsaCertificate(ecdsaKey);

            return ecdsaKey;
        }

        RSA rsaKey = RSA.Create(2048);
        certificate = CreateSelfSignedRsaCertificate(rsaKey);

        return rsaKey;
    }


    /// <summary>
    /// The house verification <see cref="Tag"/> of the framework key <see cref="CreateSigningKey"/> mints for
    /// <paramref name="signatureMethodUri"/> — this generator's own record of which algorithm signed, kept
    /// alongside the document rather than re-derived from the document's URI at verification time.
    /// </summary>
    private static Tag KeyTagFor(string signatureMethodUri) =>
        XmlSignatureWellKnown.IsEcdsaSha256SignatureUri(signatureMethodUri) ? CryptoTags.P256Signature : CryptoTags.RsaSha256Pkcs1Signature;


    /// <summary>Cert-factory carve-out (see the type remarks): a fresh self-signed RSA certificate over an already-minted framework key.</summary>
    private static X509Certificate2 CreateSelfSignedRsaCertificate(RSA rsaKey)
    {
        CertificateRequest request = new("CN=Verifiable XMLDSIG Interop", rsaKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();

        return request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
    }


    /// <summary>Cert-factory carve-out (see the type remarks): a fresh self-signed ECDSA certificate over an already-minted framework key.</summary>
    private static X509Certificate2 CreateSelfSignedEcdsaCertificate(ECDsa ecdsaKey)
    {
        CertificateRequest request = new("CN=Verifiable XMLDSIG Interop", ecdsaKey, HashAlgorithmName.SHA256);
        DateTimeOffset now = TimeProvider.System.GetUtcNow();

        return request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
    }
}
