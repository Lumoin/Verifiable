using System.Buffers;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using Verifiable.Tests.Xml;
using Verifiable.Xml;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The real-wire E2E: builds complete, REAL XAdES-B-B/B-T/B-LT/B-LTA <c>ds:Signature</c> documents by hand —
/// real ECDSA P-256 keys and certificates (<see cref="X509ChainTestRing"/>), real per-reference digests and a
/// real <c>ds:SignatureValue</c> computed over the SHIPPED leaf's own canonicalization/reference-processing
/// engines (<see cref="XmlReferenceProcessing.TryComputeDigestInput(XmlNodeTable, XmlSignature, int,
/// XmlReferenceResolver?, BaseMemoryPool, out PooledMemory?, out XmlSignatureProcessingError)"/>/
/// <see cref="XmlReferenceProcessing.TryComputeSignedInfoOctets"/>), and a real in-process-minted
/// RFC 3161 token (<see cref="X509ChainTestRingTimestamping.MintTimestampTokenAsync"/>, the same
/// minting path the CAdES/CB-AdES LTA suites use) whose message imprint is computed by the SHIPPED <see
/// cref="XAdESSignatureTimeStampImprint"/>/<see cref="XAdESArchiveTimeStampImprint"/> engines — then
/// runs the WHOLE pipeline over those wires: <see cref="XAdESSignatureFactsDelegates.ParseAsync"/> → <see
/// cref="XAdESLevelRules.Check"/> at every candidate level (proving the ladder: a B-B wire classifies B-B but
/// not B-T, etc.) → <see cref="TimestampValidation.VerifyMessageImprintAsync"/> against the leaf-recomputed
/// imprint → cryptographic verification through BOTH the BCL-<c>SignedXml</c>-backed delegate (<see
/// cref="XAdESSignatureFactsDelegates.VerifyValueAsync"/>) AND a NEW house-engine-backed delegate (<see
/// cref="XAdESHouseEngineSignatureVerification.VerifyValueAsync"/>) → <see cref="XAdESLevelRules.Promote"/>.
/// </summary>
/// <remarks>
/// No platform XAdES producer exists: the XMLDSIG core signing is exercised by
/// <c>XmlSignatureInteropCorpusGenerator</c>/<c>XmlSignatureInteropOracleTests</c> against a real independent
/// signer, and XAdES-level content here derives from spec text/the acquired schemas — the implementation's own
/// oracle boundary, unchanged.
/// </remarks>
[TestClass]
internal sealed class XAdESRealWireEndToEndTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string DsNamespace = "http://www.w3.org/2000/09/xmldsig#";
    private const string DigestMethodUri = "http://www.w3.org/2001/04/xmlenc#sha256";
    private const string SignatureMethodUri = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
    private const string SignatureId = "Signature-1";
    private const string SignatureValueId = "SignatureValue-1";
    private const string PayloadObjectId = "Payload-1";
    private const string PayloadReferenceId = "Reference-Payload-1";
    private const string SignedPropertiesId = "SignedProperties-1";
    private const string SignedPropertiesReferenceId = "Reference-SignedProperties-1";
    private const string PayloadText = "The quick brown fox jumps over the lazy dog.";
    private const string PlaceholderBase64 = "AA==";

    private static string V132 => XAdESIdentifiers.XAdESNamespaceV132;

    private static string V141 => XAdESIdentifiers.XAdESNamespaceV141;

    //Canonical XML 1.1 is legal for a XAdES property container's OWN ds:CanonicalizationMethod (the leaf's own
    //six-URI clause-6.3(d) set) but the BCL ships NO transform for it at all (XmlSignatureInteropCorpusGenerator's
    //own remarks) -- so ds:SignedInfo's own CanonicalizationMethod, which the BCL-SignedXml delegate MUST also
    //canonicalize, uses Exclusive C14N 1.0 instead (ExclusiveCanonicalizationUri), while every property
    //container the leaf alone ever reads keeps using C14N 1.1 (CanonicalizationUri) to exercise a DIFFERENT one
    //of the six than the interop-oracle corpus already covers.
    private static string CanonicalizationUri => XmlSignatureIdentifiers.CanonicalXml11Uri;

    private static string ExclusiveCanonicalizationUri => XmlSignatureWellKnown.ExclusiveCanonicalXml10Uri;


    /// <summary>
    /// Registers the ECDSA-SHA256 <see cref="System.Security.Cryptography.SignatureDescription"/>
    /// <c>XmlSignatureInteropCorpusGenerator</c> also registers: the platform's own <see cref="CryptoConfig"/>
    /// table carries no built-in entry for <see cref="XmlSignatureWellKnown.EcdsaSha256SignatureUri"/>, so
    /// <see cref="System.Security.Cryptography.Xml.SignedXml.CheckSignature()"/> cannot resolve one without a
    /// caller registering it first — needed here because <see cref="XAdESSignatureFactsDelegates.VerifyValueAsync"/>
    /// composes <c>SignedXml</c> directly, and this test class never otherwise touches
    /// <c>XmlSignatureInteropCorpusGenerator</c>'s own static constructor.
    /// </summary>
    static XAdESRealWireEndToEndTests()
    {
        CryptoConfig.AddAlgorithm(typeof(EcdsaSha256SignatureDescription), XmlSignatureWellKnown.EcdsaSha256SignatureUri);
    }


    /// <summary>The signing/time-stamping material one test's ladder is minted under. Disposed by the caller.</summary>
    private sealed class Materials: IDisposable
    {
        public required X509ChainTestRingNode Root { get; init; }

        public required X509ChainTestRingNode Signer { get; init; }

        public required X509ChainTestRingNode Tsa { get; init; }

        public void Dispose()
        {
            Tsa.Dispose();
            Signer.Dispose();
            Root.Dispose();
        }
    }


    /// <summary>The fixed reference/signature-value fields every level of one ladder shares — computed once, over the B-B content, and never recomputed as unsigned properties are appended (the additive-augmentation shape clause 6.1 itself describes).</summary>
    private readonly record struct WireCore(
        string PayloadDigestBase64,
        string SignedPropertiesDigestBase64,
        string SignatureValueBase64,
        string SigningCertificateDigestBase64,
        string CertificateBase64,
        string SigningTimeIso);


    private static Materials CreateMaterials(FakeTimeProvider timeProvider)
    {
        X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
        X509ChainTestRingNode signer = X509ChainTestRing.CreateLeaf(root, "signer.example.com", timeProvider);
        X509ChainTestRingNode tsa = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider);

        return new Materials { Root = root, Signer = signer, Tsa = tsa };
    }


    private static PkiCertificateMemory ToCertificateCarrier(byte[] der, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Renders one complete enveloping <c>ds:Signature</c> document: a real payload <c>ds:Object</c>, a
    /// <c>SignedProperties</c> reference carrying the SignedProperties Type URI, <c>ds:KeyInfo</c> as
    /// <c>X509Data</c>, and every unsigned qualifying property block appended in order — the shape every level
    /// of the ladder shares, additively.
    /// </summary>
    private static string RenderDocument(
        WireCore core,
        IReadOnlyList<string> unsignedSignaturePropertyBlocks,
        string? payloadTextOverride = null,
        string? signingTimeOverride = null,
        bool includeSigningCertificateV2 = true,
        bool injectDeprecatedSigningCertificate = false,
        string? dataObjectFormatObjectReferenceOverride = null)
    {
        string unsignedBlock = unsignedSignaturePropertyBlocks.Count == 0
            ? string.Empty
            : $"""<xades:UnsignedProperties><xades:UnsignedSignatureProperties>{string.Join(string.Empty, unsignedSignaturePropertyBlocks)}</xades:UnsignedSignatureProperties></xades:UnsignedProperties>""";

        string deprecatedBlock = injectDeprecatedSigningCertificate ? "<xades:SigningCertificate/>" : string.Empty;
        string signingCertificateV2Block = includeSigningCertificateV2
            ? $"""
                <xades:SigningCertificateV2>
                  <xades:Cert>
                    <xades:CertDigest>
                      <ds:DigestMethod Algorithm="{DigestMethodUri}"/>
                      <ds:DigestValue>{core.SigningCertificateDigestBase64}</ds:DigestValue>
                    </xades:CertDigest>
                  </xades:Cert>
                </xades:SigningCertificateV2>
                """
            : string.Empty;

        return $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="{SignatureId}">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{ExclusiveCanonicalizationUri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodUri}"/>
                <ds:Reference Id="{PayloadReferenceId}" URI="#{PayloadObjectId}">
                  <ds:Transforms><ds:Transform Algorithm="{ExclusiveCanonicalizationUri}"/></ds:Transforms>
                  <ds:DigestMethod Algorithm="{DigestMethodUri}"/>
                  <ds:DigestValue>{core.PayloadDigestBase64}</ds:DigestValue>
                </ds:Reference>
                <ds:Reference Id="{SignedPropertiesReferenceId}" URI="#{SignedPropertiesId}" Type="{XAdESIdentifiers.SignedPropertiesTypeUri}">
                  <ds:Transforms><ds:Transform Algorithm="{ExclusiveCanonicalizationUri}"/></ds:Transforms>
                  <ds:DigestMethod Algorithm="{DigestMethodUri}"/>
                  <ds:DigestValue>{core.SignedPropertiesDigestBase64}</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue Id="{SignatureValueId}">{core.SignatureValueBase64}</ds:SignatureValue>
              <ds:KeyInfo>
                <ds:X509Data><ds:X509Certificate>{core.CertificateBase64}</ds:X509Certificate></ds:X509Data>
              </ds:KeyInfo>
              <ds:Object Id="{PayloadObjectId}">{payloadTextOverride ?? PayloadText}</ds:Object>
              <ds:Object>
                <xades:QualifyingProperties xmlns:xades="{V132}" xmlns:xades141="{V141}" Target="#{SignatureId}">
                  <xades:SignedProperties Id="{SignedPropertiesId}">
                    <xades:SignedSignatureProperties>
                      <xades:SigningTime>{signingTimeOverride ?? core.SigningTimeIso}</xades:SigningTime>
                      {deprecatedBlock}
                      {signingCertificateV2Block}
                    </xades:SignedSignatureProperties>
                    <xades:SignedDataObjectProperties>
                      <xades:DataObjectFormat ObjectReference="#{dataObjectFormatObjectReferenceOverride ?? PayloadReferenceId}">
                        <xades:MimeType>text/plain</xades:MimeType>
                      </xades:DataObjectFormat>
                    </xades:SignedDataObjectProperties>
                  </xades:SignedProperties>
                  {unsignedBlock}
                </xades:QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
    }


    /// <summary>
    /// The wrapping BLOCKER's own shape: the Type-marked SignedProperties <c>ds:Reference</c> targets a
    /// RELOCATED, genuinely-signed decoy <c>xades:SignedProperties</c> living outside any <c>QualifyingProperties</c>,
    /// while the DISCOVERED <c>QualifyingProperties</c> carries a DIFFERENT, forged <c>SignedProperties</c> the
    /// attacker fully controls. Both digests are computed FRESH off this exact document shape (never reused from
    /// <see cref="RenderDocument"/>'s own shape), so cryptographic verification genuinely succeeds regardless of
    /// canonicalization subtleties.
    /// </summary>
    private static string RenderWrappingDocument(WireCore core, string forgedSigningTime)
    {
        return $"""
            <ds:Signature xmlns:ds="{DsNamespace}" Id="{SignatureId}">
              <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="{ExclusiveCanonicalizationUri}"/>
                <ds:SignatureMethod Algorithm="{SignatureMethodUri}"/>
                <ds:Reference Id="{PayloadReferenceId}" URI="#{PayloadObjectId}">
                  <ds:Transforms><ds:Transform Algorithm="{ExclusiveCanonicalizationUri}"/></ds:Transforms>
                  <ds:DigestMethod Algorithm="{DigestMethodUri}"/>
                  <ds:DigestValue>{core.PayloadDigestBase64}</ds:DigestValue>
                </ds:Reference>
                <ds:Reference Id="{SignedPropertiesReferenceId}" URI="#{SignedPropertiesId}" Type="{XAdESIdentifiers.SignedPropertiesTypeUri}">
                  <ds:Transforms><ds:Transform Algorithm="{ExclusiveCanonicalizationUri}"/></ds:Transforms>
                  <ds:DigestMethod Algorithm="{DigestMethodUri}"/>
                  <ds:DigestValue>{core.SignedPropertiesDigestBase64}</ds:DigestValue>
                </ds:Reference>
              </ds:SignedInfo>
              <ds:SignatureValue Id="{SignatureValueId}">{core.SignatureValueBase64}</ds:SignatureValue>
              <ds:KeyInfo>
                <ds:X509Data><ds:X509Certificate>{core.CertificateBase64}</ds:X509Certificate></ds:X509Data>
              </ds:KeyInfo>
              <ds:Object Id="{PayloadObjectId}">{PayloadText}</ds:Object>
              <ds:Object>
                <xades:SignedProperties xmlns:xades="{V132}" Id="{SignedPropertiesId}">
                  <xades:SignedSignatureProperties>
                    <xades:SigningTime>{core.SigningTimeIso}</xades:SigningTime>
                  </xades:SignedSignatureProperties>
                  <xades:SignedDataObjectProperties>
                    <xades:DataObjectFormat ObjectReference="#{PayloadReferenceId}"><xades:MimeType>text/plain</xades:MimeType></xades:DataObjectFormat>
                  </xades:SignedDataObjectProperties>
                </xades:SignedProperties>
              </ds:Object>
              <ds:Object>
                <xades:QualifyingProperties xmlns:xades="{V132}" xmlns:xades141="{V141}" Target="#{SignatureId}">
                  <xades:SignedProperties Id="SignedProperties-Forged">
                    <xades:SignedSignatureProperties>
                      <xades:SigningTime>{forgedSigningTime}</xades:SigningTime>
                    </xades:SignedSignatureProperties>
                    <xades:SignedDataObjectProperties>
                      <xades:DataObjectFormat ObjectReference="#{PayloadReferenceId}"><xades:MimeType>text/plain</xades:MimeType></xades:DataObjectFormat>
                    </xades:SignedDataObjectProperties>
                  </xades:SignedProperties>
                </xades:QualifyingProperties>
              </ds:Object>
            </ds:Signature>
            """;
    }


    /// <summary>Parses a document into an <see cref="XmlNodeTable"/>/<see cref="XmlSignature"/> pair, asserting both steps succeed.</summary>
    private static (XmlNodeTable Table, XmlSignature Signature) ParseSignature(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError parseError);
        Assert.IsTrue(isParsed, $"The document must be well-formed XML but was refused with {parseError.Failure} at offset {parseError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices, "The document must carry exactly one ds:Signature.");

        bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError readError);
        Assert.IsTrue(isRead, $"The ds:Signature must read but was refused with {readError.Failure}.");

        return (table!, signature!);
    }


    private static async Task<string> ComputeReferenceDigestBase64Async(XmlNodeTable table, XmlSignature signature, int referenceOrdinal, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        bool isComputed = XmlReferenceProcessing.TryComputeDigestInput(table, signature, referenceOrdinal, resolver: null, pool, out PooledMemory? digestInput, out XmlSignatureProcessingError error);
        Assert.IsTrue(isComputed, $"Reference {referenceOrdinal}'s digest input must compute but was refused with {error.Failure}.");
        using(digestInput)
        {
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                digestInput!.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            return Convert.ToBase64String(digest.AsReadOnlySpan());
        }
    }


    /// <summary>Real ECDSA P-256 signing over the SHIPPED leaf's own canonical <c>ds:SignedInfo</c> octets — the raw-framework-signing carve-out <c>XmlSignatureInteropCorpusGenerator</c>/<c>X509ChainTestRing</c> already establish (an independent minter, never the library's own signature-VALUE creation).</summary>
    private static byte[] SignSignedInfo(string document, ECDsa signingKey, BaseMemoryPool pool)
    {
        (XmlNodeTable table, XmlSignature signature) = ParseSignature(document, pool);
        using(table)
        using(signature)
        {
            bool isComputed = XmlReferenceProcessing.TryComputeSignedInfoOctets(table, signature, pool, out PooledMemory? signedInfoOctets, out XmlSignatureProcessingError error);
            Assert.IsTrue(isComputed, $"ds:SignedInfo octets must compute but were refused with {error.Failure}.");
            using(signedInfoOctets)
            {
                return signingKey.SignData(signedInfoOctets!.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
            }
        }
    }


    /// <summary>
    /// Builds one real, fully-signed XAdES wire over an arbitrary <paramref name="render"/> function: computes
    /// the payload and SignedProperties reference digests via the shipped leaf engine over a placeholder
    /// document, then signs the resulting real <c>ds:SignedInfo</c> octets with a real ECDSA key — the same
    /// probe/sign/final three-phase shape for any render function whose first two <c>ds:SignedInfo</c>
    /// references are, in order, the payload and the <c>SignedProperties</c> reference (every render function
    /// in this file honours that ordering).
    /// </summary>
    private static async Task<(string Document, WireCore Core)> BuildCustomBBAsync(
        Materials materials, DateTimeOffset signingTime, BaseMemoryPool pool,
        Func<WireCore, string> render, CancellationToken cancellationToken)
    {
        string certificateBase64 = Convert.ToBase64String(materials.Signer.Certificate.RawData);
        using DigestValue certDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            materials.Signer.Certificate.RawData, 32, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        string certDigestBase64 = Convert.ToBase64String(certDigest.AsReadOnlySpan());
        string signingTimeIso = signingTime.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);

        var probeCore = new WireCore(PlaceholderBase64, PlaceholderBase64, PlaceholderBase64, certDigestBase64, certificateBase64, signingTimeIso);
        string probeDocument = render(probeCore);

        (XmlNodeTable probeTable, XmlSignature probeSignature) = ParseSignature(probeDocument, pool);
        string payloadDigestBase64;
        string signedPropertiesDigestBase64;
        using(probeTable)
        using(probeSignature)
        {
            payloadDigestBase64 = await ComputeReferenceDigestBase64Async(probeTable, probeSignature, 0, pool, cancellationToken).ConfigureAwait(false);
            signedPropertiesDigestBase64 = await ComputeReferenceDigestBase64Async(probeTable, probeSignature, 1, pool, cancellationToken).ConfigureAwait(false);
        }

        var unsignedCore = new WireCore(payloadDigestBase64, signedPropertiesDigestBase64, PlaceholderBase64, certDigestBase64, certificateBase64, signingTimeIso);
        string unsignedDocument = render(unsignedCore);
        byte[] signatureValue = SignSignedInfo(unsignedDocument, materials.Signer.SigningKey, pool);

        var finalCore = new WireCore(payloadDigestBase64, signedPropertiesDigestBase64, Convert.ToBase64String(signatureValue), certDigestBase64, certificateBase64, signingTimeIso);
        string finalDocument = render(finalCore);

        return (finalDocument, finalCore);
    }


    /// <summary>
    /// Builds one real, fully-signed XAdES-B-B wire using the standard <see cref="RenderDocument"/> shape — the
    /// <see cref="BuildCustomBBAsync"/> specialization every non-hardening test in this file uses.
    /// </summary>
    private static Task<(string Document, WireCore Core)> BuildBBAsync(
        Materials materials, DateTimeOffset signingTime, BaseMemoryPool pool, CancellationToken cancellationToken,
        bool includeSigningCertificateV2 = true)
    {
        return BuildCustomBBAsync(materials, signingTime, pool,
            core => RenderDocument(core, [], includeSigningCertificateV2: includeSigningCertificateV2), cancellationToken);
    }


    /// <summary>Locates and reads the sole <c>SignatureTimeStamp</c> unsigned property, computing its clause 5.3 message-imprint input through the SHIPPED leaf engine.</summary>
    private static byte[] ComputeSignatureTimeStampImprint(string document, BaseMemoryPool pool)
    {
        (XmlNodeTable table, XmlSignature signature) = ParseSignature(document, pool);
        using(table)
        using(signature)
        {
            XAdESUnsignedSignatureProperties unsignedSignatureProperties = DiscoverUnsignedSignatureProperties(table, signature, out _);
            int sigTstElementIndex = -1;
            for(int i = 0; i < unsignedSignatureProperties.Properties.Count; ++i)
            {
                if(unsignedSignatureProperties.Properties[i].Name == XAdESUnsignedSignaturePropertyName.SignatureTimeStamp)
                {
                    sigTstElementIndex = unsignedSignatureProperties.Properties[i].ElementIndex;

                    break;
                }
            }

            Assert.IsGreaterThanOrEqualTo(0, sigTstElementIndex, "The document must carry a SignatureTimeStamp.");

            bool isRead = XAdESSignatureTimeStamp.TryRead(table, sigTstElementIndex, pool, out XAdESSignatureTimeStamp? signatureTimeStamp, out XAdESReadError readError);
            Assert.IsTrue(isRead, $"SignatureTimeStamp must read but was refused with {readError.Failure}.");
            using(signatureTimeStamp)
            {
                bool isComputed = XAdESSignatureTimeStampImprint.TryComputeImprintInput(table, signature, signatureTimeStamp!, pool, out PooledMemory? imprintInput, out XAdESProcessingError imprintError);
                Assert.IsTrue(isComputed, $"The SignatureTimeStamp imprint must compute but was refused with {imprintError.Failure}.");
                using(imprintInput)
                {
                    return imprintInput!.AsReadOnlySpan().ToArray();
                }
            }
        }
    }


    /// <summary>Locates and reads the sole v1.4.1-namespace <c>ArchiveTimeStamp</c>, computing its clause 5.5.2.3 not-distributed message-imprint input through the SHIPPED leaf engine.</summary>
    private static byte[] ComputeArchiveTimeStampImprint(string document, BaseMemoryPool pool)
    {
        (XmlNodeTable table, XmlSignature signature) = ParseSignature(document, pool);
        using(table)
        using(signature)
        {
            XAdESUnsignedSignatureProperties unsignedSignatureProperties = DiscoverUnsignedSignatureProperties(table, signature, out int qualifyingPropertiesObjectOrdinal);
            int archiveTimeStampElementIndex = -1;
            for(int i = 0; i < unsignedSignatureProperties.Properties.Count; ++i)
            {
                int candidate = unsignedSignatureProperties.Properties[i].ElementIndex;
                if(XmlSignatureModelGrammar.IsElement(table, candidate, XAdESIdentifiers.XAdESNamespaceV141Utf8, "ArchiveTimeStamp"u8))
                {
                    archiveTimeStampElementIndex = candidate;

                    break;
                }
            }

            Assert.IsGreaterThanOrEqualTo(0, archiveTimeStampElementIndex, "The document must carry an ArchiveTimeStamp.");

            bool isRead = XAdESArchiveTimeStamp.TryRead(table, archiveTimeStampElementIndex, pool, out XAdESArchiveTimeStamp? archiveTimeStamp, out XAdESReadError readError);
            Assert.IsTrue(isRead, $"ArchiveTimeStamp must read but was refused with {readError.Failure}.");
            using(archiveTimeStamp)
            {
                bool isComputed = XAdESArchiveTimeStampImprint.TryComputeNotDistributedImprintInput(
                    table, signature, archiveTimeStamp!, unsignedSignatureProperties, qualifyingPropertiesObjectOrdinal, resolver: null, pool, out PooledMemory? imprintInput, out XAdESProcessingError imprintError);
                Assert.IsTrue(isComputed, $"The ArchiveTimeStamp imprint must compute but was refused with {imprintError.Failure}.");
                using(imprintInput)
                {
                    return imprintInput!.AsReadOnlySpan().ToArray();
                }
            }
        }
    }


    private static XAdESUnsignedSignatureProperties DiscoverUnsignedSignatureProperties(XmlNodeTable table, XmlSignature signature, out int qualifyingPropertiesObjectOrdinal)
    {
        bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table, signature, out XAdESQualifyingPropertiesDiscoveryResult discovery, out XAdESProcessingError discoveryError);
        Assert.IsTrue(isDiscovered && discovery.HasQualifyingProperties, $"QualifyingProperties must be discovered but was refused with {discoveryError.Failure}.");

        XAdESQualifyingProperties qualifyingProperties = discovery.QualifyingProperties;
        Assert.IsTrue(qualifyingProperties.HasUnsignedProperties && qualifyingProperties.UnsignedProperties.HasUnsignedSignatureProperties, "The document must carry UnsignedSignatureProperties.");

        qualifyingPropertiesObjectOrdinal = discovery.ObjectOrdinal;

        return qualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
    }


    /// <summary>The whole built ladder: the shared <see cref="WireCore"/> (so a test can re-render its own tampered variant from the SAME real digests/signature) plus the four rendered wires.</summary>
    private sealed record LadderIngredients(WireCore Core, string BB, string BT, string BLT, string BLTA);


    /// <summary>
    /// Builds the whole B-B→B-T→B-LT→B-LTA ladder over one real signer/TSA pair: B-B's own real digests and
    /// <c>ds:SignatureValue</c> never change across levels (additive augmentation, clause 6.1) — each higher
    /// level only appends real unsigned qualifying properties, including two genuinely minted RFC 3161 tokens
    /// (the SignatureTimeStamp and the ArchiveTimeStamp) whose message imprints the SHIPPED leaf engines compute.
    /// </summary>
    private static async Task<LadderIngredients> BuildLadderAsync(Materials materials, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        DateTimeOffset signingTime = TestClock.CanonicalEpoch;
        (string bbDocument, WireCore core) = await BuildBBAsync(materials, signingTime, pool, cancellationToken).ConfigureAwait(false);

        string canonicalizationBlock = $"""<ds:CanonicalizationMethod Algorithm="{CanonicalizationUri}"/>""";

        //B-T: mint a REAL RFC 3161 token over the SHIPPED SignatureTimeStamp imprint engine's own output.
        string sigTstProbeBlock = $"""<xades:SignatureTimeStamp>{canonicalizationBlock}<xades:EncapsulatedTimeStamp>{PlaceholderBase64}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>""";
        byte[] sigTstImprint = ComputeSignatureTimeStampImprint(RenderDocument(core, [sigTstProbeBlock]), pool);
        using PkiCertificateMemory sigTstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            materials.Tsa, [materials.Tsa], sigTstImprint, signingTime.AddHours(1), pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        string sigTstBlock = $"""<xades:SignatureTimeStamp>{canonicalizationBlock}<xades:EncapsulatedTimeStamp>{Convert.ToBase64String(sigTstToken.AsReadOnlySpan())}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>""";
        string btDocument = RenderDocument(core, [sigTstBlock]);

        //B-LT: pure structural augmentation -- neither block is ever digested by anything, so no crypto is needed.
        //TimeStampValidationData carries the TSA's OWN certificate (the validation data FOR the
        //time-stamp, distinct from CertificateValues' signer-chain material) so letter x)'s content-measured
        //service check is genuinely satisfied, not merely satisfied by an empty container's presence.
        string certificateValuesBlock = $"""<xades:CertificateValues><xades:EncapsulatedX509Certificate>{core.CertificateBase64}</xades:EncapsulatedX509Certificate></xades:CertificateValues>""";
        string tsaCertificateBase64 = Convert.ToBase64String(materials.Tsa.Certificate.RawData);
        string timeStampValidationDataBlock = $"""<xades141:TimeStampValidationData><xades:CertificateValues><xades:EncapsulatedX509Certificate>{tsaCertificateBase64}</xades:EncapsulatedX509Certificate></xades:CertificateValues></xades141:TimeStampValidationData>""";
        string bltDocument = RenderDocument(core, [sigTstBlock, certificateValuesBlock, timeStampValidationDataBlock]);

        //B-LTA: a SECOND real RFC 3161 token, this time over the ArchiveTimeStamp not-distributed imprint --
        //everything unsigned that precedes it (the SignatureTimeStamp, CertificateValues, TimeStampValidationData).
        string archiveProbeBlock = $"""<xades141:ArchiveTimeStamp>{canonicalizationBlock}<xades:EncapsulatedTimeStamp>{PlaceholderBase64}</xades:EncapsulatedTimeStamp></xades141:ArchiveTimeStamp>""";
        byte[] archiveImprint = ComputeArchiveTimeStampImprint(RenderDocument(core, [sigTstBlock, certificateValuesBlock, timeStampValidationDataBlock, archiveProbeBlock]), pool);
        using PkiCertificateMemory archiveToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            materials.Tsa, [materials.Tsa], archiveImprint, signingTime.AddHours(2), pool, cancellationToken: cancellationToken).ConfigureAwait(false);
        string archiveBlock = $"""<xades141:ArchiveTimeStamp>{canonicalizationBlock}<xades:EncapsulatedTimeStamp>{Convert.ToBase64String(archiveToken.AsReadOnlySpan())}</xades:EncapsulatedTimeStamp></xades141:ArchiveTimeStamp>""";
        string bltaDocument = RenderDocument(core, [sigTstBlock, certificateValuesBlock, timeStampValidationDataBlock, archiveBlock]);

        return new LadderIngredients(core, bbDocument, btDocument, bltDocument, bltaDocument);
    }


    private static async Task<XAdESQualifyingPropertiesFacts> ParseFactsAsync(string document, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        XAdESQualifyingPropertiesParseResult result = await XAdESSignatureFactsDelegates.ParseAsync(Encoding.UTF8.GetBytes(document), pool, cancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsParsed, $"The wire must parse but was refused with {result.FailureReason}.");

        return result.Facts!;
    }


    private static async Task<(SignatureCryptographicVerification Bcl, SignatureCryptographicVerification House)> VerifyBothDelegatesAsync(
        string document, PkiCertificateMemory signingCertificate, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] documentBytes = Encoding.UTF8.GetBytes(document);
        SignatureCryptographicVerification bcl = await XAdESSignatureFactsDelegates.VerifyValueAsync(documentBytes, signingCertificate, pool, cancellationToken).ConfigureAwait(false);
        SignatureCryptographicVerification house = await XAdESHouseEngineSignatureVerification.VerifyValueAsync(documentBytes, signingCertificate, pool, cancellationToken).ConfigureAwait(false);

        return (bcl, house);
    }


    /// <summary>The format-neutral projection <see cref="BoundProvenance.TryBindByCertificateDigestAsync"/> takes — <paramref name="facts"/>'s own <c>SigningCertificateV2</c> entries, format-neutral references only (mirrors <see cref="XAdESSignatureFactsDelegates"/>'s own <c>BuildFacts</c> projection).</summary>
    private static List<SigningCertificateReference> SignerReferences(XAdESQualifyingPropertiesFacts facts) =>
        facts.SigningCertificateDigests.Select(d => d.Reference).ToList();


    /// <summary>
    /// The gate call every genuinely-signed ladder rung makes WHILE <paramref name="facts"/> (the carrier
    /// owning the pooled signing-certificate memory <paramref name="cryptographicVerification"/> references) is
    /// still alive (carrier-lifetime rule): recomputes the certificate <paramref name="cryptographicVerification"/>
    /// carries and compares it against <paramref name="facts"/>'s own signed <c>SigningCertificateV2</c> signer
    /// reference. Asserts non-null -- every caller of this helper is on a rung the fixture built to bind
    /// genuinely, so a null here is a fixture defect, not an expected outcome.
    /// </summary>
    private static async Task<BoundProvenance> BindSignerAsync(
        XAdESQualifyingPropertiesFacts facts, SignatureCryptographicVerification cryptographicVerification, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        BoundProvenance? binding = await BoundProvenance.TryBindByCertificateDigestAsync(
            SignerReferences(facts), cryptographicVerification, facts, pool, cancellationToken).ConfigureAwait(false);
        Assert.IsNotNull(binding, "The gate must bind the genuinely-signed wire's own signer reference against the certificate its crypto outcome carries.");

        return binding!;
    }


    /// <summary>
    /// A <see cref="BoundProvenance"/> minted purely to satisfy <see cref="XAdESLevelRules.Promote"/>'s required
    /// parameter when a test is proving a DIFFERENT gating axis than identity (the cryptographic outcome, or
    /// Table 2 conformance) -- witnesses <paramref name="subject"/> so <see cref="Verified{T}.TryCreateBound"/>'s
    /// own witness check never itself becomes the reason a test refuses. Mirrors <c>XAdESLevelRulesTests</c>'s
    /// own identically-named helper. Never used where a genuine certificate-digest binding is the point.
    /// </summary>
    private static BoundProvenance WitnessOnlyBinding(object subject) =>
        BoundProvenance.TryBindByResolvedMethod(new KeyId("witness-only"), "witness-only", VerificationRelationship.SignerCertificate, subject)!;


    /// <summary>
    /// The level ladder itself: <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2. Proves, over REAL wires (not hand-shaped facts), that each
    /// level's own wire classifies as that level with zero violations while classifying as the NEXT level with at least
    /// one violation — the B-B wire is B-B but not B-T, the B-T wire is B-T but not B-LT, and so on — and that BOTH
    /// cryptographic-verification delegates (BCL <c>SignedXml</c> and the house engine) agree the signature verifies
    /// at every level, since level augmentation never touches the signed content.
    /// </summary>
    [TestMethod]
    public async Task EveryLevelOfTheLadderClassifiesExactlyItsOwnLevelOnBothVerificationDelegates()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using Materials materials = CreateMaterials(timeProvider);
        LadderIngredients ladder = await BuildLadderAsync(materials, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        (string Document, AdESBaselineLevel OwnLevel, AdESBaselineLevel NextLevel)[] rungs =
        [
            (ladder.BB, AdESBaselineLevel.BB, AdESBaselineLevel.BT),
            (ladder.BT, AdESBaselineLevel.BT, AdESBaselineLevel.BLT),
            (ladder.BLT, AdESBaselineLevel.BLT, AdESBaselineLevel.BLTA),
        ];

        foreach((string document, AdESBaselineLevel ownLevel, AdESBaselineLevel nextLevel) in rungs)
        {
            (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(SignatureCryptographicOutcome.Verified, house.Outcome, $"Level {ownLevel}: the house-engine delegate must verify: {house.Reason}");
            Assert.AreEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome, $"Level {ownLevel}: the BCL SignedXml delegate must verify: {bcl.Reason}");

            using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(document, pool, TestContext.CancellationToken).ConfigureAwait(false);
            IReadOnlyList<XAdESRuleViolation> ownViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = ownLevel, Facts = facts });
            Assert.IsEmpty(ownViolations, $"Level {ownLevel}'s own wire must satisfy level {ownLevel} with zero violations; got: {string.Join("; ", ownViolations.Select(v => v.Message))}");

            IReadOnlyList<XAdESRuleViolation> nextViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = nextLevel, Facts = facts });
            Assert.IsNotEmpty(nextViolations, $"Level {ownLevel}'s own wire must NOT satisfy the higher level {nextLevel}.");
        }

        //B-LTA: same shape, plus the ArchiveTimeStamp's own message imprint re-verified against the wire, since
        //this is the level clause 6.3 pins as "shall be present" for it, unlike every level below. Reaching it
        //at all is itself part of what this test proves: BuildLadderAsync mints a SECOND real RFC 3161 token
        //over the ArchiveTimeStamp not-distributed imprint -- had the token-minting path not supported that,
        //building the ladder above would already have failed.
        (SignatureCryptographicVerification bltaBcl, SignatureCryptographicVerification bltaHouse) = await VerifyBothDelegatesAsync(ladder.BLTA, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bltaBcl.Outcome, $"B-LTA: the BCL SignedXml delegate must verify: {bltaBcl.Reason}");
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bltaHouse.Outcome, $"B-LTA: the house-engine delegate must verify: {bltaHouse.Reason}");

        using XAdESQualifyingPropertiesFacts bltaFacts = await ParseFactsAsync(ladder.BLTA, pool, TestContext.CancellationToken).ConfigureAwait(false);
        IReadOnlyList<XAdESRuleViolation> bltaViolations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLTA, Facts = bltaFacts });
        Assert.IsEmpty(bltaViolations, $"The B-LTA wire must satisfy level B-LTA with zero violations; got: {string.Join("; ", bltaViolations.Select(v => v.Message))}");
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see>'s message-imprint binding end to end: <see cref="TimestampValidation.VerifyMessageImprintAsync"/>
    /// confirms BOTH real minted tokens (the B-T <c>SignatureTimeStamp</c> and the B-LTA <c>ArchiveTimeStamp</c>)
    /// were generated over exactly the octets the SHIPPED leaf's own imprint engines recompute from the FINAL
    /// wire — an independent re-derivation, not a reuse of the octets that were minted under.
    /// </summary>
    [TestMethod]
    public async Task BothMintedTokensMessageImprintsVerifyAgainstTheLeafRecomputedInputs()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using Materials materials = CreateMaterials(timeProvider);
        LadderIngredients ladder = await BuildLadderAsync(materials, pool, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] sigTstImprint = ComputeSignatureTimeStampImprint(ladder.BT, pool);
        using XAdESQualifyingPropertiesFacts btFacts = await ParseFactsAsync(ladder.BT, pool, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp sigTst = btFacts.Timestamps.Single(t => t.Class == SignatureTimestampClass.SignatureTimestamp);
        bool sigTstImprintVerified = await TimestampValidation.VerifyMessageImprintAsync(sigTst.Token, sigTstImprint, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(sigTstImprintVerified, "The SignatureTimeStamp token's message imprint must verify against the leaf-recomputed clause 5.3 imprint input.");

        byte[] archiveImprint = ComputeArchiveTimeStampImprint(ladder.BLTA, pool);
        using XAdESQualifyingPropertiesFacts bltaFacts = await ParseFactsAsync(ladder.BLTA, pool, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp archiveTst = bltaFacts.Timestamps.Single(t => t.Class == SignatureTimestampClass.ArchiveTimestamp);
        bool archiveImprintVerified = await TimestampValidation.VerifyMessageImprintAsync(archiveTst.Token, archiveImprint, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(archiveImprintVerified, "The ArchiveTimeStamp token's message imprint must verify against the leaf-recomputed clause 5.5.2.3 not-distributed imprint input.");
    }


    /// <summary>
    /// The <see cref="Verified{T}"/> tail over <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3's Table 2: <see cref="XAdESLevelRules.Promote"/> mints a
    /// proof-of-verification on the deepest reached, genuinely conformant B-LTA wire when handed a gate-produced <see
    /// cref="BoundProvenance"/>, and mints NOTHING when the cryptographic outcome it is handed did not itself conclude
    /// <see cref="SignatureCryptographicOutcome.Verified"/> — even though the SAME facts satisfy every Table 2
    /// rule at that level AND the supplied binding is genuinely valid. The minted <see cref="Verified{T}.Context"/>
    /// carries a <see cref="KeyId"/> the GATE derived from the identified certificate's own recomputed digest (<see
    /// cref="BoundProvenance.TryBindByCertificateDigestAsync"/>), never a caller-supplied label — matching an
    /// independently computed digest of the signer's certificate.
    /// </summary>
    [TestMethod]
    public async Task PromoteMintsVerifiedOnlyWhenBothTableConformanceAndCryptographyHold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using Materials materials = CreateMaterials(timeProvider);
        LadderIngredients ladder = await BuildLadderAsync(materials, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(ladder.BLTA, pool, TestContext.CancellationToken).ConfigureAwait(false);
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLTA, Facts = facts };

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(ladder.BLTA, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);

        BoundProvenance bclBinding = await BindSignerAsync(facts, bcl, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Verified<XAdESQualifyingPropertiesFacts>? promotedFromBcl = XAdESLevelRules.Promote(context, bcl, bclBinding);
        Assert.IsNotNull(promotedFromBcl, "Promote must mint a Verified<T> when the BCL delegate reports Verified, zero Table 2 violations hold, and the gate binds the signer reference.");
        Assert.AreSame(facts, promotedFromBcl!.Value.Value, "The minted Verified<T> must wrap the SAME facts instance, never a copy.");

        BoundProvenance houseBinding = await BindSignerAsync(facts, house, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Verified<XAdESQualifyingPropertiesFacts>? promotedFromHouse = XAdESLevelRules.Promote(context, house, houseBinding);
        Assert.IsNotNull(promotedFromHouse, "Promote must mint a Verified<T> when the house-engine delegate reports Verified, zero Table 2 violations hold, and the gate binds the signer reference.");

        using DigestValue expectedSignerDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            materials.Signer.Certificate.RawData, 32, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string expectedKeyId = Convert.ToHexStringLower(expectedSignerDigest.AsReadOnlySpan());

        Assert.IsTrue(promotedFromBcl.Value.Context.TryGet<KeyId>(out KeyId bclKeyId), "The gate must derive a KeyId from the identified certificate's own recomputed digest.");
        Assert.AreEqual(expectedKeyId, bclKeyId.Value);
        Assert.IsTrue(promotedFromHouse.Value.Context.TryGet<KeyId>(out KeyId houseKeyId), "The gate must derive a KeyId from the identified certificate's own recomputed digest.");
        Assert.AreEqual(expectedKeyId, houseKeyId.Value);

        //Promote's own outcome gate refuses independently of the binding's own validity: bclBinding above is a
        //genuinely gate-produced, validly-witnessed BoundProvenance for these SAME facts, yet handing it to a
        //non-Verified outcome still mints nothing (Promote owns outcome/Table-2 gating, the gate owns
        //identity gating, and neither substitutes for the other).
        var unverifiedOutcome = new SignatureCryptographicVerification { Outcome = SignatureCryptographicOutcome.SignatureValueFailure, Reason = "synthetic refusal" };
        Verified<XAdESQualifyingPropertiesFacts>? refused = XAdESLevelRules.Promote(context, unverifiedOutcome, bclBinding);
        Assert.IsNull(refused, "Promote must mint nothing when the cryptographic outcome is not Verified, even though the SAME facts are fully Table-2-conformant and the supplied binding is genuinely valid.");
    }


    /// <summary>
    /// Negative E2E over <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-CoreValidation">
    /// XML Signature Syntax and Processing (Second Edition) §3.2.1</see>'s per-reference digest check: a payload
    /// byte changed after signing — the classic substitution attack — is refused by BOTH cryptographic-
    /// verification delegates (a per-reference digest mismatch), never silently accepted, and
    /// <see cref="XAdESLevelRules.Promote"/> mints nothing over it.
    /// </summary>
    [TestMethod]
    public async Task TamperedPayloadByteIsRefusedByBothVerificationDelegates()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using Materials materials = CreateMaterials(timeProvider);
        (string bbDocument, WireCore core) = await BuildBBAsync(materials, TestClock.CanonicalEpoch, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        //The stored ds:DigestValue was computed over the ORIGINAL payload text; substituting different text
        //here changes the canonical octets the reference covers while the stored digest stays stale.
        string tampered = RenderDocument(core, [], payloadTextOverride: "The quick brown fox jumps over a suspicious dog.");

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(tampered, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome, "The BCL delegate must refuse a tampered payload.");
        Assert.AreEqual(SignatureCryptographicOutcome.HashFailure, house.Outcome, "The house-engine delegate must refuse specifically with a per-reference hash failure.");

        using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(tampered, pool, TestContext.CancellationToken).ConfigureAwait(false);
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };

        //Two independent refusals prove "no mint over tampered input" without weakening either gate: the gate
        //ITSELF refuses to even produce a binding from a non-Verified outcome (TryBindByCertificateDigestAsync's
        //own first check) --
        BoundProvenance? tamperedBinding = await BoundProvenance.TryBindByCertificateDigestAsync(
            SignerReferences(facts), house, facts, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsNull(tamperedBinding, "The gate must refuse to bind when the cryptographic outcome it is handed is not Verified (a per-reference hash failure).");

        //-- and separately, Promote's OWN outcome gate refuses even when HANDED a technically-valid (witness-only)
        //binding, proving the outcome check does not rely on the binding having failed to reach its refusal.
        Assert.IsNull(XAdESLevelRules.Promote(context, house, WitnessOnlyBinding(facts)), "Promote must mint nothing over a tampered payload, even given a witnessed binding.");

        //Sanity: the ORIGINAL, untampered B-B wire this fixture also produced verifies cleanly.
        (SignatureCryptographicVerification originalBcl, SignatureCryptographicVerification originalHouse) = await VerifyBothDelegatesAsync(bbDocument, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, originalBcl.Outcome);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, originalHouse.Outcome);
    }


    /// <summary>
    /// Negative E2E over <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3's XA-6.3-t03 (<c>ds:Reference</c>, cardinality &#8805; 2):
    /// <c>SignedProperties</c> content (the claimed <c>SigningTime</c>) changed after signing is refused by BOTH
    /// cryptographic-verification delegates — the SignedProperties reference's own digest no longer matches,
    /// exactly the same substitution shape as the payload tamper but over the OTHER of Table 2's two mandatory
    /// <c>ds:Reference</c>s.
    /// </summary>
    [TestMethod]
    public async Task TamperedSignedPropertiesContentIsRefusedByBothVerificationDelegates()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using Materials materials = CreateMaterials(timeProvider);
        (_, WireCore core) = await BuildBBAsync(materials, TestClock.CanonicalEpoch, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        string tampered = RenderDocument(core, [], signingTimeOverride: "2099-01-01T00:00:00Z");

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(tampered, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome, "The BCL delegate must refuse tampered SignedProperties.");
        Assert.AreEqual(SignatureCryptographicOutcome.HashFailure, house.Outcome, "The house-engine delegate must refuse specifically with a per-reference hash failure.");
    }


    /// <summary>
    /// Delegate parity: a document genuinely, validly signed end-to-end under the ATTACKER's own key —
    /// every per-reference digest and the <c>ds:SignatureValue</c> itself verify cleanly against the attacker's
    /// own <c>ds:KeyInfo</c>-embedded certificate — but the caller identifies the VICTIM's certificate as the
    /// signing certificate, exactly Table 14's own "Signing Certificate" input, the value an earlier building
    /// block would have identified. <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 5.2.7.4/Table 14 states the signing certificate as an INPUT to
    /// verification, not something the wire gets to choose: a delegate that re-derives the key from
    /// <c>ds:KeyInfo</c> instead of the supplied <c>signingCertificate</c> would wrongly report <c>Verified</c>
    /// and mint a <see cref="Verified{XAdESQualifyingPropertiesFacts}"/> recording the wrong provenance. BOTH
    /// delegates must refuse identically (<see cref="SignatureCryptographicOutcome.SignatureValueFailure"/>).
    /// </summary>
    [TestMethod]
    public async Task AttackerKeyInfoDocumentIsRefusedByBothDelegatesWhenCalledWithTheVictimCertificate()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using Materials attacker = CreateMaterials(timeProvider);
        using Materials victim = CreateMaterials(timeProvider);
        (string document, _) = await BuildBBAsync(attacker, TestClock.CanonicalEpoch, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory victimCertificate = ToCertificateCarrier(victim.Signer.Certificate.RawData, pool);

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, victimCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.SignatureValueFailure, bcl.Outcome, "The BCL delegate must refuse a signature verified under the wrong certificate.");
        Assert.AreEqual(SignatureCryptographicOutcome.SignatureValueFailure, house.Outcome, "The house-engine delegate must refuse a signature verified under the wrong certificate, not silently re-derive the key from ds:KeyInfo.");

        //Sanity: the SAME document verifies cleanly on both delegates when called with the ATTACKER's own
        //certificate -- the document itself is genuinely, validly signed; only the wrong-certificate call fails.
        using PkiCertificateMemory attackerCertificate = ToCertificateCarrier(attacker.Signer.Certificate.RawData, pool);
        (SignatureCryptographicVerification bclOwn, SignatureCryptographicVerification houseOwn) = await VerifyBothDelegatesAsync(document, attackerCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bclOwn.Outcome);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, houseOwn.Outcome);
    }


    /// <summary>
    /// A document carrying TWO <c>ds:Signature</c> elements is refused by BOTH cryptographic-verification
    /// delegates with <see cref="SignatureCryptographicOutcome.SignedDataNotFound"/> — the BCL test delegate's
    /// own single-<c>ds:Signature</c> guard now agrees with the house engine's own <c>FindSignatures.Length
    /// != 1</c> refusal (the "agree beyond the crypto-compute axis"), pinning the twin's agreement even
    /// on an adversarial input neither delegate is ever actually asked to agree on in the real pipeline —
    /// <see cref="XAdESSignatureFactsDelegates.ParseAsync"/> independently refuses multi-signature documents at
    /// fact-extraction time, so no facts and no <see cref="Verified{T}"/> are ever produced over such a wire.
    /// </summary>
    [TestMethod]
    public async Task MultiSignatureDocumentIsRefusedByBothVerificationDelegates()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using Materials materials = CreateMaterials(timeProvider);
        (string firstDocument, _) = await BuildBBAsync(materials, TestClock.CanonicalEpoch, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (string secondDocument, _) = await BuildBBAsync(materials, TestClock.CanonicalEpoch.AddMinutes(1), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        string document = $"<Wrapper>{firstDocument}{secondDocument}</Wrapper>";

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.SignedDataNotFound, bcl.Outcome, "The BCL delegate must refuse a document carrying more than one ds:Signature, not silently verify the first.");
        Assert.AreEqual(SignatureCryptographicOutcome.SignedDataNotFound, house.Outcome, "The house-engine delegate must refuse a document carrying more than one ds:Signature.");
    }


    /// <summary>
    /// Negative E2E over <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 5.3's <c>SignatureTimeStamp</c>: a corrupted <c>EncapsulatedTimeStamp</c>
    /// token is refused at TIME-STAMP verification, not at signature verification — the token's own octets are
    /// never covered by any <c>ds:Reference</c>, so <c>ds:Signature</c> cryptographic verification legitimately
    /// still succeeds; only opening/validating the corrupted token itself fails, proving the pipeline refuses at
    /// the RIGHT layer.
    /// </summary>
    [TestMethod]
    public async Task TamperedTimestampTokenIsRefusedAtTimestampVerificationNotSignatureVerification()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using Materials materials = CreateMaterials(timeProvider);
        LadderIngredients ladder = await BuildLadderAsync(materials, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        using XAdESQualifyingPropertiesFacts btFacts = await ParseFactsAsync(ladder.BT, pool, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp sigTst = btFacts.Timestamps.Single(t => t.Class == SignatureTimestampClass.SignatureTimestamp);
        byte[] tokenBytes = sigTst.Token.AsReadOnlySpan().ToArray();
        tokenBytes[^8] ^= 0xFF;
        string corruptedTokenBase64 = Convert.ToBase64String(tokenBytes);

        string canonicalizationBlock = $"""<ds:CanonicalizationMethod Algorithm="{CanonicalizationUri}"/>""";
        string corruptedBlock = $"""<xades:SignatureTimeStamp>{canonicalizationBlock}<xades:EncapsulatedTimeStamp>{corruptedTokenBase64}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>""";
        string corrupted = RenderDocument(ladder.Core, [corruptedBlock]);

        //The RIGHT layer: ds:Signature cryptographic verification still succeeds, because SignatureTimeStamp's
        //own octets are outside every ds:Reference.
        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(corrupted, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome, "Corrupting the token must not affect ds:Signature verification.");
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, house.Outcome, "Corrupting the token must not affect ds:Signature verification.");

        byte[] recomputedImprint = ComputeSignatureTimeStampImprint(corrupted, pool);
        using XAdESQualifyingPropertiesFacts corruptedFacts = await ParseFactsAsync(corrupted, pool, TestContext.CancellationToken).ConfigureAwait(false);
        EmbeddedTimestamp corruptedSigTst = corruptedFacts.Timestamps.Single(t => t.Class == SignatureTimestampClass.SignatureTimestamp);
        bool imprintVerified = await TimestampValidation.VerifyMessageImprintAsync(corruptedSigTst.Token, recomputedImprint, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(imprintVerified, "The corrupted token must be refused at message-imprint verification.");
    }


    /// <summary>
    /// Negative E2E over <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3's XA-6.3-t06 (<c>SigningCertificateV2</c>, clause 5.2.2, shall
    /// be present): a Table 2 <see cref="AdESPresence.ShallBePresent"/> row removed from an otherwise genuinely,
    /// cryptographically valid signature is refused at BASELINE CLASSIFICATION, not at cryptographic
    /// verification — the document is internally self-consistent (its own digests and signature value are real
    /// and correct over its own, smaller content), proving the two checks are independent layers that each catch
    /// what the other cannot.
    /// </summary>
    [TestMethod]
    public async Task MissingMandatoryTable2PropertyIsRefusedAtClassificationNotAtCryptographicVerification()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using Materials materials = CreateMaterials(timeProvider);
        (string document, _) = await BuildBBAsync(materials, TestClock.CanonicalEpoch, pool, TestContext.CancellationToken, includeSigningCertificateV2: false).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome, "A self-consistent, genuinely-signed document must still cryptographically verify even though it is not baseline-conformant.");
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, house.Outcome, "A self-consistent, genuinely-signed document must still cryptographically verify even though it is not baseline-conformant.");

        using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(document, pool, TestContext.CancellationToken).ConfigureAwait(false);
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts });
        Assert.ContainsSingle(
            v => v is XAdESRowPresenceViolation presence && presence.Row.RequirementId == "XA-6.3-t06" && presence.IsMissing,
            violations,
            "Removing SigningCertificateV2 must be reported as its own Table 2 XA-6.3-t06 presence violation.");

        //The fixture omits SigningCertificateV2 entirely (includeSigningCertificateV2: false), so there is no
        //signer reference for the gate to bind against at all -- a WitnessOnlyBinding isolates the axis this
        //test is actually proving (Check()'s own Table 2 gating), independent of identity binding.
        Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts }, house, WitnessOnlyBinding(facts));
        Assert.IsNull(promoted, "Promote must mint nothing over a non-baseline-conformant signature, even when cryptographically Verified and handed a witnessed binding.");
    }


    /// <summary>
    /// Negative E2E over <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 4.3.4's fixed <c>SignedSignatureProperties</c> sequence: a deprecated V1
    /// <c>SigningCertificate</c> qualifying property injected alongside its V2 replacement is refused at READ time
    /// (the recognized-and-refused posture), before cryptographic verification or Table 2 classification is ever
    /// reached — the earliest layer this pipeline offers.
    /// </summary>
    [TestMethod]
    public void DeprecatedQualifyingPropertyInjectionIsRefusedAtReadTime()
    {
        var core = new WireCore(PlaceholderBase64, PlaceholderBase64, PlaceholderBase64, PlaceholderBase64, PlaceholderBase64, "2024-01-15T10:30:00Z");
        string document = RenderDocument(core, [], injectDeprecatedSigningCertificate: true);
        byte[] documentBytes = Encoding.UTF8.GetBytes(document);

        //Whole-pipeline entry point: the composition root refuses the document outright.
        XAdESQualifyingPropertiesParseResult result = XAdESSignatureFactsDelegates.ParseAsync(documentBytes, BaseMemoryPool.Shared, TestContext.CancellationToken).AsTask().GetAwaiter().GetResult();
        using(result)
        {
            Assert.IsFalse(result.IsParsed, "A deprecated SigningCertificate alongside SigningCertificateV2 must be refused at read time, never silently accepted.");
        }

        //The read-layer root cause: discovery wraps the structural container refusal as MalformedQualifyingProperties
        //(XAdESQualifyingPropertiesDiscovery's own remarks), carrying the ACTUAL cause -- SignedSignatureProperties'
        //own DeprecatedQualifyingProperty refusal (clause 4.3.4) -- as its InnerQualifyingPropertiesReadError.
        bool isParsed = XmlNodeTable.TryParse(documentBytes, BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError parseError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {parseError.Failure}.");
        using(table)
        {
            int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
            Assert.HasCount(1, signatureIndices);
            bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError readError);
            Assert.IsTrue(isRead, $"The ds:Signature must read but was refused with {readError.Failure}.");
            using(signature)
            {
                bool isDiscovered = XAdESQualifyingPropertiesDiscovery.TryDiscover(table!, signature!, out XAdESQualifyingPropertiesDiscoveryResult discovery, out XAdESProcessingError discoveryError);
                Assert.IsFalse(isDiscovered, "Discovery must refuse a QualifyingProperties element whose own SignedSignatureProperties carries a deprecated child.");
                Assert.AreEqual(XAdESProcessingFailure.MalformedQualifyingProperties, discoveryError.Failure);
                Assert.IsNotNull(discoveryError.InnerQualifyingPropertiesReadError, "The wrapping refusal must carry the structural container read's own inner refusal.");
                Assert.AreEqual(XAdESReadFailure.DeprecatedQualifyingProperty, discoveryError.InnerQualifyingPropertiesReadError!.Value.Failure);
            }
        }
    }


    /// <summary>
    /// Negative E2E over the wrapping BLOCKER: the Type-marked SignedProperties
    /// <c>ds:Reference</c> dereferences to a genuinely-signed decoy element — every reference digests the node
    /// its <c>URI</c> names, so BOTH cryptographic-verification delegates genuinely verify — while the
    /// DISCOVERED <c>QualifyingProperties</c> carries a DIFFERENT, attacker-forged <c>SignedProperties</c>.
    /// <see cref="XAdESLevelRules.Check"/> reports the clause 4.4.2 table-identity binding pin failure and
    /// <see cref="XAdESLevelRules.Promote"/> mints nothing, closing the gap clause 4.3.1/4.4.2 of
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> exist to prevent.
    /// </summary>
    [TestMethod]
    public async Task WrappingDocumentBindingFailureRefusesPromotionAndClassifiesViolation()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Materials materials = CreateMaterials(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);
        const string forgedSigningTime = "2099-01-01T00:00:00Z";

        (string document, _) = await BuildCustomBBAsync(materials, TestClock.CanonicalEpoch, pool,
            core => RenderWrappingDocument(core, forgedSigningTime), TestContext.CancellationToken).ConfigureAwait(false);

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome, "The wrapping wire's ds:Signature must still cryptographically verify -- every ds:Reference digests the node its URI names.");
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, house.Outcome, "The wrapping wire's ds:Signature must still cryptographically verify -- every ds:Reference digests the node its URI names.");

        using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(document, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(facts.Discovery.SignedPropertiesReferenceResolvedToDiscoveredNode, "The Type-matching reference must dereference to the decoy, not the discovered SignedProperties.");

        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);
        Assert.Contains(
            v => v is XAdESQualifyingPropertiesBindingViolation b && b.Failure == XAdESQualifyingPropertiesBindingFailure.SignedPropertiesReferenceNotBoundToDiscoveredNode,
            violations);

        //The wrapping fixture's forged SignedProperties carries no SigningCertificateV2 either -- there is no
        //signer reference for the gate to bind against, so a WitnessOnlyBinding isolates the axis this test
        //proves (the clause 4.4.2 table-identity binding pin Check() reports), independent of identity binding.
        Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(context, house, WitnessOnlyBinding(facts));
        Assert.IsNull(promoted, "Promote must mint nothing over a wire whose SignedProperties binding failed, even though the ds:Signature itself genuinely verifies.");
    }


    /// <summary>
    /// Negative E2E over clause 6.3's XA-6.3-02: a genuinely-signed B-B wire carrying an indirectly-incorporated
    /// <c>QualifyingPropertiesReference</c> sibling of the direct <c>QualifyingProperties</c>. <see
    /// cref="XAdESLevelRules.Check"/> reports the indirect-incorporation violation and <see cref="XAdESLevelRules.Promote"/>
    /// mints nothing, even though cryptographic verification and every other Table 2 rule hold.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3, XA-6.3-02.
    /// </summary>
    [TestMethod]
    public async Task IndirectIncorporationRefusesPromotionAndClassifiesViolation()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Materials materials = CreateMaterials(new FakeTimeProvider(TestClock.CanonicalEpoch));
        (string bbDocument, _) = await BuildBBAsync(materials, TestClock.CanonicalEpoch, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        //Never digested by anything -- a sibling of QualifyingProperties within the SAME ds:Object, resolved
        //document-wide only by discovery, which never dispatches on it beyond counting it.
        string document = bbDocument.Replace(
            "</xades:QualifyingProperties>",
            $"""</xades:QualifyingProperties><xades:QualifyingPropertiesReference xmlns:xades="{V132}" URI="http://elsewhere.example/qp.xml#qp1"/>""",
            StringComparison.Ordinal);

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, house.Outcome);

        using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(document, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(1, facts.Discovery.QualifyingPropertiesReferenceCount);

        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);
        Assert.Contains(v => v is XAdESIndirectIncorporationViolation i && i.QualifyingPropertiesReferenceCount == 1, violations);

        BoundProvenance binding = await BindSignerAsync(facts, house, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(context, house, binding);
        Assert.IsNull(promoted, "Promote must mint nothing over a signature carrying an indirectly-incorporated QualifyingPropertiesReference, even though the gate genuinely binds.");
    }


    /// <summary>
    /// Negative E2E over clause 6.3's XA-6.3-04: a genuinely-signed B-T-shaped wire whose sole <c>SignatureTimeStamp</c>
    /// entry is an <c>XMLTimeStamp</c> rather than an <c>EncapsulatedTimeStamp</c>. <see cref="XAdESLevelRules.Check"/>
    /// reports the non-RFC-3161-only violation and <see cref="XAdESLevelRules.Promote"/> mints nothing at B-T, even
    /// though the property's own wire OCCURRENCE satisfies Table 2 row XA-6.3-t24's presence/cardinality cell.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3, XA-6.3-04.
    /// </summary>
    [TestMethod]
    public async Task XmlTimeStampOnlyContainerRefusesPromotionAndClassifiesViolation()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Materials materials = CreateMaterials(new FakeTimeProvider(TestClock.CanonicalEpoch));
        (_, WireCore core) = await BuildBBAsync(materials, TestClock.CanonicalEpoch, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        string canonicalizationBlock = $"""<ds:CanonicalizationMethod Algorithm="{CanonicalizationUri}"/>""";
        string xmlTimeStampBlock = $"""<xades:SignatureTimeStamp>{canonicalizationBlock}<xades:XMLTimeStamp><foo/></xades:XMLTimeStamp></xades:SignatureTimeStamp>""";
        string document = RenderDocument(core, [xmlTimeStampBlock]);

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, house.Outcome);

        using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(document, pool, TestContext.CancellationToken).ConfigureAwait(false);
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BT, Facts = facts };
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);
        Assert.Contains(
            v => v is XAdESTimestampContainerNotRfc3161OnlyViolation r && r.Kind == XAdESTimestampContainerKind.SignatureTimeStamp,
            violations);

        BoundProvenance binding = await BindSignerAsync(facts, house, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(context, house, binding);
        Assert.IsNull(promoted, "Promote must mint nothing over a SignatureTimeStamp whose sole entry is an XMLTimeStamp, not an RFC 3161 token, even though the gate genuinely binds.");
    }


    /// <summary>
    /// Negative E2E over clause 6.3 letter k): a genuinely-signed wire whose sole <c>DataObjectFormat</c>
    /// targets the EXCLUDED <c>SignedProperties</c> reference instead of the payload reference it must cover. <see
    /// cref="XAdESLevelRules.Check"/> reports the coverage-bijection violation and <see cref="XAdESLevelRules.Promote"/>
    /// mints nothing.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, XA-6.3-t08, letter k.
    /// </summary>
    [TestMethod]
    public async Task DataObjectFormatCoverageViolationRefusesPromotionAndClassifiesLetterK()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Materials materials = CreateMaterials(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        (string document, _) = await BuildCustomBBAsync(materials, TestClock.CanonicalEpoch, pool,
            core => RenderDocument(core, [], dataObjectFormatObjectReferenceOverride: SignedPropertiesReferenceId), TestContext.CancellationToken).ConfigureAwait(false);

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, house.Outcome);

        using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(document, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(facts.IsDataObjectFormatCoverageSatisfied, "The sole DataObjectFormat targets the excluded SignedProperties reference, not the payload reference it must cover.");

        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);
        Assert.Contains(v => v is XAdESDataObjectFormatCoverageViolation, violations);

        BoundProvenance binding = await BindSignerAsync(facts, house, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(context, house, binding);
        Assert.IsNull(promoted, "Promote must mint nothing when the sole DataObjectFormat targets the excluded SignedProperties reference instead of the payload it must cover, even though the gate genuinely binds.");
    }


    /// <summary>
    /// Negative E2E over clause 6.3 letter m): a genuinely-signed wire carrying a <c>SignaturePolicyStore</c> with NO
    /// <c>SignaturePolicyIdentifier</c> at all. <see cref="XAdESLevelRules.Check"/> reports the legality violation and
    /// <see cref="XAdESLevelRules.Promote"/> mints nothing.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, XA-6.3-t23, letter m.
    /// </summary>
    [TestMethod]
    public async Task SignaturePolicyStoreWithoutIdentifierRefusesPromotionAndClassifiesLetterM()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Materials materials = CreateMaterials(new FakeTimeProvider(TestClock.CanonicalEpoch));
        (_, WireCore core) = await BuildBBAsync(materials, TestClock.CanonicalEpoch, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        string signaturePolicyStoreBlock = """
            <xades141:SignaturePolicyStore>
              <xades141:SPDocSpecification><xades:Identifier>urn:oid:1.2.3.4</xades:Identifier></xades141:SPDocSpecification>
              <xades141:SigPolDocLocalURI>http://example.com/policy-store</xades141:SigPolDocLocalURI>
            </xades141:SignaturePolicyStore>
            """;
        string document = RenderDocument(core, [signaturePolicyStoreBlock]);

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, house.Outcome);

        using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(document, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsNull(facts.SignaturePolicy, "The fixture deliberately carries no SignaturePolicyIdentifier.");

        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BB, Facts = facts };
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);
        Assert.Contains(v => v is XAdESSignaturePolicyStoreLegalityViolation, violations);

        BoundProvenance binding = await BindSignerAsync(facts, house, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(context, house, binding);
        Assert.IsNull(promoted, "Promote must mint nothing over a SignaturePolicyStore incorporated without a SignaturePolicyIdentifier, even though the gate genuinely binds.");
    }


    /// <summary>
    /// Negative E2E over clause 6.3 letter n): a genuinely-signed wire whose sole <c>SignatureTimeStamp</c> carries TWO
    /// electronic time-stamp entries. <see cref="XAdESLevelRules.Check"/> reports the cardinality violation and <see
    /// cref="XAdESLevelRules.Promote"/> mints nothing, even though Table 2 row XA-6.3-t24's own "&#8805;1" cardinality
    /// is satisfied by the count.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, XA-6.3-t24, letter n.
    /// </summary>
    [TestMethod]
    public async Task SignatureTimeStampWithTwoTokensRefusesPromotionAndClassifiesLetterN()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Materials materials = CreateMaterials(new FakeTimeProvider(TestClock.CanonicalEpoch));
        (_, WireCore core) = await BuildBBAsync(materials, TestClock.CanonicalEpoch, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        string canonicalizationBlock = $"""<ds:CanonicalizationMethod Algorithm="{CanonicalizationUri}"/>""";
        string doubledSigTstBlock =
            $"""<xades:SignatureTimeStamp>{canonicalizationBlock}<xades:EncapsulatedTimeStamp>{PlaceholderBase64}</xades:EncapsulatedTimeStamp><xades:EncapsulatedTimeStamp>{PlaceholderBase64}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>""";
        string document = RenderDocument(core, [doubledSigTstBlock]);

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, house.Outcome);

        using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(document, pool, TestContext.CancellationToken).ConfigureAwait(false);
        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BT, Facts = facts };
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);
        Assert.Contains(v => v is XAdESSignatureTimeStampCardinalityViolation c && c.TokenCount == 2, violations);

        BoundProvenance binding = await BindSignerAsync(facts, house, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(context, house, binding);
        Assert.IsNull(promoted, "Promote must mint nothing over a SignatureTimeStamp carrying two electronic time-stamps, even though the gate genuinely binds.");
    }


    /// <summary>
    /// Negative E2E over clause 6.3 letter x)/clause 6.1 c): a B-T-shaped wire augmented with real
    /// <c>CertificateValues</c> but an EMPTY <c>TimeStampValidationData</c> — a container satisfying the service
    /// by mere presence rather than content. <see cref="XAdESLevelRules.Check"/> reports the validation-data
    /// service violation at B-LT and <see cref="XAdESLevelRules.Promote"/> mints nothing.
    /// Anchored to <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, XA-6.3-t40, letter x, and clause 6.1 c).
    /// </summary>
    [TestMethod]
    public async Task EmptyTimeStampValidationDataRefusesPromotionAndClassifiesLetterX()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Materials materials = CreateMaterials(new FakeTimeProvider(TestClock.CanonicalEpoch));
        (_, WireCore core) = await BuildBBAsync(materials, TestClock.CanonicalEpoch, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory signingCertificate = ToCertificateCarrier(materials.Signer.Certificate.RawData, pool);

        string canonicalizationBlock = $"""<ds:CanonicalizationMethod Algorithm="{CanonicalizationUri}"/>""";
        string sigTstBlock = $"""<xades:SignatureTimeStamp>{canonicalizationBlock}<xades:EncapsulatedTimeStamp>{PlaceholderBase64}</xades:EncapsulatedTimeStamp></xades:SignatureTimeStamp>""";
        string certificateValuesBlock = $"""<xades:CertificateValues><xades:EncapsulatedX509Certificate>{core.CertificateBase64}</xades:EncapsulatedX509Certificate></xades:CertificateValues>""";
        string emptyTimeStampValidationDataBlock = "<xades141:TimeStampValidationData/>";
        string document = RenderDocument(core, [sigTstBlock, certificateValuesBlock, emptyTimeStampValidationDataBlock]);

        (SignatureCryptographicVerification bcl, SignatureCryptographicVerification house) = await VerifyBothDelegatesAsync(document, signingCertificate, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, bcl.Outcome);
        Assert.AreEqual(SignatureCryptographicOutcome.Verified, house.Outcome);

        using XAdESQualifyingPropertiesFacts facts = await ParseFactsAsync(document, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(facts.ValidationDataForTimestampsHasContent, "An empty TimeStampValidationData must not be recorded as content.");

        var context = new XAdESLevelRuleContext { Level = AdESBaselineLevel.BLT, Facts = facts };
        IReadOnlyList<XAdESRuleViolation> violations = XAdESLevelRules.Check(context);
        Assert.Contains(v => v is XAdESValidationDataServiceViolation, violations);

        BoundProvenance binding = await BindSignerAsync(facts, house, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Verified<XAdESQualifyingPropertiesFacts>? promoted = XAdESLevelRules.Promote(context, house, binding);
        Assert.IsNull(promoted, "Promote must mint nothing at B-LT when TimeStampValidationData is present but carries no content, even though the gate genuinely binds.");
    }
}
