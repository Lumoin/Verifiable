using System;
using System.Buffers;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using AlgorithmIdentifier = Verifiable.Cryptography.Pki.AlgorithmIdentifier;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="CAdESSignatureCreation"/>: the CAdES-B-B three-phase creation split of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1</see> — <c>PrepareAsync</c>/<c>Complete</c>/<c>SignAsync</c> — and its algorithm
/// gating.
/// </summary>
/// <remarks>
/// <para>
/// The signing key under test is minted through <see cref="BouncyCastleKeyMaterialCreator"/> (the repo's
/// test-key convention), and a self-signed certificate carrying its exact public key is minted through a
/// platform <see cref="ECDsa"/>/<see cref="RSA"/> object reconstructed from that same key material — the
/// certificate-minting vehicle is platform code, but the key material the library signs with never comes
/// from it. Every produced signature is checked by at least two of three independent readers that share no
/// code with <see cref="CAdESSignatureCreation"/>: the platform <see cref="SignedCms"/> reader, the
/// independently-registered BouncyCastle <see cref="VerifyCmsSignedDataDelegate"/> backend, and the shipped
/// <see cref="CAdESVerification"/> path.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CAdESSignatureCreationTests
{
    /// <summary>The BouncyCastle-backed <see cref="VerifyCmsSignedDataDelegate"/> registration qualifier.</summary>
    private const string BouncyCastleQualifier = "BouncyCastle";

    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time every test's signature carries.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The content every attached test signs.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the CAdES creation content"u8.ToArray());


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A CAdES-B-B signature the convenience <c>SignAsync</c> produces over an ECDSA P-256 signer verifies
    /// under the platform <see cref="SignedCms"/> reader — a reader sharing no code with the creation surface.
    /// </summary>
    [TestMethod]
    public async Task AttachedEcdsaSignatureVerifiesUnderThePlatformCmsReader()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            var platformReader = new SignedCms();
            platformReader.Decode(signedData.AsReadOnlySpan().ToArray());
            platformReader.CheckSignature(verifySignatureOnly: true);

            Assert.HasCount(1, platformReader.SignerInfos, "Exactly one SignerInfo (clause 4.6: no degenerate no-signer case).");
            Assert.AreSequenceEqual(Content.ToArray(), platformReader.ContentInfo.Content, "The platform reader must recover the attached content unchanged.");
        }
    }


    /// <summary>
    /// The same signature verifies under the independently registered BouncyCastle CMS backend, and its
    /// verified content surfaces the ESS <c>signing-certificate-v2</c> attribute CAdES depends on.
    /// </summary>
    [TestMethod]
    public async Task AttachedEcdsaSignatureVerifiesUnderTheIndependentBouncyCastleOracle()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            using CmsVerifiedContent verified = await ResolveBouncyCastleVerifier()(signedData, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(Content.Span.SequenceEqual(verified.Content.Span), "The BouncyCastle oracle must recover the same attached content.");
            Assert.IsTrue(verified.TryGetSignedAttribute(CAdESSignatureFacts.SigningCertificateV2AttributeOid, out _), "The signed ESS signing-certificate-v2 attribute must survive an independent verifier.");
        }
    }


    /// <summary>
    /// The same signature reaches the shipped <see cref="CAdESVerification"/> path — the DoD requirement
    /// that this stage's output verifies through the production consumer, not only a hand-rolled reader.
    /// </summary>
    [TestMethod]
    public async Task AttachedEcdsaSignatureVerifiesUnderTheShippedCAdESVerificationPath()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(signedData, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsValid, $"The shipped CAdES-B-B verifier must accept the created signature (status: {result.Status}).");
            Assert.AreEqual(CAdESLevel.Baseline, result.Level, "No timestamp was attached, so the level is baseline.");
            Assert.AreEqual(SigningTime, result.SigningTime, "The signing-time attribute must round-trip.");
            Assert.IsTrue(certificate.AsReadOnlySpan().SequenceEqual(result.SignerCertificate!.AsReadOnlySpan()), "The bound signer certificate must be the one supplied at creation.");
        }
    }


    /// <summary>
    /// An RSA-2048 signer's CAdES-B-B signature verifies under both the platform reader and the independent
    /// BouncyCastle oracle — the non-elliptic-curve path through <c>Complete</c> needs no P1363-to-DER
    /// conversion, so this proves that branch is exercised and correct.
    /// </summary>
    [TestMethod]
    public async Task AttachedRsaSignatureVerifiesUnderThePlatformReaderAndTheBouncyCastleOracle()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintRsa2048Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            var platformReader = new SignedCms();
            platformReader.Decode(signedData.AsReadOnlySpan().ToArray());
            platformReader.CheckSignature(verifySignatureOnly: true);

            using CmsVerifiedContent verified = await ResolveBouncyCastleVerifier()(signedData, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(Content.Span.SequenceEqual(verified.Content.Span), "The BouncyCastle oracle must recover the same attached content for the RSA signer.");
        }
    }


    /// <summary>
    /// Proves the data-to-sign/signature-value split (R-3): phase (1)'s output is signed entirely OUTSIDE the
    /// library — a raw platform <see cref="ECDsa"/> operation on a key the registered signing seam never
    /// touches — and phase (2) assembles a signature that still verifies under both the platform reader and
    /// the BouncyCastle oracle. This is the shape a remote signer (CSC, ETSI TS 119 432) uses.
    /// </summary>
    [TestMethod]
    public async Task TheExternalSignerSplitProducesASignatureTheOraclesAccept()
    {
        using ECDsa externalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(externalKey, NotBefore, NotAfter);
        using PkiCertificateMemory certificate = ToPkiCertificate(platformCertificate.RawData, BaseMemoryPool.Shared);

        using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareAsync(
            certificate, Content, null, PkiDigestAlgorithm.Sha256, SigningTime, algorithmConstraints: null,
            cmsAlgorithmProtectionSignatureAlgorithmOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //Signed with the raw platform key directly — no SigningDelegate, no CryptoFunctionRegistry, nothing
        //the creation surface's own signing path touches.
        byte[] externalSignatureP1363 = externalKey.SignData(preparation.SigningInput.AsReadOnlySpan().ToArray(), HashAlgorithmName.SHA256);
        using IMemoryOwner<byte> externalSignatureDer = EcdsaSignatureEncoding.ConvertP1363ToDer(externalSignatureP1363, BaseMemoryPool.Shared, out int derLength);

        using CmsSignedData signedData = CAdESSignatureCreation.Complete(
            preparation, certificate, CryptoAlgorithm.P256, externalSignatureDer.Memory[..derLength], additionalCertificates: null, BaseMemoryPool.Shared);

        var platformReader = new SignedCms();
        platformReader.Decode(signedData.AsReadOnlySpan().ToArray());
        platformReader.CheckSignature(verifySignatureOnly: true);

        using CmsVerifiedContent verified = await ResolveBouncyCastleVerifier()(signedData, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(Content.Span.SequenceEqual(verified.Content.Span), "The externally-signed value must still bind the same content under an independent oracle.");
    }


    /// <summary>
    /// A detached signature (§4.5) omits <c>eContent</c> and still verifies under the platform reader when
    /// the original content is supplied externally — the standard .NET detached-CMS verification shape.
    /// </summary>
    [TestMethod]
    public async Task ADetachedSignatureOmitsEContentAndVerifiesExternally()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using DigestValue detachedDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                Content, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag, BaseMemoryPool.Shared,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, null, detachedDigest.AsReadOnlyMemory(), SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            var platformReader = new SignedCms(new ContentInfo(Content.ToArray()), detached: true);
            platformReader.Decode(signedData.AsReadOnlySpan().ToArray());
            platformReader.CheckSignature(verifySignatureOnly: true);
        }
    }


    /// <summary>MD5 is refused unconditionally as a creation-side digest (clause 6.2.1 SHALL NOT).</summary>
    [TestMethod]
    public async Task RefusesMd5AsACreationDigest()
    {
        var md5 = new PkiDigestAlgorithm(new AlgorithmIdentifier("1.2.840.113549.2.5"), CryptoTags.Sha256Digest, 16);
        using var certificate = MintP256Certificate();

        await Assert.ThrowsExactlyAsync<NotSupportedException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareAsync(
                certificate, Content, null, md5, SigningTime, algorithmConstraints: null,
                cmsAlgorithmProtectionSignatureAlgorithmOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// SHA-1 is refused as a creation-side digest; the consequence is that this surface never emits the
    /// SHA-1-only ESS <c>signing-certificate</c> v1 form (requirement i).
    /// </summary>
    [TestMethod]
    public async Task RefusesSha1AsACreationDigest()
    {
        using var certificate = MintP256Certificate();

        await Assert.ThrowsExactlyAsync<NotSupportedException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareAsync(
                certificate, Content, null, new PkiDigestAlgorithm(AlgorithmIdentifier.Sha1, CryptoTags.Sha256Digest, 20), SigningTime,
                algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// A caller-supplied cryptographic-constraints table that does not assert SHA-256 reliable at the signing
    /// instant refuses creation (ETSI EN 319 102-1 clause 5.1.4.3).
    /// </summary>
    [TestMethod]
    public async Task RefusesADigestTheCryptographicConstraintsTableDoesNotAssertReliable()
    {
        using var certificate = MintP256Certificate();
        var constraints = new CryptographicConstraints
        {
            Entries = [new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, null, TrustedUntil: SigningTime.AddDays(-1))]
        };

        await Assert.ThrowsExactlyAsync<NotSupportedException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareAsync(
                certificate, Content, null, PkiDigestAlgorithm.Sha256, SigningTime, constraints,
                cmsAlgorithmProtectionSignatureAlgorithmOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>A cryptographic-constraints table that DOES assert SHA-256 reliable at the signing instant lets creation proceed.</summary>
    [TestMethod]
    public async Task AcceptsADigestTheCryptographicConstraintsTableAssertsReliable()
    {
        using var certificate = MintP256Certificate();
        var constraints = new CryptographicConstraints
        {
            Entries = [new AlgorithmReliabilityEntry(AlgorithmIdentifier.Sha256, null, TrustedUntil: SigningTime.AddDays(1))]
        };

        using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareAsync(
            certificate, Content, null, PkiDigestAlgorithm.Sha256, SigningTime, constraints,
            cmsAlgorithmProtectionSignatureAlgorithmOid: null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsGreaterThan(0, preparation.SigningInput.Length, "A constraints table asserting the digest reliable must let preparation succeed.");
    }


    /// <summary>A signing algorithm this surface does not curate (Ed25519 — not a CAdES ECDSA/RSA algorithm) is refused.</summary>
    [TestMethod]
    public async Task RefusesASigningAlgorithmThisSurfaceDoesNotSupport()
    {
        using var certificate = MintP256Certificate();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ed25519Keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
        using(ed25519Keys.PublicKey)
        using(ed25519Keys.PrivateKey)
        {
            await Assert.ThrowsExactlyAsync<NotSupportedException>(async () =>
            {
                using CmsSignedData _ = await CAdESSignatureCreation.SignAsync(
                    certificate, ed25519Keys.PrivateKey, Content, null, SigningTime, additionalCertificates: null,
                    algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The ESS <c>signing-certificate-v2</c> attribute omits <c>issuerSerial</c> (requirement g) and omits the
    /// <c>hashAlgorithm</c> field for the default SHA-256 case (X.690 clause 11.5's DEFAULT-omission rule).
    /// </summary>
    [TestMethod]
    public async Task TheSigningCertificateV2AttributeOmitsIssuerSerialAndTheDefaultHashAlgorithm()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            VerifyCmsSignedDataDelegate verify = ResolveDefaultVerifier();
            using CmsVerifiedContent verified = await verify(signedData, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(verified.TryGetSignedAttribute(CAdESSignatureFacts.SigningCertificateV2AttributeOid, out CmsSignedAttribute? attribute));

            var reader = new AsnReader(attribute!.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader signingCertificate = reader.ReadSequence();
            AsnReader certs = signingCertificate.ReadSequence();
            AsnReader essCertId = certs.ReadSequence();

            //The default-omitted hashAlgorithm means the very first element is the certHash OCTET STRING, not a SEQUENCE.
            Assert.AreEqual(new Asn1Tag(UniversalTagNumber.OctetString), essCertId.PeekTag(), "The default SHA-256 hashAlgorithm must be omitted (X.690 clause 11.5).");
            _ = essCertId.ReadOctetString();
            Assert.IsFalse(essCertId.HasData, "issuerSerial must be omitted (requirement g).");
            Assert.IsFalse(certs.HasData, "Exactly one ESSCertIDv2.");
            Assert.IsFalse(signingCertificate.HasData, "The policies field shall not be used (clauses 5.2.2.2/.3).");
        }
    }


    /// <summary>The opt-in <c>cms-algorithm-protection</c> attribute (RFC 6211) is present only when requested, and names the correct digest/signature algorithm pair.</summary>
    [TestMethod]
    public async Task TheCmsAlgorithmProtectionAttributeIsAddedOnlyWhenRequested()
    {
        const string CmsAlgorithmProtectionOid = "1.2.840.113549.1.9.52";
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData withoutAttribute = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, null, null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);
            using CmsSignedData withAttribute = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, null, null, includeCmsAlgorithmProtection: true, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            VerifyCmsSignedDataDelegate verify = ResolveDefaultVerifier();
            using CmsVerifiedContent withoutVerified = await verify(withoutAttribute, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            using CmsVerifiedContent withVerified = await verify(withAttribute, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(withoutVerified.TryGetSignedAttribute(CmsAlgorithmProtectionOid, out _), "Opting out must not add the attribute.");
            Assert.IsTrue(withVerified.TryGetSignedAttribute(CmsAlgorithmProtectionOid, out CmsSignedAttribute? attribute), "Opting in must add the attribute.");

            var reader = new AsnReader(attribute!.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader protection = reader.ReadSequence();
            AsnReader digestAlgorithm = protection.ReadSequence();
            Assert.AreEqual(WellKnownOids.Sha256, digestAlgorithm.ReadObjectIdentifier(), "digestAlgorithm must name the digest this signer used.");
            AsnReader signatureAlgorithm = protection.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true));
            Assert.AreEqual("1.2.840.10045.4.3.2", signatureAlgorithm.ReadObjectIdentifier(), "signatureAlgorithm must name ecdsa-with-SHA256 for a P-256 signer.");
        }
    }


    /// <summary>
    /// <c>SignedData.certificates</c> carries the signer certificate first (requirement a) plus every
    /// supplied additional certificate, skipping an entry whose DER is identical to the signer's own
    /// (requirement e, avoiding duplication).
    /// </summary>
    [TestMethod]
    public async Task AdditionalCertificatesAreIncludedAndExactDuplicatesAreSkipped()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using ECDsa chainKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using X509Certificate2 platformChainCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(chainKey, NotBefore, NotAfter);
            using PkiCertificateMemory chainCertificate = ToPkiCertificate(platformChainCertificate.RawData, BaseMemoryPool.Shared);
            using PkiCertificateMemory duplicateOfSigner = ToPkiCertificate(certificate.AsReadOnlySpan(), BaseMemoryPool.Shared);

            using CAdESSignaturePreparation preparation = await CAdESSignatureCreation.PrepareAsync(
                certificate, Content, null, PkiDigestAlgorithm.Sha256, SigningTime, null, null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            byte[] p1363 = await SignWithPrivateKeyMaterialAsync(privateKey, preparation.SigningInput.AsReadOnlyMemory(), TestContext.CancellationToken).ConfigureAwait(false);
            using IMemoryOwner<byte> der = EcdsaSignatureEncoding.ConvertP1363ToDer(p1363, BaseMemoryPool.Shared, out int derLength);

            using CmsSignedData signedData = CAdESSignatureCreation.Complete(
                preparation, certificate, CryptoAlgorithm.P256, der.Memory[..derLength], [chainCertificate, duplicateOfSigner], BaseMemoryPool.Shared);

            var platformReader = new SignedCms();
            platformReader.Decode(signedData.AsReadOnlySpan().ToArray());
            platformReader.CheckSignature(verifySignatureOnly: true);

            Assert.HasCount(2, platformReader.Certificates, "The signer certificate plus the one distinct additional certificate; the exact duplicate is skipped.");
        }
    }


    /// <summary>Neither or both of <c>content</c>/<c>detachedContentDigest</c> is rejected (§4.5 requires exactly one).</summary>
    [TestMethod]
    public async Task PrepareRequiresExactlyOneOfContentOrDetachedDigest()
    {
        using var certificate = MintP256Certificate();

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareAsync(
                certificate, null, null, PkiDigestAlgorithm.Sha256, SigningTime, null, null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);

        byte[] digestBytes = new byte[32];
        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareAsync(
                certificate, Content, digestBytes, PkiDigestAlgorithm.Sha256, SigningTime, null, null, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    /// <summary>Both <c>SignedData.version</c> and <c>SignerInfo.version</c> are 1 (clause 4.4's NOTE: <c>id-data</c>, IssuerAndSerialNumber, no v1 attribute certificates).</summary>
    [TestMethod]
    public async Task TheCmsAndSignerInfoVersionsAreBothOne()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, null, null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            var reader = new AsnReader(signedData.AsReadOnlyMemory(), AsnEncodingRules.DER);
            AsnReader contentInfo = reader.ReadSequence();
            _ = contentInfo.ReadObjectIdentifier();
            AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            AsnReader cmsSignedData = explicitContent.ReadSequence();

            Assert.IsTrue(cmsSignedData.TryReadInt32(out int signedDataVersion));
            Assert.AreEqual(1, signedDataVersion, "SignedData.version must be 1.");

            _ = cmsSignedData.ReadSetOf();                 //digestAlgorithms
            _ = cmsSignedData.ReadSequence();               //encapContentInfo
            _ = cmsSignedData.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 0)); //certificates
            AsnReader signerInfos = cmsSignedData.ReadSetOf();
            AsnReader signerInfo = signerInfos.ReadSequence();
            Assert.IsTrue(signerInfo.TryReadInt32(out int signerInfoVersion));
            Assert.AreEqual(1, signerInfoVersion, "SignerInfo.version must be 1 (IssuerAndSerialNumber SignerIdentifier).");
        }
    }


    /// <summary>Resolves the registered BouncyCastle <see cref="VerifyCmsSignedDataDelegate"/> — an independent backend that shares no code with <see cref="CAdESSignatureCreation"/>.</summary>
    private static VerifyCmsSignedDataDelegate ResolveBouncyCastleVerifier() =>
        CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate), BouncyCastleQualifier)
            ?? throw new InvalidOperationException("No BouncyCastle VerifyCmsSignedDataDelegate has been registered.");


    /// <summary>Resolves the default-registered <see cref="VerifyCmsSignedDataDelegate"/>.</summary>
    private static VerifyCmsSignedDataDelegate ResolveDefaultVerifier() =>
        CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate))
            ?? throw new InvalidOperationException("No default VerifyCmsSignedDataDelegate has been registered.");


    /// <summary>
    /// Mints a P-256 signer certificate for a test that needs no signing key of its own (an algorithm-gating
    /// or <c>PrepareAsync</c>-only leg) — the private key half of <see cref="MintP256Signer"/> is minted and
    /// immediately disposed rather than left unused and undisposed.
    /// </summary>
    private static PkiCertificateMemory MintP256Certificate()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintP256Signer();
        privateKey.Dispose();

        return certificate;
    }


    /// <summary>
    /// Mints a P-256 signer: key material via <see cref="BouncyCastleKeyMaterialCreator"/> (the repo's test-key
    /// convention), and a self-signed certificate over the exact same public point, minted through a platform
    /// <see cref="ECDsa"/> reconstructed from the BouncyCastle-produced coordinates — the certificate vehicle
    /// is platform code, the key material the library signs with is not.
    /// </summary>
    private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintP256Signer()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using(keys.PublicKey)
        {
            byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(keys.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
            var ecParameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = keys.PrivateKey.AsReadOnlySpan().ToArray(),
                Q = new ECPoint
                {
                    X = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
                    Y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray()
                }
            };

            using ECDsa platformKey = ECDsa.Create(ecParameters);
            using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(platformKey, NotBefore, NotAfter);
            PkiCertificateMemory certificate = ToPkiCertificate(platformCertificate.RawData, BaseMemoryPool.Shared);

            return (certificate, keys.PrivateKey);
        }
    }


    /// <summary>
    /// Mints an RSA-2048 signer: key material via <see cref="BouncyCastleKeyMaterialCreator"/> (PKCS#1
    /// private key bytes, matching what <see cref="RSA.ImportRSAPrivateKey"/> expects directly), and a
    /// self-signed certificate over the same key minted through a platform <see cref="RSA"/> reconstructed
    /// from those bytes.
    /// </summary>
    private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintRsa2048Signer()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
        using(keys.PublicKey)
        {
            using RSA platformKey = RSA.Create();
            platformKey.ImportRSAPrivateKey(keys.PrivateKey.AsReadOnlySpan(), out _);

            using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(platformKey, NotBefore, NotAfter);
            PkiCertificateMemory certificate = ToPkiCertificate(platformCertificate.RawData, BaseMemoryPool.Shared);

            return (certificate, keys.PrivateKey);
        }
    }


    /// <summary>Signs <paramref name="dataToSign"/> with a raw <see cref="PrivateKeyMemory"/> through the registered signing seam, for a test that needs the resulting bytes rather than a full <see cref="CmsSignedData"/>.</summary>
    private static async ValueTask<byte[]> SignWithPrivateKeyMaterialAsync(PrivateKeyMemory privateKey, ReadOnlyMemory<byte> dataToSign, CancellationToken cancellationToken)
    {
        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);

        (Signature signature, CryptoEvent? _) = await signingDelegate(
            privateKey.AsReadOnlyMemory(), dataToSign, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        using(signature)
        {
            return signature.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>Copies DER bytes into a pooled <see cref="PkiCertificateMemory"/> tagged as an X.509 certificate.</summary>
    private static PkiCertificateMemory ToPkiCertificate(ReadOnlySpan<byte> der, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(der.Length);
        der.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}
