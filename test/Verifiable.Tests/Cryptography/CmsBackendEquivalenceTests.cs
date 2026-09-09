using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Proves the CMS SignedData verification seam is provider-neutral across three independent backends: the
/// Microsoft backend (the default, over <c>SignedCms</c>), the BouncyCastle backend, and the fully managed
/// backend (own ASN.1 parse, delegating only the elliptic-curve primitive to the registered seam). All three
/// verify the same signed data and produce equivalent <see cref="CmsVerifiedContent"/> — the same content,
/// signer certificate, and signed attributes — so CAdES and eMRTD Passive Authentication, which depend only
/// on the verified-content shape, work over any backend unchanged.
/// </summary>
[TestClass]
internal sealed class CmsBackendEquivalenceTests
{
    private const string BouncyCastleQualifier = "BouncyCastle";
    private const string ManagedQualifier = "Managed";

    private static DateTimeOffset NotBefore { get; } = SyntheticPassportFactory.NotBefore;
    private static DateTimeOffset NotAfter { get; } = SyntheticPassportFactory.NotAfter;
    private static DateTimeOffset SigningTime { get; } = new(2025, 3, 14, 0, 0, 0, TimeSpan.Zero);


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task AllThreeBackendsVerifyTheSameSignedDataEquivalently()
    {
        //The key feeds CertificateRequest directly to mint the self-signed signer certificate (cert-factory carve-out).
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cross-backend content"u8, signerCertificate, SigningTime);

        using CmsVerifiedContent fromMicrosoft = await Resolve(qualifier: null)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromBouncyCastle = await Resolve(BouncyCastleQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromManaged = await Resolve(ManagedQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //Cross-check both the BouncyCastle and the managed backends against the Microsoft reference.
        AssertEquivalent(fromMicrosoft, fromBouncyCastle, "BouncyCastle");
        AssertEquivalent(fromMicrosoft, fromManaged, "managed");
    }


    /// <summary>
    /// The RSA arm of the same provider-neutrality, across the digest algorithms and key lengths
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119300_119399/119312/01.04.03_60/ts_119312v010403p.pdf">
    /// ETSI TS 119 312 V1.4.3</see> calls for: clause A.9 Table A.8 makes SHA-256 and SHA-512 with RSA the
    /// token-requester algorithms, and Tables 9-10 make 3&#160;072 bits the natural post-2025 modulus. The
    /// managed backend routes RSA to the registered hash-parameterized seam (RSASSA-PKCS1-v1_5, exponent
    /// 65537) and must agree with the two reference backends on every row.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf">ETSI EN 319 422 V1.1.1</see>
    /// 4.2.3-sigalg.
    /// </remarks>
    /// <param name="keySizeBits">The RSA modulus size the signer's key is minted at.</param>
    /// <param name="digestAlgorithmName">The digest algorithm the signer digests and signs under.</param>
    [TestMethod]
    [DataRow(2048, "SHA256")]
    [DataRow(3072, "SHA512")]
    [DataRow(4096, "SHA384")]
    public async Task AllThreeBackendsVerifyAnRsaSignedDataEquivalently(int keySizeBits, string digestAlgorithmName)
    {
        //The key feeds CertificateRequest directly to mint the self-signed signer certificate (cert-factory carve-out).
        using RSA signingKey = RSA.Create(keySizeBits);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES(
            "the cross-backend content"u8, signerCertificate, SigningTime, digestAlgorithm: new HashAlgorithmName(digestAlgorithmName));

        using CmsVerifiedContent fromMicrosoft = await Resolve(qualifier: null)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromBouncyCastle = await Resolve(BouncyCastleQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromManaged = await Resolve(ManagedQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //Cross-check both the BouncyCastle and the managed backends against the Microsoft reference.
        AssertEquivalent(fromMicrosoft, fromBouncyCastle, "BouncyCastle");
        AssertEquivalent(fromMicrosoft, fromManaged, "managed");
    }


    /// <summary>
    /// The managed backend's RSA acceptance band has a floor: a modulus below 2048 bits — below every strength
    /// ETSI TS 119 312 V1.4.3 Tables 9-10 keep legal — is refused as unsupported rather than verified. The
    /// reference backend verifies the very same structure, which is the difference between a policy floor and
    /// a broken signature.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf">ETSI EN 319 422 V1.1.1</see>
    /// 4.2.4-keylength.
    /// </remarks>
    [TestMethod]
    public async Task TheManagedBackendRefusesAnRsaModulusBelowTheAcceptanceBand()
    {
        //The key feeds CertificateRequest directly to mint the self-signed signer certificate (cert-factory carve-out).
        using RSA signingKey = RSA.Create(1024);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cross-backend content"u8, signerCertificate, SigningTime);

        using(CmsVerifiedContent fromMicrosoft = await Resolve(qualifier: null)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false))
        {
            Assert.IsGreaterThan(0, fromMicrosoft.Content.Length, "The reference backend verifies the sub-floor structure, so the managed refusal below is policy, not breakage.");
        }

        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await Resolve(ManagedQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "A modulus below the 2048-bit floor must be refused as unsupported, never verified.").ConfigureAwait(false);

        //The refusal is the acceptance band's own, not the former 2048-/4096-bit whitelist's "supports only"
        //message or an unrelated failure that happens to share the exception type.
        Assert.Contains("accepts RSA moduli from 2048 to 16384 bits", refusal.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// The positive half of the combined-identifier arms: a structure whose <c>SignerInfo</c> states the
    /// combined <c>shaNNNWithRSAEncryption</c> signature algorithm — the form independent CMS producers write,
    /// where the platform CMS signer writes the bare <c>rsaEncryption</c> — verifies through the managed
    /// backend for each of the three hashes, and equivalently through the reference backend. Without these
    /// rows only the bare-identifier arm would ever be exercised positively.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/319422/01.01.01_60/en_319422v010101p.pdf">ETSI EN 319 422 V1.1.1</see>
    /// 4.2.3-sigalg.
    /// </remarks>
    /// <param name="signatureAlgorithm">The BouncyCastle name of the combined RSA signature algorithm the structure is signed under.</param>
    [TestMethod]
    [DataRow("SHA256WITHRSA")]
    [DataRow("SHA384WITHRSA")]
    [DataRow("SHA512WITHRSA")]
    public async Task TheManagedBackendVerifiesCombinedRsaSignatureAlgorithmIdentifiers(string signatureAlgorithm)
    {
        using RSA authorityKey = RSA.Create(2048);
        using X509Certificate2 authority = CmsSignedDataTestFactory.MintSelfSignedTimeStampingCertificate(authorityKey, NotBefore, NotAfter);
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenWithRsaAuthorityAsync(
            authority, authorityKey, Encoding.UTF8.GetBytes("the combined-identifier fixture"), SigningTime,
            BaseMemoryPool.Shared, signatureAlgorithm, TestContext.CancellationToken).ConfigureAwait(false);

        using CmsSignedData carrier = CmsSignedData.FromBytes(token.AsReadOnlySpan(), BaseMemoryPool.Shared);
        using CmsVerifiedContent fromMicrosoft = await Resolve(qualifier: null)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromManaged = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        AssertEquivalent(fromMicrosoft, fromManaged, "managed");
    }


    /// <summary>
    /// The managed backend refuses a combined RSA signature algorithm whose pinned hash disagrees with the
    /// SignerInfo digest algorithm — the algorithm-substitution shape: a genuinely
    /// <c>sha512WithRSAEncryption</c>-signed structure whose signature algorithm octets are patched to
    /// <c>sha256WithRSAEncryption</c> names two different computations at once and is refused rather than
    /// resolved in either identifier's favor. The refusal is the
    /// <see href="https://www.rfc-editor.org/rfc/rfc6211#section-3.1">RFC 6211 §3.1</see> item 2 compare's
    /// own: the generator pinned the genuine identifier inside the signed <c>CMSAlgorithmProtection</c>
    /// attribute, so the patched, unsigned <c>SignerInfo</c> field disagrees with the signed copy — exactly
    /// the substitution §1 describes the attribute closing.
    /// </summary>
    /// <remarks>
    /// BouncyCastle 2.7.0 emits the <c>id-aa-cmsAlgorithmProtect</c> signed attribute
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6211#section-3">RFC 6211 §3</see>) alongside the
    /// SignerInfo signature algorithm the fixture patches, so the target OID's DER value occurs twice in the
    /// minted token.
    /// </remarks>
    [TestMethod]
    public async Task TheManagedBackendRefusesAnRsaSignatureAlgorithmDisagreeingWithTheDigestAlgorithm()
    {
        using RSA authorityKey = RSA.Create(3072);
        using X509Certificate2 authority = CmsSignedDataTestFactory.MintSelfSignedTimeStampingCertificate(authorityKey, NotBefore, NotAfter);

        //A combined-identifier structure: the independent BouncyCastle generator writes
        //sha512WithRSAEncryption as the SignerInfo signature algorithm, where the platform CMS signer would
        //write the bare rsaEncryption form.
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenWithRsaAuthorityAsync(
            authority, authorityKey, Encoding.UTF8.GetBytes("the algorithm-substitution fixture"), SigningTime,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //BouncyCastle 2.7.0 emits the RFC 6211 id-aa-cmsAlgorithmProtect signed attribute (OID
        //1.2.840.113549.1.9.52; see https://www.rfc-editor.org/rfc/rfc6211#section-3), so the
        //sha512WithRSAEncryption arc occurs twice in offset order: the protection attribute's pinned
        //signature-algorithm value inside signedAttrs first, then SignerInfo.signatureAlgorithm last. The DER
        //value octets of sha512WithRSAEncryption and sha256WithRSAEncryption differ only in their last octet,
        //so patching the last (SignerInfo.signatureAlgorithm) occurrence while the protection attribute keeps
        //naming the original produces exactly the disagreement shape under test.
        ReadOnlySpan<byte> sha512WithRsaOidValue = WellKnownOids.Sha512WithRsaEncryptionDerValue;
        ReadOnlySpan<byte> tokenSpan = token.AsReadOnlySpan();
        int matchIndex = -1;
        int matchCount = 0;
        for(int i = 0; i <= tokenSpan.Length - sha512WithRsaOidValue.Length; i++)
        {
            if(tokenSpan.Slice(i, sha512WithRsaOidValue.Length).SequenceEqual(sha512WithRsaOidValue))
            {
                matchIndex = i;
                matchCount++;
            }
        }

        Assert.AreEqual(2, matchCount, "The sha512WithRSAEncryption arc must occur exactly twice: the RFC 6211 CMSAlgorithmProtection signed attribute and the SignerInfo signature algorithm.");

        byte[] patched = tokenSpan.ToArray();
        patched[matchIndex + sha512WithRsaOidValue.Length - 1] = WellKnownOids.Sha256WithRsaEncryptionDerValue[^1];
        using CmsSignedData substituted = CmsSignedData.FromBytes(patched, BaseMemoryPool.Shared);

        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(
                    substituted, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "A combined signature algorithm disagreeing with the SignerInfo digest algorithm must be refused, never resolved in either's favor.").ConfigureAwait(false);

        //The refusal is the RFC 6211 §3.1 item 2 compare's own — the signed attribute pins
        //sha512WithRSAEncryption while the patched SignerInfo names sha256WithRSAEncryption — not the
        //signature failing to verify under the forged identifier's hash, which is what an implementation that
        //trusted the substituted identifier outright would report.
        Assert.Contains("CMSAlgorithmProtection attribute's signature algorithm does not match", refusal.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// The managed backend's own RSA profile rule — a combined identifier's pinned hash must agree with the
    /// SignerInfo digest algorithm — refuses the disagreement even when the RFC 6211 compare cannot see one:
    /// patching BOTH occurrences of the <c>sha512WithRSAEncryption</c> arc (the signed
    /// <c>CMSAlgorithmProtection</c> copy and the unsigned <c>SignerInfo</c> field) to
    /// <c>sha256WithRSAEncryption</c> leaves the two agreeing with each other while both disagree with the
    /// SHA-512 digest algorithm, so the <see href="https://www.rfc-editor.org/rfc/rfc6211#section-3.1">RFC
    /// 6211 §3.1</see> compare passes and the profile's identifier-agreement rule behind it is what refuses —
    /// the invariant holds for a shape the attribute cannot catch.
    /// </summary>
    [TestMethod]
    public async Task TheManagedBackendRefusesACombinedRsaIdentifierDisagreeingWithTheDigestAlgorithmWhenTheProtectionAttributeAgrees()
    {
        using RSA authorityKey = RSA.Create(3072);
        using X509Certificate2 authority = CmsSignedDataTestFactory.MintSelfSignedTimeStampingCertificate(authorityKey, NotBefore, NotAfter);
        using PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenWithRsaAuthorityAsync(
            authority, authorityKey, Encoding.UTF8.GetBytes("the agreeing-substitution fixture"), SigningTime,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ReadOnlySpan<byte> sha512WithRsaOidValue = WellKnownOids.Sha512WithRsaEncryptionDerValue;
        ReadOnlySpan<byte> tokenSpan = token.AsReadOnlySpan();
        byte[] patched = tokenSpan.ToArray();
        int matchCount = 0;
        for(int i = 0; i <= tokenSpan.Length - sha512WithRsaOidValue.Length; i++)
        {
            if(tokenSpan.Slice(i, sha512WithRsaOidValue.Length).SequenceEqual(sha512WithRsaOidValue))
            {
                patched[i + sha512WithRsaOidValue.Length - 1] = WellKnownOids.Sha256WithRsaEncryptionDerValue[^1];
                matchCount++;
            }
        }

        Assert.AreEqual(2, matchCount, "The sha512WithRSAEncryption arc must occur exactly twice: the RFC 6211 CMSAlgorithmProtection signed attribute and the SignerInfo signature algorithm, and both are patched so they agree with each other.");

        using CmsSignedData substituted = CmsSignedData.FromBytes(patched, BaseMemoryPool.Shared);
        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(
                    substituted, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "A combined signature algorithm disagreeing with the SignerInfo digest algorithm must be refused by the profile's own agreement rule when the protection attribute agrees with the substituted identifier.").ConfigureAwait(false);

        //The profile rule's refusal, reached because the patched attribute and SignerInfo agree — proving the
        //agreement invariant does not rest on the RFC 6211 compare alone.
        Assert.Contains("agreeing with the signature algorithm", refusal.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task TheManagedBackendVerifiesACAdESBaselineSignature()
    {
        //The key feeds CertificateRequest directly to mint the self-signed signer certificate (cert-factory carve-out).
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cross-backend content"u8, signerCertificate, SigningTime);

        //The managed backend surfaces the signing-certificate-v2 attribute CAdES checks, so the CAdES rules
        //hold over its verified content exactly as over the default backend.
        using CmsVerifiedContent verified = await Resolve(ManagedQualifier)(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verified.TryGetSignedAttribute(CmsSignedDataTestFactory.SigningCertificateV2Oid, out _), "The managed backend must surface the signing-certificate-v2 attribute CAdES depends on.");
    }


    [TestMethod]
    public async Task TheManagedBackendRejectsTamperedContent()
    {
        //The key feeds CertificateRequest directly to mint the self-signed signer certificate (cert-factory carve-out).
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdES("the cross-backend content"u8, signerCertificate, SigningTime);
        using CmsSignedData tampered = CmsSignedDataTestFactory.TamperContent(carrier, "the cross-backend content"u8);

        await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await Resolve(ManagedQualifier)(tampered, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            }).ConfigureAwait(false);
    }


    /// <summary>
    /// The same provider-neutrality over the DETACHED seam: all three backends verify one detached signature
    /// against the octets carried beside it and surface the same verified content, so a host may choose which
    /// of them an Associated Signature Container's CAdES objects are verified on.
    /// </summary>
    /// <returns>The running test.</returns>
    [TestMethod]
    public async Task AllThreeDetachedBackendsVerifyTheSameDetachedSignatureEquivalently()
    {
        //The key feeds CertificateRequest directly to mint the self-signed signer certificate (cert-factory carve-out).
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using SignedContentMemory content = SignedContentMemory.FromBytes("the cross-backend detached content"u8, BaseMemoryPool.Shared);
        using CmsSignedData carrier = CmsSignedDataTestFactory.SignAsCAdESDetached(content.AsReadOnlySpan(), signerCertificate, SigningTime);

        using CmsVerifiedContent fromMicrosoft = await ResolveDetached(qualifier: null)(carrier, content, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromBouncyCastle = await ResolveDetached(BouncyCastleQualifier)(carrier, content, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromManaged = await ResolveDetached(ManagedQualifier)(carrier, content, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        AssertEquivalent(fromMicrosoft, fromBouncyCastle, "BouncyCastle");
        AssertEquivalent(fromMicrosoft, fromManaged, "managed");
        Assert.AreEqual(
            Convert.ToHexString(content.AsReadOnlySpan()),
            Convert.ToHexString(fromMicrosoft.Content.Span),
            "The verified content of a detached signature is the octets the caller supplied.");
    }


    /// <summary>
    /// Every detached backend refuses a structure that encapsulates content of its own rather than checking it
    /// against the octets supplied beside it: two contents with only one of them checked is the shape a
    /// substitution attack takes, and the refusal has to hold whichever backend a host registered.
    /// </summary>
    /// <returns>The running test.</returns>
    [TestMethod]
    public async Task EveryDetachedBackendRefusesAStructureCarryingItsOwnContent()
    {
        //The key feeds CertificateRequest directly to mint the self-signed signer certificate (cert-factory carve-out).
        using ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(signingKey, NotBefore, NotAfter);
        using CmsSignedData encapsulating = CmsSignedDataTestFactory.SignAsCAdES("the cross-backend content"u8, signerCertificate, SigningTime);

        //The octets supplied beside the structure are the ones it encapsulates, which is the case a backend
        //that simply verified would accept: the message-digest attribute matches and the signature holds. The
        //refusal is a rule about the shape, not a consequence of a mismatch.
        using SignedContentMemory same = SignedContentMemory.FromBytes("the cross-backend content"u8, BaseMemoryPool.Shared);

        foreach(string? qualifier in new[] { null, BouncyCastleQualifier, ManagedQualifier })
        {
            VerifyDetachedCmsSignedDataDelegate verify = ResolveDetached(qualifier);
            await Assert.ThrowsExactlyAsync<CryptographicException>(
                async () =>
                {
                    using CmsVerifiedContent _ = await verify(encapsulating, same, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
                },
                $"The backend registered for qualifier '{qualifier ?? "(default)"}' must refuse a structure that carries its own content.").ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Asserts two verified-content results are equivalent: the same content type, content, signer
    /// certificate, and signed attributes (by object identifier and value).
    /// </summary>
    private static void AssertEquivalent(CmsVerifiedContent reference, CmsVerifiedContent other, string backendName)
    {
        Assert.AreEqual(reference.ContentType, other.ContentType, $"The {backendName} backend must report the same encapsulated content type.");
        Assert.AreEqual(Convert.ToHexString(reference.Content.Span), Convert.ToHexString(other.Content.Span), $"The {backendName} backend must surface the same encapsulated content.");
        Assert.IsTrue(
            reference.SignerCertificate.AsReadOnlyMemory().Span.SequenceEqual(other.SignerCertificate.AsReadOnlyMemory().Span),
            $"The {backendName} backend must surface the same signer certificate.");

        Assert.HasCount(reference.SignedAttributes.Count, other.SignedAttributes, $"The {backendName} backend must surface the same number of signed attributes.");
        foreach(CmsSignedAttribute attribute in reference.SignedAttributes)
        {
            Assert.IsTrue(other.TryGetSignedAttribute(attribute.AttributeType, out CmsSignedAttribute? match), $"The {backendName} backend must surface the signed attribute {attribute.AttributeType}.");
            Assert.IsTrue(attribute.AsReadOnlySpan().SequenceEqual(match!.AsReadOnlySpan()), $"The signed attribute {attribute.AttributeType} must have the same value under the {backendName} backend.");
        }
    }


    private static VerifyCmsSignedDataDelegate Resolve(string? qualifier) =>
        CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate), qualifier)
            ?? throw new InvalidOperationException($"No VerifyCmsSignedDataDelegate has been registered for qualifier '{qualifier ?? "(default)"}'.");


    /// <summary>
    /// Resolves the detached CMS verification backend registered under one qualifier.
    /// </summary>
    /// <param name="qualifier">The registration qualifier, or <see langword="null"/> for the default.</param>
    /// <returns>The registered backend.</returns>
    /// <exception cref="InvalidOperationException">Thrown when nothing is registered under that qualifier.</exception>
    private static VerifyDetachedCmsSignedDataDelegate ResolveDetached(string? qualifier) =>
        CryptographicKeyFactory.GetFunction<VerifyDetachedCmsSignedDataDelegate>(typeof(VerifyDetachedCmsSignedDataDelegate), qualifier)
            ?? throw new InvalidOperationException($"No VerifyDetachedCmsSignedDataDelegate has been registered for qualifier '{qualifier ?? "(default)"}'.");
}
