using System;
using System.Buffers;
using System.Collections.Generic;
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

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for parallel signers — a CMS <c>SignedData</c> whose <c>signerInfos</c> holds more than
/// one <c>SignerInfo</c> over the same encapsulated content
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">RFC 5652 §5.1</see>), each a whole CAdES
/// signer of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1</see>, as distinct from the <c>countersignature</c> of clause 5.2.7, which signs
/// another signature's value.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every structure here is produced by the shipped surfaces</strong> — the multi-signer
/// <see cref="CAdESSignatureCreation.Complete(IReadOnlyList{CAdESSignerCompletion}, IReadOnlyList{PkiCertificateMemory}?, MemoryPool{byte})"/>,
/// the parallel three-phase split
/// (<see cref="CAdESSignatureCreation.PrepareParallelSignatureAsync"/> /
/// <see cref="CAdESSignatureCreation.CompleteParallelSignature"/> /
/// <see cref="CAdESSignatureCreation.AddParallelSignatureAsync(CmsSignedData, PkiCertificateMemory, PrivateKeyMemory, DigestValue?, DateTimeOffset, CryptographicConstraints?, bool, MemoryPool{byte}, CancellationToken, CAdESOptionalSignedAttributes?)"/>),
/// <see cref="CmsSignedDataAugmentation.AddSignerInfo"/> and
/// <see cref="CmsSignedDataReduction.SelectSigner"/> — over key material from
/// <see cref="BouncyCastleKeyMaterialCreator"/>, the repository's test-key convention.
/// </para>
/// <para>
/// <strong>What verifies what.</strong> The platform <see cref="SignedCms"/> reader verifies every signer of
/// the whole structure at once, sharing no code with the creation surfaces. The shipped
/// <see cref="CAdESVerification.VerifyAsync"/> path and the independently registered BouncyCastle
/// <see cref="VerifyCmsSignedDataDelegate"/> each verify one signature, so each signer of a multi-signer
/// structure reaches them through <see cref="CmsSignedDataReduction.SelectSigner"/>'s projection — which is
/// itself under test: a projection that altered any covered octet would fail those verifications.
/// Byte-preservation is asserted against the raw octets directly.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CAdESParallelSignatureTests
{
    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time the first signer states.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The signing time the parallel signer states, later the way a second party's signature is.</summary>
    private static DateTimeOffset ParallelSigningTime { get; } = TestClock.CanonicalEpoch.AddMinutes(45);

    /// <summary>The content every signer here signs.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the parallel-signed CAdES content"u8.ToArray());

    /// <summary>The registration qualifier of the independent BouncyCastle CMS backend.</summary>
    private static string BouncyCastleQualifier => "BouncyCastle";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// A parallel signer joins an existing attached CAdES-B-B signature, and every signer verifies: the whole
    /// structure under the platform reader (which checks each signature), and each signer through the shipped
    /// verification path and the independent BouncyCastle backend via <see cref="CmsSignedDataReduction.SelectSigner"/>'s
    /// projection.
    /// </summary>
    [TestMethod]
    public async Task AParallelSignerJoinsAnAttachedSignatureAndEverySignerVerifiesIndependently()
    {
        using ParallelSignatureScenario scenario = ParallelSignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData joined = await CAdESSignatureCreation.AddParallelSignatureAsync(
            baseline, scenario.SecondCertificate, scenario.SecondPrivateKey, detachedContentDigest: null,
            ParallelSigningTime, algorithmConstraints: null, includeCmsAlgorithmProtection: false,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] octets = joined.AsReadOnlySpan().ToArray();
        var platformReader = new SignedCms();
        platformReader.Decode(octets);
        platformReader.CheckSignature(verifySignatureOnly: true);
        Assert.HasCount(2, platformReader.SignerInfos, "The joined structure carries the original signer and the parallel one (RFC 5652 §5.1, more than one SignerInfo).");

        var verifiedSignerCertificates = new List<byte[]>();
        for(int signerIndex = 0; signerIndex < 2; ++signerIndex)
        {
            using CmsSignedData projection = CmsSignedDataReduction.SelectSigner(joined, signerIndex, BaseMemoryPool.Shared);
            using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(
                projection, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsValid, $"The shipped path must accept the signer the projection at index {signerIndex} keeps (status: {result.Status}).");
            verifiedSignerCertificates.Add(result.SignerCertificate!.AsReadOnlySpan().ToArray());

            using CmsVerifiedContent verified = await ResolveBouncyCastleVerifier()(
                projection, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(Content.Span.SequenceEqual(verified.Content.Span), $"The independent BouncyCastle backend must recover the same content for the signer at index {signerIndex}.");
        }

        Assert.IsTrue(
            ContainsCertificate(verifiedSignerCertificates, scenario.FirstCertificate) && ContainsCertificate(verifiedSignerCertificates, scenario.SecondCertificate),
            "The two projections bind the two distinct signer certificates — each signer's ESS signing-certificate-v2 resolves its own party, never the other's.");
    }


    /// <summary>
    /// The parallel placement preserves the original <c>SignerInfo</c>'s octets bit-exactly, unions the new
    /// signer's digest algorithm into <c>digestAlgorithms</c> exactly once, places the new signer's
    /// certificate, and leaves both <c>SET OF</c> fields in the X.690 clause 11.6 order a strict DER reader
    /// enforces — and a second joiner sharing an already-listed digest algorithm adds no duplicate entry.
    /// </summary>
    [TestMethod]
    public async Task TheParallelPlacementPreservesTheOriginalSignerAndUnionsTheDigestAlgorithms()
    {
        using ParallelSignatureScenario scenario = ParallelSignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        byte[] baselineOctets = baseline.AsReadOnlySpan().ToArray();
        CmsTlvBounds originalSigner = CmsStructureOracle.LocateLengthChain(baselineOctets, signerIndex: 0)[4];
        byte[] originalSignerOctets = baselineOctets[originalSigner.Start..originalSigner.End];

        using CmsSignedData joined = await CAdESSignatureCreation.AddParallelSignatureAsync(
            baseline, scenario.SecondCertificate, scenario.SecondPrivateKey, detachedContentDigest: null,
            ParallelSigningTime, algorithmConstraints: null, includeCmsAlgorithmProtection: false,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] joinedOctets = joined.AsReadOnlySpan().ToArray();
        Assert.IsGreaterThanOrEqualTo(0, joinedOctets.AsSpan().IndexOf(originalSignerOctets),
            "The original SignerInfo's octets survive the placement verbatim — the preservation rule the augmentation class states.");

        SignedDataStructure structure = ReadStructure(joinedOctets);
        Assert.AreEqual(1, structure.Version, "Both SignerInfo structures are version 1 with IssuerAndSerialNumber, so RFC 5652 §5.1's rule keeps SignedData.version at 1.");
        Assert.HasCount(2, structure.DigestAlgorithmOids, "The joiner's algorithm joined the original's; nothing else did.");
        Assert.Contains(PkiDigestAlgorithm.Sha256.Identifier.Oid, structure.DigestAlgorithmOids, "The original signer's SHA-256 is listed.");
        Assert.Contains(PkiDigestAlgorithm.Sha384.Identifier.Oid, structure.DigestAlgorithmOids, "The P-384 joiner's SHA-384 joined it — the union RFC 5652 §5.1's collection is intended to list.");
        Assert.AreEqual(2, structure.SignerInfoCount, "Two SignerInfo structures stand side by side.");
        Assert.IsTrue(ContainsEncoding(structure.CertificateEncodings, scenario.FirstCertificate), "The original signer's certificate is still placed.");
        Assert.IsTrue(ContainsEncoding(structure.CertificateEncodings, scenario.SecondCertificate), "The joiner's certificate joined SignedData.certificates (requirement a).");

        //A third signer under SHA-256 — already listed by the original signer — adds no duplicate entry.
        using CmsSignedData joinedTwice = await CAdESSignatureCreation.AddParallelSignatureAsync(
            joined, scenario.ThirdCertificate, scenario.ThirdPrivateKey, detachedContentDigest: null,
            ParallelSigningTime, algorithmConstraints: null, includeCmsAlgorithmProtection: false,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        SignedDataStructure twice = ReadStructure(joinedTwice.AsReadOnlySpan().ToArray());
        Assert.AreEqual(3, twice.SignerInfoCount, "The third signer joined as a third SignerInfo.");
        Assert.HasCount(2, twice.DigestAlgorithmOids, "SHA-256 is listed once however many signers share it.");
    }


    /// <summary>
    /// Several prepared signers complete one fresh <c>SignedData</c> together through the multi-signer
    /// completion, every signer verifies, and the single-signer completion is exactly that surface over one
    /// entry — the same inputs produce identical octets through both.
    /// </summary>
    [TestMethod]
    public async Task SeveralPreparedSignersCompleteOneFreshSignedDataTogether()
    {
        using ParallelSignatureScenario scenario = ParallelSignatureScenario.Create();

        using CAdESSignaturePreparation firstPreparation = await PrepareAsync(scenario.FirstCertificate, PkiDigestAlgorithm.Sha256, SigningTime).ConfigureAwait(false);
        using CAdESSignaturePreparation secondPreparation = await PrepareAsync(scenario.SecondCertificate, PkiDigestAlgorithm.Sha384, ParallelSigningTime).ConfigureAwait(false);
        using PooledMemory firstSignature = await SignPreparationAsync(scenario.FirstPrivateKey, firstPreparation, TestContext.CancellationToken).ConfigureAwait(false);
        using PooledMemory secondSignature = await SignPreparationAsync(scenario.SecondPrivateKey, secondPreparation, TestContext.CancellationToken).ConfigureAwait(false);

        using CmsSignedData signedData = CAdESSignatureCreation.Complete(
            [
                new CAdESSignerCompletion(firstPreparation, scenario.FirstCertificate, CryptoAlgorithm.P256, firstSignature.AsReadOnlyMemory()),
                new CAdESSignerCompletion(secondPreparation, scenario.SecondCertificate, CryptoAlgorithm.P384, secondSignature.AsReadOnlyMemory())
            ],
            additionalCertificates: null,
            BaseMemoryPool.Shared);

        byte[] octets = signedData.AsReadOnlySpan().ToArray();
        var platformReader = new SignedCms();
        platformReader.Decode(octets);
        platformReader.CheckSignature(verifySignatureOnly: true);
        Assert.HasCount(2, platformReader.SignerInfos, "Both prepared signers stand in the completed structure.");

        SignedDataStructure structure = ReadStructure(octets);
        Assert.HasCount(2, structure.DigestAlgorithmOids, "Each distinct digest algorithm is listed once.");
        Assert.Contains(PkiDigestAlgorithm.Sha256.Identifier.Oid, structure.DigestAlgorithmOids, "The first signer's SHA-256 is listed.");
        Assert.Contains(PkiDigestAlgorithm.Sha384.Identifier.Oid, structure.DigestAlgorithmOids, "The second signer's SHA-384 is listed.");

        for(int signerIndex = 0; signerIndex < 2; ++signerIndex)
        {
            using CmsSignedData projection = CmsSignedDataReduction.SelectSigner(signedData, signerIndex, BaseMemoryPool.Shared);
            using CAdESVerificationResult result = await CAdESVerification.VerifyAsync(
                projection, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsValid, $"The shipped path must accept the completed signer at index {signerIndex} (status: {result.Status}).");
        }

        //The single-signer completion is the multi-signer surface over one entry: the same preparation and
        //signature value produce identical octets through both entry points.
        using CmsSignedData throughSingle = CAdESSignatureCreation.Complete(
            firstPreparation, scenario.FirstCertificate, CryptoAlgorithm.P256, firstSignature.AsReadOnlyMemory(),
            additionalCertificates: null, BaseMemoryPool.Shared);
        using CmsSignedData throughList = CAdESSignatureCreation.Complete(
            [new CAdESSignerCompletion(firstPreparation, scenario.FirstCertificate, CryptoAlgorithm.P256, firstSignature.AsReadOnlyMemory())],
            additionalCertificates: null, BaseMemoryPool.Shared);
        Assert.IsTrue(throughSingle.AsReadOnlySpan().SequenceEqual(throughList.AsReadOnlySpan()),
            "One signer through the single-signer form and through the list form is the same structure, octet for octet.");
    }


    /// <summary>
    /// A parallel signer joins a detached signature (RFC 5652 §5.2: the content travels by other means) through
    /// the digest carrier, whose tag names the algorithm — and the joined structure verifies under the platform
    /// reader against the externally supplied content.
    /// </summary>
    [TestMethod]
    public async Task AParallelSignerJoinsADetachedSignatureThroughTheDigestCarrier()
    {
        using ParallelSignatureScenario scenario = ParallelSignatureScenario.Create();
        using DigestValue contentDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            Content, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using CmsSignedData detachedBaseline = await CAdESSignatureCreation.SignAsync(
            scenario.FirstCertificate, scenario.FirstPrivateKey, content: null, contentDigest.AsReadOnlyMemory(),
            SigningTime, additionalCertificates: null, algorithmConstraints: null,
            includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        //The P-384 joiner prepares under SHA-384, so its carrier is the SHA-384 digest of the same content —
        //the carrier's tag and the joiner's profile must agree, which the refusal test asserts from the
        //other side.
        using DigestValue joinerDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            Content, PkiDigestAlgorithm.Sha384.OutputByteLength, PkiDigestAlgorithm.Sha384.DigestTag,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData joined = await CAdESSignatureCreation.AddParallelSignatureAsync(
            detachedBaseline, scenario.SecondCertificate, scenario.SecondPrivateKey, joinerDigest,
            ParallelSigningTime, algorithmConstraints: null, includeCmsAlgorithmProtection: false,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        var platformReader = new SignedCms(new ContentInfo(Content.ToArray()), detached: true);
        platformReader.Decode(joined.AsReadOnlySpan().ToArray());
        platformReader.CheckSignature(verifySignatureOnly: true);
        Assert.HasCount(2, platformReader.SignerInfos, "Both detached signers verify against the externally supplied content.");
    }


    /// <summary>
    /// The parallel preparation refuses the shapes that would leave a digest and a content in dispute: a digest
    /// carrier beside an attached content, a detached structure with no digest, and a carrier whose tag names a
    /// different algorithm than the preparation states — the carrier's own tag is the algorithm's source of
    /// truth, so a disagreeing pair is refused rather than one half trusted.
    /// </summary>
    [TestMethod]
    public async Task TheParallelPreparationRefusesDisagreeingContentAndDigestShapes()
    {
        using ParallelSignatureScenario scenario = ParallelSignatureScenario.Create();
        using CmsSignedData attachedBaseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using DigestValue sha256Digest = await CryptographicKeyEvents.ComputeDigestAsync(
            Content, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareParallelSignatureAsync(
                attachedBaseline, scenario.SecondCertificate, sha256Digest, PkiDigestAlgorithm.Sha256, ParallelSigningTime,
                algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }, "A digest carrier beside an attached content is the two-contents substitution shape and is refused.");

        using CmsSignedData detachedBaseline = await CAdESSignatureCreation.SignAsync(
            scenario.FirstCertificate, scenario.FirstPrivateKey, content: null, sha256Digest.AsReadOnlyMemory(),
            SigningTime, additionalCertificates: null, algorithmConstraints: null,
            includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareParallelSignatureAsync(
                detachedBaseline, scenario.SecondCertificate, detachedContentDigest: null, PkiDigestAlgorithm.Sha256, ParallelSigningTime,
                algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }, "A detached structure without the externally held content's digest leaves nothing for message-digest to state.");

        using DigestValue sha384Digest = await CryptographicKeyEvents.ComputeDigestAsync(
            Content, PkiDigestAlgorithm.Sha384.OutputByteLength, PkiDigestAlgorithm.Sha384.DigestTag,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using CAdESSignaturePreparation _ = await CAdESSignatureCreation.PrepareParallelSignatureAsync(
                detachedBaseline, scenario.SecondCertificate, sha384Digest, PkiDigestAlgorithm.Sha256, ParallelSigningTime,
                algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }, "A carrier whose tag names SHA-384 cannot prepare a SHA-256 signature: the pair must agree.");
    }


    /// <summary>
    /// The multi-signer completion refuses an empty signer list (the degenerate certificate-only form of
    /// clause 4.6 is not a signature), preparations that disagree on attached against detached, and attached
    /// preparations whose content octets differ — one <c>encapContentInfo</c> holds one content.
    /// </summary>
    [TestMethod]
    public async Task TheMultiSignerCompletionRefusesAnEmptyListAndDisagreeingContents()
    {
        using ParallelSignatureScenario scenario = ParallelSignatureScenario.Create();

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => CAdESSignatureCreation.Complete([], additionalCertificates: null, BaseMemoryPool.Shared),
            "An empty signer list is the degenerate no-signer form and is refused.");

        using CAdESSignaturePreparation attached = await PrepareAsync(scenario.FirstCertificate, PkiDigestAlgorithm.Sha256, SigningTime).ConfigureAwait(false);
        using DigestValue contentDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            Content, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using CAdESSignaturePreparation detached = await CAdESSignatureCreation.PrepareAsync(
            scenario.SecondCertificate, content: null, contentDigest.AsReadOnlyMemory(), PkiDigestAlgorithm.Sha256,
            ParallelSigningTime, algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PooledMemory attachedSignature = await SignPreparationAsync(scenario.FirstPrivateKey, attached, TestContext.CancellationToken).ConfigureAwait(false);
        using PooledMemory detachedSignature = await SignPreparationAsync(scenario.SecondPrivateKey, detached, TestContext.CancellationToken).ConfigureAwait(false);
        _ = Assert.ThrowsExactly<ArgumentException>(
            () => CAdESSignatureCreation.Complete(
                [
                    new CAdESSignerCompletion(attached, scenario.FirstCertificate, CryptoAlgorithm.P256, attachedSignature.AsReadOnlyMemory()),
                    new CAdESSignerCompletion(detached, scenario.SecondCertificate, CryptoAlgorithm.P384, detachedSignature.AsReadOnlyMemory())
                ],
                additionalCertificates: null, BaseMemoryPool.Shared),
            "An attached preparation and a detached one cannot share one encapContentInfo.");

        ReadOnlyMemory<byte> otherContent = new("a different content the second signer prepared over"u8.ToArray());
        using CAdESSignaturePreparation first = await PrepareAsync(scenario.FirstCertificate, PkiDigestAlgorithm.Sha256, SigningTime).ConfigureAwait(false);
        using CAdESSignaturePreparation other = await CAdESSignatureCreation.PrepareAsync(
            scenario.SecondCertificate, otherContent, detachedContentDigest: null, PkiDigestAlgorithm.Sha384,
            ParallelSigningTime, algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        using PooledMemory firstSignature = await SignPreparationAsync(scenario.FirstPrivateKey, first, TestContext.CancellationToken).ConfigureAwait(false);
        using PooledMemory otherSignature = await SignPreparationAsync(scenario.SecondPrivateKey, other, TestContext.CancellationToken).ConfigureAwait(false);
        _ = Assert.ThrowsExactly<ArgumentException>(
            () => CAdESSignatureCreation.Complete(
                [
                    new CAdESSignerCompletion(first, scenario.FirstCertificate, CryptoAlgorithm.P256, firstSignature.AsReadOnlyMemory()),
                    new CAdESSignerCompletion(other, scenario.SecondCertificate, CryptoAlgorithm.P384, otherSignature.AsReadOnlyMemory())
                ],
                additionalCertificates: null, BaseMemoryPool.Shared),
            "Two attached preparations over different octets cannot share one eContent.");
    }


    /// <summary>
    /// The placement primitive refuses what RFC 5652 makes structurally wrong: a bit-identical duplicate
    /// <c>SignerInfo</c> (a <c>SET OF</c> holds distinct values), a <c>SignerInfo</c> whose patched version is
    /// not 1 (§5.1's version rule would demand a <c>SignedData.version</c> rewrite the preserving operation
    /// does not perform), and octets that are not a <c>SignerInfo</c> at all.
    /// </summary>
    [TestMethod]
    public async Task ThePlacementRefusesDuplicatesPatchedVersionsAndNonSignerInfoOctets()
    {
        using ParallelSignatureScenario scenario = ParallelSignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        byte[] baselineOctets = baseline.AsReadOnlySpan().ToArray();
        CmsTlvBounds signerBounds = CmsStructureOracle.LocateLengthChain(baselineOctets, signerIndex: 0)[4];
        byte[] signerOctets = baselineOctets[signerBounds.Start..signerBounds.End];

        using(PooledMemory duplicate = PooledMemory.FromBytes(signerOctets, BaseMemoryPool.Shared, CryptoTags.CmsEncodedSignerInfo))
        {
            _ = Assert.ThrowsExactly<ArgumentException>(
                () => CmsSignedDataAugmentation.AddSignerInfo(baseline, duplicate, certificates: null, BaseMemoryPool.Shared),
                "The structure already carries this exact SignerInfo; a SET OF holds distinct values.");
        }

        //The SignerInfo SEQUENCE opens with version INTEGER 02 01 01; its value octet sits two past the
        //INTEGER's own tag. Patching it to 3 states the subjectKeyIdentifier version without the identifier.
        byte[] patchedOctets = (byte[])signerOctets.Clone();
        int versionValueOffset = (signerBounds.ContentStart - signerBounds.Start) + 2;
        Assert.AreEqual(1, patchedOctets[versionValueOffset], "The patch lands on the version value octet.");
        patchedOctets[versionValueOffset] = 3;
        using(PooledMemory patched = PooledMemory.FromBytes(patchedOctets, BaseMemoryPool.Shared, CryptoTags.CmsEncodedSignerInfo))
        {
            _ = Assert.ThrowsExactly<ArgumentException>(
                () => CmsSignedDataAugmentation.AddSignerInfo(baseline, patched, certificates: null, BaseMemoryPool.Shared),
                "A version other than 1 changes what RFC 5652 §5.1 assigns to SignedData.version and is refused.");
        }

        using(PooledMemory notASignerInfo = PooledMemory.FromBytes([0x06, 0x03, 0x2A, 0x03, 0x04], BaseMemoryPool.Shared, CryptoTags.CmsEncodedSignerInfo))
        {
            _ = Assert.ThrowsExactly<ArgumentException>(
                () => CmsSignedDataAugmentation.AddSignerInfo(baseline, notASignerInfo, certificates: null, BaseMemoryPool.Shared),
                "An OBJECT IDENTIFIER is not a SignerInfo SEQUENCE.");
        }

        //A three-field prefix — SEQUENCE { INTEGER 1, SEQUENCE {}, SEQUENCE {} } — is not a SignerInfo:
        //RFC 5652 §5.3's mandatory signatureAlgorithm and signature are absent, and the empty digestAlgorithm
        //opens with no algorithm object identifier. The review's own probe octets, kept as the regression.
        using(PooledMemory truncated = PooledMemory.FromBytes(
            [0x30, 0x07, 0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00], BaseMemoryPool.Shared, CryptoTags.CmsEncodedSignerInfo))
        {
            _ = Assert.ThrowsExactly<ArgumentException>(
                () => CmsSignedDataAugmentation.AddSignerInfo(baseline, truncated, certificates: null, BaseMemoryPool.Shared),
                "A SignerInfo missing its mandatory trailing fields is refused, never spliced.");
        }

        //A full field walk followed by trailing junk inside the SEQUENCE: version, sid, a real SHA-256
        //AlgorithmIdentifier, a signatureAlgorithm SEQUENCE, a one-octet signature — then a NULL where only
        //the optional unsignedAttrs [1] IMPLICIT may stand.
        using(PooledMemory trailingJunk = PooledMemory.FromBytes(
            [
                0x30, 0x19,
                0x02, 0x01, 0x01,
                0x30, 0x00,
                0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                0x30, 0x00,
                0x04, 0x01, 0xAA,
                0x05, 0x00
            ], BaseMemoryPool.Shared, CryptoTags.CmsEncodedSignerInfo))
        {
            _ = Assert.ThrowsExactly<ArgumentException>(
                () => CmsSignedDataAugmentation.AddSignerInfo(baseline, trailingJunk, certificates: null, BaseMemoryPool.Shared),
                "Octets after the signature that are not the unsignedAttrs [1] field are refused.");
        }
    }


    /// <summary>
    /// Detached signers under one digest algorithm are held to one content commitment on both creation paths:
    /// joining an existing detached structure with a same-algorithm digest of different content is refused
    /// against the existing signer's own <c>message-digest</c> attribute, and the multi-signer completion
    /// refuses two same-algorithm detached preparations over different digests — while an agreeing pair
    /// completes and verifies. Signers under different algorithms stay joinable (the shipped SHA-256/SHA-384
    /// detached join test), because without the content their digests cannot be compared.
    /// </summary>
    [TestMethod]
    public async Task DetachedSignersUnderOneAlgorithmAreHeldToOneContentCommitment()
    {
        using ParallelSignatureScenario scenario = ParallelSignatureScenario.Create();
        using DigestValue contentDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            Content, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> otherContent = new("a different document the joiner would misattest"u8.ToArray());
        using DigestValue otherDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            otherContent, PkiDigestAlgorithm.Sha256.OutputByteLength, PkiDigestAlgorithm.Sha256.DigestTag,
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //The join path: the existing signer's message-digest attribute is the commitment the joiner's
        //same-algorithm digest is held against.
        using CmsSignedData detachedBaseline = await CAdESSignatureCreation.SignAsync(
            scenario.FirstCertificate, scenario.FirstPrivateKey, content: null, contentDigest.AsReadOnlyMemory(),
            SigningTime, additionalCertificates: null, algorithmConstraints: null,
            includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
        {
            using CmsSignedData _ = await CAdESSignatureCreation.AddParallelSignatureAsync(
                detachedBaseline, scenario.ThirdCertificate, scenario.ThirdPrivateKey, otherDigest,
                ParallelSigningTime, algorithmConstraints: null, includeCmsAlgorithmProtection: false,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        }, "A same-algorithm joiner attesting to different content is the substitution shape and is refused.");

        //The completion path: two same-algorithm detached preparations over different digests are refused...
        using CAdESSignaturePreparation overContent = await CAdESSignatureCreation.PrepareAsync(
            scenario.FirstCertificate, content: null, contentDigest.AsReadOnlyMemory(), PkiDigestAlgorithm.Sha256,
            SigningTime, algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CAdESSignaturePreparation overOther = await CAdESSignatureCreation.PrepareAsync(
            scenario.ThirdCertificate, content: null, otherDigest.AsReadOnlyMemory(), PkiDigestAlgorithm.Sha256,
            ParallelSigningTime, algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using PooledMemory overContentSignature = await SignPreparationAsync(scenario.FirstPrivateKey, overContent, TestContext.CancellationToken).ConfigureAwait(false);
        using PooledMemory overOtherSignature = await SignPreparationAsync(scenario.ThirdPrivateKey, overOther, TestContext.CancellationToken).ConfigureAwait(false);
        _ = Assert.ThrowsExactly<ArgumentException>(
            () => CAdESSignatureCreation.Complete(
                [
                    new CAdESSignerCompletion(overContent, scenario.FirstCertificate, CryptoAlgorithm.P256, overContentSignature.AsReadOnlyMemory()),
                    new CAdESSignerCompletion(overOther, scenario.ThirdCertificate, CryptoAlgorithm.P256, overOtherSignature.AsReadOnlyMemory())
                ],
                additionalCertificates: null, BaseMemoryPool.Shared),
            "Two same-algorithm detached preparations over different digests cannot claim one shared content.");

        //...while an agreeing pair completes and both signers verify against the shared external content.
        using CAdESSignaturePreparation agreeing = await CAdESSignatureCreation.PrepareAsync(
            scenario.ThirdCertificate, content: null, contentDigest.AsReadOnlyMemory(), PkiDigestAlgorithm.Sha256,
            ParallelSigningTime, algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using PooledMemory anchorSignature = await SignPreparationAsync(scenario.FirstPrivateKey, overContent, TestContext.CancellationToken).ConfigureAwait(false);
        using PooledMemory agreeingSignature = await SignPreparationAsync(scenario.ThirdPrivateKey, agreeing, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData completed = CAdESSignatureCreation.Complete(
            [
                new CAdESSignerCompletion(overContent, scenario.FirstCertificate, CryptoAlgorithm.P256, anchorSignature.AsReadOnlyMemory()),
                new CAdESSignerCompletion(agreeing, scenario.ThirdCertificate, CryptoAlgorithm.P256, agreeingSignature.AsReadOnlyMemory())
            ],
            additionalCertificates: null, BaseMemoryPool.Shared);

        var platformReader = new SignedCms(new ContentInfo(Content.ToArray()), detached: true);
        platformReader.Decode(completed.AsReadOnlySpan().ToArray());
        platformReader.CheckSignature(verifySignatureOnly: true);
        Assert.HasCount(2, platformReader.SignerInfos, "Two agreeing detached signers complete one structure and both verify against the shared content.");
    }


    /// <summary>
    /// The projection keeps exactly the addressed signer — bit-identical to the member it stood as in the
    /// source — refuses an index the structure does not carry, and hands back an equal structure when the
    /// addressed signer is already the only one.
    /// </summary>
    [TestMethod]
    public async Task SelectSignerProjectsTheAddressedSignerAndRefusesAnAbsentIndex()
    {
        using ParallelSignatureScenario scenario = ParallelSignatureScenario.Create();
        using CmsSignedData baseline = await scenario.SignBaselineAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using CmsSignedData joined = await CAdESSignatureCreation.AddParallelSignatureAsync(
            baseline, scenario.SecondCertificate, scenario.SecondPrivateKey, detachedContentDigest: null,
            ParallelSigningTime, algorithmConstraints: null, includeCmsAlgorithmProtection: false,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] joinedOctets = joined.AsReadOnlySpan().ToArray();
        for(int signerIndex = 0; signerIndex < 2; ++signerIndex)
        {
            CmsTlvBounds member = CmsStructureOracle.LocateLengthChain(joinedOctets, signerIndex)[4];
            byte[] memberOctets = joinedOctets[member.Start..member.End];

            using CmsSignedData projection = CmsSignedDataReduction.SelectSigner(joined, signerIndex, BaseMemoryPool.Shared);
            byte[] projectionOctets = projection.AsReadOnlySpan().ToArray();
            var platformReader = new SignedCms();
            platformReader.Decode(projectionOctets);
            platformReader.CheckSignature(verifySignatureOnly: true);
            Assert.HasCount(1, platformReader.SignerInfos, $"The projection at index {signerIndex} keeps exactly one signer.");

            CmsTlvBounds kept = CmsStructureOracle.LocateLengthChain(projectionOctets, signerIndex: 0)[4];
            Assert.AreSequenceEqual(memberOctets, projectionOctets[kept.Start..kept.End],
                "The kept SignerInfo is the addressed member, octet for octet.");
        }

        _ = Assert.ThrowsExactly<CryptographicException>(
            () => CmsSignedDataReduction.SelectSigner(joined, signerIndex: 5, BaseMemoryPool.Shared),
            "An index the structure does not carry is refused rather than clamped.");
        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => CmsSignedDataReduction.SelectSigner(joined, signerIndex: -1, BaseMemoryPool.Shared),
            "A negative index is refused.");

        using CmsSignedData projectionOfSole = CmsSignedDataReduction.SelectSigner(baseline, signerIndex: 0, BaseMemoryPool.Shared);
        Assert.IsTrue(baseline.AsReadOnlySpan().SequenceEqual(projectionOfSole.AsReadOnlySpan()),
            "Projecting the only signer of a single-signer structure is the structure itself.");
    }


    /// <summary>The located outer fields of one strict DER read of a produced structure.</summary>
    /// <param name="Version">The <c>SignedData.version</c> value.</param>
    /// <param name="DigestAlgorithmOids">Every <c>digestAlgorithms</c> member's algorithm object identifier, in the set's encoding order; the strict reader enforces X.690 clause 11.6 order on the way.</param>
    /// <param name="CertificateEncodings">The whole encoding of every <c>certificates</c> member.</param>
    /// <param name="SignerInfoCount">The number of <c>signerInfos</c> members; the strict reader enforces clause 11.6 order on this set too.</param>
    private sealed record SignedDataStructure(
        int Version,
        IReadOnlyList<string> DigestAlgorithmOids,
        IReadOnlyList<byte[]> CertificateEncodings,
        int SignerInfoCount);


    /// <summary>
    /// Reads a produced structure with a strict DER <see cref="AsnReader"/> — which enforces the X.690 clause
    /// 11.6 <c>SET OF</c> order on <c>digestAlgorithms</c> and <c>signerInfos</c> as this library's own managed
    /// backend does — and returns the outer facts the assertions here are made about.
    /// </summary>
    /// <param name="octets">The whole Signed Data Object octets.</param>
    /// <returns>The located facts.</returns>
    private static SignedDataStructure ReadStructure(byte[] octets)
    {
        AsnReader contentInfo = new AsnReader(octets, AsnEncodingRules.DER).ReadSequence();
        _ = contentInfo.ReadObjectIdentifier();
        AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        AsnReader signedData = explicitContent.ReadSequence();

        Assert.IsTrue(signedData.TryReadInt32(out int version), "SignedData opens with its version INTEGER.");

        AsnReader digestAlgorithms = signedData.ReadSetOf();
        var digestAlgorithmOids = new List<string>();
        while(digestAlgorithms.HasData)
        {
            digestAlgorithmOids.Add(digestAlgorithms.ReadSequence().ReadObjectIdentifier());
        }

        _ = signedData.ReadSequence();
        var certificateEncodings = new List<byte[]>();
        AsnReader certificates = signedData.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 0));
        while(certificates.HasData)
        {
            certificateEncodings.Add(certificates.ReadEncodedValue().ToArray());
        }

        AsnReader signerInfos = signedData.ReadSetOf();
        int signerInfoCount = 0;
        while(signerInfos.HasData)
        {
            _ = signerInfos.ReadSequence();
            ++signerInfoCount;
        }

        return new SignedDataStructure(version, digestAlgorithmOids, certificateEncodings, signerInfoCount);
    }


    /// <summary>States whether one of the collected certificate DERs is <paramref name="certificate"/>'s own.</summary>
    /// <param name="encodings">The collected whole encodings.</param>
    /// <param name="certificate">The certificate to look for.</param>
    /// <returns>Whether an exact-DER match is present.</returns>
    private static bool ContainsEncoding(IReadOnlyList<byte[]> encodings, PkiCertificateMemory certificate)
    {
        for(int i = 0; i < encodings.Count; ++i)
        {
            if(certificate.AsReadOnlySpan().SequenceEqual(encodings[i]))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>States whether one of the collected signer certificates is <paramref name="certificate"/>'s own.</summary>
    /// <param name="collected">The certificate DERs the verifications surfaced.</param>
    /// <param name="certificate">The certificate to look for.</param>
    /// <returns>Whether an exact-DER match is present.</returns>
    private static bool ContainsCertificate(List<byte[]> collected, PkiCertificateMemory certificate)
    {
        for(int i = 0; i < collected.Count; ++i)
        {
            if(certificate.AsReadOnlySpan().SequenceEqual(collected[i]))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Prepares CAdES-B-B signed attributes over <see cref="Content"/> for one signer.</summary>
    /// <param name="certificate">The signer's certificate.</param>
    /// <param name="digestAlgorithm">The digest algorithm the signer prepares under.</param>
    /// <param name="signingTime">The signing time the signer states.</param>
    /// <returns>The preparation. The caller disposes it.</returns>
    private async ValueTask<CAdESSignaturePreparation> PrepareAsync(PkiCertificateMemory certificate, PkiDigestAlgorithm digestAlgorithm, DateTimeOffset signingTime) =>
        await CAdESSignatureCreation.PrepareAsync(
            certificate, Content, detachedContentDigest: null, digestAlgorithm, signingTime,
            algorithmConstraints: null, cmsAlgorithmProtectionSignatureAlgorithmOid: null,
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>
    /// Signs a preparation's <c>SigningInput</c> through the registered signing seam and converts the
    /// fixed-width IEEE P1363 result to the DER <c>Ecdsa-Sig-Value</c> the wire encoding takes, carried as
    /// the tagged, length-tracked <see cref="PooledMemory"/> rather than a naked buffer-and-length pair.
    /// </summary>
    /// <param name="privateKey">The signing key material.</param>
    /// <param name="preparation">The preparation whose signing input is signed.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The DER signature value, tagged <see cref="CryptoTags.DerEncodedSignatureValue"/>. The caller owns and disposes it.</returns>
    private static async ValueTask<PooledMemory> SignPreparationAsync(
        PrivateKeyMemory privateKey, CAdESSignaturePreparation preparation, CancellationToken cancellationToken)
    {
        CryptoAlgorithm algorithm = privateKey.Tag.Get<CryptoAlgorithm>();
        Purpose purpose = privateKey.Tag.Get<Purpose>();
        SigningDelegate signing = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose);
        (Signature signature, CryptoEvent? evt) = await signing(
            privateKey.AsReadOnlyMemory(), preparation.SigningInput.AsReadOnlyMemory(), BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using(signature)
        {
            if(evt is not null)
            {
                CryptographicKeyEvents.DefaultSink(evt);
            }

            IMemoryOwner<byte> buffer = EcdsaSignatureEncoding.ConvertP1363ToDer(
                signature.AsReadOnlySpan(), BaseMemoryPool.Shared, out int length);

            return new PooledMemory(buffer, length, CryptoTags.DerEncodedSignatureValue);
        }
    }


    /// <summary>Resolves the registered BouncyCastle <see cref="VerifyCmsSignedDataDelegate"/> — an independent backend that shares no code with the creation surfaces.</summary>
    private static VerifyCmsSignedDataDelegate ResolveBouncyCastleVerifier() =>
        CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate), BouncyCastleQualifier)
            ?? throw new InvalidOperationException("No BouncyCastle VerifyCmsSignedDataDelegate has been registered.");


    /// <summary>
    /// The material every test here starts from: three signing parties, each with its own key material and its
    /// own distinctly named self-signed certificate — the first two on different curves so the digest-algorithm
    /// union has something to unite, the third sharing the first's so the no-duplicate leg has something to
    /// skip.
    /// </summary>
    internal sealed class ParallelSignatureScenario: IDisposable
    {
        /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
        private bool disposed;


        /// <summary>Gets the first (baseline) signer's certificate.</summary>
        internal required PkiCertificateMemory FirstCertificate { get; init; }

        /// <summary>Gets the first signer's private key material.</summary>
        internal required PrivateKeyMemory FirstPrivateKey { get; init; }

        /// <summary>Gets the parallel (P-384) signer's certificate.</summary>
        internal required PkiCertificateMemory SecondCertificate { get; init; }

        /// <summary>Gets the parallel signer's private key material.</summary>
        internal required PrivateKeyMemory SecondPrivateKey { get; init; }

        /// <summary>Gets the third (P-256, digest-sharing) signer's certificate.</summary>
        internal required PkiCertificateMemory ThirdCertificate { get; init; }

        /// <summary>Gets the third signer's private key material.</summary>
        internal required PrivateKeyMemory ThirdPrivateKey { get; init; }


        /// <summary>Builds the scenario: mints the three parties.</summary>
        /// <returns>The scenario. The caller disposes it.</returns>
        internal static ParallelSignatureScenario Create()
        {
            (PkiCertificateMemory firstCertificate, PrivateKeyMemory firstKey) = MintP256Party("CN=Verifiable CAdES First Signer");
            (PkiCertificateMemory secondCertificate, PrivateKeyMemory secondKey) = MintP384Party("CN=Verifiable CAdES Parallel Signer");
            (PkiCertificateMemory thirdCertificate, PrivateKeyMemory thirdKey) = MintP256Party("CN=Verifiable CAdES Third Signer");

            return new ParallelSignatureScenario
            {
                FirstCertificate = firstCertificate,
                FirstPrivateKey = firstKey,
                SecondCertificate = secondCertificate,
                SecondPrivateKey = secondKey,
                ThirdCertificate = thirdCertificate,
                ThirdPrivateKey = thirdKey
            };
        }


        /// <summary>Signs <see cref="Content"/> as a CAdES-B-B baseline through the shipped creation surface.</summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>The baseline signature. The caller disposes it.</returns>
        internal async ValueTask<CmsSignedData> SignBaselineAsync(CancellationToken cancellationToken) =>
            await CAdESSignatureCreation.SignAsync(
                FirstCertificate, FirstPrivateKey, Content, null, SigningTime, additionalCertificates: null,
                algorithmConstraints: null, includeCmsAlgorithmProtection: false, BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);


        /// <summary>
        /// Mints a P-256 signer: key material through <see cref="BouncyCastleKeyMaterialCreator"/> (the
        /// repository's test-key convention), and a self-signed certificate over the same public point through
        /// a platform <see cref="ECDsa"/> reconstructed from it — the certificate vehicle is platform code, the
        /// key material is not.
        /// </summary>
        /// <param name="subjectName">The subject distinguished name, distinct per party so no two certificates share an issuer name.</param>
        /// <returns>The certificate and the private key material, both owned by the caller.</returns>
        private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintP256Party(string subjectName)
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
                using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(
                    platformKey, NotBefore, NotAfter, subjectName);

                return (ToCertificateCarrier(platformCertificate.RawData), keys.PrivateKey);
            }
        }


        /// <summary>
        /// Mints a P-384 signer the same way <see cref="MintP256Party"/> does, on the curve whose SHA-384
        /// pairing exercises the digest-algorithm union.
        /// </summary>
        /// <param name="subjectName">The subject distinguished name.</param>
        /// <returns>The certificate and the private key material, both owned by the caller.</returns>
        private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintP384Party(string subjectName)
        {
            PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP384Keys(BaseMemoryPool.Shared);
            using(keys.PublicKey)
            {
                byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(keys.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P384);
                var ecParameters = new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP384,
                    D = keys.PrivateKey.AsReadOnlySpan().ToArray(),
                    Q = new ECPoint
                    {
                        X = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
                        Y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray()
                    }
                };

                using ECDsa platformKey = ECDsa.Create(ecParameters);
                using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(
                    platformKey, NotBefore, NotAfter, subjectName);

                return (ToCertificateCarrier(platformCertificate.RawData), keys.PrivateKey);
            }
        }


        /// <summary>Copies DER bytes into a pooled carrier tagged as an X.509 certificate.</summary>
        /// <param name="certificate">The DER-encoded certificate.</param>
        /// <returns>The carrier; the caller disposes it.</returns>
        private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate)
        {
            IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
            certificate.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            if(disposed)
            {
                return;
            }

            disposed = true;
            ThirdPrivateKey.Dispose();
            ThirdCertificate.Dispose();
            SecondPrivateKey.Dispose();
            SecondCertificate.Dispose();
            FirstPrivateKey.Dispose();
            FirstCertificate.Dispose();
        }
    }
}
