using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Veritas.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Collections;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Strict, minted-wire-bytes negatives (and cheap positive twins) for the level-aware
/// <see cref="CBAdESSignatureValidation.ValidateAsync(ReadOnlyMemory{byte}, ParseCBAdESSign1Delegate, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, ReadOnlyMemory{byte}?, CBAdESUnknownDetachedObjectMechanismDelegate?, AdESBaselineLevel, BuildPayloadTimestampMessageImprintInputDelegate, TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate, TryBuildReferencesOnlyTimestampMessageImprintInputDelegate, BaseMemoryPool, CancellationToken)"/>
/// overload and the shared level-scoped rule surface (<see cref="CBAdESLevelRules"/>) it composes, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 6.3 (Table 14) and Annex A.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Independently minted wire bytes.</strong> Every message this file feeds to <c>ValidateAsync</c> is
/// assembled by this file's own <see cref="CborWriter"/> oracle helpers — never by calling
/// <see cref="CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader"/>, <see cref="CBAdESSignatureCreation"/>,
/// or <see cref="CBAdESSignatureAugmentation"/> — mirroring <c>CBAdESSignatureValidationTests</c>'s own
/// discipline for the B-B negatives one stage below this one. Table 8 element labels (<c>sigTst</c>=1,
/// <c>valData</c>=2, <c>refs</c>=4), Annex A.1.1 map keys (<c>xRefs</c>=1, <c>x5t</c>=1, <c>xVals</c>=1,
/// <c>x509Cert</c>=1), clause 5.4.3.1/5.4.3.3 map keys (<c>val</c>=1, <c>type</c>=2, <c>encoding</c>=3,
/// <c>specRef</c>=4, <c>tstTokens</c>=1), the protected-header labels (<c>alg</c>=1, CWT Claims=15,
/// <c>x5t</c>=34), the CWT <c>iat</c> claim key (6), the <c>uHeaders</c> IANA label (268), and the
/// <c>COSE_Sign1_Tagged</c> tag (18) are all written as literal integers with a citing comment, never through
/// <see cref="CBAdESUnsignedHeaders"/>/<see cref="CBAdESSignatureSerialization"/>'s own label/key constants —
/// the same production surfaces a shared defect there could otherwise hide behind.
/// <see cref="WellKnownCoseAlgorithms"/> (the IANA COSE Algorithms registry) IS referenced directly, matching
/// the sibling file's precedent for that specific external registry.
/// </para>
/// <para>
/// <strong>Genuine time-stamp tokens via the independent BouncyCastle oracle.</strong> Every RFC 3161 token
/// this file mints under SHA-256 goes through <see cref="X509ChainTestRingTimestamping.MintTimestampTokenAsync"/>
/// — a CMS <c>SignedData</c> writer and ECDSA signer none of which is the library's own reader under test.
/// <strong>Deviation, recorded here:</strong> the CB-6.2.1-02 MD5 negative needs a genuinely CMS-signed token
/// whose <c>TSTInfo.messageImprint.hashAlgorithm</c> names MD5, which
/// <see cref="X509ChainTestRingTimestamping.MintTimestampTokenOverImprint"/> refuses to mint (its own OID
/// switch recognizes only the SHA-2 family) — this file's <see cref="MintTokenWithArbitraryImprintAlgorithm"/>
/// duplicates that method's CMS-signing shape locally (never modifying the shared test-infrastructure file,
/// to avoid colliding with other test files also extending it) with the OID restriction lifted.
/// </para>
/// <para>
/// <strong>Every violation asserted by TYPE.</strong> Every negative test recovers its violation via
/// <see cref="FindViolation{TViolation}"/> and asserts on the closed-sum record's own properties (<c>Kind</c>,
/// <c>Reason</c>, <c>TokenCount</c>, <c>RequirementId</c>) — never on <see cref="CBAdESRuleViolation.Message"/>
/// text. Several negatives deliberately tolerate additional, unasserted violations alongside the one under
/// test (e.g. a garbage token's bytes also fail to read) — the collect posture never stops at the first
/// violation, and this file's fixtures are chosen to keep the assertion target unambiguous regardless.
/// </para>
/// <para>
/// <strong>No-throw convention.</strong> Every negative routes through
/// <see cref="ValidateAtLevelExpectingNoThrowAsync"/>, which fails the test loudly via <see cref="Assert.Fail(string?)"/>
/// if <c>ValidateAsync</c> ever throws on this untrusted input, rather than letting an unexpected exception
/// surface as an unhandled test-runner error.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESLevelValidationNegativeTests
{
    /// <summary>The <c>sigTst</c> Table 8 element label (clause 5.3.1).</summary>
    private const int SignatureTimestampLabel = 1;

    /// <summary>The <c>valData</c> Table 8 element label (clause 5.3.1).</summary>
    private const int ValidationDataLabel = 2;

    /// <summary>The <c>refs</c> Table 8 element label (clause 5.3.1, Annex A.1.1).</summary>
    private const int ReferencesLabel = 4;

    /// <summary>The <c>arcTst</c> Table 8 element label (clause 5.3.1).</summary>
    private const int ArchiveTimestampLabel = 3;

    /// <summary>The MD5 digest-algorithm object identifier (rsadsi digestAlgorithm md5), for the CB-6.2.1-02 negative.</summary>
    private const string Md5AlgorithmOid = "1.2.840.113549.2.5";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    // CB-6.3-c: exactly one token per sigTst instance.

    /// <summary>
    /// CB-6.3-c: a <c>sigTst</c> element whose <c>tstContainer</c> encapsulates TWO genuine, correctly-bound
    /// RFC 3161 tokens is collected as a <see cref="CBAdESSignatureTimestampTokenCountViolation"/> naming the
    /// count, even though both tokens individually open and bind — the one-token-per-instance rule is a
    /// structural cardinality check, independent of token validity.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-21.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncCollectsSignatureTimestampTokenCountViolationWhenSigTstEncapsulatesTwoTokens()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades two-token sigTst negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] firstTokenBytes;
        using(PkiCertificateMemory firstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], signature, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            firstTokenBytes = firstToken.AsReadOnlySpan().ToArray();
        }

        byte[] secondTokenBytes;
        using(PkiCertificateMemory secondToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], signature, TestClock.CanonicalEpoch.AddSeconds(1), BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            secondTokenBytes = secondToken.AsReadOnlySpan().ToArray();
        }

        byte[] sigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer,
            [
                new TstTokenWireSpec(firstTokenBytes, Type: null, Encoding: null, SpecRef: null),
                new TstTokenWireSpec(secondTokenBytes, Type: null, Encoding: null, SpecRef: null)
            ]));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([sigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A sigTst encapsulating two tokens must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESSignatureTimestampTokenCountViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-6.3-c must be collected.");
        Assert.AreEqual(2, violation!.TokenCount);
    }


    // CB-6.3-02: baseline TstToken narrowing (RFC 3161 legacy shape only).

    /// <summary>
    /// CB-6.3-02: a <c>sigTst</c> token carrying a <c>type</c> member is not the RFC 3161 legacy shape, even
    /// at level B-B, where <c>sigTst</c>'s own PRESENCE is legal ("*" — should-not, not shall-not).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncCollectsTimestampTokenNotBaselineViolationForATypedTokenAtLevelBaseline()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades typed-token negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        //The token's own Val bytes need not be genuinely readable -- CB-6.3-02 fires purely on the presence of
        //`type`, independent of whether the token opens; a garbage Val additionally surfaces a tolerated
        //CBAdESTimestampTokenBindingViolation(TokenNotRead), which this test does not assert on.
        byte[] sigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer,
            [
                new TstTokenWireSpec([0x01, 0x02, 0x03], Type: "not-rfc-3161", Encoding: null, SpecRef: null)
            ]));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([sigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A typed (non-RFC-3161) sigTst token must fail closed even at level B-B.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESTimestampTokenNotBaselineViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-6.3-02 must be collected.");
        Assert.AreEqual(CBAdESTimestampContainerKind.SignatureTimestamp, violation!.Kind);
    }


    /// <summary>
    /// CB-6.3-02: an <c>adoTst</c> token carrying a <c>type</c> member is not the RFC 3161
    /// legacy shape, even though <c>adoTst</c> is a SIGNED header parameter never reachable through
    /// <c>uHeaders</c> — the narrowing reaches it through <see cref="CBAdESLevelRuleContext.PayloadTimestamps"/>.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncCollectsTimestampTokenNotBaselineViolationForATypedAdoTstTokenAtLevelBaseline()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] payload = "cb-ades adoTst typed-token negative payload"u8.ToArray();

        //The token's own Val bytes need not be genuinely readable -- CB-6.3-02 fires purely on the presence of
        //`type`, independent of whether the token opens; a garbage Val additionally surfaces a tolerated
        //CBAdESTimestampTokenBindingViolation(TokenNotRead), which this test does not assert on.
        byte[] protectedHeader = BuildProtectedHeaderBytesWithPayloadTimestamp(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec([0x01, 0x02, 0x03], Type: "not-rfc-3161", Encoding: null, SpecRef: null)]));
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeadersArrayBytes: null, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A typed (non-RFC-3161) adoTst token must fail closed even at level B-B.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESTimestampTokenNotBaselineViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-6.3-02 must be collected for adoTst too.");
        Assert.AreEqual(CBAdESTimestampContainerKind.PayloadTimestamp, violation!.Kind);
    }


    /// <summary>
    /// Positive twin: a genuine, untyped (RFC 3161 legacy shape), correctly-bound <c>adoTst</c>
    /// token over the attached COSE Payload validates successfully.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-02.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncSucceedsForAConformantPayloadTimestampAtLevelBaseline()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] payload = "cb-ades conformant adoTst positive payload"u8.ToArray();

        //CB-5.2.6-05: the adoTst message-imprint input for an attached payload is the CBOR byte string
        //wrapping the payload bytes (never the raw payload bytes alone) -- built independently here, never via
        //CBAdESMessageImprints, matching this file's independent-oracle discipline.
        var imprintInputWriterBuffer = new ArrayBufferWriter<byte>();
        var imprintInputWriter = new CborWriter(imprintInputWriterBuffer, CborOptions.RfcCanonical);
        imprintInputWriter.WriteByteString(payload);
        byte[] payloadTimestampImprintInput = imprintInputWriterBuffer.WrittenSpan.ToArray();

        byte[] tokenBytes;
        using(PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], payloadTimestampImprintInput, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            tokenBytes = token.AsReadOnlySpan().ToArray();
        }

        byte[] protectedHeader = BuildProtectedHeaderBytesWithPayloadTimestamp(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(tokenBytes, Type: null, Encoding: null, SpecRef: null)]));
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeadersArrayBytes: null, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A genuine, untyped, correctly-bound adoTst token must validate at level B-B.");
    }


    // CB-6.3-23: refs forbidden at B-LT/B-LTA.

    /// <summary>CB-6.3-23: a <c>refs</c> element present at level B-LT is forbidden.</summary>
    [TestMethod]
    public async Task ValidateAsyncCollectsRefsFamilyForbiddenViolationWhenReferencesArePresentAtLevelBLT()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades refs-at-blt negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] referenceDigest = await CreateSha256DigestBytesAsync("a certificate refs references"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] refsElement = BuildUnsignedHeaderElementBytes(ReferencesLabel, writer =>
            WriteReferencesWithOneCertificateOracle(writer, new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([refsElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BLT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "refs present at B-LT must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESRefsFamilyForbiddenViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-6.3-23 must be collected.");
        Assert.AreEqual(CBAdESRefsFamilyKind.References, violation!.Kind);
        Assert.AreEqual("CB-6.3-23", violation.RequirementId);
    }


    // CB-6.3-21: sigTst presence at B-T+.

    /// <summary>CB-6.3-21: no <c>sigTst</c> element anywhere in <c>uHeaders</c> (indeed, no <c>uHeaders</c> at all) fails at level B-T.</summary>
    [TestMethod]
    public async Task ValidateAsyncCollectsSignatureTimestampMissingViolationWhenSigTstIsAbsentAtLevelBT()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades no-sigtst negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeadersArrayBytes: null, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A missing sigTst at level B-T must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        Assert.HasCount(1, failure.Violations, "With no uHeaders member at all, only CB-6.3-21 applies at B-T -- no other level rule has anything to react to.");
        var violation = FindViolation<CBAdESSignatureTimestampMissingViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-6.3-21 must be collected.");
    }


    // Token-imprint binding: mismatch and MD5 message-imprint algorithm.

    /// <summary>
    /// A genuine, CMS-verifiable RFC 3161 <c>sigTst</c> token whose message imprint was minted over different
    /// octets than the actual COSE signature value is collected as a
    /// <see cref="CBAdESTimestampTokenBindingViolation"/> with <see cref="CBAdESTimestampTokenBindingFailureReason.ImprintMismatch"/>.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-5.3.3-02.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncCollectsTimestampTokenBindingViolationWhenTheTokenImprintDoesNotMatchTheSignatureValue()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades imprint-mismatch negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        //Minted over unrelated octets, never over the actual signature value -- the message imprint this
        //token states will not equal the SHA-256 digest of `signature`.
        byte[] tokenBytes;
        using(PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], "not the signature value"u8.ToArray(), TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            tokenBytes = token.AsReadOnlySpan().ToArray();
        }

        byte[] sigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(tokenBytes, Type: null, Encoding: null, SpecRef: null)]));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([sigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A sigTst token whose imprint does not bind the signature value must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESTimestampTokenBindingViolation>(failure.Violations);
        Assert.IsNotNull(violation, "The imprint-mismatch violation must be collected.");
        Assert.AreEqual(CBAdESTimestampTokenBindingKind.SignatureTimestamp, violation!.Kind);
        Assert.AreEqual(CBAdESTimestampTokenBindingFailureReason.ImprintMismatch, violation.Reason);
    }


    /// <summary>
    /// CB-6.2.1-02: a genuinely CMS-signed <c>sigTst</c> token whose <c>TSTInfo.messageImprint.hashAlgorithm</c>
    /// names MD5 cannot be read at all (<see cref="PkiDigestAlgorithm.FromOid"/> never resolves MD5's OID),
    /// surfacing as a <see cref="CBAdESTimestampTokenBindingViolation"/> with
    /// <see cref="CBAdESTimestampTokenBindingFailureReason.TokenNotRead"/> — MD5 is refused by construction,
    /// never by a dedicated MD5-named check at this layer.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncCollectsTimestampTokenBindingViolationForAnMd5MessageImprintToken()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades md5-imprint negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        //The digest bytes' content is immaterial -- MD5's own OID is what makes the token unreadable, not
        //whether these particular 16 bytes are a genuine MD5 digest of anything.
        byte[] arbitraryMd5SizedDigest = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        byte[] tokenBytes = MintTokenWithArbitraryImprintAlgorithm(tsa.Authority, Md5AlgorithmOid, arbitraryMd5SizedDigest, TestClock.CanonicalEpoch);

        byte[] sigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(tokenBytes, Type: null, Encoding: null, SpecRef: null)]));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([sigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "An MD5 message-imprint sigTst token must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESTimestampTokenBindingViolation>(failure.Violations);
        Assert.IsNotNull(violation, "The MD5 token must surface as an unreadable token, never silently accepted.");
        Assert.AreEqual(CBAdESTimestampTokenBindingKind.SignatureTimestamp, violation!.Kind);
        Assert.AreEqual(CBAdESTimestampTokenBindingFailureReason.TokenNotRead, violation.Reason);
    }


    // CB-A.1.1-30: refs-to-valData cross-component consistency.

    /// <summary>
    /// CB-A.1.1-30: a certificate reference in <c>refs</c> whose digest resolves to NOTHING present in the
    /// signature's own <c>valData</c> is collected as a <see cref="CBAdESReferencesValidationDataConsistencyViolation"/>.
    /// Evaluated at level B-B, which the async CB-A.1.1-30 check does not itself condition on, isolating this
    /// assertion from every level-scoped structural rule.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncCollectsReferencesValidationDataConsistencyViolationWhenACertificateReferenceDoesNotResolve()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] x5tDigestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, x5tDigestBytes);
        byte[] payload = "cb-ades unresolved-reference negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wrongPreimageDigest = await CreateSha256DigestBytesAsync("this is not the certificate valData carries"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] actualValDataCertificateBytes = "the actual certificate bytes placed in valData"u8.ToArray();

        byte[] refsElement = BuildUnsignedHeaderElementBytes(ReferencesLabel, writer =>
            WriteReferencesWithOneCertificateOracle(writer, new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), wrongPreimageDigest));
        byte[] valDataElement = BuildUnsignedHeaderElementBytes(ValidationDataLabel, writer =>
            WriteValidationDataWithOneCertificateOracle(writer, actualValDataCertificateBytes));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([refsElement, valDataElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A refs entry that resolves to nothing in a present valData must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESReferencesValidationDataConsistencyViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-A.1.1-30 must be collected.");
        Assert.AreEqual(CBAdESReferenceMaterialKind.Certificate, violation!.Kind);
    }


    /// <summary>
    /// Positive twin: the SAME shape as the CB-A.1.1-30 negative above, except the <c>valData</c> certificate
    /// bytes are exactly the pre-image the <c>refs</c> digest was computed over, so the reference resolves and
    /// the whole signature validates.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncSucceedsWhenACertificateReferenceResolvesToValidationData()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] x5tDigestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, x5tDigestBytes);
        byte[] payload = "cb-ades resolved-reference positive payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] certificateBytes = "the certificate both refs and valData agree on"u8.ToArray();
        byte[] certificateDigest = await CreateSha256DigestBytesAsync(certificateBytes, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] refsElement = BuildUnsignedHeaderElementBytes(ReferencesLabel, writer =>
            WriteReferencesWithOneCertificateOracle(writer, new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), certificateDigest));
        byte[] valDataElement = BuildUnsignedHeaderElementBytes(ValidationDataLabel, writer =>
            WriteValidationDataWithOneCertificateOracle(writer, certificateBytes));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([refsElement, valDataElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A refs entry whose digest matches the valData certificate present must validate.");
    }


    /// <summary>
    /// CB-A.1.1-30: the disjunction's <c>arcTst</c> arm alone, with NO <c>valData</c>
    /// element anywhere, still triggers the check — an unresolvable <c>refs</c> certificate reference is
    /// collected even though <c>valData</c> was never incorporated, since <c>arcTst</c> incorporation is now
    /// enough to trigger it on its own.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncCollectsReferencesValidationDataConsistencyViolationWhenArcTstAloneTriggersItWithNoValidationData()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] x5tDigestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, x5tDigestBytes);
        byte[] payload = "cb-ades arcTst-alone-triggers-a.1.1-30 negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wrongPreimageDigest = await CreateSha256DigestBytesAsync("this is not present anywhere in this signature"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] refsElement = BuildUnsignedHeaderElementBytes(ReferencesLabel, writer =>
            WriteReferencesWithOneCertificateOracle(writer, new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), wrongPreimageDigest));

        //A correctly-bound arcTst instance -- the point under test is CB-A.1.1-30's TRIGGER, not the arcTst
        //token's own binding, so it is minted genuinely rather than left to fail for an unrelated reason.
        byte[] arcTstImprintInput = BuildArcTstImprintInputOracle(protectedHeader, [], payload, signature, precedingUHeadersElements: []);
        byte[] arcTstTokenBytes;
        using(PkiCertificateMemory arcTstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], arcTstImprintInput, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            arcTstTokenBytes = arcTstToken.AsReadOnlySpan().ToArray();
        }

        byte[] arcTstElement = BuildUnsignedHeaderElementBytes(ArchiveTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(arcTstTokenBytes, Type: null, Encoding: null, SpecRef: null)]));

        //refs precedes arcTst in wire order; no valData element anywhere.
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([refsElement, arcTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        //Level BB isolates this assertion from every level-scoped structural rule (identical convention to the
        //valData-half CB-A.1.1-30 tests above) -- CB-A.1.1-30 itself is not level-gated.
        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A refs entry that resolves to nothing, with arcTst (not valData) incorporated, must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESReferencesValidationDataConsistencyViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-A.1.1-30 must be collected on the arcTst arm alone.");
        Assert.AreEqual(CBAdESReferenceMaterialKind.Certificate, violation!.Kind);
    }


    /// <summary>
    /// CB-A.1.1-30: the RESOLUTION candidate set widens to material
    /// embedded in the signature's own <c>arcTst</c> instances' tokens — a <c>refs</c> certificate reference
    /// whose digest matches the certificate the <c>arcTst</c> token itself embeds resolves, with NO
    /// <c>valData</c> element anywhere in the signature (the same arcTst-alone-triggers shape as the negative
    /// above, except the reference's digest is the genuine pre-image this time).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncSucceedsWhenACertificateReferenceResolvesToAnArchiveTimestampTokenEmbeddedCertificate()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] x5tDigestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, x5tDigestBytes);
        byte[] payload = "cb-ades arcTst-embedded-material resolves positive payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] authorityCertificateDigest = await CreateSha256DigestBytesAsync(tsa.Authority.Certificate.RawData, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] refsElement = BuildUnsignedHeaderElementBytes(ReferencesLabel, writer =>
            WriteReferencesWithOneCertificateOracle(writer, new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), authorityCertificateDigest));

        //A correctly-bound arcTst instance embedding the TSA authority's own certificate (MintTimestampTokenAsync's
        //second argument) -- the point under test is the WIDENED candidate set, not the arcTst token's own
        //binding, so it is minted genuinely (mirroring the arcTst-alone-trigger negative's own convention).
        byte[] arcTstImprintInput = BuildArcTstImprintInputOracle(protectedHeader, [], payload, signature, precedingUHeadersElements: []);
        byte[] arcTstTokenBytes;
        using(PkiCertificateMemory arcTstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], arcTstImprintInput, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            arcTstTokenBytes = arcTstToken.AsReadOnlySpan().ToArray();
        }

        byte[] arcTstElement = BuildUnsignedHeaderElementBytes(ArchiveTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(arcTstTokenBytes, Type: null, Encoding: null, SpecRef: null)]));

        //refs precedes arcTst in wire order; no valData element anywhere -- the widened candidate set
        //must still resolve the reference from the arcTst token's own embedded certificate.
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([refsElement, arcTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A refs certificate reference whose digest matches an arcTst token's own embedded certificate resolves, widening CB-A.1.1-30's candidate set beyond valData alone.");
    }


    /// <summary>
    /// A genuine <c>sigTst</c> token embedding its OWN identified signer certificate resolves at level B-LT
    /// with no <c>valData</c> needed at all — letter h's "embedded in the electronic time-stamp itself"
    /// disjunct.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-h, CB-6.3-k.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncSucceedsWhenTheTokenSignerCertificateIsEmbeddedInTheTokenItself()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades signer-certificate-embedded positive payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tokenBytes;
        using(PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], signature, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            tokenBytes = token.AsReadOnlySpan().ToArray();
        }

        byte[] sigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(tokenBytes, Type: null, Encoding: null, SpecRef: null)]));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([sigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BLT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A token embedding its own identified signer certificate resolves without valData.");
    }


    /// <summary>
    /// A <c>sigTst</c> token that opens and CMS-verifies cleanly — its own
    /// <c>certificates</c> field's sole member is a tag-valid untagged SEQUENCE that fails
    /// <see cref="ManagedCertificate.Parse"/>, collapsing <see cref="TimestampTokenInfo.EmbeddedMaterialStatus"/>
    /// to <see cref="CmsEmbeddedMaterialStatus.Malformed"/> (an independent embedded-material
    /// re-parse; RFC 5652 §5.4's signature does not cover <c>certificates</c>, so the token's own signature
    /// still verifies) — reaches and fails the per-token signer-certificate coverage check at level B-LT:
    /// neither the embedded arm (no attributed signer) nor the <c>valData</c> arm (a Malformed embedded-material
    /// read leaves no signer identity to compare against) resolves. Rerouted through
    /// <see cref="ManagedCmsVerification.VerifyCmsSignedDataAsync"/> for the test's duration, proving the split
    /// platform-independently: the Managed backend's member-tolerant <c>certificates</c> walk is what lets the
    /// token's own signature verify despite the broken member, while the independent embedded-material re-parse
    /// still collapses to <c>Malformed</c> — verification tolerance never loosens this coverage check.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-h, CB-6.3-k.
    /// </remarks>
    [TestMethod]
    [DoNotParallelize]
    public async Task ValidateAsyncCollectsCoverageViolationWhenTheTokenOpensButEmbeddedMaterialReparsesMalformed()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades malformed-embedded-material coverage negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tokenBytes;
        using(PkiCertificateMemory bareToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], signature, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        using(PkiCertificateMemory brokenToken = RebuildTokenWithCertificatesField(bareToken, tsa.Authority.Certificate.RawData, BuildBrokenCertificateMember()))
        {
            tokenBytes = brokenToken.AsReadOnlySpan().ToArray();
        }

        byte[] sigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(tokenBytes, Type: null, Encoding: null, SpecRef: null)]));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([sigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        VerifyCmsSignedDataDelegate? original = CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate));
        try
        {
            CryptographicKeyFactory.RegisterFunction(typeof(VerifyCmsSignedDataDelegate), (VerifyCmsSignedDataDelegate)ManagedCmsVerification.VerifyCmsSignedDataAsync);

            using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
                wireBytes, publicKey, AdESBaselineLevel.BLT, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsValid, "A token whose embedded material reparses Malformed must fail the per-token coverage check at B-LT.");
            var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
            var violation = FindViolation<CBAdESTimestampSignerCertificateCoverageViolation>(failure.Violations);
            Assert.IsNotNull(violation, "CB-6.3-h must be collected for a token whose embedded material could not be read.");
            Assert.AreEqual(CBAdESTimestampTokenBindingKind.SignatureTimestamp, violation!.Kind);
        }
        finally
        {
            if(original is not null)
            {
                CryptographicKeyFactory.RegisterFunction(typeof(VerifyCmsSignedDataDelegate), original);
            }
        }
    }


    /// <summary>
    /// The <c>valData</c> identity-match disjunct is independently reachable
    /// through ANY correctly-implemented <see cref="VerifyCmsSignedDataDelegate"/>, not only the two shipped
    /// backends. This test registers a TEST-only backend
    /// (<see cref="VerifyCmsSignedDataExternallyKeyedStub"/>) that resolves a signer's key by a means OTHER
    /// than the token's own embedded <c>certificates</c> field, then opens a token whose <c>certificates</c>
    /// field carries NOTHING at all — a shape both shipped backends refuse. The token's own signer identity
    /// (sid) still resolves against a <c>valData</c> candidate carrying the matching certificate, and fails to
    /// resolve when no candidate matches. Registering a test delegate is the extension architecture, not a
    /// test seam (this file's own class remarks) — it mutates <see cref="CryptographicKeyFactory"/>'s DEFAULT
    /// <see cref="VerifyCmsSignedDataDelegate"/> slot for the duration, so parallel execution is disabled and
    /// the original registration is restored in every case.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-h, CB-6.3-k.
    /// </remarks>
    [TestMethod]
    [DoNotParallelize]
    public async Task IsTimestampTokenSignerCertificateResolvedAsyncResolvesByIdentityAgainstValidationDataForAnExternallyKeyedBackendToken()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider);

        using PkiCertificateMemory bareToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            authority, [authority], "externally-keyed content"u8.ToArray(), TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory strippedToken = RebuildTokenWithCertificatesField(bareToken);

        VerifyCmsSignedDataDelegate? original = CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate));
        try
        {
            CryptographicKeyFactory.RegisterFunction(typeof(VerifyCmsSignedDataDelegate), (VerifyCmsSignedDataDelegate)VerifyCmsSignedDataExternallyKeyedStub);

            using TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(
                strippedToken, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TimestampTokenInfoStatus.Read, tokenInfo.Status, "The externally-keyed stub opens the token even though it embeds no certificates.");
            Assert.IsEmpty(tokenInfo.EmbeddedCertificates, "The token's own certificates field was rebuilt with zero entries.");
            Assert.IsNull(tokenInfo.SignerCertificate, "No embedded certificate can identify the signer.");

            var matchingCandidate = new AdESPkiObject { Val = authority.Certificate.RawData };
            bool resolvedWithCandidate = await CBAdESLevelRules.IsTimestampTokenSignerCertificateResolvedAsync(
                tokenInfo, [matchingCandidate], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(resolvedWithCandidate, "The token's own signer identity (sid) matches the authority certificate present in valData.");

            bool resolvedWithoutCandidate = await CBAdESLevelRules.IsTimestampTokenSignerCertificateResolvedAsync(
                tokenInfo, [], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(resolvedWithoutCandidate, "With no valData candidates and no embedded certificate, the signer identity is unresolvable.");
        }
        finally
        {
            if(original is not null)
            {
                CryptographicKeyFactory.RegisterFunction(typeof(VerifyCmsSignedDataDelegate), original);
            }
        }
    }


    /// <summary>
    /// No <c>arcTst</c> instance anywhere in <c>uHeaders</c> (indeed, no <c>uHeaders</c> at all) is collected
    /// as a <see cref="CBAdESArchiveTimestampMissingViolation"/> at the declared level B-LTA.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-29.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncCollectsArchiveTimestampMissingViolationWhenNoArcTstIsPresentAtDeclaredBLTA()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades no-arctst-at-blta negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeadersArrayBytes: null, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BLTA, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A missing arcTst at the declared level B-LTA must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESArchiveTimestampMissingViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-6.3-29 must be collected.");
        Assert.AreEqual("CB-6.3-29", violation!.RequirementId);
    }


    /// <summary>
    /// Read-tolerance: the SAME absent-arcTst shape as the negative above, at every level BELOW the
    /// declared B-LTA, never collects <see cref="CBAdESArchiveTimestampMissingViolation"/> — arcTst is the soft
    /// "*" (should-not, not shall-not) at B-B/B-T/B-LT, per Table 14.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-29.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncDoesNotCollectArchiveTimestampMissingViolationBelowDeclaredBLTA()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades no-arctst-below-blta positive payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeadersArrayBytes: null, payload, signature);

        foreach(AdESBaselineLevel level in new[] { AdESBaselineLevel.BB, AdESBaselineLevel.BT, AdESBaselineLevel.BLT })
        {
            using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
                wireBytes, publicKey, level, TestContext.CancellationToken).ConfigureAwait(false);

            if(!result.IsValid)
            {
                var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
                Assert.IsNull(FindViolation<CBAdESArchiveTimestampMissingViolation>(failure.Violations),
                    $"CB-6.3-29 must not fire at level {level}, however many OTHER level rules this minimal message fails.");
            }
        }
    }


    /// <summary>
    /// Below the declared B-LTA, a present <c>arcTst</c> instance gets token-SHAPE
    /// checks only — its message imprint is not load-bearing (read-tolerance), restoring the prior
    /// behavior. A genuinely CMS-signed, openable token minted over the WRONG imprint input — which WOULD
    /// mismatch if the imprint were checked — validates cleanly at the declared level B-B, isolating this
    /// assertion from every other level-scoped rule (the same B-B isolation convention the CB-A.1.1-30 tests
    /// above use).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncDoesNotCheckArchiveTimestampImprintBelowDeclaredBLTA()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades arcTst-imprint-not-checked-below-blta payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        //Minted over arbitrary bytes, never the genuine clause 5.3.5.3 imprint input -- WOULD mismatch if the
        //imprint were checked; the token itself still opens and CMS-verifies cleanly.
        byte[] arcTstTokenBytes;
        using(PkiCertificateMemory arcTstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], "not the genuine arcTst imprint input"u8.ToArray(), TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            arcTstTokenBytes = arcTstToken.AsReadOnlySpan().ToArray();
        }

        byte[] arcTstElement = BuildUnsignedHeaderElementBytes(ArchiveTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(arcTstTokenBytes, Type: null, Encoding: null, SpecRef: null)]));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([arcTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A present arcTst instance at a declared level below B-LTA gets token-shape checks only; an imprint that would mismatch if checked must not fail validation (read-tolerance).");
    }


    /// <summary>
    /// Two <c>arcTst</c> instances, each carrying one genuine token minted over ITS OWN prefix-bound message
    /// imprint (5.3.5.3's validation variant), both validate successfully — the second instance's own imprint
    /// input includes the first instance's raw <c>uHeaders</c> element bytes, proving the prefix is bound to
    /// each instance's OWN position, not a fixed "everything before the whole array" reading.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncSucceedsForTwoArchiveTimestampInstancesEachBoundToItsOwnPrefix()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades repeated-arctst prefix positive payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        //arcTst#1 is the FIRST uHeaders element: its own prefix (elements strictly before it) is empty
        //(present uHeaders, empty slice -- zero contributed items, not a placeholder).
        byte[] firstImprintInput = BuildArcTstImprintInputOracle(protectedHeader, [], payload, signature, precedingUHeadersElements: []);
        byte[] firstTokenBytes;
        using(PkiCertificateMemory firstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], firstImprintInput, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            firstTokenBytes = firstToken.AsReadOnlySpan().ToArray();
        }

        byte[] firstArcTstElement = BuildUnsignedHeaderElementBytes(ArchiveTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(firstTokenBytes, Type: null, Encoding: null, SpecRef: null)]));

        //arcTst#2 is the SECOND uHeaders element: its own prefix is exactly [arcTst#1's raw element bytes].
        byte[] secondImprintInput = BuildArcTstImprintInputOracle(protectedHeader, [], payload, signature, precedingUHeadersElements: [firstArcTstElement]);
        byte[] secondTokenBytes;
        using(PkiCertificateMemory secondToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], secondImprintInput, TestClock.CanonicalEpoch.AddSeconds(1), BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            secondTokenBytes = secondToken.AsReadOnlySpan().ToArray();
        }

        byte[] secondArcTstElement = BuildUnsignedHeaderElementBytes(ArchiveTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(secondTokenBytes, Type: null, Encoding: null, SpecRef: null)]));

        //CB-6.3-21: level B-LTA implies B-T, so a genuine sigTst instance is required too -- placed AFTER both
        //arcTst instances so it never enters either one's own prefix (their positions are 0 and 1).
        byte[] sigTstElement = await BuildGenuineSignatureTimestampElementAsync(tsa, signature, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([firstArcTstElement, secondArcTstElement, sigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BLTA, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "Both prefix-bound arcTst instances must validate; the second instance's own imprint covers the first.");
        Assert.IsNotNull(result.Verified!.Value.Value.UnsignedHeaders);
        Assert.HasCount(3, result.Verified.Value.Value.UnsignedHeaders!);
    }


    /// <summary>
    /// The negative direction: an <c>arcTst</c> instance at the SECOND position, but
    /// carrying a token minted as if it were the FIRST (an empty prefix, ignoring the sibling instance that
    /// actually precedes it), is rejected — the validator's own prefix bound is this instance's OWN position,
    /// never a fixed "position zero" or "whole array" reading.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncCollectsImprintMismatchWhenASecondArchiveTimestampInstanceIsMintedOverTheWrongPrefix()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades repeated-arctst prefix negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] firstImprintInput = BuildArcTstImprintInputOracle(protectedHeader, [], payload, signature, precedingUHeadersElements: []);
        byte[] firstTokenBytes;
        using(PkiCertificateMemory firstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], firstImprintInput, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            firstTokenBytes = firstToken.AsReadOnlySpan().ToArray();
        }

        byte[] firstArcTstElement = BuildUnsignedHeaderElementBytes(ArchiveTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(firstTokenBytes, Type: null, Encoding: null, SpecRef: null)]));

        //WRONG: minted over an empty prefix (as if this were arcTst#1), even though this instance is actually
        //SECOND -- its own correct prefix is [firstArcTstElement], never empty.
        byte[] wrongSecondImprintInput = BuildArcTstImprintInputOracle(protectedHeader, [], payload, signature, precedingUHeadersElements: []);
        byte[] secondTokenBytes;
        using(PkiCertificateMemory secondToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], wrongSecondImprintInput, TestClock.CanonicalEpoch.AddSeconds(1), BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            secondTokenBytes = secondToken.AsReadOnlySpan().ToArray();
        }

        byte[] secondArcTstElement = BuildUnsignedHeaderElementBytes(ArchiveTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(secondTokenBytes, Type: null, Encoding: null, SpecRef: null)]));

        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([firstArcTstElement, secondArcTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BLTA, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "The second arcTst instance's wrongly-prefixed token must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESTimestampTokenBindingViolation>(failure.Violations);
        Assert.IsNotNull(violation, "The imprint-mismatch violation must be collected for the second instance's token.");
        Assert.AreEqual(CBAdESTimestampTokenBindingKind.ArchiveTimestamp, violation!.Kind);
        Assert.AreEqual(CBAdESTimestampTokenBindingFailureReason.ImprintMismatch, violation.Reason);
    }


    /// <summary>
    /// One <c>arcTst</c> instance carrying TWO genuine tokens, both minted over the SAME (this instance's own)
    /// message-imprint input, both validate — EVERY token in one instance verifies over that
    /// instance's SAME input. This also proves letter (j)/(c) orthogonality by construction: had the sigTst-only
    /// exactly-one-token narrowing (<see cref="CBAdESSignatureTimestampTokenCountViolation"/>) misfired on this
    /// multi-token <c>arcTst</c> instance, <see cref="CBAdESValidationResult.IsValid"/> would be
    /// <see langword="false"/> here.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-29, CB-6.3-j.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncVerifiesEveryTokenInAMultiTokenArchiveTimestampInstanceAgainstTheSameImprintInput()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades multi-token arctst positive payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] imprintInput = BuildArcTstImprintInputOracle(protectedHeader, [], payload, signature, precedingUHeadersElements: []);

        byte[] firstTokenBytes;
        using(PkiCertificateMemory firstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], imprintInput, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            firstTokenBytes = firstToken.AsReadOnlySpan().ToArray();
        }

        //A distinct second Time-Stamping Authority for the second token -- additional requirement (j): "Each
        //arcTst may contain more than one electronic time-stamp issued by different TSAs."
        using TsaFixture secondTsa = CreateTsaFixture();
        byte[] secondTokenBytes;
        using(PkiCertificateMemory secondToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            secondTsa.Authority, [secondTsa.Authority], imprintInput, TestClock.CanonicalEpoch.AddSeconds(1), BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            secondTokenBytes = secondToken.AsReadOnlySpan().ToArray();
        }

        byte[] arcTstElement = BuildUnsignedHeaderElementBytes(ArchiveTimestampLabel, writer =>
            WriteTstContainerOracle(writer,
            [
                new TstTokenWireSpec(firstTokenBytes, Type: null, Encoding: null, SpecRef: null),
                new TstTokenWireSpec(secondTokenBytes, Type: null, Encoding: null, SpecRef: null)
            ]));

        //CB-6.3-21: level B-LTA implies B-T, so a genuine sigTst instance is required too -- placed AFTER the
        //arcTst instance so it never enters its own (position-0) prefix.
        byte[] sigTstElement = await BuildGenuineSignatureTimestampElementAsync(tsa, signature, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([arcTstElement, sigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BLTA, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "Both tokens of one multi-token arcTst instance, from two different TSAs, must verify over the same imprint input.");
        Assert.IsNotNull(result.Verified!.Value.Value.UnsignedHeaders);
        Assert.HasCount(2, result.Verified.Value.Value.UnsignedHeaders!, "One arcTst instance carrying two tokens, plus the required sigTst instance -- never two sibling arcTst instances (contrast with sigTst's own multi-TSA pattern).");
    }


    /// <summary>
    /// The wrongly-prefixed negative above leaves a <see cref="MeteredHousePool"/>
    /// exactly balanced — every rented token/imprint-input/digest carrier across both <c>arcTst</c> instances'
    /// message-imprint builds returns to the pool even on the collected-violations path. A metered variant of
    /// the SAME failure this file's <see cref="ValidateAsyncWithLevelViolationsPathLeavesMeteredPoolBalanced"/>
    /// already proves for CB-A.1.1-30 — the failure path disposes <c>headers</c>/<c>unsignedHeaders</c>
    /// internally rather than handing them to the returned <see cref="CBAdESRuleViolationsFailure"/>.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncWithLevelArchiveTimestampWrongPrefixPathLeavesMeteredPoolBalanced()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades arctst metered-pool negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] firstImprintInput = BuildArcTstImprintInputOracle(protectedHeader, [], payload, signature, precedingUHeadersElements: []);
        byte[] firstTokenBytes;
        using(PkiCertificateMemory firstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], firstImprintInput, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            firstTokenBytes = firstToken.AsReadOnlySpan().ToArray();
        }

        byte[] firstArcTstElement = BuildUnsignedHeaderElementBytes(ArchiveTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(firstTokenBytes, Type: null, Encoding: null, SpecRef: null)]));

        //WRONG: minted over an empty prefix (as if this were arcTst#1), even though this instance is actually
        //SECOND -- mirrors ValidateAsyncCollectsImprintMismatchWhenASecondArchiveTimestampInstanceIsMintedOverTheWrongPrefix.
        byte[] wrongSecondImprintInput = BuildArcTstImprintInputOracle(protectedHeader, [], payload, signature, precedingUHeadersElements: []);
        byte[] secondTokenBytes;
        using(PkiCertificateMemory secondToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], wrongSecondImprintInput, TestClock.CanonicalEpoch.AddSeconds(1), BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            secondTokenBytes = secondToken.AsReadOnlySpan().ToArray();
        }

        byte[] secondArcTstElement = BuildUnsignedHeaderElementBytes(ArchiveTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(secondTokenBytes, Type: null, Encoding: null, SpecRef: null)]));

        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([firstArcTstElement, secondArcTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using var metered = new MeteredHousePool();
        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BLTA, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "The second arcTst instance's wrongly-prefixed token must fail closed.");
        Assert.IsNotNull(FindViolation<CBAdESTimestampTokenBindingViolation>(((CBAdESRuleViolationsFailure)result.Failure!).Violations),
            "The imprint-mismatch violation must be collected for the second instance's token.");

        //result now OWNS the decoded headers/unsignedHeaders --
        //disposing it explicitly here, before the outstanding-count check, is what "returns to the pool" means;
        //the trailing 'using' above remains a no-op safety net (Dispose is idempotent).
        result.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount,
            "Every carrier rented across both arcTst instances' message-imprint builds and token opens must return to the pool once the result -- which now owns the decoded facts on this failure arm -- is disposed.");
    }


    // Positive twins combining several structurally-cheap legs.

    /// <summary>
    /// Positive twin of the two-token, typed-token, and imprint-mismatch negatives above: exactly ONE genuine,
    /// untyped (RFC 3161 legacy shape), correctly-bound <c>sigTst</c> token at level B-T validates successfully.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-02, CB-6.3-21.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncSucceedsForAConformantSignatureTimestampAtLevelBT()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades conformant sigTst positive payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tokenBytes;
        using(PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], signature, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            tokenBytes = token.AsReadOnlySpan().ToArray();
        }

        byte[] sigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(tokenBytes, Type: null, Encoding: null, SpecRef: null)]));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([sigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "One genuine, untyped, correctly-bound sigTst token must validate at level B-T.");
        Assert.IsNotNull(result.Verified!.Value.Value.UnsignedHeaders);
        Assert.HasCount(1, result.Verified.Value.Value.UnsignedHeaders!);
    }


    /// <summary>
    /// Positive twin of the refs-forbidden-at-B-LT and sigTst-missing-at-B-T negatives above: a B-LT message
    /// carrying a genuine <c>sigTst</c> and a <c>valData</c> element, with no <c>refs</c> element anywhere,
    /// validates successfully.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-22.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncSucceedsForAConformantBLTMessageWithValidationDataAndNoReferences()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades conformant b-lt positive payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tokenBytes;
        using(PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], signature, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            tokenBytes = token.AsReadOnlySpan().ToArray();
        }

        byte[] sigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(tokenBytes, Type: null, Encoding: null, SpecRef: null)]));
        byte[] valDataElement = BuildUnsignedHeaderElementBytes(ValidationDataLabel, writer =>
            WriteValidationDataWithOneCertificateOracle(writer, "an unrelated validation-data certificate"u8.ToArray()));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([sigTstElement, valDataElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BLT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "sigTst present + valData present + no refs must validate at level B-LT.");
        Assert.IsNotNull(result.Verified!.Value.Value.UnsignedHeaders);
        Assert.HasCount(2, result.Verified.Value.Value.UnsignedHeaders!);
    }


    /// <summary>
    /// The level-aware <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload's
    /// malformed-token path -- a <c>sigTst</c> token whose <c>Val</c> bytes cannot be opened as CMS at all
    /// (<see cref="TimestampTokenInfo.ReadFromTokenAsync"/>'s own fail-closed
    /// catch, collected as <see cref="CBAdESTimestampTokenBindingFailureReason.TokenNotRead"/>) -- leaves a
    /// <see cref="MeteredHousePool"/> exactly balanced: the rented token carrier
    /// (<see cref="PkiCertificateMemory"/>) returns via its own <c>using</c>
    /// inside <c>VerifyOneTimestampTokenAsync</c> even though the token never opens.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncWithLevelMalformedSignatureTimestampTokenLeavesMeteredPoolBalanced()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades malformed-token metered-pool negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        //Untyped (no `type` member, the RFC 3161 legacy shape), so CB-6.3-02 never fires -- garbage Val bytes
        //alone drive TokenNotRead, exercising VerifyOneTimestampTokenAsync's own fail-closed catch from inside
        //the level-aware token loop.
        byte[] sigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec([0x01, 0x02, 0x03, 0x04], Type: null, Encoding: null, SpecRef: null)]));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([sigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using var metered = new MeteredHousePool();
        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BT, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A sigTst token that cannot be opened must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESTimestampTokenBindingViolation>(failure.Violations);
        Assert.IsNotNull(violation, "The unopenable token must surface as TokenNotRead.");
        Assert.AreEqual(CBAdESTimestampTokenBindingFailureReason.TokenNotRead, violation!.Reason);

        //result now OWNS the decoded headers/unsignedHeaders;
        //disposing it explicitly here is what "returns to the pool" means for this failure arm.
        result.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount,
            "The malformed-token path inside the level-aware token loop must not leak the rented token carrier or any parse-side carrier once the result -- which now owns the decoded facts -- is disposed.");
    }


    /// <summary>
    /// The level-aware <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload's
    /// violations path -- reaching <see cref="CBAdESLevelRules.CheckReferencesResolveToValidationDataAsync"/>,
    /// collecting CB-A.1.1-30's cross-consistency violation, and
    /// handing the decoded <c>headers</c>/<c>unsignedHeaders</c> to the returned
    /// <see cref="CBAdESRuleViolationsFailure"/>'s <see cref="CBAdESValidationResult"/> rather than disposing
    /// them internally (see that type's own remarks) -- leaves a <see cref="MeteredHousePool"/> exactly
    /// balanced once that result is disposed.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncWithLevelViolationsPathLeavesMeteredPoolBalanced()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] x5tDigestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, x5tDigestBytes);
        byte[] payload = "cb-ades violations-path metered-pool negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wrongPreimageDigest = await CreateSha256DigestBytesAsync("this is not the certificate valData carries"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] actualValDataCertificateBytes = "the actual certificate bytes placed in valData"u8.ToArray();

        byte[] refsElement = BuildUnsignedHeaderElementBytes(ReferencesLabel, writer =>
            WriteReferencesWithOneCertificateOracle(writer, new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), wrongPreimageDigest));
        byte[] valDataElement = BuildUnsignedHeaderElementBytes(ValidationDataLabel, writer =>
            WriteValidationDataWithOneCertificateOracle(writer, actualValDataCertificateBytes));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([refsElement, valDataElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using var metered = new MeteredHousePool();
        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, AdESBaselineLevel.BB, metered.Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "An unresolved refs entry must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        Assert.IsNotNull(FindViolation<CBAdESReferencesValidationDataConsistencyViolation>(failure.Violations), "CB-A.1.1-30 must be collected.");

        //result now OWNS the decoded headers/unsignedHeaders;
        //disposing it explicitly here is what "returns to the pool" means for this failure arm.
        result.Dispose();
        Assert.AreEqual(0, metered.OutstandingCount,
            "The violations path hands the decoded headers/unsignedHeaders to the returned result rather than leaking them, so the pool balances once that result -- which now owns them -- is disposed.");
    }


    /// <summary>
    /// A cancellation token that becomes canceled as a side effect of
    /// <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CryptoEventSink?, CancellationToken)"/>'s
    /// own genuine signature verification (step d, BEFORE the level-aware token loop begins -- <c>Cose.VerifyAsync</c>
    /// checks cancellation only at entry, never again after calling <c>verificationDelegate</c>) is observed
    /// while the level-aware <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload iterates the
    /// <c>uHeaders</c> TOKEN LOOP over TWO genuine, separate <c>sigTst</c> instances -- the loop aborts on the
    /// FIRST instance's own <see cref="TimestampTokenInfo.ReadFromTokenAsync"/> call
    /// (its CMS-verify seam's own <see cref="CancellationToken.ThrowIfCancellationRequested"/>) and never
    /// reaches the second. A <see cref="MeteredHousePool"/> proves every carrier rented up to that point -- the
    /// parse-side carriers and the first token's own rented carrier -- is disposed rather than leaked.
    /// </summary>
    /// <remarks>
    /// Three sentinels pin exactly where the loop stopped, since neither a matching
    /// <see cref="OperationCanceledException.CancellationToken"/> nor a balanced pool alone can tell zero, one,
    /// and both sigTst instances apart: (1) <c>cancelTriggerCallCount</c> proves the COSE-level verification
    /// delegate -- the cancellation TRIGGER -- runs exactly once, strictly before any token is opened; (2)
    /// <c>secondToken</c> is minted over an extra embedded certificate so its wire length can never coincide
    /// with <c>firstToken</c>'s, and <see cref="MeteredHousePool.RentedCountOfSize"/> at that length being zero
    /// proves the second instance's own token bytes were never rented at all -- ruling out the loop swallowing
    /// the first cancellation and continuing on to the second; (3) the same query at the first token's OWN
    /// length being at least one proves the loop reached that far, ruling out an abort even earlier that never
    /// touches any token.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncWithLevelObservesCancellationDuringTheTokenLoopAndLeavesMeteredPoolBalanced()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;
        using TsaFixture tsa = CreateTsaFixture();

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] protectedHeader = BuildBaselineProtectedHeaderBytes(WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, digestBytes);
        byte[] payload = "cb-ades token-loop cancellation metered-pool negative payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] firstTokenBytes;
        using(PkiCertificateMemory firstToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], signature, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            firstTokenBytes = firstToken.AsReadOnlySpan().ToArray();
        }

        //Minted over an extra embedded certificate (the root, alongside the authority) so its wire length can
        //never coincide with firstTokenBytes's -- the discriminating rent-size sentinel below needs a length
        //that belongs to this instance and no other.
        byte[] secondTokenBytes;
        using(PkiCertificateMemory secondToken = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority, tsa.Root], signature, TestClock.CanonicalEpoch.AddSeconds(1), BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false))
        {
            secondTokenBytes = secondToken.AsReadOnlySpan().ToArray();
        }

        Assert.AreNotEqual(firstTokenBytes.Length, secondTokenBytes.Length,
            "The two tokens' wire lengths must differ, or the discriminating rent-size sentinel below could not tell which of them was ever rented.");

        //Two SEPARATE sigTst instances (Table 14 note 7's legal repeated-sigTst pattern) -- the loop must reach
        //only the first before the already-canceled token aborts it; the second must never be touched at all.
        byte[] firstSigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(firstTokenBytes, Type: null, Encoding: null, SpecRef: null)]));
        byte[] secondSigTstElement = BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(secondTokenBytes, Type: null, Encoding: null, SpecRef: null)]));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([firstSigTstElement, secondSigTstElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using var cts = new CancellationTokenSource();
        int cancelTriggerCallCount = 0;

        //Genuinely verifies (the signature IS valid), then cancels as a side effect BEFORE returning --
        //Cose.VerifyAsync itself never re-checks cancellation after calling this delegate, so step d still
        //reports success; the now-canceled token is only observed once the level-aware token loop reaches its
        //own first per-token async step. The counter pins that this cancellation TRIGGER itself runs exactly
        //once, never once per uHeaders element.
        VerificationDelegate verifyThenCancel = async (dataToVerify, signatureToVerify, publicKeyMaterial, context, cancellationToken) =>
        {
            Interlocked.Increment(ref cancelTriggerCallCount);
            (bool isVerified, CryptoEvent? evt) = await MicrosoftCryptographicFunctions.VerifyP256Async(dataToVerify, signatureToVerify, publicKeyMaterial, new FakeTimeProvider(TestClock.CanonicalEpoch), context, cancellationToken).ConfigureAwait(false);
            await cts.CancelAsync().ConfigureAwait(false);

            return (isVerified, evt);
        };

        using var metered = new MeteredHousePool();

        OperationCanceledException exception = await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
            await CBAdESSignatureValidation.ValidateAsync(
                wireBytes,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CoseSerialization.BuildSigStructure,
                publicKey,
                verifyThenCancel,
                dereference: null,
                dereferenceContext: null,
                externalDetachedPayload: null,
                unknownMechanismHandler: null,
                AdESBaselineLevel.BT,
                CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
                metered.Pool,
                cancellationToken: cts.Token).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(cts.Token, exception.CancellationToken, "The propagated exception must carry the exact token the verification delegate canceled.");
        Assert.AreEqual(0, metered.OutstandingCount,
            "A cancellation observed while the level-aware token loop processes the first of two sigTst instances must leave every carrier rented up to that point -- the parse-side carriers and the first token's own rented carrier -- disposed, never leaked, with the second instance never reached at all.");
        Assert.AreEqual(1, cancelTriggerCallCount,
            "The cancellation trigger -- the COSE-level verification delegate -- must run exactly once, strictly before the level-aware token loop begins at all.");
        Assert.IsGreaterThanOrEqualTo(1, metered.RentedCountOfSize(firstTokenBytes.Length),
            "The loop must have reached the first sigTst instance's own token carrier -- ruling out a regression that aborts even earlier, before any token is touched at all.");
        Assert.AreEqual(0, metered.RentedCountOfSize(secondTokenBytes.Length),
            "The second sigTst instance's own token bytes -- of a deliberately distinct wire length -- must never be rented at all, ruling out the loop swallowing the first token's cancellation and continuing on to process the second.");
    }


    // Shared oracle helpers -- CBOR assembly (independent of every production encoder).

    /// <summary>
    /// Writes one <c>tstContainer</c> value directly: <c>{1: [+TstToken]}</c> (clause 5.4.3.3).
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="tokens">The tokens to encapsulate, in order.</param>
    private static void WriteTstContainerOracle(CborWriter writer, IReadOnlyList<TstTokenWireSpec> tokens)
    {
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // tstTokens, clause 5.4.3.3.
        writer.WriteStartArray(tokens.Count);
        foreach(TstTokenWireSpec token in tokens)
        {
            WriteTstTokenOracle(writer, token);
        }

        writer.WriteEndArray();
        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes one <c>TstToken</c> value directly: <c>{1: bstr val, ?2: tstr type, ?3: uri encoding, ?4: uri specRef}</c>
    /// (clause 5.4.3.3).
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="token">The token to write.</param>
    private static void WriteTstTokenOracle(CborWriter writer, TstTokenWireSpec token)
    {
        int memberCount = 1
            + (token.Type is not null ? 1 : 0)
            + (token.Encoding is not null ? 1 : 0)
            + (token.SpecRef is not null ? 1 : 0);

        writer.WriteStartMap(memberCount);
        writer.WriteInt32(1); // val, clause 5.4.3.3.
        writer.WriteByteString(token.Val);

        if(token.Type is not null)
        {
            writer.WriteInt32(2); // type, clause 5.4.3.3.
            writer.WriteTextString(token.Type);
        }

        if(token.Encoding is not null)
        {
            writer.WriteInt32(3); // encoding, clause 5.4.3.3.
            writer.WriteTag(CborTag.Uri);
            writer.WriteTextString(token.Encoding);
        }

        if(token.SpecRef is not null)
        {
            writer.WriteInt32(4); // specRef, clause 5.4.3.3.
            writer.WriteTag(CborTag.Uri);
            writer.WriteTextString(token.SpecRef);
        }

        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes one <c>refs</c> value directly (Annex A.1.1), carrying exactly one <c>xRefs</c> entry:
    /// <c>{1: [CertId]}</c> where <c>CertId = {1: [hashAlg, hashVal]}</c> (only the mandatory <c>x5t</c> member).
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="algorithm">The reference's digest-algorithm identifier.</param>
    /// <param name="digest">The reference's digest bytes.</param>
    private static void WriteReferencesWithOneCertificateOracle(CborWriter writer, AdESDigestAlgorithmIdentifier algorithm, byte[] digest)
    {
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // xRefs, Annex A.1.1, Table A.1.
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // x5t, Annex A.1.1, Table A.1.
        WriteHashAlgorithmDigestPairOracle(writer, algorithm, digest);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes one <c>valData</c> value directly (clause 5.3.4), carrying exactly one <c>xVals</c> entry under
    /// the <c>x509Cert</c> arm: <c>{1: [{1: pkiOb}]}</c> where <c>pkiOb = {1: bstr val}</c>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="certificateBytes">The certificate bytes to place.</param>
    private static void WriteValidationDataWithOneCertificateOracle(CborWriter writer, byte[] certificateBytes)
    {
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // xVals, clause 5.3.4, Table 11.
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // x509Cert, clause 5.3.4.
        writer.WriteStartMap(1);
        writer.WriteInt32(1); // val, clause 5.4.3.1 (pkiOb).
        writer.WriteByteString(certificateBytes);
        writer.WriteEndMap();
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
    }


    /// <summary>
    /// Independently assembles the <c>arcTst</c> message-imprint input (clause 5.3.5.3, twelve steps) for a
    /// <c>COSE_Sign1</c> signature with an attached payload and no RFC 9338 countersignature — never calling
    /// <see cref="Verifiable.Cbor.CBAdESMessageImprints"/>, matching this file's independent-oracle discipline.
    /// </summary>
    /// <param name="bodyProtectedHeader">The body-layer protected-header bytes (step 3).</param>
    /// <param name="externallySuppliedData">The externally supplied application data (step 5); empty for none.</param>
    /// <param name="payload">The attached COSE Payload bytes (steps 6/7).</param>
    /// <param name="signatureValue">The COSE signature value's raw content bytes (step 9).</param>
    /// <param name="precedingUHeadersElements">
    /// The already-encoded <c>UHeaderInstance</c> element bytes that precede the specific <c>arcTst</c> instance
    /// under construction, in wire order (steps 10/11, validation variant) — empty when this instance is the
    /// first element in <c>uHeaders</c> (a present-but-empty prefix contributes zero items, never a
    /// placeholder, since <c>uHeaders</c> itself is never absent here — the <c>arcTst</c> instance under test is
    /// always one of its own members).
    /// </param>
    /// <returns>The encoded message-imprint input bytes.</returns>
    private static byte[] BuildArcTstImprintInputOracle(
        byte[] bodyProtectedHeader,
        byte[] externallySuppliedData,
        byte[] payload,
        byte[] signatureValue,
        IReadOnlyList<byte[]> precedingUHeadersElements)
    {
        int itemCount = 1  // step 2: context text "Signature1" (COSE_Sign1, no signer layer -- step 4 skipped).
            + 1            // step 3: body-layer protected header.
            + 1            // step 5: externally supplied data.
            + 1            // steps 6/7: payload (attached).
            + 1            // step 9: signature value.
            + precedingUHeadersElements.Count; // steps 10/11: the preceding elements, verbatim, in order.

        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(itemCount);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(bodyProtectedHeader);
        writer.WriteByteString(externallySuppliedData);
        writer.WriteByteString(payload);
        writer.WriteByteString(signatureValue);

        foreach(byte[] element in precedingUHeadersElements)
        {
            //Each uHeaders array element is itself a CBOR byte string wrapping the UHeaderInstance map
            //(CB-5.3.1-04); precedingUHeadersElements carries the unwrapped map bytes (the same shape
            //BuildUnsignedHeaderElementBytes returns), so the wrapping happens here -- matching exactly what
            //BuildUnsignedHeadersArrayBytes does when placing the same element into the wire uHeaders array,
            //and what the production reader's ReadEncodedValue() extracts back out at that array position.
            writer.WriteByteString(element);
        }

        writer.WriteEndArray();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Mints a genuine, correctly-bound <c>sigTst</c> element over <paramref name="signature"/> and encodes it
    /// directly — the CB-6.3-21 presence every level B-T and above requires, needed by the arcTst-focused
    /// B-LTA fixtures beside this method precisely because level B-LTA implies B-T.
    /// </summary>
    /// <param name="tsa">The Time-Stamping Authority fixture to mint under.</param>
    /// <param name="signature">The COSE signature value <c>sigTst</c>'s trivial message imprint (clause 5.3.3) binds.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> element bytes.</returns>
    private static async ValueTask<byte[]> BuildGenuineSignatureTimestampElementAsync(TsaFixture tsa, byte[] signature, CancellationToken cancellationToken)
    {
        byte[] tokenBytes;
        using(PkiCertificateMemory token = await X509ChainTestRingTimestamping.MintTimestampTokenAsync(
            tsa.Authority, [tsa.Authority], signature, TestClock.CanonicalEpoch, BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            tokenBytes = token.AsReadOnlySpan().ToArray();
        }

        return BuildUnsignedHeaderElementBytes(SignatureTimestampLabel, writer =>
            WriteTstContainerOracle(writer, [new TstTokenWireSpec(tokenBytes, Type: null, Encoding: null, SpecRef: null)]));
    }


    /// <summary>
    /// Writes the shared "digest algorithm + digest value" two-element <c>COSE_CertHash</c>/<c>DigAlgVal</c>
    /// array shape directly: <c>[hashAlg, hashVal]</c>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="algorithm">The digest-algorithm identifier.</param>
    /// <param name="digest">The digest bytes.</param>
    private static void WriteHashAlgorithmDigestPairOracle(CborWriter writer, AdESDigestAlgorithmIdentifier algorithm, byte[] digest)
    {
        writer.WriteStartArray(2);
        WriteDigestAlgorithmIdentifierOracle(writer, algorithm);
        writer.WriteByteString(digest);
        writer.WriteEndArray();
    }


    /// <summary>
    /// Writes a digest-algorithm identifier per the CDDL's <c>int / tstr</c> union directly.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="identifier">The identifier to write.</param>
    /// <exception cref="NotSupportedException"><paramref name="identifier"/> is an unknown arm.</exception>
    private static void WriteDigestAlgorithmIdentifierOracle(CborWriter writer, AdESDigestAlgorithmIdentifier identifier)
    {
        _ = identifier switch
        {
            AdESDigestAlgorithmIntegerIdentifier integer => WriteInteger(writer, integer),
            AdESDigestAlgorithmTextIdentifier text => WriteText(writer, text),
            _ => throw new NotSupportedException($"Unknown digest-algorithm identifier arm '{identifier.GetType()}'.")
        };

        static bool WriteInteger(CborWriter w, AdESDigestAlgorithmIntegerIdentifier value)
        {
            w.WriteInt32(value.Value);
            return true;
        }

        static bool WriteText(CborWriter w, AdESDigestAlgorithmTextIdentifier value)
        {
            w.WriteTextString(value.Value);
            return true;
        }
    }


    /// <summary>
    /// Assembles a minimal, conformant CB-AdES B-B protected-header map directly: <c>alg</c> (1), CWT Claims
    /// (15) with the <c>iat</c> claim (key 6), and <c>x5t</c> (34) — the same three-member shape every
    /// exemplar in this directory mints, in ascending label order.
    /// </summary>
    /// <param name="algorithm">The <c>alg</c> value (IANA COSE Algorithms identifier).</param>
    /// <param name="issuedAt">The claimed signing time for the mandatory CWT Claims member.</param>
    /// <param name="x5tDigestBytes">The <c>x5t</c> digest bytes, always under SHA-256.</param>
    /// <returns>The encoded protected-header map bytes.</returns>
    private static byte[] BuildBaselineProtectedHeaderBytes(int algorithm, DateTimeOffset issuedAt, byte[] x5tDigestBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(3);

        writer.WriteInt32(1); // alg, RFC 9052 section 3.1.
        writer.WriteInt32(algorithm);

        writer.WriteInt32(15); // CWT Claims, RFC 9597 / clause 5.1.9.
        writer.WriteStartMap(1);
        writer.WriteInt32(6); // iat, RFC 8392 section 3.1.6.
        writer.WriteInt64(issuedAt.ToUnixTimeSeconds());
        writer.WriteEndMap();

        writer.WriteInt32(34); // x5t, RFC 9360 section 2 / clause 5.1.7.
        WriteHashAlgorithmDigestPairOracle(writer, new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), x5tDigestBytes);

        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Assembles the same minimal, conformant CB-AdES B-B protected-header map
    /// <see cref="BuildBaselineProtectedHeaderBytes"/> writes, plus one <c>adoTst</c> member (265, clause
    /// 5.2.6) — the fourth member sorts last under canonical CBOR map-key ordering (RFC 8949
    /// §4.2.1: shorter encodings first, so labels 1/15/34/265 already fall in ascending order).
    /// </summary>
    /// <param name="algorithm">The <c>alg</c> value (IANA COSE Algorithms identifier).</param>
    /// <param name="issuedAt">The claimed signing time for the mandatory CWT Claims member.</param>
    /// <param name="x5tDigestBytes">The <c>x5t</c> digest bytes, always under SHA-256.</param>
    /// <param name="writeAdoTst">Writes the <c>adoTst</c> member's <c>tstContainer</c> value (see <see cref="WriteTstContainerOracle"/>).</param>
    /// <returns>The encoded protected-header map bytes.</returns>
    private static byte[] BuildProtectedHeaderBytesWithPayloadTimestamp(int algorithm, DateTimeOffset issuedAt, byte[] x5tDigestBytes, Action<CborWriter> writeAdoTst)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(4);

        writer.WriteInt32(1); // alg, RFC 9052 section 3.1.
        writer.WriteInt32(algorithm);

        writer.WriteInt32(15); // CWT Claims, RFC 9597 / clause 5.1.9.
        writer.WriteStartMap(1);
        writer.WriteInt32(6); // iat, RFC 8392 section 3.1.6.
        writer.WriteInt64(issuedAt.ToUnixTimeSeconds());
        writer.WriteEndMap();

        writer.WriteInt32(34); // x5t, RFC 9360 section 2 / clause 5.1.7.
        WriteHashAlgorithmDigestPairOracle(writer, new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), x5tDigestBytes);

        writer.WriteInt32(265); // adoTst, clause 5.2.6.
        writeAdoTst(writer);

        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes one <c>UHeaderInstance</c> element directly: a one-entry map keyed by <paramref name="label"/>,
    /// whose value <paramref name="writeValue"/> writes (clause 5.3.1, Table 8).
    /// </summary>
    /// <param name="label">The element's Table 8 label.</param>
    /// <param name="writeValue">Writes the element's value.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    private static byte[] BuildUnsignedHeaderElementBytes(int label, Action<CborWriter> writeValue)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(label);
        writeValue(writer);
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes the whole <c>uHeaders</c> array directly: one <c>bstr</c> per element, in order (clause 5.3.1).
    /// </summary>
    /// <param name="elements">The already-encoded <c>UHeaderInstance</c> element bytes, in order.</param>
    /// <returns>The encoded <c>uHeaders</c> array bytes.</returns>
    private static byte[] BuildUnsignedHeadersArrayBytes(IReadOnlyList<byte[]> elements)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(elements.Count);
        foreach(byte[] element in elements)
        {
            writer.WriteByteString(element);
        }

        writer.WriteEndArray();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Writes the unprotected headers map directly, carrying <paramref name="uHeadersArrayBytes"/> as the
    /// single <c>uHeaders</c> member (clause 5.3.1, Annex B label 268), or empty when <see langword="null"/>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="uHeadersArrayBytes">The encoded <c>uHeaders</c> array bytes, or <see langword="null"/> to omit the member entirely.</param>
    private static void WriteUnprotectedMapOracle(CborWriter writer, byte[]? uHeadersArrayBytes)
    {
        if(uHeadersArrayBytes is null)
        {
            writer.WriteStartMap(0);
            writer.WriteEndMap();
            return;
        }

        writer.WriteStartMap(1);
        writer.WriteInt32(268); // uHeaders, clause 5.3.1, Annex B.
        writer.WriteEncodedValue(uHeadersArrayBytes);
        writer.WriteEndMap();
    }


    /// <summary>
    /// Assembles the whole <c>COSE_Sign1</c> wire message directly: the tag-18 prefix, the fixed 4-element
    /// array (RFC 9052 section 4.2), <paramref name="protectedHeader"/> as the <c>body_protected</c> byte
    /// string, an unprotected map carrying <paramref name="uHeadersArrayBytes"/> (or none), the attached
    /// <paramref name="payload"/>, and <paramref name="signature"/>.
    /// </summary>
    /// <param name="protectedHeader">The protected header bytes (the <c>body_protected</c> byte string).</param>
    /// <param name="uHeadersArrayBytes">The encoded <c>uHeaders</c> array bytes, or <see langword="null"/> to omit the unprotected member entirely.</param>
    /// <param name="payload">The attached payload bytes.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <returns>The encoded <c>COSE_Sign1</c> wire bytes.</returns>
    private static byte[] BuildCoseSign1Bytes(byte[] protectedHeader, byte[]? uHeadersArrayBytes, byte[] payload, byte[] signature)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteTag(new CborTag((ulong)18)); // COSE_Sign1_Tagged, RFC 9052 section 2 / clause 4.3.
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);
        WriteUnprotectedMapOracle(writer, uHeadersArrayBytes);
        writer.WriteByteString(payload);
        writer.WriteByteString(signature);
        writer.WriteEndArray();
        return writerBuffer.WrittenSpan.ToArray();
    }


    // Shared oracle helpers -- signing, digesting, minting, validating.

    /// <summary>
    /// Signs <paramref name="sigStructure"/> with <paramref name="privateKey"/> via
    /// <see cref="MicrosoftCryptographicFunctionsAdapter.SignP256Async"/>, returning the raw signature bytes for
    /// direct splicing into an independently minted <c>COSE_Sign1</c> array.
    /// </summary>
    /// <param name="privateKey">The private key to sign with.</param>
    /// <param name="sigStructure">The Sig_structure bytes to sign.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The raw signature bytes.</returns>
    private static async ValueTask<byte[]> SignSigStructureAsync(PrivateKeyMemory privateKey, byte[] sigStructure, CancellationToken cancellationToken)
    {
        (Signature signature, _) = await MicrosoftCryptographicFunctions.SignP256Async(privateKey.AsReadOnlyMemory(), sigStructure, BaseMemoryPool.Shared, cancellationToken: cancellationToken, timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch)).ConfigureAwait(false);
        using(signature)
        {
            return signature.AsReadOnlySpan().ToArray();
        }
    }


    /// <summary>
    /// Computes a real SHA-256 digest over <paramref name="input"/> through the registered digest delegate,
    /// never a hand-rolled hash.
    /// </summary>
    /// <param name="input">The bytes to digest.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The digest bytes.</returns>
    private static async ValueTask<byte[]> CreateSha256DigestBytesAsync(byte[] input, CancellationToken cancellationToken)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        return digest.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Decomposes an already-minted token's own <c>SignedData</c> and rebuilds it with its <c>certificates</c>
    /// field's <c>SET OF CertificateChoices</c> content replaced verbatim by <paramref name="certificateEntries"/>
    /// (each already a complete TLV), or with the field OMITTED entirely when none are supplied — the
    /// malformed-embedded-material fixture technique, independently duplicated from <c>TimestampTokenEmbeddedMaterialTests</c>'s
    /// identically-shaped helper (this repo's established convention for a small, class-scoped byte-splice
    /// helper, matching this file's own <c>MintTokenWithArbitraryImprintAlgorithm</c> precedent). The token's
    /// signature does not cover <c>certificates</c> (RFC 5652 §5.4), so splicing this field leaves the
    /// signature verifiable.
    /// </summary>
    /// <param name="token">The already-minted token.</param>
    /// <param name="certificateEntries">The raw TLV bytes of every <c>CertificateChoices</c> entry the rebuilt field carries, in order; empty to omit the field entirely.</param>
    /// <returns>The doctored token; the caller disposes it.</returns>
    private static PkiCertificateMemory RebuildTokenWithCertificatesField(PkiCertificateMemory token, params ReadOnlyMemory<byte>[] certificateEntries)
    {
        var outer = new System.Formats.Asn1.AsnReader(token.AsReadOnlySpan().ToArray(), System.Formats.Asn1.AsnEncodingRules.DER);
        System.Formats.Asn1.AsnReader contentInfo = outer.ReadSequence();
        string contentType = contentInfo.ReadObjectIdentifier();
        System.Formats.Asn1.AsnReader explicitContent = contentInfo.ReadSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0));
        System.Formats.Asn1.AsnReader signedData = explicitContent.ReadSequence();

        ReadOnlyMemory<byte> version = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte> digestAlgorithms = signedData.ReadEncodedValue();
        ReadOnlyMemory<byte> encapContentInfo = signedData.ReadEncodedValue();

        if(signedData.HasData && signedData.PeekTag() == new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0, isConstructed: true))
        {
            //The token's own certificates field, discarded: the rebuilt field below replaces it entirely with
            //certificateEntries (or omits it) rather than preserving it.
            _ = signedData.ReadEncodedValue();
        }

        ReadOnlyMemory<byte> signerInfos = signedData.ReadEncodedValue();
        signedData.ThrowIfNotEmpty();

        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            writer.WriteObjectIdentifier(contentType);
            using(writer.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0)))
            {
                using(writer.PushSequence())
                {
                    writer.WriteEncodedValue(version.Span);
                    writer.WriteEncodedValue(digestAlgorithms.Span);
                    writer.WriteEncodedValue(encapContentInfo.Span);
                    if(certificateEntries.Length > 0)
                    {
                        using(writer.PushSetOf(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0)))
                        {
                            foreach(ReadOnlyMemory<byte> entry in certificateEntries)
                            {
                                writer.WriteEncodedValue(entry.Span);
                            }
                        }
                    }

                    writer.WriteEncodedValue(signerInfos.Span);
                }
            }
        }

        byte[] encoded = writer.Encode();
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(encoded.Length);
        encoded.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
    }


    /// <summary>
    /// Builds a structurally otherwise well-formed X.509 certificate whose <c>[0]</c> EXPLICIT version wrapper
    /// carries <c>5</c>, a value RFC 5280 §4.1.2.1 admits only 0, 1, or 2 for — <see cref="ManagedCertificate.Parse"/>
    /// rejects it on that one narrower check while the outer tag still passes tag discrimination as a legal
    /// untagged-<c>Certificate</c> candidate, mirroring <c>TimestampTokenEmbeddedMaterialTests.BuildBrokenCertificateMember</c>'s
    /// identically-shaped malformed-certificates fixture.
    /// </summary>
    /// <returns>The broken member's TLV.</returns>
    private static byte[] BuildBrokenCertificateMember()
    {
        var writer = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using(writer.PushSequence())                                        //Certificate.
        {
            using(writer.PushSequence())                                    //tbsCertificate.
            {
                using(writer.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0)))
                {
                    writer.WriteInteger(5);                                 //RFC 5280 §4.1.2.1 admits only 0, 1, 2.
                }

                writer.WriteInteger(1);                                     //serialNumber stand-in.
                using(writer.PushSequence())                                //signature AlgorithmIdentifier stand-in.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                }

                using(writer.PushSequence())                                //issuer -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //validity.
                {
                    writer.WriteUtcTime(TestClock.CanonicalEpoch.AddYears(-1));
                    writer.WriteUtcTime(TestClock.CanonicalEpoch.AddYears(9));
                }

                using(writer.PushSequence())                                //subject -- an empty Name suffices.
                {
                }

                using(writer.PushSequence())                                //subjectPublicKeyInfo.
                {
                    using(writer.PushSequence())
                    {
                        writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                    }

                    writer.WriteBitString([0x00]);
                }
            }

            using(writer.PushSequence())                                    //signatureAlgorithm stand-in.
            {
                writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            writer.WriteBitString([]);                                      //signatureValue stand-in.
        }

        return writer.Encode();
    }


    /// <summary>
    /// A TEST-ONLY <see cref="VerifyCmsSignedDataDelegate"/> standing in for a verification backend that
    /// resolves a signer's key by a means OTHER than the structure's own embedded <c>certificates</c> field
    /// (an external trust anchor, for instance) — proving <see cref="CBAdESLevelRules.IsTimestampTokenSignerCertificateResolvedAsync"/>'s
    /// <c>valData</c> identity-match disjunct is independently reachable.
    /// Registering a custom delegate under the registry's extension seam is this library's own extension
    /// architecture (the same seam <c>TestSetup</c> itself registers the shipped backends through), not a test
    /// seam. This method parses only the outer <c>ContentInfo</c>/<c>SignedData</c> shape (own the format) to
    /// extract the encapsulated <c>eContentType</c>/<c>eContent</c> a genuine backend would surface, and
    /// returns it directly without re-verifying the CMS signature value itself — the signature math is already
    /// proven by every other test in this file and by <c>ManagedCmsVerification</c>'s own suite; this stub's
    /// only job is to unblock <see cref="TimestampTokenInfo.ReadFromTokenAsync"/> for a token whose
    /// <c>certificates</c> field is deliberately empty, a shape both shipped backends refuse.
    /// </summary>
    /// <param name="signedData">The CMS SignedData carrier with encapsulated content.</param>
    /// <param name="pool">The memory pool for the content allocation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The stubbed verified content. The caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "contentOwner and placeholderCertificate both transfer ownership into the returned " +
            "CmsVerifiedContent (that type's own constructor remarks: 'Ownership of the content buffer and " +
            "every certificate transfers to this instance'), which the caller disposes -- this method's own " +
            "doc comment states that explicitly. Roslyn tracks the locally-rented owners themselves, not the " +
            "fact that they are reachable through the returned CmsVerifiedContent one constructor call later.")]
    private static ValueTask<CmsVerifiedContent> VerifyCmsSignedDataExternallyKeyedStub(
        Verifiable.Cryptography.Pki.CmsSignedData signedData, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        var outer = new System.Formats.Asn1.AsnReader(signedData.AsReadOnlySpan().ToArray(), System.Formats.Asn1.AsnEncodingRules.BER);
        System.Formats.Asn1.AsnReader contentInfo = outer.ReadSequence();
        _ = contentInfo.ReadObjectIdentifier();
        System.Formats.Asn1.AsnReader explicitContent = contentInfo.ReadSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0));
        System.Formats.Asn1.AsnReader parsedSignedData = explicitContent.ReadSequence();

        _ = parsedSignedData.ReadInteger();                                  //version
        _ = parsedSignedData.ReadSetOf();                                    //digestAlgorithms

        System.Formats.Asn1.AsnReader encapContentInfo = parsedSignedData.ReadSequence();
        string eContentType = encapContentInfo.ReadObjectIdentifier();
        byte[] eContent = [];
        if(encapContentInfo.HasData)
        {
            System.Formats.Asn1.AsnReader explicitEContent = encapContentInfo.ReadSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0));
            eContent = explicitEContent.ReadOctetString();
        }

        IMemoryOwner<byte> contentOwner = pool.Rent(eContent.Length);
        eContent.CopyTo(contentOwner.Memory.Span);

        //A placeholder single-element certificate list: CmsVerifiedContent's own constructor requires a
        //non-empty Certificates list and a valid SignerIndex, but ReadFromTokenAsync consults neither -- only
        //ContentType and Content -- so its actual bytes carry no meaning here.
        IMemoryOwner<byte> placeholderOwner = pool.Rent(1);
        placeholderOwner.Memory.Span[0] = 0;
        var placeholderCertificate = new PkiCertificateMemory(placeholderOwner, PkiCertificateTags.X509Certificate);

        return ValueTask.FromResult(new CmsVerifiedContent(eContentType, contentOwner, eContent.Length, [placeholderCertificate], signerIndex: 0, []));
    }


    /// <summary>
    /// Calls the level-aware <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload over
    /// <see cref="BaseMemoryPool.Shared"/>; see the pool-parameterized overload below for a caller that supplies
    /// its own pool (a <see cref="MeteredHousePool"/> leak-regression test, for instance).
    /// </summary>
    /// <param name="wireBytes">The candidate CB-AdES wire bytes.</param>
    /// <param name="publicKey">The verifying public key.</param>
    /// <param name="level">The baseline level to check against.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The validation result. The caller owns and disposes it.</returns>
    private static ValueTask<CBAdESValidationResult> ValidateAtLevelExpectingNoThrowAsync(
        byte[] wireBytes, PublicKeyMemory publicKey, AdESBaselineLevel level, CancellationToken cancellationToken) =>
        ValidateAtLevelExpectingNoThrowAsync(wireBytes, publicKey, level, BaseMemoryPool.Shared, cancellationToken);


    /// <summary>
    /// Calls the level-aware <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload through the
    /// production <see cref="CBAdESSignatureSerialization"/>/<see cref="CoseSerialization"/>/
    /// <see cref="CBAdESLevelMessageImprintAdapters"/> seams, failing the test loudly if the call ever throws —
    /// the explicit no-throw assertion every test in this file relies on.
    /// </summary>
    /// <param name="wireBytes">The candidate CB-AdES wire bytes.</param>
    /// <param name="publicKey">The verifying public key.</param>
    /// <param name="level">The baseline level to check against.</param>
    /// <param name="pool">The memory pool to validate over.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The validation result. The caller owns and disposes it.</returns>
    private static async ValueTask<CBAdESValidationResult> ValidateAtLevelExpectingNoThrowAsync(
        byte[] wireBytes, PublicKeyMemory publicKey, AdESBaselineLevel level, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        Exception? unexpectedException = null;
        try
        {
            return await CBAdESSignatureValidation.ValidateAsync(
                wireBytes,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CoseSerialization.BuildSigStructure,
                publicKey,
                MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
                dereference: null,
                dereferenceContext: null,
                externalDetachedPayload: null,
                unknownMechanismHandler: null,
                level,
                CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
                pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex)
        {
            unexpectedException = ex;
        }

        Fail(unexpectedException);
        return default!;

        /// <summary>Reports <paramref name="exception"/> as an unconditional test failure and never returns.</summary>
        /// <param name="exception">The exception <see cref="ValidateAtLevelExpectingNoThrowAsync"/> caught.</param>
        [DoesNotReturn]
        static void Fail(Exception? exception) =>
            Assert.Fail($"CBAdESSignatureValidation.ValidateAsync must never throw on untrusted wire bytes; threw {exception?.GetType().Name}: {exception?.Message}");
    }


    /// <summary>
    /// Mints a genuinely CMS-signed RFC 3161 time-stamp token whose <c>TSTInfo.messageImprint.hashAlgorithm</c>
    /// names an arbitrary algorithm OID — an independent BouncyCastle construction that lifts the SHA-2-only
    /// restriction <see cref="X509ChainTestRingTimestamping.MintTimestampTokenOverImprint"/> enforces, needed
    /// for the CB-6.2.1-02 MD5 negative (see the class remarks for why this duplicates rather than modifies
    /// that shared test-infrastructure method). The token's own CMS signature and its <c>ESSCertIDv2</c>
    /// certificate reference stay genuinely SHA-256/ECDSA, exactly like the shared oracle — only the TSTInfo's
    /// stated message-imprint algorithm is arbitrary.
    /// </summary>
    /// <param name="authority">The Time-Stamping Authority node whose key signs the token.</param>
    /// <param name="imprintAlgorithmOid">The object identifier <c>TSTInfo.messageImprint.hashAlgorithm</c> states.</param>
    /// <param name="imprintDigestBytes">The bytes <c>TSTInfo.messageImprint.hashedMessage</c> states; content is immaterial for an algorithm this library never resolves.</param>
    /// <param name="generationTime">The <c>genTime</c> the authority states.</param>
    /// <returns>The DER-encoded <c>TimeStampToken</c> bytes.</returns>
    private static byte[] MintTokenWithArbitraryImprintAlgorithm(
        X509ChainTestRingNode authority, string imprintAlgorithmOid, byte[] imprintDigestBytes, DateTimeOffset generationTime)
    {
        BcX509Certificate bcAuthority = OcspTestFixtures.ToBouncyCastleCertificate(authority.Certificate);
        AsymmetricKeyParameter authorityPrivateKey = OcspTestFixtures.ToBouncyCastlePrivateKey(authority.SigningKey);

        SignerInfoGenerator signerInfoGenerator = new SignerInfoGeneratorBuilder()
            .Build(new Asn1SignatureFactory(X509ChainTestRing.EcdsaWithSha256SignatureName, authorityPrivateKey), bcAuthority);
        var tokenGenerator = new TimeStampTokenGenerator(
            signerInfoGenerator,
            Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256),
            new DerObjectIdentifier(X509ChainTestRingTimestamping.TestPolicyOid),
            isIssuerSerialIncluded: false);

        tokenGenerator.SetCertificates(CollectionUtilities.CreateStore(new List<BcX509Certificate> { bcAuthority }));

        var requestGenerator = new TimeStampRequestGenerator();
        requestGenerator.SetCertReq(true);
        TimeStampRequest request = requestGenerator.Generate(new DerObjectIdentifier(imprintAlgorithmOid), imprintDigestBytes);

        using Salt serialNumber = X509ChainTestRing.CreateSerialNumber();
        TimeStampToken token = tokenGenerator.Generate(
            request, new BcBigInteger(1, serialNumber.AsReadOnlySpan().ToArray()), generationTime.UtcDateTime);

        return token.GetEncoded();
    }


    /// <summary>Returns the first entry of <paramref name="violations"/> that is of type <typeparamref name="TViolation"/>, or <see langword="null"/>.</summary>
    /// <typeparam name="TViolation">The violation type to look for.</typeparam>
    /// <param name="violations">The collected violations.</param>
    /// <returns>The first matching violation, or <see langword="null"/>.</returns>
    private static TViolation? FindViolation<TViolation>(IReadOnlyList<CBAdESRuleViolation> violations) where TViolation : CBAdESRuleViolation
    {
        for(int i = 0; i < violations.Count; ++i)
        {
            if(violations[i] is TViolation match)
            {
                return match;
            }
        }

        return null;
    }


    /// <summary>Builds a Root CA and Time-Stamping Authority anchored to <see cref="TestClock.CanonicalEpoch"/>.</summary>
    /// <returns>The fixture; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both nodes transfers to the returned TsaFixture, which the caller disposes; the catch disposes the root on a partial failure.")]
    private static TsaFixture CreateTsaFixture()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider);
        try
        {
            X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider);
            return new TsaFixture(root, authority);
        }
        catch
        {
            root.Dispose();
            throw;
        }
    }


    /// <summary>
    /// The wire-level shape of one <c>TstToken</c> this file's independent oracle writes — a plain data
    /// carrier, not a codec: <see cref="WriteTstTokenOracle"/> is the only place that turns it into bytes.
    /// </summary>
    /// <param name="Val">The token's own encoded octets.</param>
    /// <param name="Type">The non-RFC-3161 <c>type</c> discriminator, or <see langword="null"/> to omit it.</param>
    /// <param name="Encoding">The <c>encoding</c> member's URI text, or <see langword="null"/> to omit it.</param>
    /// <param name="SpecRef">The <c>specRef</c> member's URI text, or <see langword="null"/> to omit it.</param>
    private sealed record TstTokenWireSpec(byte[] Val, string? Type, string? Encoding, string? SpecRef);


    /// <summary>The minted Root CA and Time-Stamping Authority nodes for one scenario, disposed together.</summary>
    /// <param name="Root">The Root CA node.</param>
    /// <param name="Authority">The Time-Stamping Authority node, issued by <see cref="Root"/>.</param>
    private sealed record TsaFixture(X509ChainTestRingNode Root, X509ChainTestRingNode Authority): IDisposable
    {
        /// <inheritdoc/>
        public void Dispose()
        {
            Authority.Dispose();
            Root.Dispose();
        }
    }
}
