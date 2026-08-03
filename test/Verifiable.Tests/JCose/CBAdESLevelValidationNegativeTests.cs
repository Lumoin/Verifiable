using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
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
/// <see cref="CBAdESSignatureValidation.ValidateAsync(ReadOnlyMemory{byte}, ParseCBAdESSign1Delegate, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, ReadOnlyMemory{byte}?, CBAdESUnknownDetachedObjectMechanismDelegate?, CBAdESBaselineLevel, BuildPayloadTimestampMessageImprintInputDelegate, TryBuildSignatureAndReferencesTimestampMessageImprintInputDelegate, TryBuildReferencesOnlyTimestampMessageImprintInputDelegate, BaseMemoryPool, CancellationToken)"/>
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
/// <strong>Deviation, recorded loudly:</strong> the CB-6.2.1-02 MD5 negative needs a genuinely CMS-signed token
/// whose <c>TSTInfo.messageImprint.hashAlgorithm</c> names MD5, which
/// <see cref="X509ChainTestRingTimestamping.MintTimestampTokenOverImprint"/> refuses to mint (its own OID
/// switch recognizes only the SHA-2 family) — this file's <see cref="MintTokenWithArbitraryImprintAlgorithm"/>
/// duplicates that method's CMS-signing shape locally (never modifying the shared test-infrastructure file,
/// to avoid colliding with sibling wavecb S4 agents also extending it) with the OID restriction lifted.
/// </para>
/// <para>
/// <strong>Every violation asserted by TYPE.</strong> Every negative test recovers its violation via
/// <see cref="FindViolation{TViolation}"/> and asserts on the closed-sum record's own properties (<c>Kind</c>,
/// <c>Reason</c>, <c>TokenCount</c>, <c>RequirementId</c>) — never on <see cref="CBAdESRuleViolation.Message"/>
/// text. Several negatives deliberately tolerate additional, unasserted violations alongside the one under
/// test (e.g. a garbage token's bytes also fail to read) — the collect posture (R-5) never stops at the first
/// violation, and this file's fixtures are chosen to keep the assertion target unambiguous regardless.
/// </para>
/// <para>
/// <strong>No-throw convention (R-5).</strong> Every negative routes through
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

    /// <summary>The MD5 digest-algorithm object identifier (rsadsi digestAlgorithm md5), for the CB-6.2.1-02 negative.</summary>
    private const string Md5AlgorithmOid = "1.2.840.113549.2.5";


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    // ------------------------------------------------------------------------------------------------------
    // CB-6.3-c: exactly one token per sigTst instance.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>
    /// CB-6.3-c: a <c>sigTst</c> element whose <c>tstContainer</c> encapsulates TWO genuine, correctly-bound
    /// RFC 3161 tokens is collected as a <see cref="CBAdESSignatureTimestampTokenCountViolation"/> naming the
    /// count, even though both tokens individually open and bind — the one-token-per-instance rule is a
    /// structural cardinality check, independent of token validity.
    /// </summary>
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
            wireBytes, publicKey, CBAdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A sigTst encapsulating two tokens must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESSignatureTimestampTokenCountViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-6.3-c must be collected.");
        Assert.AreEqual(2, violation!.TokenCount);
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-6.3-02: baseline TstToken narrowing (RFC 3161 legacy shape only).
    // ------------------------------------------------------------------------------------------------------

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
            wireBytes, publicKey, CBAdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A typed (non-RFC-3161) sigTst token must fail closed even at level B-B.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESTimestampTokenNotBaselineViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-6.3-02 must be collected.");
        Assert.AreEqual(CBAdESTimestampContainerKind.SignatureTimestamp, violation!.Kind);
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-6.3-23: refs forbidden at B-LT/B-LTA.
    // ------------------------------------------------------------------------------------------------------

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
            WriteReferencesWithOneCertificateOracle(writer, new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), referenceDigest));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([refsElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, CBAdESBaselineLevel.BLT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "refs present at B-LT must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESRefsFamilyForbiddenViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-6.3-23 must be collected.");
        Assert.AreEqual(CBAdESRefsFamilyKind.References, violation!.Kind);
        Assert.AreEqual("CB-6.3-23", violation.RequirementId);
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-6.3-21: sigTst presence at B-T+.
    // ------------------------------------------------------------------------------------------------------

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
            wireBytes, publicKey, CBAdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A missing sigTst at level B-T must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        Assert.HasCount(1, failure.Violations, "With no uHeaders member at all, only CB-6.3-21 applies at B-T -- no other level rule has anything to react to.");
        var violation = FindViolation<CBAdESSignatureTimestampMissingViolation>(failure.Violations);
        Assert.IsNotNull(violation, "CB-6.3-21 must be collected.");
    }


    // ------------------------------------------------------------------------------------------------------
    // Token-imprint binding: mismatch and MD5 message-imprint algorithm.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>
    /// A genuine, CMS-verifiable RFC 3161 <c>sigTst</c> token whose message imprint was minted over different
    /// octets than the actual COSE signature value is collected as a
    /// <see cref="CBAdESTimestampTokenBindingViolation"/> with <see cref="CBAdESTimestampTokenBindingFailureReason.ImprintMismatch"/>.
    /// </summary>
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
            wireBytes, publicKey, CBAdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

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
            wireBytes, publicKey, CBAdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "An MD5 message-imprint sigTst token must fail closed.");
        var failure = Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var violation = FindViolation<CBAdESTimestampTokenBindingViolation>(failure.Violations);
        Assert.IsNotNull(violation, "The MD5 token must surface as an unreadable token, never silently accepted.");
        Assert.AreEqual(CBAdESTimestampTokenBindingKind.SignatureTimestamp, violation!.Kind);
        Assert.AreEqual(CBAdESTimestampTokenBindingFailureReason.TokenNotRead, violation.Reason);
    }


    // ------------------------------------------------------------------------------------------------------
    // CB-A.1.1-30: refs-to-valData cross-component consistency.
    // ------------------------------------------------------------------------------------------------------

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
            WriteReferencesWithOneCertificateOracle(writer, new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), wrongPreimageDigest));
        byte[] valDataElement = BuildUnsignedHeaderElementBytes(ValidationDataLabel, writer =>
            WriteValidationDataWithOneCertificateOracle(writer, actualValDataCertificateBytes));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([refsElement, valDataElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, CBAdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

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
            WriteReferencesWithOneCertificateOracle(writer, new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), certificateDigest));
        byte[] valDataElement = BuildUnsignedHeaderElementBytes(ValidationDataLabel, writer =>
            WriteValidationDataWithOneCertificateOracle(writer, certificateBytes));
        byte[] uHeaders = BuildUnsignedHeadersArrayBytes([refsElement, valDataElement]);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, uHeaders, payload, signature);

        using CBAdESValidationResult result = await ValidateAtLevelExpectingNoThrowAsync(
            wireBytes, publicKey, CBAdESBaselineLevel.BB, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A refs entry whose digest matches the valData certificate present must validate.");
    }


    // ------------------------------------------------------------------------------------------------------
    // Positive twins combining several structurally-cheap legs.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>
    /// Positive twin of the two-token, typed-token, and imprint-mismatch negatives above: exactly ONE genuine,
    /// untyped (RFC 3161 legacy shape), correctly-bound <c>sigTst</c> token at level B-T validates successfully.
    /// </summary>
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
            wireBytes, publicKey, CBAdESBaselineLevel.BT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "One genuine, untyped, correctly-bound sigTst token must validate at level B-T.");
        Assert.IsNotNull(result.UnsignedHeaders);
        Assert.HasCount(1, result.UnsignedHeaders!);
    }


    /// <summary>
    /// Positive twin of the refs-forbidden-at-B-LT and sigTst-missing-at-B-T negatives above: a B-LT message
    /// carrying a genuine <c>sigTst</c> and a <c>valData</c> element, with no <c>refs</c> element anywhere,
    /// validates successfully.
    /// </summary>
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
            wireBytes, publicKey, CBAdESBaselineLevel.BLT, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "sigTst present + valData present + no refs must validate at level B-LT.");
        Assert.IsNotNull(result.UnsignedHeaders);
        Assert.HasCount(2, result.UnsignedHeaders!);
    }


    // ------------------------------------------------------------------------------------------------------
    // Shared oracle helpers -- CBOR assembly (independent of every production encoder).
    // ------------------------------------------------------------------------------------------------------

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
    private static void WriteReferencesWithOneCertificateOracle(CborWriter writer, CBAdESDigestAlgorithmIdentifier algorithm, byte[] digest)
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
    /// Writes the shared "digest algorithm + digest value" two-element <c>COSE_CertHash</c>/<c>DigAlgVal</c>
    /// array shape directly: <c>[hashAlg, hashVal]</c>.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="algorithm">The digest-algorithm identifier.</param>
    /// <param name="digest">The digest bytes.</param>
    private static void WriteHashAlgorithmDigestPairOracle(CborWriter writer, CBAdESDigestAlgorithmIdentifier algorithm, byte[] digest)
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
    private static void WriteDigestAlgorithmIdentifierOracle(CborWriter writer, CBAdESDigestAlgorithmIdentifier identifier)
    {
        _ = identifier switch
        {
            CBAdESDigestAlgorithmIntegerIdentifier integer => WriteInteger(writer, integer),
            CBAdESDigestAlgorithmTextIdentifier text => WriteText(writer, text),
            _ => throw new NotSupportedException($"Unknown digest-algorithm identifier arm '{identifier.GetType()}'.")
        };

        static bool WriteInteger(CborWriter w, CBAdESDigestAlgorithmIntegerIdentifier value)
        {
            w.WriteInt32(value.Value);
            return true;
        }

        static bool WriteText(CborWriter w, CBAdESDigestAlgorithmTextIdentifier value)
        {
            w.WriteTextString(value.Value);
            return true;
        }
    }


    /// <summary>
    /// Assembles a minimal, conformant CB-AdES B-B protected-header map directly: <c>alg</c> (1), CWT Claims
    /// (15) with the <c>iat</c> claim (key 6), and <c>x5t</c> (34) — the same three-member shape every S3/S4
    /// exemplar in this directory mints, in ascending label order.
    /// </summary>
    /// <param name="algorithm">The <c>alg</c> value (IANA COSE Algorithms identifier).</param>
    /// <param name="issuedAt">The claimed signing time for the mandatory CWT Claims member.</param>
    /// <param name="x5tDigestBytes">The <c>x5t</c> digest bytes, always under SHA-256.</param>
    /// <returns>The encoded protected-header map bytes.</returns>
    private static byte[] BuildBaselineProtectedHeaderBytes(int algorithm, DateTimeOffset issuedAt, byte[] x5tDigestBytes)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(3);

        writer.WriteInt32(1); // alg, RFC 9052 section 3.1.
        writer.WriteInt32(algorithm);

        writer.WriteInt32(15); // CWT Claims, RFC 9597 / clause 5.1.9.
        writer.WriteStartMap(1);
        writer.WriteInt32(6); // iat, RFC 8392 section 3.1.6.
        writer.WriteInt64(issuedAt.ToUnixTimeSeconds());
        writer.WriteEndMap();

        writer.WriteInt32(34); // x5t, RFC 9360 section 2 / clause 5.1.7.
        WriteHashAlgorithmDigestPairOracle(writer, new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), x5tDigestBytes);

        writer.WriteEndMap();
        return writer.Encode();
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
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(label);
        writeValue(writer);
        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>
    /// Encodes the whole <c>uHeaders</c> array directly: one <c>bstr</c> per element, in order (clause 5.3.1).
    /// </summary>
    /// <param name="elements">The already-encoded <c>UHeaderInstance</c> element bytes, in order.</param>
    /// <returns>The encoded <c>uHeaders</c> array bytes.</returns>
    private static byte[] BuildUnsignedHeadersArrayBytes(IReadOnlyList<byte[]> elements)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(elements.Count);
        foreach(byte[] element in elements)
        {
            writer.WriteByteString(element);
        }

        writer.WriteEndArray();
        return writer.Encode();
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
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)18); // COSE_Sign1_Tagged, RFC 9052 section 2 / clause 4.3.
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);
        WriteUnprotectedMapOracle(writer, uHeadersArrayBytes);
        writer.WriteByteString(payload);
        writer.WriteByteString(signature);
        writer.WriteEndArray();
        return writer.Encode();
    }


    // ------------------------------------------------------------------------------------------------------
    // Shared oracle helpers -- signing, digesting, minting, validating.
    // ------------------------------------------------------------------------------------------------------

    /// <summary>
    /// Signs <paramref name="sigStructure"/> with <paramref name="privateKey"/> via
    /// <see cref="MicrosoftCryptographicFunctions.SignP256Async"/>, returning the raw signature bytes for
    /// direct splicing into an independently minted <c>COSE_Sign1</c> array.
    /// </summary>
    /// <param name="privateKey">The private key to sign with.</param>
    /// <param name="sigStructure">The Sig_structure bytes to sign.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The raw signature bytes.</returns>
    private static async ValueTask<byte[]> SignSigStructureAsync(PrivateKeyMemory privateKey, byte[] sigStructure, CancellationToken cancellationToken)
    {
        (Signature signature, _) = await MicrosoftCryptographicFunctions.SignP256Async(
            privateKey.AsReadOnlyMemory(), sigStructure, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
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
    /// Calls the level-aware <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload through the
    /// production <see cref="CBAdESSignatureSerialization"/>/<see cref="CoseSerialization"/>/
    /// <see cref="CBAdESLevelMessageImprintAdapters"/> seams, failing the test loudly if the call ever throws —
    /// the explicit no-throw assertion every test in this file relies on (R-5).
    /// </summary>
    /// <param name="wireBytes">The candidate CB-AdES wire bytes.</param>
    /// <param name="publicKey">The verifying public key.</param>
    /// <param name="level">The baseline level to check against.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The validation result. The caller owns and disposes it.</returns>
    private static async ValueTask<CBAdESValidationResult> ValidateAtLevelExpectingNoThrowAsync(
        byte[] wireBytes, PublicKeyMemory publicKey, CBAdESBaselineLevel level, CancellationToken cancellationToken)
    {
        Exception? unexpectedException = null;
        try
        {
            return await CBAdESSignatureValidation.ValidateAsync(
                wireBytes,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CoseSerialization.BuildSigStructure,
                publicKey,
                MicrosoftCryptographicFunctions.VerifyP256Async,
                dereference: null,
                dereferenceContext: null,
                externalDetachedPayload: null,
                unknownMechanismHandler: null,
                level,
                CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);
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
            Assert.Fail($"CBAdESSignatureValidation.ValidateAsync must never throw on untrusted wire bytes (R-5); threw {exception?.GetType().Name}: {exception?.Message}");
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
