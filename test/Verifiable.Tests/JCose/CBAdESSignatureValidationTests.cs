using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Fail-closed-posture tests for the CB-AdES B-B validation orchestrator (<see cref="CBAdESSignatureValidation"/>)
/// and its <c>Verifiable.Cbor</c> binding (<see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Independently minted wire bytes.</strong> Every message this file feeds to
/// <see cref="CBAdESSignatureValidation.ValidateAsync(ReadOnlyMemory{byte}, ParseCBAdESSign1Delegate, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, ReadOnlyMemory{byte}?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
/// is assembled by this file's own <see cref="CborWriter"/> oracle helpers — never by calling
/// <see cref="CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader"/> (the creation-side encoder) or
/// <see cref="CBAdESSignatureCreation"/>, the S1/S2 negative-quartet precedent this file follows
/// (<c>CBAdESSignedHeaderModelTests</c>, <c>CBAdESUnsignedComponentSerializationTests</c>). Header labels
/// (<c>alg</c>=1, <c>crit</c>=2, <c>content type</c>=3, CWT Claims=15, <c>x5t</c>=34, <c>sigD</c>=267,
/// <c>uHeaders</c>=268), <c>sigD</c>'s own map keys (1-4), the CWT <c>iat</c> claim key (6), and the
/// <c>COSE_Sign1_Tagged</c> CBOR tag (18) are all written as literal integers with a citing comment, never
/// through <see cref="CoseHeaderParameters"/>/<see cref="CBAdESHeaderParameters"/>/<see cref="CoseTags"/> — the
/// same registries <see cref="CBAdESSignatureSerialization"/> itself consumes, so a shared defect there could
/// not hide behind this file's own expectations. <see cref="WellKnownCoseAlgorithms"/> (the IANA COSE
/// Algorithms registry) IS referenced directly, matching the S1 exemplar's own precedent for that specific
/// registry (external, RFC-assigned identifiers, not a CB-AdES-local Table key).
/// </para>
/// <para>
/// <strong>The Sig_structure builder is the shared COSE substrate, not the encoder under test.</strong>
/// <see cref="CoseSerialization.BuildSigStructure"/> is reused directly (both to mint each message's signature
/// bytes and as the <c>buildSigStructure</c> parameter <see cref="CBAdESSignatureValidation.ValidateAsync"/>
/// itself requires) — it is RFC 9052 §4.4's generic <c>Sig_structure</c> assembly, already exercised by
/// <c>Verifiable.Tests.Cose.CoseTests</c>, and is never touched by <see cref="CBAdESSignatureSerialization"/> or
/// <see cref="CBAdESHeaderRules"/>. Reusing it here is R-2 (reuse over reinvention), not a firewall breach.
/// </para>
/// <para>
/// <strong>Key material.</strong> Every signature is minted with the P-256 key-provisioning pattern
/// <c>Verifiable.Tests.Cose.CoseTests</c> establishes: <see cref="TestKeyMaterialProvider.CreateP256KeyMaterial"/>
/// (Microsoft ECDsa backend) paired with <see cref="MicrosoftCryptographicFunctions.SignP256Async"/>/
/// <see cref="MicrosoftCryptographicFunctions.VerifyP256Async"/>.
/// </para>
/// <para>
/// <strong>No-throw convention (R-5).</strong> Every test that feeds malformed or non-conformant wire bytes
/// (or a payload-resolution failure) routes through <see cref="ValidateExpectingNoThrowAsync"/>, which fails
/// the test loudly — via <see cref="Assert.Fail(string?)"/> — if <c>ValidateAsync</c> ever throws, rather than
/// letting an unexpected exception surface as an unhandled test-runner error. The five explicit
/// <see cref="ArgumentNullException"/> tests are the only cases that call <c>ValidateAsync</c> directly, since
/// they exist precisely to observe that one specific, intentional throw.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESSignatureValidationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A minimal conformant B-B <c>COSE_Sign1</c> (<c>alg</c> + <c>iat</c> CWT Claims + one <c>x5t</c>, attached
    /// payload, a genuine signature over the correct Sig_structure) validates successfully, and the decoded
    /// facts on the result match what was minted.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncSucceedsForMinimalConformantBBMessage()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        (byte[] protectedHeader, byte[] payload, byte[] signature) = await CreateBaselineSignedComponentsAsync(
            privateKey, digestBytes, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A minimal conformant B-B message must validate.");
        Assert.IsFalse(result.PayloadIsDetached);
        Assert.IsNull(result.UnsignedHeaders);
        Assert.IsNotNull(result.Headers);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, result.Headers!.Algorithm);
        Assert.AreEqual(TestClock.CanonicalEpoch, result.Headers.CwtClaims!.IssuedAt);
        Assert.IsNotNull(result.Headers.X5T);
        Assert.AreEqual(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), result.Headers.X5T!.HashAlgorithm);
        Assert.IsTrue(digestBytes.AsSpan().SequenceEqual(result.Headers.X5T.Digest.AsReadOnlySpan()));
    }


    /// <summary>
    /// A CWT-Claims <c>iat</c> encoded with the CBOR floating-point arm of <c>NumericDate</c>
    /// (RFC 8392 section 2's <c>int / float</c> union) validates successfully -- the wavecb S3 FX-A
    /// regression. Before <see cref="CBAdESSign1ParseResult.RawProtectedHeader"/> existed, this class rebuilt
    /// the Sig_structure's <c>body_protected</c> bytes by calling back into
    /// <see cref="CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader"/>, whose <c>EncodeCwtClaims</c>
    /// ALWAYS writes <c>iat</c> through the integer arm -- so a genuinely conformant signature over a float-form
    /// <c>iat</c> re-encoded to DIFFERENT <c>body_protected</c> bytes than the ones actually signed, and failed
    /// as <see cref="CBAdESSignatureInvalidFailure"/> even though nothing about the wire bytes was
    /// non-conformant (this is the exact failure this test asserted before the fix; the class remarks record
    /// the reasoning). Carrying the raw wire bytes captured at parse instead of re-encoding closes this gap.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncSucceedsWhenCwtClaimsIatIsEncodedAsFloatNumericDate()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        DateTimeOffset expectedIssuedAt = TestClock.CanonicalEpoch;

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(1); // alg, RFC 9052 section 3.1.
        writer.WriteInt32(WellKnownCoseAlgorithms.Es256);
        writer.WriteInt32(15); // CWT Claims, RFC 9597 / clause 5.1.9.
        writer.WriteStartMap(1);
        writer.WriteInt32(6); // iat, RFC 8392 section 3.1.6.
        writer.WriteDouble(expectedIssuedAt.ToUnixTimeSeconds()); // NumericDate's float arm, RFC 8392 section 2.
        writer.WriteEndMap();
        writer.WriteInt32(34); // x5t, RFC 9360 section 2 / clause 5.1.7.
        WriteHashAlgorithmDigestPairOracle(writer, new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes);
        writer.WriteEndMap();
        byte[] protectedHeader = writer.Encode();

        byte[] payload = "payload signed under a float-form CWT-Claims iat"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A genuine signature over a float-form CWT-Claims iat must validate -- " +
            "the Sig_structure must be built from the wire bytes captured at parse, never a re-encoding that " +
            "could pick the wrong NumericDate union arm.");
        Assert.IsFalse(result.PayloadIsDetached);
        Assert.IsNotNull(result.Headers);
        Assert.AreEqual(expectedIssuedAt, result.Headers!.CwtClaims!.IssuedAt, "The float-form iat must still decode to the exact signing time.");
        Assert.IsTrue(digestBytes.AsSpan().SequenceEqual(result.Headers.X5T!.Digest.AsReadOnlySpan()), "The verification path must have consumed the actual wire bytes -- the x5t digest decoded from the result must match what was minted.");
    }


    /// <summary>
    /// An untagged <c>COSE_Sign1</c> (no <c>COSE_Sign1_Tagged</c> prefix) parses and validates successfully --
    /// the wavecb S3 FX-F regression. Clause 4.3 states CB-AdES signatures MAY be encoded untagged as well as
    /// tagged; <see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/> peek-gates the tag read so this
    /// spec-legal input is accepted, a deliberate divergence from <see cref="CoseSerialization.ParseCoseSign1"/>'s
    /// own tagged-only behavior for the generic multi-profile COSE_Sign1 substrate.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncSucceedsForUntaggedCoseSign1()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        (byte[] protectedHeader, byte[] payload, byte[] signature) = await CreateBaselineSignedComponentsAsync(
            privateKey, digestBytes, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] taggedWireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        // The COSE_Sign1_Tagged prefix (tag 18, RFC 9052 section 2) encodes as the single byte 0xD2 for this
        // small tag value -- stripping it leaves the identical bytes in their spec-legal untagged form.
        Assert.AreEqual(0xD2, taggedWireBytes[0]);
        byte[] untaggedWireBytes = taggedWireBytes[1..];

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            untaggedWireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "An untagged COSE_Sign1 is spec-legal per ETSI TS 119 152-1 V1.1.1 clause 4.3 and must validate.");
        Assert.IsFalse(result.PayloadIsDetached);
        Assert.IsNotNull(result.Headers);
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, result.Headers!.Algorithm);
        Assert.AreEqual(TestClock.CanonicalEpoch, result.Headers.CwtClaims!.IssuedAt);
    }


    /// <summary>
    /// An unprotected headers map declaring two members (CB-4.4-01: at most the one <c>uHeaders</c> member is
    /// permitted) fails closed to <see cref="CBAdESMalformedEncodingFailure"/> at the parse step.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncFailsClosedWhenUnprotectedMapCarriesExtraMember()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        (byte[] protectedHeader, byte[] payload, byte[] signature) = await CreateBaselineSignedComponentsAsync(
            privateKey, digestBytes, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, writer =>
        {
            writer.WriteStartMap(2);
            writer.WriteInt32(268); // uHeaders, clause 5.3.1 Table 8.
            writer.WriteByteString([0x01]);
            writer.WriteInt32(300); // an arbitrary label this document does not assign to the unprotected map.
            writer.WriteByteString([0x02]);
            writer.WriteEndMap();
        }, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESMalformedEncodingFailure>(result.Failure);
    }


    /// <summary>
    /// An unprotected headers map whose sole member uses a text-string key instead of an integer label
    /// (CB-4.6-01) fails closed to <see cref="CBAdESMalformedEncodingFailure"/>.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncFailsClosedWhenUnprotectedMapKeyIsNotAnInteger()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        (byte[] protectedHeader, byte[] payload, byte[] signature) = await CreateBaselineSignedComponentsAsync(
            privateKey, digestBytes, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString("uHeaders");
            writer.WriteByteString([0x01]);
            writer.WriteEndMap();
        }, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESMalformedEncodingFailure>(result.Failure);
    }


    /// <summary>
    /// A protected headers map carrying the <c>alg</c> label (1) twice (CB-4.6-01, via
    /// <see cref="CborReaderExtensions.ReadAscendingMapKey"/>'s strictly-ascending requirement) fails closed to
    /// <see cref="CBAdESMalformedEncodingFailure"/>. Minted with a <see cref="CborConformanceMode.Lax"/> writer,
    /// which bypasses the writer's own canonical-ordering enforcement, so this malformed shape can be
    /// constructed at all.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncFailsClosedOnDuplicateProtectedHeaderLabels()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        keyMaterial.PrivateKey.Dispose(); // Not needed -- parsing fails while decoding the protected header, before any signature is checked.

        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(2);
        writer.WriteInt32(1); // alg, RFC 9052 section 3.1.
        writer.WriteInt32(WellKnownCoseAlgorithms.Es256);
        writer.WriteInt32(1); // alg again -- duplicate, non-ascending label.
        writer.WriteInt32(WellKnownCoseAlgorithms.Es256);
        writer.WriteEndMap();
        byte[] protectedHeader = writer.Encode();

        byte[] payload = "payload over a duplicate-labelled header"u8.ToArray();
        byte[] signature = [0x01, 0x02, 0x03]; // Never verified -- parsing fails before the signature step.
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESMalformedEncodingFailure>(result.Failure);
    }


    /// <summary>A well-formed message with its final five bytes removed fails closed, never throws.</summary>
    [TestMethod]
    public async Task ValidateAsyncFailsClosedOnTruncatedInput()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        (byte[] protectedHeader, byte[] payload, byte[] signature) = await CreateBaselineSignedComponentsAsync(
            privateKey, digestBytes, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);
        byte[] truncated = wireBytes[..^5];

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            truncated, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESMalformedEncodingFailure>(result.Failure);
    }


    /// <summary>A well-formed message with a stray trailing byte appended fails closed, never throws.</summary>
    [TestMethod]
    public async Task ValidateAsyncFailsClosedOnTrailingBytes()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        (byte[] protectedHeader, byte[] payload, byte[] signature) = await CreateBaselineSignedComponentsAsync(
            privateKey, digestBytes, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);
        byte[] withTrailingByte = [.. wireBytes, 0x00];

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            withTrailingByte, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESMalformedEncodingFailure>(result.Failure);
    }


    /// <summary>
    /// <c>COSE_Sign1</c> is a fixed 4-element array (RFC 9052 section 4.2); a message whose top-level array
    /// declares 3 elements (the signature omitted entirely) fails closed.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncFailsClosedWhenTopLevelArrayIsNotFourElements()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        (byte[] protectedHeader, byte[] payload, _) = await CreateBaselineSignedComponentsAsync(
            privateKey, digestBytes, TestContext.CancellationToken).ConfigureAwait(false);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)18); // COSE_Sign1_Tagged, RFC 9052 section 2 / clause 4.3.
        writer.WriteStartArray(3);
        writer.WriteByteString(protectedHeader);
        WriteEmptyUnprotectedMap(writer);
        writer.WriteByteString(payload);
        writer.WriteEndArray();
        byte[] wireBytes = writer.Encode();

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESMalformedEncodingFailure>(result.Failure);
    }


    /// <summary>Adversarially deep top-level CBOR array nesting fails closed, never throws or crashes.</summary>
    [TestMethod]
    public async Task ValidateAsyncFailsClosedOnDepthBombNesting()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        keyMaterial.PrivateKey.Dispose(); // Not needed -- this input never reaches the signature step.

        byte[] wireBytes = BuildDeeplyNestedArrayBytes(10_000);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESMalformedEncodingFailure>(result.Failure);

        /// <summary>
        /// Builds <paramref name="depth"/> nested single-element CBOR arrays around one integer -- otherwise
        /// well-formed, only its nesting depth is adversarial. Mirrors the S1/S2
        /// <c>BuildDeeplyNestedArrayBytes</c> precedent; local to this test since no other test in this file
        /// needs it.
        /// </summary>
        /// <param name="depth">The nesting depth.</param>
        /// <returns>The encoded bytes.</returns>
        static byte[] BuildDeeplyNestedArrayBytes(int depth)
        {
            var nestedWriter = new CborWriter(CborConformanceMode.Canonical);
            for(int i = 0; i < depth; i++)
            {
                nestedWriter.WriteStartArray(1);
            }

            nestedWriter.WriteInt32(0);

            for(int i = 0; i < depth; i++)
            {
                nestedWriter.WriteEndArray();
            }

            return nestedWriter.Encode();
        }
    }


    /// <summary>
    /// A protected header with <c>alg</c> and <c>x5t</c> but no CWT Claims (label 15) reports exactly one
    /// <see cref="CBAdESCwtClaimsMissingViolation"/> (CB-6.3-10) -- the wavecb S3 FX-E flip.
    /// <see cref="CBAdESProtectedHeaders.CwtClaims"/> is nullable and
    /// <see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/> no longer fails the parse over its absence
    /// (an earlier revision of this test asserted <see cref="CBAdESMalformedEncodingFailure"/> instead, since
    /// the parser used to enforce <c>iat</c>'s mandatory presence itself); the rules surface
    /// (<see cref="CBAdESHeaderRules.Check"/>) now owns this check, exactly like every other B-B rule.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncReportsCwtClaimsMissingViolationWhenCwtClaimsIsAbsent()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(1); // alg, RFC 9052 section 3.1.
        writer.WriteInt32(WellKnownCoseAlgorithms.Es256);
        writer.WriteInt32(34); // x5t, RFC 9360 section 2 / clause 5.1.7. CWT Claims (15) deliberately omitted.
        WriteHashAlgorithmDigestPairOracle(writer, new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes);
        writer.WriteEndMap();
        byte[] protectedHeader = writer.Encode();

        byte[] payload = "payload signed under a header with no iat"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var ruleFailure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(1, ruleFailure.Violations);
        Assert.IsInstanceOfType<CBAdESCwtClaimsMissingViolation>(ruleFailure.Violations[0]);
    }


    /// <summary>
    /// A protected header carrying both an MD5-identified <c>x5t</c> (CB-6.2.1-02) AND no CWT Claims (CB-6.3-10)
    /// reports BOTH violations -- the collect posture (S3 coordinator ruling (2)) is finally observable for this
    /// pairing now that <see cref="CBAdESCwtClaimsMissingViolation"/> is live (wavecb S3 FX-E).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncReportsBothCwtClaimsMissingAndMd5ViolationsWhenBothApply()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        // Arbitrary 16 bytes -- neither the model nor the codec validates digest length against the claimed algorithm.
        byte[] md5DigestBytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(1); // alg, RFC 9052 section 3.1.
        writer.WriteInt32(WellKnownCoseAlgorithms.Es256);
        writer.WriteInt32(34); // x5t, RFC 9360 section 2 / clause 5.1.7. CWT Claims (15) deliberately omitted.
        WriteHashAlgorithmDigestPairOracle(writer, new CBAdESDigestAlgorithmTextIdentifier("MD5"), md5DigestBytes);
        writer.WriteEndMap();
        byte[] protectedHeader = writer.Encode();

        byte[] payload = "payload signed under a header with no iat and an MD5-identified x5t"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var ruleFailure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(2, ruleFailure.Violations, "Both the missing-iat and the MD5-digest violations must be collected together.");

        bool sawCwtClaimsMissing = false;
        CBAdESMd5DigestAlgorithmViolation? md5Violation = null;
        foreach(CBAdESRuleViolation violation in ruleFailure.Violations)
        {
            switch(violation)
            {
                case CBAdESCwtClaimsMissingViolation:
                    sawCwtClaimsMissing = true;
                    break;
                case CBAdESMd5DigestAlgorithmViolation md5:
                    md5Violation = md5;
                    break;
            }
        }

        Assert.IsTrue(sawCwtClaimsMissing, "The missing-iat violation must be among the collected violations.");
        Assert.IsNotNull(md5Violation, "The MD5-digest violation must be among the collected violations.");
        Assert.AreEqual(CBAdESMd5DigestAlgorithmSurface.CertificateThumbprint, md5Violation!.Surface);
    }


    /// <summary>
    /// A CWT-Claims map (label 15) carrying <c>iat</c> alongside a sibling RFC 8392 claim (<c>sub</c>, claim key
    /// 2) parses successfully, decodes <c>iat</c> correctly, and the message validates -- the wavecb S3 FX-E
    /// tolerant-sibling-claims regression. Clause 5.1.9 restricts nothing beyond requiring <c>iat</c>'s presence
    /// (CB-6.3-10); a sibling claim is spec-legal wire content, not grounds to fail closed. Validation succeeds
    /// because the Sig_structure is built from the raw wire bytes captured at parse (wavecb S3 FX-A), never a
    /// re-encoding that could drop the sibling claim.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncSucceedsWhenCwtClaimsCarriesASiblingClaimAlongsideIat()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        DateTimeOffset expectedIssuedAt = TestClock.CanonicalEpoch;

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(3);
        writer.WriteInt32(1); // alg, RFC 9052 section 3.1.
        writer.WriteInt32(WellKnownCoseAlgorithms.Es256);
        writer.WriteInt32(15); // CWT Claims, RFC 9597 / clause 5.1.9.
        writer.WriteStartMap(2);
        writer.WriteInt32(2); // sub, RFC 8392 section 3.1.2 -- a sibling claim, ascending before iat (6).
        writer.WriteTextString("urn:test:subject");
        writer.WriteInt32(6); // iat, RFC 8392 section 3.1.6.
        writer.WriteInt64(expectedIssuedAt.ToUnixTimeSeconds());
        writer.WriteEndMap();
        writer.WriteInt32(34); // x5t, RFC 9360 section 2 / clause 5.1.7.
        WriteHashAlgorithmDigestPairOracle(writer, new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes);
        writer.WriteEndMap();
        byte[] protectedHeader = writer.Encode();

        byte[] payload = "payload signed under a CWT-Claims map carrying a sibling claim"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A sibling claim alongside iat inside CWT Claims is spec-legal wire content (clause 5.1.9) and must not fail closed.");
        Assert.IsNotNull(result.Headers);
        Assert.AreEqual(expectedIssuedAt, result.Headers!.CwtClaims!.IssuedAt, "iat must decode correctly even with a sibling claim present in the same map.");
    }


    /// <summary>
    /// An independently minted message whose protected header carries a <c>tstr</c>-arm <c>crit</c> element and
    /// a <c>tstr</c>-keyed unprofiled header entry parses and validates successfully -- the wavecb S3 FX-H
    /// reader-side regression, exercising <see cref="CBAdESSignatureSerialization.ParseCBAdESSign1"/>'s general
    /// COSE <c>label: int / tstr</c> union support (RFC 9052 §1.4/§3.1, clause 4.4 NOTE 4) purely from
    /// independently minted wire bytes, never through this stage's own encoder -- the creation-side round trip
    /// (<c>CBAdESSignatureCreationTests.TextArmCriticalLabelAndUnprofiledHeaderRoundTripThroughCreateAndValidate</c>)
    /// covers the writer side.
    /// </summary>
    [TestMethod]
    public async Task ParseAcceptsIndependentlyMintedTextArmCritAndUnprofiledHeader()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);

        var unprofiledValueWriter = new CborWriter(CborConformanceMode.Canonical);
        unprofiledValueWriter.WriteByteString(new byte[] { 0xCA, 0xFE });
        byte[] expectedUnprofiledBytes = unprofiledValueWriter.Encode();

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(1); // alg, RFC 9052 section 3.1.
        writer.WriteInt32(WellKnownCoseAlgorithms.Es256);
        writer.WriteInt32(2); // crit, RFC 9052 section 3.1 -- crit's syntax reuses the general label: int / tstr union unnarrowed (clause 5.1.10).
        writer.WriteStartArray(1);
        writer.WriteTextString("x-test-crit"); // A tstr-arm crit element, RFC 9052 section 1.4's label union.
        writer.WriteEndArray();
        writer.WriteInt32(15); // CWT Claims, RFC 9597 / clause 5.1.9.
        WriteCwtClaimsOracle(writer, TestClock.CanonicalEpoch);
        writer.WriteInt32(34); // x5t, RFC 9360 section 2 / clause 5.1.7.
        WriteHashAlgorithmDigestPairOracle(writer, new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes);
        // A tstr-labeled unprofiled protected header (clause 4.4 NOTE 4, CB-4.4-07) -- sorts after x5t (34) under
        // RFC 8949 section 4.2.3's canonical (length-first) ordering, since its 11-byte encoding is longer than
        // x5t's own 2-byte label encoding.
        writer.WriteTextString("x-test-ext");
        writer.WriteEncodedValue(expectedUnprofiledBytes);
        writer.WriteEndMap();
        byte[] protectedHeader = writer.Encode();

        byte[] payload = "payload signed under a header carrying a tstr-arm crit element and a tstr-keyed unprofiled header"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A tstr-arm crit element and a tstr-keyed unprofiled header are spec-legal wire content (RFC 9052 section 1.4/3.1, clause 4.4 NOTE 4) and must not fail closed.");
        Assert.IsNotNull(result.Headers);
        Assert.IsNotNull(result.Headers!.CriticalLabels);
        Assert.Contains(new CoseHeaderTextLabel("x-test-crit"), result.Headers.CriticalLabels!, "The tstr-arm crit element must decode.");
        Assert.IsNotNull(result.Headers.UnprofiledHeaders);
        var unprofiledLabel = new CoseHeaderTextLabel("x-test-ext");
        Assert.IsTrue(result.Headers.UnprofiledHeaders!.ContainsKey(unprofiledLabel));
        Assert.IsTrue(expectedUnprofiledBytes.AsSpan().SequenceEqual(result.Headers.UnprofiledHeaders[unprofiledLabel].Span));
    }


    /// <summary>
    /// A protected header whose top-level map keys mix an integer and a text-string label in NON-CANONICAL order
    /// fails closed -- the wavecb S3 FX-H negative regression for the fix spec's own WARNING: a naive "every
    /// integer key before every text key" shortcut is wrong, since a SHORTER text-string key's canonical
    /// encoding can sort before a LONGER integer key's under RFC 8949 section 4.2.3's length-first rule. This
    /// message writes the 3-byte canonical encoding of integer label 999 BEFORE the 2-byte canonical encoding of
    /// text-string key "a" -- the wrong order under length-first ordering, even though "the integer before the
    /// string" might look plausible under an arm-based ordering guess.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncFailsClosedWhenProtectedHeaderMixesIntAndTextLabelsOutOfCanonicalOrder()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        keyMaterial.PrivateKey.Dispose(); // Not needed -- parsing fails while decoding the protected header, before any signature is checked.

        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(2);
        // An arbitrary unprofiled label -- its 3-byte canonical encoding is deliberately written FIRST, ahead of
        // the shorter text-string key below, to construct a non-canonical top-level key order (RFC 8949 section
        // 4.2.3's length-first rule: shorter encodings sort first).
        writer.WriteInt32(999);
        writer.WriteByteString([0x01]);
        // A 2-byte canonical text-string key -- SHORTER than the preceding 3-byte integer key, so writing it
        // second violates the length-first ordering.
        writer.WriteTextString("a");
        writer.WriteByteString([0x02]);
        writer.WriteEndMap();
        byte[] protectedHeader = writer.Encode();

        byte[] payload = "payload over a non-canonically ordered mixed int/tstr protected header"u8.ToArray();
        byte[] signature = [0x01, 0x02, 0x03]; // Never verified -- parsing fails before the signature step.
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESMalformedEncodingFailure>(result.Failure);
    }


    /// <summary>
    /// A message carrying none of <c>x5t</c>, <c>x5ts</c>, or <c>x5chain</c> reports exactly one
    /// <see cref="CBAdESCertificateReferenceTriWayViolation"/> (CB-5.2.2-07, D9).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncReportsCertificateReferenceTriWayViolationWhenNoneOfX5tX5tsX5chainIsPresent()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] protectedHeader = BuildProtectedHeaderBytes(
            WellKnownCoseAlgorithms.Es256, TestClock.CanonicalEpoch, x5t: null, criticalLabels: null, contentType: null, sigD: null);

        byte[] payload = "payload with no certificate reference at all"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var ruleFailure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(1, ruleFailure.Violations);
        Assert.IsInstanceOfType<CBAdESCertificateReferenceTriWayViolation>(ruleFailure.Violations[0]);
    }


    /// <summary>
    /// A message carrying both <c>content type</c> and <c>sigD</c> reports exactly one
    /// <see cref="CBAdESContentTypeDetachedObjectsExclusivityViolation"/> (CB-5.1.3-03) -- isolated from the
    /// other <c>sigD</c>-adjacent rules by an otherwise fully conformant message (tri-way satisfied via
    /// <c>x5t</c>, <c>crit</c> includes <c>sigD</c>'s label, the payload is detached, and the mechanism is
    /// third-party so neither built-in mechanism's digest-presence rule applies).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncReportsContentTypeDetachedObjectsExclusivityViolation()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        var sigD = new SigDWireSpec("urn:test:third-party-mechanism", ["https://example.org/detached-object"], null, null);

        byte[] protectedHeader = BuildProtectedHeaderBytes(
            WellKnownCoseAlgorithms.Es256,
            TestClock.CanonicalEpoch,
            (new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes),
            criticalLabels: [267], // sigD's assigned label, CB-5.1.10-04.
            contentType: "text/plain",
            sigD: sigD);

        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, [], []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload: null, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var ruleFailure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(1, ruleFailure.Violations);
        Assert.IsInstanceOfType<CBAdESContentTypeDetachedObjectsExclusivityViolation>(ruleFailure.Violations[0]);
    }


    /// <summary>
    /// A message carrying <c>sigD</c> with no <c>crit</c> member at all reports exactly one
    /// <see cref="CBAdESDetachedObjectsCriticalLabelViolation"/> (CB-5.1.10-04).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncReportsDetachedObjectsCriticalLabelViolationWhenSigDLabelAbsentFromCrit()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        var sigD = new SigDWireSpec("urn:test:third-party-mechanism", ["https://example.org/detached-object"], null, null);

        byte[] protectedHeader = BuildProtectedHeaderBytes(
            WellKnownCoseAlgorithms.Es256,
            TestClock.CanonicalEpoch,
            (new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes),
            criticalLabels: null, // crit absent -- sigD's label (267) is therefore not included.
            contentType: null,
            sigD: sigD);

        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, [], []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload: null, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var ruleFailure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(1, ruleFailure.Violations);
        Assert.IsInstanceOfType<CBAdESDetachedObjectsCriticalLabelViolation>(ruleFailure.Violations[0]);
    }


    /// <summary>
    /// A message whose <c>sigD</c> selects <c>ObjectIdByURIHash</c> but carries no <c>hashM</c> (and therefore
    /// no <c>hashV</c>) reports exactly one <see cref="CBAdESDetachedObjectsUriHashMechanismDigestViolation"/>
    /// (CB-5.2.8.2.3-02: "both hashM and hashV shall be present").
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncReportsUriHashMechanismDigestViolationWhenHashMIsAbsent()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        var sigD = new SigDWireSpec("http://uri.etsi.org/19152/ObjectIdByURIHash", ["https://example.org/detached-object"], null, null);

        byte[] protectedHeader = BuildProtectedHeaderBytes(
            WellKnownCoseAlgorithms.Es256,
            TestClock.CanonicalEpoch,
            (new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes),
            criticalLabels: [267],
            contentType: null,
            sigD: sigD);

        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, [], []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload: null, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var ruleFailure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(1, ruleFailure.Violations);
        Assert.IsInstanceOfType<CBAdESDetachedObjectsUriHashMechanismDigestViolation>(ruleFailure.Violations[0]);
    }


    /// <summary>
    /// A message whose <c>x5t</c> names MD5 through the <c>tstr</c> arm of the digest-algorithm identifier
    /// union reports exactly one <see cref="CBAdESMd5DigestAlgorithmViolation"/> (CB-6.2.1-02) naming
    /// <see cref="CBAdESMd5DigestAlgorithmSurface.CertificateThumbprint"/>.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncReportsMd5DigestAlgorithmViolationOnTextIdentifier()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        // Arbitrary 16 bytes -- neither the model nor the codec validates digest length against the claimed algorithm.
        byte[] md5DigestBytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

        byte[] protectedHeader = BuildProtectedHeaderBytes(
            WellKnownCoseAlgorithms.Es256,
            TestClock.CanonicalEpoch,
            (new CBAdESDigestAlgorithmTextIdentifier("MD5"), md5DigestBytes),
            criticalLabels: null,
            contentType: null,
            sigD: null);

        byte[] payload = "payload signed under an MD5-identified x5t"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var ruleFailure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(1, ruleFailure.Violations);
        var md5Violation = (CBAdESMd5DigestAlgorithmViolation)ruleFailure.Violations[0];
        Assert.AreEqual(CBAdESMd5DigestAlgorithmSurface.CertificateThumbprint, md5Violation.Surface);
    }


    /// <summary>
    /// An otherwise-conformant message whose signature bytes are tampered fails with
    /// <see cref="CBAdESSignatureInvalidFailure"/>.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncFailsWithSignatureInvalidOnTamperedSignatureBytes()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        (byte[] protectedHeader, byte[] payload, byte[] signature) = await CreateBaselineSignedComponentsAsync(
            privateKey, digestBytes, TestContext.CancellationToken).ConfigureAwait(false);

        byte[] tamperedSignature = (byte[])signature.Clone();
        tamperedSignature[0] ^= 0xFF;

        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, tamperedSignature);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes, publicKey, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESSignatureInvalidFailure>(result.Failure);
    }


    /// <summary>
    /// A conformant <c>ObjectIdByURIHash</c> message whose signed <c>hashV</c> entry does not match the
    /// dereferenced object's actual digest fails with <see cref="CBAdESDetachedObjectDigestMismatchFailure"/>
    /// naming the mismatched <c>pars</c> reference (CB-5.2.8.2.3-05).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncFailsWithDetachedObjectDigestMismatchWhenHashVDoesNotMatchDereferencedContent()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        const string reference = "https://example.org/detached-object-1";
        byte[] wrongDigest = new byte[32]; // All-zero -- not the SHA-256 digest of any content this test dereferences.

        var sigD = new SigDWireSpec(
            "http://uri.etsi.org/19152/ObjectIdByURIHash", // CB-5.2.8.2.3-01.
            [reference],
            new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256),
            [wrongDigest]);

        byte[] protectedHeader = BuildProtectedHeaderBytes(
            WellKnownCoseAlgorithms.Es256,
            TestClock.CanonicalEpoch,
            (new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes),
            criticalLabels: [267],
            contentType: null,
            sigD: sigD);

        // CB-5.2.8.2.3-06: the COSE Payload contributes as an empty stream to the signature-value computation
        // under ObjectIdByURIHash.
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, [], []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload: null, signature);

        byte[] actualContent = "the actual dereferenced detached object bytes"u8.ToArray();
        CBAdESDetachedObjectDereferenceDelegate dereference = (uriReference, context, pool, cancellationToken) =>
            ValueTask.FromResult<CBAdESDetachedObjectDereferenceResult>(
                new CBAdESDetachedObjectDereferenceSuccess(PooledMemory.FromBytes(actualContent, pool, Tag.Create(Purpose.Data))));

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes,
            publicKey,
            dereference,
            new CBAdESDetachedObjectDereferenceContext(null, null),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESDetachedObjectDigestMismatchFailure>(result.Failure);
        Assert.AreEqual(reference, ((CBAdESDetachedObjectDigestMismatchFailure)result.Failure!).Reference);
    }


    /// <summary>
    /// A conformant <c>ObjectIdByURI</c> message whose dereference delegate reports failure fails with
    /// <see cref="CBAdESDetachedObjectUnresolvableFailure"/> naming the unresolved <c>pars</c> reference.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncFailsWithDetachedObjectUnresolvableWhenDereferenceDelegateReportsFailure()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        const string reference = "https://example.org/unreachable-object";
        var sigD = new SigDWireSpec("http://uri.etsi.org/19152/ObjectIdByURI", [reference], null, null); // CB-5.2.8.2.2-01.

        byte[] protectedHeader = BuildProtectedHeaderBytes(
            WellKnownCoseAlgorithms.Es256,
            TestClock.CanonicalEpoch,
            (new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes),
            criticalLabels: [267],
            contentType: null,
            sigD: sigD);

        // Never reached by verification -- resolution fails at dereference, before Cose.VerifyAsync runs.
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, [], []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload: null, signature);

        CBAdESDetachedObjectDereferenceDelegate alwaysFails = (uriReference, context, pool, cancellationToken) =>
            ValueTask.FromResult<CBAdESDetachedObjectDereferenceResult>(
                new CBAdESDetachedObjectDereferenceFailure("simulated network failure"));

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes,
            publicKey,
            alwaysFails,
            new CBAdESDetachedObjectDereferenceContext(null, null),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.IsInstanceOfType<CBAdESDetachedObjectUnresolvableFailure>(result.Failure);
        Assert.AreEqual(reference, ((CBAdESDetachedObjectUnresolvableFailure)result.Failure!).Reference);
    }


    /// <summary>
    /// wavecb S3 FX-N (1): an otherwise-fully-conformant third-party-<c>mId</c> message reaches dispatch (crit
    /// includes 267, no <c>content type</c> -- unlike <see cref="ValidateAsyncReportsContentTypeDetachedObjectsExclusivityViolation"/>
    /// and <see cref="ValidateAsyncReportsDetachedObjectsCriticalLabelViolationWhenSigDLabelAbsentFromCrit"/>
    /// above, whose third-party <c>mId</c> messages both fail closed at step b's rule check and never reach the
    /// unknown-mechanism handler at all); the handler resolves the COSE Payload, the signature was genuinely
    /// computed over THAT payload, and validation succeeds.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncSucceedsWhenUnknownMechanismHandlerResolvesPayload()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        const string reference = "https://example.org/fx-n/dispatch-object";
        byte[] handlerPayload = "the payload the third-party unknown-mechanism handler resolves"u8.ToArray();
        byte[] wireBytes = await CreateThirdPartyMechanismDispatchMessageAsync(
            privateKey, reference, handlerPayload, TestContext.CancellationToken).ConfigureAwait(false);

        CBAdESUnknownDetachedObjectMechanismDelegate handler = (mechanismIdentifier, references, hashAlgorithm, context, pool, cancellationToken) =>
            ValueTask.FromResult(PooledMemory.FromBytes(handlerPayload, pool, Tag.Create(Purpose.Data)));

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes,
            publicKey,
            dereference: null,
            dereferenceContext: new CBAdESDetachedObjectDereferenceContext(null, null),
            unknownMechanismHandler: handler,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "Validation must succeed once the unknown-mechanism handler resolves the exact payload the signature was computed over.");
        Assert.IsTrue(result.PayloadIsDetached);
    }


    /// <summary>
    /// wavecb S3 FX-N (2), routine leg: the unknown-mechanism handler throws
    /// <see cref="CBAdESDetachedObjectDereferenceException"/> -- the delegate's own documented routine-failure
    /// signal (wavecb S3 FX-J) -- and validation reports <see cref="CBAdESDetachedObjectUnresolvableFailure"/>
    /// carrying the exception's message, never propagating the exception itself.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncFailsWithDetachedObjectUnresolvableWhenUnknownMechanismHandlerThrowsRoutineDereferenceException()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        const string reference = "https://example.org/fx-n/dispatch-object-routine-failure";
        const string simulatedReason = "simulated third-party retrieval failure";
        byte[] wireBytes = await CreateThirdPartyMechanismDispatchMessageAsync(
            privateKey, reference, [], TestContext.CancellationToken).ConfigureAwait(false);

        CBAdESUnknownDetachedObjectMechanismDelegate handler = (mechanismIdentifier, references, hashAlgorithm, context, pool, cancellationToken) =>
            throw new CBAdESDetachedObjectDereferenceException(simulatedReason);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes,
            publicKey,
            dereference: null,
            dereferenceContext: new CBAdESDetachedObjectDereferenceContext(null, null),
            unknownMechanismHandler: handler,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        var failure = Assert.IsInstanceOfType<CBAdESDetachedObjectUnresolvableFailure>(result.Failure);
        Assert.Contains(simulatedReason, failure.Reason, StringComparison.Ordinal);
    }


    /// <summary>
    /// wavecb S3 FX-N (2), non-routine leg: the unknown-mechanism handler throws
    /// <see cref="InvalidOperationException"/> -- NOT the delegate's documented routine-failure signal -- and
    /// <see cref="CBAdESSignatureValidation.ValidateAsync(ReadOnlyMemory{byte}, ParseCBAdESSign1Delegate, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, ReadOnlyMemory{byte}?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
    /// propagates it unmodified (wavecb S3 FX-J's narrowed catch names only <see cref="CBAdESDetachedObjectDereferenceException"/>).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncPropagatesNonRoutineExceptionFromUnknownMechanismHandler()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        const string reference = "https://example.org/fx-n/dispatch-object-non-routine-failure";
        const string nonRoutineMessage = "a non-routine implementer-infrastructure fault";
        byte[] wireBytes = await CreateThirdPartyMechanismDispatchMessageAsync(
            privateKey, reference, [], TestContext.CancellationToken).ConfigureAwait(false);

        CBAdESUnknownDetachedObjectMechanismDelegate handler = (mechanismIdentifier, references, hashAlgorithm, context, pool, cancellationToken) =>
            throw new InvalidOperationException(nonRoutineMessage);

        InvalidOperationException exception = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
            await CBAdESSignatureValidation.ValidateAsync(
                wireBytes,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CoseSerialization.BuildSigStructure,
                publicKey,
                MicrosoftCryptographicFunctions.VerifyP256Async,
                dereference: null,
                dereferenceContext: new CBAdESDetachedObjectDereferenceContext(null, null),
                externalDetachedPayload: null,
                unknownMechanismHandler: handler,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(nonRoutineMessage, exception.Message);
    }


    /// <summary>
    /// wavecb S3 FX-N (3): the same third-party-<c>mId</c> dispatch-reaching message, but no unknown-mechanism
    /// handler is supplied at all -- validation reports <see cref="CBAdESDetachedObjectUnresolvableFailure"/>
    /// citing CB-5.2.6-07/CB-5.2.8-08.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncFailsWithDetachedObjectUnresolvableWhenNoUnknownMechanismHandlerIsSupplied()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        const string reference = "https://example.org/fx-n/dispatch-object-no-handler";
        byte[] wireBytes = await CreateThirdPartyMechanismDispatchMessageAsync(
            privateKey, reference, [], TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await ValidateExpectingNoThrowAsync(
            wireBytes,
            publicKey,
            dereference: null,
            dereferenceContext: new CBAdESDetachedObjectDereferenceContext(null, null),
            unknownMechanismHandler: null,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        var failure = Assert.IsInstanceOfType<CBAdESDetachedObjectUnresolvableFailure>(result.Failure);
        Assert.IsNull(failure.Reference);
        Assert.Contains("CB-5.2.6-07", failure.Reason, StringComparison.Ordinal);
    }


    /// <summary>
    /// The wavecb S3 FX-D leak regression: a <see cref="CancellationTokenSource"/> is canceled as a SIDE EFFECT
    /// of the <c>sigD</c> <c>ObjectIdByURI</c> dereference delegate, which then still returns success -- so
    /// resolution (step c) completes normally, and the cancellation is observed only later, by
    /// <see cref="Cose.VerifyAsync(CoseSign1Message, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CryptoEventSink?, CancellationToken)"/>'s
    /// own guard inside step d -- exactly the code region the wavecb S3 FX-D <c>try</c>/<c>catch</c> wraps. This
    /// is a caller-cancellation throw, not the malformed-input R-5 no-throw contract (see the type remarks), so
    /// this test deliberately bypasses <see cref="ValidateExpectingNoThrowAsync"/> and asserts the throw
    /// directly. A <see cref="MeteredHousePool"/> proves <c>parseResult</c>'s four owned carriers
    /// (<c>ProtectedHeaders</c>/<c>RawProtectedHeader</c>/<c>Signature</c>/<c>UnsignedHeaders</c>) — reachable
    /// only through the FX-D catch on this exact path, since resolution itself never fails — are disposed rather
    /// than leaked.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncPropagatesCancellationObservedDuringResolutionWithoutLeakingParseResultCarriers()
    {
        using MeteredHousePool pool = new();

        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        const string reference = "https://example.org/cancellation-regression-object";
        var sigD = new SigDWireSpec("http://uri.etsi.org/19152/ObjectIdByURI", [reference], null, null); // CB-5.2.8.2.2-01.

        byte[] protectedHeader = BuildProtectedHeaderBytes(
            WellKnownCoseAlgorithms.Es256,
            TestClock.CanonicalEpoch,
            (new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes),
            criticalLabels: [267],
            contentType: null,
            sigD: sigD);

        //Never reached by verification -- Cose.VerifyAsync's own cancellation guard fires before the signature
        //is ever checked, so the exact bytes signed over do not matter to this test.
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, [], []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload: null, signature);

        using var cts = new CancellationTokenSource();
        var context = new CBAdESDetachedObjectDereferenceContext(null, cts);

        CBAdESDetachedObjectDereferenceDelegate cancelThenSucceed = async (uriReference, dereferenceContext, rentPool, cancellationToken) =>
        {
            await ((CancellationTokenSource)dereferenceContext.State!).CancelAsync().ConfigureAwait(false);
            return new CBAdESDetachedObjectDereferenceSuccess(PooledMemory.FromBytes("dereferenced-object"u8.ToArray(), rentPool, Tag.Create(Purpose.Data)));
        };

        OperationCanceledException exception = await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
            await CBAdESSignatureValidation.ValidateAsync(
                wireBytes,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CoseSerialization.BuildSigStructure,
                publicKey,
                MicrosoftCryptographicFunctions.VerifyP256Async,
                cancelThenSucceed,
                context,
                externalDetachedPayload: null,
                unknownMechanismHandler: null,
                pool.Pool,
                cts.Token).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(cts.Token, exception.CancellationToken, "The propagated exception must carry the exact token the dereference delegate canceled.");
        Assert.AreEqual(0, pool.OutstandingCount,
            "The wavecb S3 FX-D catch clause must dispose parseResult's owned carriers when Cose.VerifyAsync observes the cancellation the dereference delegate triggered mid-resolution, not leak them.");
    }


    /// <summary>A <see langword="null"/> <c>parse</c> delegate raises <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public async Task ValidateAsyncThrowsArgumentNullExceptionWhenParseIsNull()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey) = await CreateBaselineMessageAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        {
            await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
                await CBAdESSignatureValidation.ValidateAsync(
                    wireBytes,
                    parse: null!,
                    CoseSerialization.BuildSigStructure,
                    publicKey,
                    MicrosoftCryptographicFunctions.VerifyP256Async,
                    dereference: null,
                    dereferenceContext: null,
                    externalDetachedPayload: null,
                    unknownMechanismHandler: null,
                    BaseMemoryPool.Shared,
                    TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
    }


    /// <summary>A <see langword="null"/> <c>buildSigStructure</c> delegate raises <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public async Task ValidateAsyncThrowsArgumentNullExceptionWhenBuildSigStructureIsNull()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey) = await CreateBaselineMessageAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        {
            await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
                await CBAdESSignatureValidation.ValidateAsync(
                    wireBytes,
                    CBAdESSignatureSerialization.ParseCBAdESSign1,
                    buildSigStructure: null!,
                    publicKey,
                    MicrosoftCryptographicFunctions.VerifyP256Async,
                    dereference: null,
                    dereferenceContext: null,
                    externalDetachedPayload: null,
                    unknownMechanismHandler: null,
                    BaseMemoryPool.Shared,
                    TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
    }


    /// <summary>A <see langword="null"/> <c>publicKey</c> raises <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public async Task ValidateAsyncThrowsArgumentNullExceptionWhenPublicKeyIsNull()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey) = await CreateBaselineMessageAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        {
            await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
                await CBAdESSignatureValidation.ValidateAsync(
                    wireBytes,
                    CBAdESSignatureSerialization.ParseCBAdESSign1,
                    CoseSerialization.BuildSigStructure,
                    publicKey: null!,
                    MicrosoftCryptographicFunctions.VerifyP256Async,
                    dereference: null,
                    dereferenceContext: null,
                    externalDetachedPayload: null,
                    unknownMechanismHandler: null,
                    BaseMemoryPool.Shared,
                    TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
    }


    /// <summary>A <see langword="null"/> <c>verificationDelegate</c> raises <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public async Task ValidateAsyncThrowsArgumentNullExceptionWhenVerificationDelegateIsNull()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey) = await CreateBaselineMessageAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        {
            await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
                await CBAdESSignatureValidation.ValidateAsync(
                    wireBytes,
                    CBAdESSignatureSerialization.ParseCBAdESSign1,
                    CoseSerialization.BuildSigStructure,
                    publicKey,
                    verificationDelegate: null!,
                    dereference: null,
                    dereferenceContext: null,
                    externalDetachedPayload: null,
                    unknownMechanismHandler: null,
                    BaseMemoryPool.Shared,
                    TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
    }


    /// <summary>A <see langword="null"/> <c>pool</c> raises <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public async Task ValidateAsyncThrowsArgumentNullExceptionWhenPoolIsNull()
    {
        (byte[] wireBytes, PublicKeyMemory publicKey) = await CreateBaselineMessageAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using(publicKey)
        {
            await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
                await CBAdESSignatureValidation.ValidateAsync(
                    wireBytes,
                    CBAdESSignatureSerialization.ParseCBAdESSign1,
                    CoseSerialization.BuildSigStructure,
                    publicKey,
                    MicrosoftCryptographicFunctions.VerifyP256Async,
                    dereference: null,
                    dereferenceContext: null,
                    externalDetachedPayload: null,
                    unknownMechanismHandler: null,
                    pool: null!,
                    TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Calls <see cref="CBAdESSignatureValidation.ValidateAsync(ReadOnlyMemory{byte}, ParseCBAdESSign1Delegate, BuildSigStructureDelegate, PublicKeyMemory, VerificationDelegate, CBAdESDetachedObjectDereferenceDelegate?, CBAdESDetachedObjectDereferenceContext?, ReadOnlyMemory{byte}?, CBAdESUnknownDetachedObjectMechanismDelegate?, BaseMemoryPool, CancellationToken)"/>
    /// through the production <see cref="CBAdESSignatureSerialization"/> delegates and the shared
    /// <see cref="CoseSerialization.BuildSigStructure"/> substrate, failing the test loudly if the call ever
    /// throws — the explicit no-throw assertion every negative test in this file relies on (R-5: validating
    /// untrusted or non-conformant wire bytes never throws; only a null required argument does, and those cases
    /// call <c>ValidateAsync</c> directly instead of through this helper).
    /// </summary>
    /// <param name="wireBytes">The candidate CB-AdES wire bytes.</param>
    /// <param name="publicKey">The verifying public key.</param>
    /// <param name="dereference">The <c>sigD</c> dereference seam, or <see langword="null"/>.</param>
    /// <param name="dereferenceContext">The per-call dereference context, or <see langword="null"/>.</param>
    /// <param name="externalDetachedPayload">The out-of-band detached payload, or <see langword="null"/>.</param>
    /// <param name="unknownMechanismHandler">The unknown-<c>mId</c> handler, or <see langword="null"/>.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The validation result. The caller owns and disposes it.</returns>
    private static async ValueTask<CBAdESValidationResult> ValidateExpectingNoThrowAsync(
        byte[] wireBytes,
        PublicKeyMemory publicKey,
        CBAdESDetachedObjectDereferenceDelegate? dereference = null,
        CBAdESDetachedObjectDereferenceContext? dereferenceContext = null,
        ReadOnlyMemory<byte>? externalDetachedPayload = null,
        CBAdESUnknownDetachedObjectMechanismDelegate? unknownMechanismHandler = null,
        CancellationToken cancellationToken = default)
    {
        //wavecb S3 FX-I (MSTEST0058): the failure report must not live textually inside the catch block --
        //capture the exception here, then report it via Fail (below) once execution has left the try/catch, so
        //the analyzer's "assert may not fail the test if no exception is thrown" concern does not apply (this
        //Assert.Fail is unconditional on the exception path, never conditional on a caught type match).
        Exception? unexpectedException = null;
        try
        {
            return await CBAdESSignatureValidation.ValidateAsync(
                wireBytes,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CoseSerialization.BuildSigStructure,
                publicKey,
                MicrosoftCryptographicFunctions.VerifyP256Async,
                dereference,
                dereferenceContext,
                externalDetachedPayload,
                unknownMechanismHandler,
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
        /// <param name="exception">The exception <see cref="ValidateExpectingNoThrowAsync"/> caught.</param>
        [DoesNotReturn]
        static void Fail(Exception? exception) =>
            Assert.Fail($"CBAdESSignatureValidation.ValidateAsync must never throw on untrusted wire bytes (R-5); threw {exception?.GetType().Name}: {exception?.Message}");
    }


    /// <summary>
    /// Builds a minimal conformant B-B message (fresh P-256 key material, <c>alg</c>+<c>iat</c>+<c>x5t</c>,
    /// attached payload) purely as a valid-message fixture for the six <see cref="ArgumentNullException"/>
    /// tests, which need a syntactically well-formed input to reach the parameter checks.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The wire bytes and the matching public key. The caller owns and disposes the public key.</returns>
    private static async ValueTask<(byte[] WireBytes, PublicKeyMemory PublicKey)> CreateBaselineMessageAsync(CancellationToken cancellationToken)
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        (byte[] protectedHeader, byte[] payload, byte[] signature) = await CreateBaselineSignedComponentsAsync(
            privateKey, digestBytes, cancellationToken).ConfigureAwait(false);
        byte[] wireBytes = BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload, signature);

        return (wireBytes, keyMaterial.PublicKey);
    }


    /// <summary>
    /// Builds the shared "reaches unknown-mechanism dispatch" fixture the four wavecb S3 FX-N tests perturb only
    /// in their unknown-mechanism-handler wiring: a third-party <c>sigD.mId</c>, <c>crit</c> including
    /// <c>sigD</c>'s own label (267), no <c>content type</c>, and an <c>x5t</c> tri-way member -- otherwise
    /// fully B-B conformant, so <see cref="CBAdESHeaderRules.Check"/> collects zero violations and validation
    /// reaches step c's payload resolution, unlike <see cref="ValidateAsyncReportsContentTypeDetachedObjectsExclusivityViolation"/>
    /// and <see cref="ValidateAsyncReportsDetachedObjectsCriticalLabelViolationWhenSigDLabelAbsentFromCrit"/>
    /// above, whose third-party <c>mId</c> messages fail closed at step b and never reach dispatch at all.
    /// </summary>
    /// <param name="privateKey">The private key to sign with.</param>
    /// <param name="reference">The single <c>sigD.pars</c> reference this fixture carries.</param>
    /// <param name="signedPayload">
    /// The bytes the Sig_structure covers -- the empty array unless the caller (the handler-success leg) needs
    /// the signature to verify over the exact payload an unknown-mechanism handler will later resolve.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The wire bytes.</returns>
    private static async ValueTask<byte[]> CreateThirdPartyMechanismDispatchMessageAsync(
        PrivateKeyMemory privateKey, string reference, byte[] signedPayload, CancellationToken cancellationToken)
    {
        byte[] digestBytes = await CreateSha256DigestBytesAsync("signing certificate"u8.ToArray(), cancellationToken).ConfigureAwait(false);
        var sigD = new SigDWireSpec("urn:test:third-party-mechanism-dispatch", [reference], null, null);

        byte[] protectedHeader = BuildProtectedHeaderBytes(
            WellKnownCoseAlgorithms.Es256,
            TestClock.CanonicalEpoch,
            (new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digestBytes),
            criticalLabels: [267],
            contentType: null,
            sigD: sigD);

        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, signedPayload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, cancellationToken).ConfigureAwait(false);

        return BuildCoseSign1Bytes(protectedHeader, WriteEmptyUnprotectedMap, payload: null, signature);
    }


    /// <summary>
    /// Builds a minimal conformant B-B protected header (<c>alg</c>+<c>iat</c>+<c>x5t</c>, no other members),
    /// an attached payload, and a signature computed over the corresponding Sig_structure with
    /// <paramref name="privateKey"/> — the shared "otherwise conformant" fixture the structural-malformation
    /// and tamper tests each perturb in exactly one way.
    /// </summary>
    /// <param name="privateKey">The private key to sign with.</param>
    /// <param name="x5tDigestBytes">The signing certificate's digest bytes, for the <c>x5t</c> member.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The protected header bytes, the payload bytes, and the signature bytes.</returns>
    private static async ValueTask<(byte[] ProtectedHeader, byte[] Payload, byte[] Signature)> CreateBaselineSignedComponentsAsync(
        PrivateKeyMemory privateKey, byte[] x5tDigestBytes, CancellationToken cancellationToken)
    {
        byte[] protectedHeader = BuildProtectedHeaderBytes(
            WellKnownCoseAlgorithms.Es256,
            TestClock.CanonicalEpoch,
            (new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), x5tDigestBytes),
            criticalLabels: null,
            contentType: null,
            sigD: null);

        byte[] payload = "cb-ades baseline payload"u8.ToArray();
        byte[] sigStructure = CoseSerialization.BuildSigStructure(protectedHeader, payload, []);
        byte[] signature = await SignSigStructureAsync(privateKey, sigStructure, cancellationToken).ConfigureAwait(false);

        return (protectedHeader, payload, signature);
    }


    /// <summary>
    /// Signs <paramref name="sigStructure"/> with <paramref name="privateKey"/> via
    /// <see cref="MicrosoftCryptographicFunctions.SignP256Async"/> — the P-256 key-provisioning pattern
    /// <c>Verifiable.Tests.Cose.CoseTests</c> establishes — returning the raw signature bytes for direct
    /// splicing into an independently minted <c>COSE_Sign1</c> array.
    /// </summary>
    /// <param name="privateKey">The private key to sign with.</param>
    /// <param name="sigStructure">The Sig_structure bytes to sign.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
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
    /// Computes a real SHA-256 digest over <paramref name="input"/> through the registered digest delegate
    /// (<see cref="CryptographicKeyEvents.ComputeDigestAsync"/>), tagged with <see cref="CryptoTags.Sha256Digest"/>
    /// — the fixture every <c>x5t</c>/<c>hashV</c> digest in this file is built from, never a hand-rolled hash.
    /// </summary>
    /// <param name="input">The bytes to digest.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The digest bytes.</returns>
    private static async ValueTask<byte[]> CreateSha256DigestBytesAsync(byte[] input, CancellationToken cancellationToken)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        return digest.AsReadOnlySpan().ToArray();
    }


    /// <summary>
    /// Assembles a CB-AdES protected-header map directly with <see cref="CborWriter"/> primitives, independent
    /// of <see cref="CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader"/> — this file's independent
    /// protected-header oracle. <c>alg</c> (1) and CWT Claims (15) are always written; <c>crit</c> (2),
    /// <c>content type</c> (3), <c>x5t</c> (34), and <c>sigD</c> (267) are written only when supplied, always in
    /// ascending label order (the fixed 1 &lt; 2 &lt; 3 &lt; 15 &lt; 34 &lt; 267 write sequence below is already
    /// ascending for every subset), matching CB-4.7-02's canonical-encoding requirement — so
    /// <see cref="CBAdESSignatureValidation"/>'s own re-encode-on-verify step reproduces these exact bytes for a
    /// conformant message.
    /// </summary>
    /// <param name="algorithm">The <c>alg</c> value (IANA COSE Algorithms identifier).</param>
    /// <param name="issuedAt">The claimed signing time for the mandatory CWT Claims member.</param>
    /// <param name="x5t">The <c>x5t</c> algorithm/digest pair, or <see langword="null"/> to omit it.</param>
    /// <param name="criticalLabels">The <c>crit</c> labels, or <see langword="null"/> to omit the member.</param>
    /// <param name="contentType">The <c>content type</c> media-type string, or <see langword="null"/> to omit it.</param>
    /// <param name="sigD">The <c>sigD</c> wire spec, or <see langword="null"/> to omit it.</param>
    /// <returns>The encoded protected-header map bytes.</returns>
    private static byte[] BuildProtectedHeaderBytes(
        int algorithm,
        DateTimeOffset issuedAt,
        (CBAdESDigestAlgorithmIdentifier Algorithm, byte[] Digest)? x5t,
        IReadOnlyList<int>? criticalLabels,
        string? contentType,
        SigDWireSpec? sigD)
    {
        int memberCount = 2 // alg + CWT Claims, always present.
            + (criticalLabels is not null ? 1 : 0)
            + (contentType is not null ? 1 : 0)
            + (x5t is not null ? 1 : 0)
            + (sigD is not null ? 1 : 0);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(1); // alg, RFC 9052 section 3.1.
        writer.WriteInt32(algorithm);

        if(criticalLabels is not null)
        {
            writer.WriteInt32(2); // crit, RFC 9052 section 3.1.
            writer.WriteStartArray(criticalLabels.Count);
            foreach(int label in criticalLabels)
            {
                writer.WriteInt32(label);
            }

            writer.WriteEndArray();
        }

        if(contentType is not null)
        {
            writer.WriteInt32(3); // content type, RFC 9052 section 3.1.
            writer.WriteTextString(contentType);
        }

        writer.WriteInt32(15); // CWT Claims, RFC 9597 / clause 5.1.9.
        WriteCwtClaimsOracle(writer, issuedAt);

        if(x5t is not null)
        {
            writer.WriteInt32(34); // x5t, RFC 9360 section 2 / clause 5.1.7.
            WriteHashAlgorithmDigestPairOracle(writer, x5t.Value.Algorithm, x5t.Value.Digest);
        }

        if(sigD is not null)
        {
            writer.WriteInt32(267); // sigD, clause 5.2.1 Table 1.
            WriteSigDOracle(writer, sigD);
        }

        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>
    /// Writes the RFC 9597 CWT-Claims header value directly — a one-member map, claim key 6 (<c>iat</c>,
    /// RFC 8392 section 3.1.6) to a whole-seconds <c>NumericDate</c> integer.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="issuedAt">The claimed signing time.</param>
    private static void WriteCwtClaimsOracle(CborWriter writer, DateTimeOffset issuedAt)
    {
        writer.WriteStartMap(1);
        writer.WriteInt32(6); // iat, RFC 8392 section 3.1.6.
        writer.WriteInt64(issuedAt.ToUnixTimeSeconds());
        writer.WriteEndMap();
    }


    /// <summary>
    /// Writes the shared "digest algorithm + digest value" two-element <c>COSE_CertHash</c> array shape
    /// (RFC 9360 section 2 / clause 5.1.7) directly.
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
    /// Writes a digest-algorithm identifier per the CDDL's <c>int / tstr</c> union directly — the <c>int</c>
    /// arm as a CBOR integer, the <c>tstr</c> arm as a CBOR text string.
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
    /// Writes a <c>sigD</c> map directly per clause 5.2.8.1's CDDL: <c>mId</c> (map key 1, a tag-32 URI),
    /// <c>pars</c> (map key 2), and — when <see cref="SigDWireSpec.HashAlgorithm"/> is supplied — <c>hashM</c>
    /// (map key 3) and <c>hashV</c> (map key 4).
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="spec">The <c>sigD</c> wire spec to write.</param>
    private static void WriteSigDOracle(CborWriter writer, SigDWireSpec spec)
    {
        int memberCount = 2 + (spec.HashAlgorithm is not null ? 2 : 0);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(1); // mId, clause 5.2.8.1.
        writer.WriteTag(CborTag.Uri); // #6.32(tstr), RFC 8949 section 3.4.5.3.
        writer.WriteTextString(spec.MechanismIdentifier);

        writer.WriteInt32(2); // pars, clause 5.2.8.1.
        writer.WriteStartArray(spec.References.Count);
        foreach(string reference in spec.References)
        {
            writer.WriteTextString(reference);
        }

        writer.WriteEndArray();

        if(spec.HashAlgorithm is not null)
        {
            writer.WriteInt32(3); // hashM, clause 5.2.8.1.
            WriteDigestAlgorithmIdentifierOracle(writer, spec.HashAlgorithm);

            writer.WriteInt32(4); // hashV, clause 5.2.8.1.
            writer.WriteStartArray(spec.DigestValues!.Count);
            foreach(byte[] digest in spec.DigestValues)
            {
                writer.WriteByteString(digest);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();
    }


    /// <summary>Writes the empty unprotected headers map (no <c>uHeaders</c> member).</summary>
    /// <param name="writer">The CBOR writer.</param>
    private static void WriteEmptyUnprotectedMap(CborWriter writer)
    {
        writer.WriteStartMap(0);
        writer.WriteEndMap();
    }


    /// <summary>
    /// Assembles the whole <c>COSE_Sign1</c> wire message directly: the tag-18 prefix, the fixed 4-element
    /// array (RFC 9052 section 4.2), <paramref name="protectedHeader"/> as the <c>body_protected</c> byte
    /// string, an unprotected map written by <paramref name="writeUnprotectedMap"/>, the payload (or the
    /// <c>nil</c> detached sentinel, clause 4.5, when <paramref name="payload"/> is <see langword="null"/>), and
    /// <paramref name="signature"/>.
    /// </summary>
    /// <param name="protectedHeader">The protected header bytes (the <c>body_protected</c> byte string).</param>
    /// <param name="writeUnprotectedMap">Writes the unprotected headers map.</param>
    /// <param name="payload">The attached payload bytes, or <see langword="null"/> for the detached sentinel.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <returns>The encoded <c>COSE_Sign1</c> wire bytes.</returns>
    private static byte[] BuildCoseSign1Bytes(
        byte[] protectedHeader,
        Action<CborWriter> writeUnprotectedMap,
        ReadOnlyMemory<byte>? payload,
        byte[] signature)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)18); // COSE_Sign1_Tagged, RFC 9052 section 2 / clause 4.3.
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);
        writeUnprotectedMap(writer);

        if(payload is null)
        {
            writer.WriteNull(); // The detached-payload sentinel, clause 4.5.
        }
        else
        {
            writer.WriteByteString(payload.Value.Span);
        }

        writer.WriteByteString(signature);
        writer.WriteEndArray();
        return writer.Encode();
    }


    /// <summary>
    /// The wire-level shape of a <c>sigD</c> component this file's independent oracle writes — a plain data
    /// carrier, not a codec: <see cref="WriteSigDOracle"/> is the only place that turns it into bytes.
    /// </summary>
    /// <param name="MechanismIdentifier">The <c>mId</c> value.</param>
    /// <param name="References">The <c>pars</c> entries, in wire order.</param>
    /// <param name="HashAlgorithm">The <c>hashM</c> value, or <see langword="null"/> to omit <c>hashM</c>/<c>hashV</c> entirely.</param>
    /// <param name="DigestValues">
    /// The <c>hashV</c> entries, in wire order, one per <paramref name="References"/> entry — required
    /// (non-null) exactly when <paramref name="HashAlgorithm"/> is non-null.
    /// </param>
    private sealed record SigDWireSpec(
        string MechanismIdentifier,
        IReadOnlyList<string> References,
        CBAdESDigestAlgorithmIdentifier? HashAlgorithm,
        IReadOnlyList<byte[]>? DigestValues);
}
