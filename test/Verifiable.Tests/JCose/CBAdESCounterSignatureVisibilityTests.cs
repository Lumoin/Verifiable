using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests proving labels 11/12 (RFC 9338 version 2 countersignatures) are VISIBLE to the CB-AdES level-rule and
/// validation orchestrators — closing the silent fall-throughs where <see cref="CBAdESLevelRules.Check"/> and
/// <see cref="CBAdESSignatureValidation"/>'s per-element switches previously had no arm for either label at
/// all.
/// </summary>
/// <remarks>
/// <para>
/// <strong>CB-6.3-30 is the governing row throughout this file.</strong> Table 14's "counter signature" row is
/// level-invariant may-be-present with no lettered additional requirement — presence is NEVER a violation at
/// any level; every test in this file that constructs a signature carrying a counter-signature element also
/// asserts that presence alone never contributes a violation, only malformed content or a failing signature
/// does.
/// </para>
/// <para>
/// <strong>Firewall discipline.</strong> Every crypto-verification test mints its fixture inside its own nested
/// block scope and passes only the resulting <c>byte[]</c> wire copy to <c>ValidateAsync</c>, mirroring
/// <see cref="CBAdESSignatureFlowTests"/>'s own convention.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESCounterSignatureVisibilityTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous test observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// CB-6.3-30: a <c>uHeaders</c> element carrying a full or abbreviated counter-signature
    /// contributes ZERO additional violations to <see cref="CBAdESLevelRules.Check"/>, at every one of the four
    /// Table 14 baseline levels — proven by comparing the violation set with and without the element present,
    /// rather than asserting an empty set outright (higher levels legitimately collect OTHER violations, e.g.
    /// the missing-<c>sigTst</c> rule from B-T onward, which must remain unaffected by the counter-signature
    /// element's own presence).
    /// </summary>
    /// <param name="level">The baseline level under test.</param>
    [TestMethod]
    [DataRow(AdESBaselineLevel.BB)]
    [DataRow(AdESBaselineLevel.BT)]
    [DataRow(AdESBaselineLevel.BLT)]
    [DataRow(AdESBaselineLevel.BLTA)]
    public void CheckNeverReportsAViolationForCounterSignaturePresenceAtAnyLevel(AdESBaselineLevel level)
    {
        CBAdESUnsignedHeaderElement placeholder = new CBAdESUnsignedHeaderElementUnknown(new CBAdESUnsignedHeaderElementIntegerLabel(9001), new byte[] { 0x01 });
        CBAdESUnsignedHeaderElement fullCounterSignature = new CBAdESUnsignedHeaderElementFullCounterSignature(new byte[] { 0x83, 0x40, 0xA0, 0x41, 0x00 });
        CBAdESUnsignedHeaderElement abbreviatedCounterSignature = new CBAdESUnsignedHeaderElementAbbreviatedCounterSignature(new byte[] { 0x41, 0x00 });

        using var withoutCounterSignature = new CBAdESUnsignedHeaders([placeholder]);
        using var withFullCounterSignature = new CBAdESUnsignedHeaders([placeholder, fullCounterSignature]);
        using var withAbbreviatedCounterSignature = new CBAdESUnsignedHeaders([placeholder, abbreviatedCounterSignature]);

        IReadOnlyList<CBAdESRuleViolation> baselineViolations = CBAdESLevelRules.Check(new CBAdESLevelRuleContext { Level = level, UnsignedHeaders = withoutCounterSignature });
        IReadOnlyList<CBAdESRuleViolation> fullViolations = CBAdESLevelRules.Check(new CBAdESLevelRuleContext { Level = level, UnsignedHeaders = withFullCounterSignature });
        IReadOnlyList<CBAdESRuleViolation> abbreviatedViolations = CBAdESLevelRules.Check(new CBAdESLevelRuleContext { Level = level, UnsignedHeaders = withAbbreviatedCounterSignature });

        Assert.HasCount(baselineViolations.Count, fullViolations, $"A full counter-signature element must contribute zero additional violations at {level} (CB-6.3-30).");
        Assert.HasCount(baselineViolations.Count, abbreviatedViolations, $"An abbreviated counter-signature element must contribute zero additional violations at {level} (CB-6.3-30).");
    }


    /// <summary>
    /// CB-6.3-30: a caller that never supplies <c>parseCounterSignatureHeaderValue</c>
    /// gets structural acceptance ONLY — even wildly malformed counter-signature content collects zero
    /// violations, since the caller never opted into decoding it. Presence is never a violation on its own, and
    /// this orchestrator only inspects content a caller asked it to.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncNeverInspectsCounterSignatureContentWhenNoDecodeDelegateIsSupplied()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] malformedCounterSignatureValue = [0x18, 0x2A]; //A well-formed CBOR item (the integer 42) -- structurally valid uHeaders element content, but not a COSE_Countersignature array shape, so it splices/encodes cleanly and fails only at RFC 9338 decode time.
        var element = new CBAdESUnsignedHeaderElementFullCounterSignature(malformedCounterSignatureValue);

        byte[] wireCopy = await BuildSignatureWithUnsignedHeaderElementAsync(privateKey, element, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "With no decode delegate supplied, even malformed counter-signature content must not fail validation (opt-in seam, CB-6.3-30).");
    }


    /// <summary>
    /// Malformed counter-signature content collects a
    /// <see cref="CBAdESCounterSignatureMalformedViolation"/> once the caller opts in by supplying
    /// <c>parseCounterSignatureHeaderValue</c> — fail-closed decode, never a thrown exception.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-6.3-30.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncCollectsMalformedViolationWhenDecodeDelegateIsSuppliedAndContentIsMalformed()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyMaterial.PublicKey;
        using PrivateKeyMemory privateKey = keyMaterial.PrivateKey;

        byte[] malformedCounterSignatureValue = [0x18, 0x2A]; //A well-formed CBOR item (the integer 42) -- structurally valid uHeaders element content, but not a COSE_Countersignature array shape, so it splices/encodes cleanly and fails only at RFC 9338 decode time.
        var element = new CBAdESUnsignedHeaderElementFullCounterSignature(malformedCounterSignatureValue);

        byte[] wireCopy = await BuildSignatureWithUnsignedHeaderElementAsync(privateKey, element, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            archiveTimestampExternallySuppliedData: default,
            parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Malformed counter-signature content must fail validation once the caller opts into decoding it.");
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var failure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(1, failure.Violations);
        Assert.IsInstanceOfType<CBAdESCounterSignatureMalformedViolation>(failure.Violations[0]);
    }


    /// <summary>
    /// A genuine, correctly-signed abbreviated counter-signature (label 12) over the
    /// primary signature's own body-layer protected header/payload/signature verifies cleanly when the caller
    /// supplies the correct countersigner public key — proving the full decode-plus-verify path through
    /// <see cref="CoseCounterSign.VerifyAsync(CoseCounterSignature, CountersignTarget, ReadOnlyMemory{byte}, BuildCountersignStructureDelegate, PublicKeyMemory, CancellationToken)"/>
    /// verb, composed rather than re-implemented.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.1.6-01, CB-5.3.1-05.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncSucceedsWithZeroViolationsForAGenuineAbbreviatedCounterSignature()
    {
        var primaryKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory primaryPublicKey = primaryKeyMaterial.PublicKey;
        using PrivateKeyMemory primaryPrivateKey = primaryKeyMaterial.PrivateKey;

        var counterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory counterSignerPublicKey = counterSignerKeyMaterial.PublicKey;
        using PrivateKeyMemory counterSignerPrivateKey = counterSignerKeyMaterial.PrivateKey;

        byte[] wireCopy = await BuildSignatureWithGenuineCounterSignatureAsync(
            primaryPrivateKey, counterSignerPrivateKey, isAbbreviated: true, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            primaryPublicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            archiveTimestampExternallySuppliedData: default,
            parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
            buildCountersignStructure: CoseSerialization.BuildCountersignStructure,
            resolveCounterSignaturePublicKey: _ => counterSignerPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A genuine abbreviated counter-signature, resolved to its real countersigner key, must verify with zero violations.");
    }


    /// <summary>
    /// The SAME genuine counter-signature fixture as
    /// <see cref="ValidateAsyncSucceedsWithZeroViolationsForAGenuineAbbreviatedCounterSignature"/>, but resolved
    /// against the WRONG public key, collects a <see cref="CBAdESCounterSignatureVerificationFailedViolation"/>
    /// — proving a failing countersignature is a collected violation, never silently accepted.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.1.6-04.
    /// </remarks>
    [TestMethod]
    public async Task ValidateAsyncCollectsVerificationFailedViolationWhenResolvedKeyIsWrong()
    {
        var primaryKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory primaryPublicKey = primaryKeyMaterial.PublicKey;
        using PrivateKeyMemory primaryPrivateKey = primaryKeyMaterial.PrivateKey;

        var counterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PrivateKeyMemory counterSignerPrivateKey = counterSignerKeyMaterial.PrivateKey;
        counterSignerKeyMaterial.PublicKey.Dispose();

        var wrongKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory wrongPublicKey = wrongKeyMaterial.PublicKey;
        wrongKeyMaterial.PrivateKey.Dispose();

        byte[] wireCopy = await BuildSignatureWithGenuineCounterSignatureAsync(
            primaryPrivateKey, counterSignerPrivateKey, isAbbreviated: true, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            primaryPublicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            archiveTimestampExternallySuppliedData: default,
            parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
            buildCountersignStructure: CoseSerialization.BuildCountersignStructure,
            resolveCounterSignaturePublicKey: _ => wrongPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A genuine counter-signature resolved against the WRONG public key must fail validation.");
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var failure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(1, failure.Violations);
        Assert.IsInstanceOfType<CBAdESCounterSignatureVerificationFailedViolation>(failure.Violations[0]);
    }


    /// <summary>
    /// CB-5.2.8-09: a full counter-signature (label 11) whose OWN protected
    /// header carries <c>sigD</c> collects a <see cref="CBAdESCounterSignatureDetachedObjectsViolation"/> once
    /// the caller opts into decoding it via <c>decodeCounterSignatureProtectedHeader</c> -- "sigD ... shall
    /// never appear on a counter signature" (ETSI TS 119 152-1 V1.1.1, clause 5.2.8.1).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncCollectsDetachedObjectsViolationWhenACounterSignaturesOwnProtectedHeaderCarriesSigD()
    {
        var primaryKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory primaryPublicKey = primaryKeyMaterial.PublicKey;
        using PrivateKeyMemory primaryPrivateKey = primaryKeyMaterial.PrivateKey;

        var counterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PrivateKeyMemory counterSignerPrivateKey = counterSignerKeyMaterial.PrivateKey;
        counterSignerKeyMaterial.PublicKey.Dispose();

        byte[] wireCopy = await BuildSignatureWithCounterSignatureCarryingSigDAsync(
            primaryPrivateKey, counterSignerPrivateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            primaryPublicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            archiveTimestampExternallySuppliedData: default,
            parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
            decodeCounterSignatureProtectedHeader: CBAdESSignatureSerialization.DecodeCBAdESProtectedHeader,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "sigD on a counter signature's own protected header must fail validation (CB-5.2.8-09).");
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var failure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(1, failure.Violations);
        Assert.IsInstanceOfType<CBAdESCounterSignatureDetachedObjectsViolation>(failure.Violations[0]);
    }


    /// <summary>
    /// Label 11's value type is <c>COSE_Countersignature /
    /// [+ COSE_Countersignature]</c> (RFC 9338 §2 Table 1) -- a single uHeaders element carrying the array arm
    /// with TWO full countersignatures, one genuine against the resolved key and one signed by a DIFFERENT key
    /// (so it fails against that same resolved key), must have BOTH processed: exactly one
    /// <see cref="CBAdESCounterSignatureVerificationFailedViolation"/> (the second element) proves neither is
    /// silently skipped (which would report zero violations) nor the array arm rejected outright (which would
    /// report a <see cref="CBAdESCounterSignatureMalformedViolation"/> instead).
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncLoopsOverEveryCountersignatureInTheOneOrMoreArrayArm()
    {
        var primaryKeyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory primaryPublicKey = primaryKeyMaterial.PublicKey;
        using PrivateKeyMemory primaryPrivateKey = primaryKeyMaterial.PrivateKey;

        var genuineCounterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory genuineCounterSignerPublicKey = genuineCounterSignerKeyMaterial.PublicKey;
        using PrivateKeyMemory genuineCounterSignerPrivateKey = genuineCounterSignerKeyMaterial.PrivateKey;

        var otherCounterSignerKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PrivateKeyMemory otherCounterSignerPrivateKey = otherCounterSignerKeyMaterial.PrivateKey;
        otherCounterSignerKeyMaterial.PublicKey.Dispose();

        byte[] wireCopy = await BuildSignatureWithTwoFullCounterSignaturesAsync(
            primaryPrivateKey, genuineCounterSignerPrivateKey, otherCounterSignerPrivateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            primaryPublicKey,
            dereference: null, dereferenceContext: null, externalDetachedPayload: null, unknownMechanismHandler: null,
            AdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            archiveTimestampExternallySuppliedData: default,
            parseCounterSignatureHeaderValue: CoseSerialization.ParseCounterSignatureHeaderValue,
            buildCountersignStructure: CoseSerialization.BuildCountersignStructure,
            resolveCounterSignaturePublicKey: _ => genuineCounterSignerPublicKey,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "The second (wrong-key) countersignature in the array arm must fail validation.");
        Assert.IsInstanceOfType<CBAdESRuleViolationsFailure>(result.Failure);
        var failure = (CBAdESRuleViolationsFailure)result.Failure!;
        Assert.HasCount(1, failure.Violations,
            "Exactly one of the two countersignatures must fail -- proving BOTH were processed, not just the first (which alone would report zero) nor neither.");
        Assert.IsInstanceOfType<CBAdESCounterSignatureVerificationFailedViolation>(failure.Violations[0]);
    }


    /// <summary>
    /// Builds a minimal B-B message and splices in a SINGLE label-11 uHeaders element whose own value is the
    /// <c>[+ COSE_Countersignature]</c> array arm (RFC 9338 §2 Table 1) carrying two independently produced full
    /// countersignatures over the SAME target.
    /// </summary>
    /// <param name="primaryPrivateKey">The primary signer's private key.</param>
    /// <param name="genuineCounterSignerPrivateKey">The first element's own signing key.</param>
    /// <param name="otherCounterSignerPrivateKey">The second element's own signing key (deliberately different).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The final wire bytes.</returns>
    private static async ValueTask<byte[]> BuildSignatureWithTwoFullCounterSignaturesAsync(
        PrivateKeyMemory primaryPrivateKey,
        PrivateKeyMemory genuineCounterSignerPrivateKey,
        PrivateKeyMemory otherCounterSignerPrivateKey,
        CancellationToken cancellationToken)
    {
        byte[] payloadBytes = "CBAdESCounterSignatureVisibilityTests two-element array-arm payload"u8.ToArray();

        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            "CBAdESCounterSignatureVisibilityTests placeholder signing certificate"u8.ToArray(),
            32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        using var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);

        using var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
        var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure, primaryPrivateKey,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        var target = new CoseSign1CountersignTarget(
            creationResult.Message.ProtectedHeader.AsReadOnlyMemory(),
            creationResult.Message.Payload,
            creationResult.Message.Signature.AsReadOnlyMemory());

        using EncodedCoseProtectedHeader genuineHeader = EncodedCoseProtectedHeader.FromBytes(ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
        using CounterSignatureV2 genuine = await CoseCounterSign.CountersignFullAsync(
            target, genuineHeader, counterSignerUnprotectedHeader: null, externalAad: ReadOnlyMemory<byte>.Empty,
            CoseSerialization.BuildCountersignStructure, genuineCounterSignerPrivateKey, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        using EncodedCoseProtectedHeader otherHeader = EncodedCoseProtectedHeader.FromBytes(ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);
        using CounterSignatureV2 other = await CoseCounterSign.CountersignFullAsync(
            target, otherHeader, counterSignerUnprotectedHeader: null, externalAad: ReadOnlyMemory<byte>.Empty,
            CoseSerialization.BuildCountersignStructure, otherCounterSignerPrivateKey, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        using EncodedCoseCounterSignature encodedGenuine = CoseSerialization.WriteCounterSignatureV2(genuine, BaseMemoryPool.Shared);
        using EncodedCoseCounterSignature encodedOther = CoseSerialization.WriteCounterSignatureV2(other, BaseMemoryPool.Shared);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(2);
        writer.WriteEncodedValue(encodedGenuine.AsReadOnlySpan());
        writer.WriteEncodedValue(encodedOther.AsReadOnlySpan());
        writer.WriteEndArray();
        byte[] arrayArmValue = writer.Encode();

        var element = new CBAdESUnsignedHeaderElementFullCounterSignature(arrayArmValue);

        return SpliceElementAndSerialize(creationResult.Message, element);
    }


    /// <summary>
    /// The SAME shape as <see cref="BuildSignatureWithGenuineCounterSignatureAsync"/>'s full-form arm, but the
    /// countersigner's OWN protected header carries <c>alg</c> and <c>sigD</c> (never empty) -- CB-5.2.8-09's
    /// own fixture.
    /// </summary>
    /// <param name="primaryPrivateKey">The primary signer's private key.</param>
    /// <param name="counterSignerPrivateKey">The countersigner's private key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The final wire bytes.</returns>
    private static async ValueTask<byte[]> BuildSignatureWithCounterSignatureCarryingSigDAsync(
        PrivateKeyMemory primaryPrivateKey,
        PrivateKeyMemory counterSignerPrivateKey,
        CancellationToken cancellationToken)
    {
        byte[] payloadBytes = "CBAdESCounterSignatureVisibilityTests sigD-on-countersignature payload"u8.ToArray();

        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            "CBAdESCounterSignatureVisibilityTests placeholder signing certificate"u8.ToArray(),
            32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        using var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);

        using var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
        var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure, primaryPrivateKey,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        var target = new CoseSign1CountersignTarget(
            creationResult.Message.ProtectedHeader.AsReadOnlyMemory(),
            creationResult.Message.Payload,
            creationResult.Message.Signature.AsReadOnlyMemory());

        var sigDEntries = new List<CBAdESDetachedObjectEntry> { new("https://example.org/countersignature-sigd", digest: null, contentType: null) };
        using var counterSignerDetachedObjects = new CBAdESDetachedObjects(CBAdESDetachedMechanisms.ObjectIdByURI, sigDEntries, hashAlgorithm: null);
        using var counterSignerHeaders = new CBAdESProtectedHeaders(
            WellKnownCoseAlgorithms.Es256,
            cwtClaims: null,
            detachedObjects: counterSignerDetachedObjects,
            criticalLabels: [new CoseHeaderIntegerLabel(CBAdESHeaderParameters.SigD)]);
        using EncodedCoseProtectedHeader counterSignerProtectedHeader = CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader(counterSignerHeaders, BaseMemoryPool.Shared);

        using CounterSignatureV2 counterSignature = await CoseCounterSign.CountersignFullAsync(
            target, counterSignerProtectedHeader, counterSignerUnprotectedHeader: null, externalAad: ReadOnlyMemory<byte>.Empty,
            CoseSerialization.BuildCountersignStructure, counterSignerPrivateKey, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        using EncodedCoseCounterSignature encoded = CoseSerialization.WriteCounterSignatureV2(counterSignature, BaseMemoryPool.Shared);
        var element = new CBAdESUnsignedHeaderElementFullCounterSignature(encoded.AsReadOnlyMemory().ToArray());

        return SpliceElementAndSerialize(creationResult.Message, element);
    }


    /// <summary>
    /// Signs a minimal, otherwise-conformant B-B message and splices <paramref name="element"/> in as the sole
    /// <c>uHeaders</c> element, mirroring <c>CBAdESSignatureAugmentation</c>'s own byte-preserving splice
    /// pattern — the identical primitives that verb composes, used directly here since no
    /// dedicated "add a counter-signature" augmentation verb exists yet.
    /// </summary>
    /// <param name="privateKey">The primary signer's private key.</param>
    /// <param name="element">The counter-signature <c>uHeaders</c> element to splice in.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The final wire bytes.</returns>
    private static async ValueTask<byte[]> BuildSignatureWithUnsignedHeaderElementAsync(
        PrivateKeyMemory privateKey,
        CBAdESUnsignedHeaderElement element,
        CancellationToken cancellationToken)
    {
        byte[] payloadBytes = "CBAdESCounterSignatureVisibilityTests payload"u8.ToArray();

        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            "CBAdESCounterSignatureVisibilityTests placeholder signing certificate"u8.ToArray(),
            32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        using var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);

        using var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
        var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure, privateKey,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        return SpliceElementAndSerialize(creationResult.Message, element);
    }


    /// <summary>
    /// Signs a minimal B-B message with <paramref name="primaryPrivateKey"/>, countersigns its own body-layer
    /// protected header/payload/signature with <paramref name="counterSignerPrivateKey"/> through
    /// <see cref="CoseCounterSign"/> verb, encodes the result through <see cref="CoseSerialization.WriteCounterSignatureV2"/>/
    /// <see cref="CoseSerialization.WriteCounterSignature0V2"/>, and splices it in as a
    /// <see cref="CBAdESUnsignedHeaderElementFullCounterSignature"/>/<see cref="CBAdESUnsignedHeaderElementAbbreviatedCounterSignature"/>
    /// <c>uHeaders</c> element.
    /// </summary>
    /// <param name="primaryPrivateKey">The primary signer's private key.</param>
    /// <param name="counterSignerPrivateKey">The countersigner's private key.</param>
    /// <param name="isAbbreviated"><see langword="true"/> for label 12; <see langword="false"/> for label 11.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The final wire bytes.</returns>
    private static async ValueTask<byte[]> BuildSignatureWithGenuineCounterSignatureAsync(
        PrivateKeyMemory primaryPrivateKey,
        PrivateKeyMemory counterSignerPrivateKey,
        bool isAbbreviated,
        CancellationToken cancellationToken)
    {
        byte[] payloadBytes = "CBAdESCounterSignatureVisibilityTests genuine counter-signature payload"u8.ToArray();

        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            "CBAdESCounterSignatureVisibilityTests placeholder signing certificate"u8.ToArray(),
            32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        using var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);

        using var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
        var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers, payloadInput, unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure, primaryPrivateKey,
            dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
            BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

        var target = new CoseSign1CountersignTarget(
            creationResult.Message.ProtectedHeader.AsReadOnlyMemory(),
            creationResult.Message.Payload,
            creationResult.Message.Signature.AsReadOnlyMemory());

        if(isAbbreviated)
        {
            using CounterSignature0V2 counterSignature = await CoseCounterSign.CountersignAbbreviatedAsync(
                target, externalAad: ReadOnlyMemory<byte>.Empty, CoseSerialization.BuildCountersignStructure,
                counterSignerPrivateKey, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            using EncodedCoseCounterSignature encoded = CoseSerialization.WriteCounterSignature0V2(counterSignature, BaseMemoryPool.Shared);
            var element = new CBAdESUnsignedHeaderElementAbbreviatedCounterSignature(encoded.AsReadOnlyMemory().ToArray());

            return SpliceElementAndSerialize(creationResult.Message, element);
        }
        else
        {
            using EncodedCoseProtectedHeader counterSignerProtectedHeader = EncodedCoseProtectedHeader.FromBytes(ReadOnlySpan<byte>.Empty, BaseMemoryPool.Shared);

            using CounterSignatureV2 counterSignature = await CoseCounterSign.CountersignFullAsync(
                target, counterSignerProtectedHeader, counterSignerUnprotectedHeader: null, externalAad: ReadOnlyMemory<byte>.Empty,
                CoseSerialization.BuildCountersignStructure, counterSignerPrivateKey, BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            using EncodedCoseCounterSignature encoded = CoseSerialization.WriteCounterSignatureV2(counterSignature, BaseMemoryPool.Shared);
            var element = new CBAdESUnsignedHeaderElementFullCounterSignature(encoded.AsReadOnlyMemory().ToArray());

            return SpliceElementAndSerialize(creationResult.Message, element);
        }
    }


    /// <summary>
    /// Splices <paramref name="element"/> into <paramref name="primary"/>'s unprotected header (there is no
    /// pre-existing <c>uHeaders</c> to retain) and re-serializes around the SAME protected header, payload, and
    /// signature carriers — mirroring <c>CBAdESSignatureAugmentation.EncodeAndSerialize</c>'s exact pattern.
    /// </summary>
    /// <param name="primary">The already-signed primary message. Not disposed here.</param>
    /// <param name="element">The <c>uHeaders</c> element to splice in as the sole entry.</param>
    /// <returns>The final wire bytes.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "message borrows primary's own ProtectedHeader/Payload/Signature carriers verbatim -- " +
            "read-only, never disposed here, matching CBAdESSignatureAugmentation.EncodeAndSerialize's own " +
            "documented relationship to the carriers it borrows.")]
    private static byte[] SpliceElementAndSerialize(CoseSign1Message primary, CBAdESUnsignedHeaderElement element)
    {
        bool spliced = CBAdESSignatureSerialization.TrySpliceCBAdESUnprotectedHeader(
            rawUnsignedHeaders: null, decodedElementCount: 0, skipDecodedIndexes: null, newElement: element,
            BaseMemoryPool.Shared, out IReadOnlyDictionary<int, object>? unprotectedHeader);
        Assert.IsTrue(spliced, "Splicing a single new element into an absent uHeaders must always succeed.");

        var message = new CoseSign1Message(primary.ProtectedHeader, unprotectedHeader, primary.Payload, primary.Signature);

        using EncodedCoseSign1 wireBytes = CBAdESSignatureSerialization.SerializeCBAdESSign1(message, payloadIsDetached: false, BaseMemoryPool.Shared);

        return wireBytes.AsReadOnlySpan().ToArray();
    }
}
