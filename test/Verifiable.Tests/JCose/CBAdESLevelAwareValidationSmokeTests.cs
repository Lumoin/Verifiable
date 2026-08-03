using System;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Smoke-level wiring tests for the level-aware <see cref="CBAdESSignatureValidation.ValidateAsync"/> overloads
/// (wavecb S4, m4): the plumbing that composes the shared B-B core with
/// <see cref="Verifiable.Cryptography.Pki.CBAdESLevelRules"/> and the async token-imprint pass, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>. Exhaustive level-rule and token-imprint-binding coverage (positive and
/// negative sigTst/adoTst/sigRTst/rfsTst/arcTst legs, the valData service disjunction, CB-A.1.1-30, CB-A.1.1-02)
/// is the wave's dedicated test agents' own surface; this file only proves the new overloads exist with the
/// documented contract, never throw where the B-B-only overloads never threw, and run end to end against a
/// genuine signature minted through the shipped <see cref="CBAdESSignatureCreation"/>/<see cref="Verifiable.Cbor.CBAdESLevelMessageImprintAdapters"/>
/// composition.
/// </summary>
/// <remarks>
/// <strong>Firewall discipline.</strong> The one happy-path test mints its message inside its own nested block
/// scope and passes only the resulting <c>byte[]</c> wire copy to <c>ValidateAsync</c>, mirroring
/// <c>CBAdESSignatureFlowTests</c>'s own convention.
/// </remarks>
[TestClass]
internal sealed class CBAdESLevelAwareValidationSmokeTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>A <see langword="null"/> <c>buildPayloadTimestampImprintInput</c> delegate raises <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public async Task ValidateAsyncWithLevelThrowsArgumentNullExceptionWhenBuildPayloadTimestampImprintInputIsNull()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
            await CBAdESSignatureValidation.ValidateAsync(
                ReadOnlyMemory<byte>.Empty,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CoseSerialization.BuildSigStructure,
                publicKey,
                dereference: null,
                dereferenceContext: null,
                externalDetachedPayload: null,
                unknownMechanismHandler: null,
                CBAdESBaselineLevel.BB,
                buildPayloadTimestampImprintInput: null!,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>A <see langword="null"/> <c>buildSignatureAndReferencesTimestampImprintInput</c> delegate raises <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public async Task ValidateAsyncWithLevelThrowsArgumentNullExceptionWhenBuildSignatureAndReferencesTimestampImprintInputIsNull()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
            await CBAdESSignatureValidation.ValidateAsync(
                ReadOnlyMemory<byte>.Empty,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CoseSerialization.BuildSigStructure,
                publicKey,
                dereference: null,
                dereferenceContext: null,
                externalDetachedPayload: null,
                unknownMechanismHandler: null,
                CBAdESBaselineLevel.BB,
                CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                buildSignatureAndReferencesTimestampImprintInput: null!,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>A <see langword="null"/> <c>buildReferencesOnlyTimestampImprintInput</c> delegate raises <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public async Task ValidateAsyncWithLevelThrowsArgumentNullExceptionWhenBuildReferencesOnlyTimestampImprintInputIsNull()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
            await CBAdESSignatureValidation.ValidateAsync(
                ReadOnlyMemory<byte>.Empty,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CoseSerialization.BuildSigStructure,
                publicKey,
                dereference: null,
                dereferenceContext: null,
                externalDetachedPayload: null,
                unknownMechanismHandler: null,
                CBAdESBaselineLevel.BB,
                CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                buildReferencesOnlyTimestampImprintInput: null!,
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>A <see langword="null"/> <c>pool</c> raises <see cref="ArgumentNullException"/> on the level-aware overload.</summary>
    [TestMethod]
    public async Task ValidateAsyncWithLevelThrowsArgumentNullExceptionWhenPoolIsNull()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;

        await Assert.ThrowsExactlyAsync<ArgumentNullException>(async () =>
            await CBAdESSignatureValidation.ValidateAsync(
                ReadOnlyMemory<byte>.Empty,
                CBAdESSignatureSerialization.ParseCBAdESSign1,
                CoseSerialization.BuildSigStructure,
                publicKey,
                dereference: null,
                dereferenceContext: null,
                externalDetachedPayload: null,
                unknownMechanismHandler: null,
                CBAdESBaselineLevel.BB,
                CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
                CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
                pool: null!,
                TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }


    /// <summary>
    /// Malformed wire bytes fail closed as <see cref="CBAdESMalformedEncodingFailure"/> on the level-aware
    /// overload, exactly like the B-B-only overload (R-5) — the level pass never runs because the shared core
    /// never reaches success.
    /// </summary>
    [TestMethod]
    public async Task ValidateAsyncWithLevelReportsMalformedEncodingWithoutThrowing()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            new byte[] { 0xFF, 0x00 },
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            unknownMechanismHandler: null,
            CBAdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "Malformed wire bytes must not validate.");
        Assert.IsInstanceOfType<CBAdESMalformedEncodingFailure>(result.Failure);
    }


    /// <summary>
    /// A genuine, minimal conformant B-B message (no <c>uHeaders</c> at all) validates successfully through
    /// the level-aware overload at <see cref="CBAdESBaselineLevel.BB"/>, end to end against the SHIPPED
    /// <see cref="Verifiable.Cbor.CBAdESLevelMessageImprintAdapters"/> seams — proof the new plumbing composes,
    /// not a substitute for the wave's dedicated positive/negative level-rule and token-binding coverage.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "headers is deliberately not using-scoped: ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call, which this " +
            "test disposes via 'using creationResult' -- the identical pattern CBAdESSignatureFlowTests uses.")]
    [TestMethod]
    public async Task ValidateAsyncWithLevelSucceedsForMinimalConformantBBMessageWithNoTimestamps()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            "CBAdESLevelAwareValidationSmokeTests placeholder signing certificate"u8.ToArray(),
            32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var thumbprint = new CBAdESCertificateThumbprint(new CBAdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), digest);

        byte[] payloadBytes = "wavecb S4 m4 level-aware smoke test payload"u8.ToArray();

        byte[] wireCopy;
        {
            var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);
            var payloadInput = new CBAdESAttachedPayloadInput(payloadBytes);

            using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
                headers, payloadInput, unsignedHeaders: null,
                CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader, CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
                CoseSerialization.BuildSigStructure, privateKey,
                dereference: null, dereferenceContext: null, unknownMechanismHandler: null,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);
            wireCopy = wireBytes.AsReadOnlySpan().ToArray();
        }

        //Firewall: only wireCopy crosses from here on.
        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireCopy,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            unknownMechanismHandler: null,
            CBAdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, "A minimal conformant B-B message with no uHeaders must validate at level BB.");
        Assert.IsNull(result.UnsignedHeaders, "No uHeaders element was minted, so none should decode.");
        Assert.AreEqual(WellKnownCoseAlgorithms.Es256, result.Headers!.Algorithm);
    }
}
