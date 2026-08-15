using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// The CB-AdES certificate-accepting <see cref="CBAdESSignatureValidation.ValidateAsync"/> overload earns
/// <see cref="BoundProvenance"/> through
/// <see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>, and the bare-<see cref="PublicKeyMemory"/>
/// overloads stay the honest bring-your-own-key <see cref="AssertedProvenance"/> primitive.
/// </summary>
[TestClass]
internal sealed class CBAdESSigningCertificateBindingTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Positive: a CB-AdES signature whose protected header commits <c>x5t</c> over the SAME certificate the
    /// certificate-accepting overload is handed, genuinely signed under that certificate's own key, mints a
    /// <see cref="BoundProvenance"/> — <see cref="ResolutionSource.CertificateDigest"/>,
    /// <see cref="VerificationRelationship.SignerCertificate"/>, and a <see cref="KeyId"/> equal to the
    /// independently recomputed certificate digest.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "thumbprint and headers are deliberately not using-scoped: ownership of the thumbprint " +
            "transfers into headers at construction, and headers' ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which SignAndSerializeAsync disposes via 'using creationResult'. " +
            "Roslyn's CA2000 analysis cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task CertificateOverloadMintsBoundOnGenuineSignatureCommittingItsOwnDigest()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CertificateChainMaterial signer = TestCertificateChainProvider.CreateP256ChainMaterial(timeProvider);

        using DigestValue certDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.LeafDerBytes.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string expectedKeyId = Convert.ToHexStringLower(certDigest.AsReadOnlySpan());

        DigestValue x5tDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.LeafDerBytes.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        byte[] expectedX5TDigestBytes = x5tDigest.AsReadOnlySpan().ToArray();

        //Ownership of x5tDigest transfers into thumbprint, then into headers (both own their operand -- see each
        //type's own remarks), then into the CBAdESSignatureCreationResult SignAndSerializeAsync disposes -- the
        //independent expectedX5TDigestBytes copy above is what the final assertion below compares against.
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), x5tDigest);
        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);

        byte[] wireBytes = await SignAndSerializeAsync(headers, signer.LeafSigningKey, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireBytes,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            signer.LeafDerBytes,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.Failure?.Message);
        Assert.IsNotNull(result.Verified);
        Assert.IsTrue(result.Verified!.Value.IsIdentityBound, "The certificate-accepting overload must mint Bound, not Asserted.");
        Assert.IsTrue(result.Verified.Value.Provenance is BoundProvenance, "The minted provenance must be a BoundProvenance instance.");
        var bound = (BoundProvenance)result.Verified.Value.Provenance!;
        Assert.AreEqual(ResolutionSource.CertificateDigest, bound.Source);
        Assert.AreEqual(VerificationRelationship.SignerCertificate, bound.Relationship);
        Assert.AreEqual(expectedKeyId, bound.Identity?.Value);
        Assert.IsTrue(expectedX5TDigestBytes.AsSpan().SequenceEqual(result.Verified.Value.Value.Headers.X5T!.Digest.AsReadOnlySpan()),
            "The verified facts' Headers must carry the signed x5t (the same commitment the binding recomputed against).");
    }


    /// <summary>
    /// Negative (the substitution this certificate-binding gate closes): the COSE signature value genuinely verifies under attacker
    /// certificate Y's own key (Y really signed it), but the protected header's own <c>x5t</c> commits victim
    /// certificate X's digest — "verified under Y, signed-reference names X". The certificate-accepting overload
    /// must refuse to mint ANYTHING, never silently downgrading to an unbound label.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "thumbprint and headers are deliberately not using-scoped: ownership of the thumbprint " +
            "transfers into headers at construction, and headers' ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which SignAndSerializeAsync disposes via 'using creationResult'. " +
            "Roslyn's CA2000 analysis cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task CertificateOverloadRefusesWhenTheHeaderCommitsADifferentCertificateThanTheOneItVerifiedUnder()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CertificateChainMaterial victim = TestCertificateChainProvider.CreateP256ChainMaterial(timeProvider);
        using CertificateChainMaterial attacker = TestCertificateChainProvider.CreateFreshP256ChainMaterial("cbades-attacker.example.test", timeProvider);

        DigestValue victimDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            victim.LeafDerBytes.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Ownership of victimDigest transfers into thumbprint, then into headers, then into the
        //CBAdESSignatureCreationResult SignAndSerializeAsync disposes -- see the positive test's identical note.
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), victimDigest);
        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);

        //Genuinely signed with the ATTACKER's own key -- the COSE signature value itself verifies cleanly under
        //attacker.LeafDerBytes; only the header's own commitment lies about which certificate that is.
        byte[] wireBytes = await SignAndSerializeAsync(headers, attacker.LeafSigningKey, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireBytes,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            attacker.LeafDerBytes,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "The digest commitment mismatch must refuse the whole validation, never silently mint an unbound label.");
        Assert.IsNull(result.Verified);
        Assert.IsInstanceOfType<CBAdESSigningCertificateBindingFailure>(result.Failure);
        Assert.IsNotNull(result.Headers, "The decoded facts must still be reachable through Headers even on a binding refusal.");
    }


    /// <summary>
    /// BYOK stays honest: the bare-<see cref="PublicKeyMemory"/> overload never binds, regardless of whether the
    /// protected header carries an <c>x5t</c> claim — <see cref="Verified{T}.IsIdentityBound"/> is
    /// <see langword="false"/> and the provenance is an <see cref="AssertedProvenance"/> label only.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "thumbprint and headers are deliberately not using-scoped: ownership of the thumbprint " +
            "transfers into headers at construction, and headers' ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which SignAndSerializeAsync disposes via 'using creationResult'. " +
            "Roslyn's CA2000 analysis cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task BareKeyOverloadStaysAssertedAndNeverBinds()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        DigestValue x5tDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            "CB-AdES bare-key binding fixture"u8.ToArray(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Ownership of x5tDigest transfers into thumbprint, then into headers, then into the
        //CBAdESSignatureCreationResult SignAndSerializeAsync disposes -- see the positive test's identical note.
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), x5tDigest);
        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);

        byte[] wireBytes = await SignAndSerializeAsync(headers, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireBytes,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.Failure?.Message);
        Assert.IsNotNull(result.Verified);
        Assert.IsFalse(result.Verified!.Value.IsIdentityBound, "The bare-key overload must never bind -- it is the honest BYOK primitive.");
        Assert.IsTrue(result.Verified.Value.Provenance is AssertedProvenance, "The bare-key overload's provenance must be an AssertedProvenance label.");
    }


    /// <summary>
    /// Level-aware positive: a CB-AdES signature whose protected header commits <c>x5t</c> over the SAME
    /// certificate the level-aware certificate-accepting overload is handed, genuinely signed under that
    /// certificate's own key, validated at a checked <see cref="AdESBaselineLevel"/> mints a
    /// <see cref="BoundProvenance"/> through the SAME <c>BindAndMintAsync</c> terminal step the B-B-only overload
    /// uses — <see cref="ResolutionSource.CertificateDigest"/>, and the verified facts carry the checked level.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "thumbprint and headers are deliberately not using-scoped: ownership of the thumbprint " +
            "transfers into headers at construction, and headers' ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which SignAndSerializeAsync disposes via 'using creationResult'. " +
            "Roslyn's CA2000 analysis cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task LevelAwareCertificateOverloadMintsBoundAtTheCheckedLevel()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CertificateChainMaterial signer = TestCertificateChainProvider.CreateP256ChainMaterial(timeProvider);

        using DigestValue certDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.LeafDerBytes.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string expectedKeyId = Convert.ToHexStringLower(certDigest.AsReadOnlySpan());

        DigestValue x5tDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.LeafDerBytes.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Ownership of x5tDigest transfers into thumbprint, then into headers -- see the B-B-only positive test's
        //identical note.
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), x5tDigest);
        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);

        byte[] wireBytes = await SignAndSerializeAsync(headers, signer.LeafSigningKey, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireBytes,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            signer.LeafDerBytes,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            unknownMechanismHandler: null,
            AdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.Failure?.Message);
        Assert.IsNotNull(result.Verified);
        Assert.IsTrue(result.Verified!.Value.IsIdentityBound, "The level-aware certificate-accepting overload must mint Bound, not Asserted.");
        Assert.IsTrue(result.Verified.Value.Provenance is BoundProvenance, "The minted provenance must be a BoundProvenance instance.");
        var bound = (BoundProvenance)result.Verified.Value.Provenance!;
        Assert.AreEqual(ResolutionSource.CertificateDigest, bound.Source);
        Assert.AreEqual(VerificationRelationship.SignerCertificate, bound.Relationship);
        Assert.AreEqual(expectedKeyId, bound.Identity?.Value);
        Assert.AreEqual(AdESBaselineLevel.BB, result.Verified.Value.Value.Level, "The bound facts must carry the level this call checked against.");
    }


    /// <summary>
    /// Level-aware negative-substitution (the substitution this certificate-binding gate closes on the level-aware path too): the
    /// COSE signature value genuinely verifies under attacker certificate Y's own key, but the protected
    /// header's own <c>x5t</c> commits victim certificate X's digest. The level-aware certificate-accepting
    /// overload must refuse to mint ANYTHING, never silently downgrading to an unbound label, and the decoded
    /// facts must still be reachable through <see cref="CBAdESValidationResult.Headers"/>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "thumbprint and headers are deliberately not using-scoped: ownership of the thumbprint " +
            "transfers into headers at construction, and headers' ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which SignAndSerializeAsync disposes via 'using creationResult'. " +
            "Roslyn's CA2000 analysis cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task LevelAwareCertificateOverloadRefusesWhenTheHeaderCommitsADifferentCertificateThanTheOneItVerifiedUnder()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CertificateChainMaterial victim = TestCertificateChainProvider.CreateP256ChainMaterial(timeProvider);
        using CertificateChainMaterial attacker = TestCertificateChainProvider.CreateFreshP256ChainMaterial("cbades-level-aware-attacker.example.test", timeProvider);

        DigestValue victimDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            victim.LeafDerBytes.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Ownership of victimDigest transfers into thumbprint, then into headers -- see the B-B-only negative
        //test's identical note.
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), victimDigest);
        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);

        //Genuinely signed with the ATTACKER's own key -- the COSE signature value itself verifies cleanly under
        //attacker.LeafDerBytes; only the header's own commitment lies about which certificate that is.
        byte[] wireBytes = await SignAndSerializeAsync(headers, attacker.LeafSigningKey, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireBytes,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            attacker.LeafDerBytes,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            unknownMechanismHandler: null,
            AdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "The digest commitment mismatch must refuse the whole validation, never silently mint an unbound label.");
        Assert.IsNull(result.Verified);
        Assert.IsInstanceOfType<CBAdESSigningCertificateBindingFailure>(result.Failure);
        Assert.IsNotNull(result.Headers, "The decoded facts must still be reachable through Headers even on a binding refusal.");
    }


    /// <summary>
    /// The level-aware BARE-KEY overload stays the honest bring-your-own-key primitive: it still mints an
    /// <see cref="AssertedProvenance"/> <see cref="Verified{T}"/> (<see cref="Verified{T}.IsIdentityBound"/>
    /// <see langword="false"/>) at a checked level, never binding -- unlike the level-aware certificate-accepting
    /// overload above.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "thumbprint and headers are deliberately not using-scoped: ownership of the thumbprint " +
            "transfers into headers at construction, and headers' ownership transfers into the returned " +
            "CBAdESSignatureCreationResult on a successful CBAdESSignatureCreation.SignAsync call (see that " +
            "type's own ownership remarks), which SignAndSerializeAsync disposes via 'using creationResult'. " +
            "Roslyn's CA2000 analysis cannot see across that async call boundary into the transfer.")]
    [TestMethod]
    public async Task LevelAwareBareKeyOverloadStaysAssertedAndNeverBinds()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        DigestValue x5tDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            "CB-AdES level-aware bare-key binding fixture"u8.ToArray(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Ownership of x5tDigest transfers into thumbprint, then into headers -- see the B-B-only bare-key test's
        //identical note.
        var thumbprint = new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(WellKnownCoseAlgorithms.Sha256), x5tDigest);
        var headers = new CBAdESProtectedHeaders(WellKnownCoseAlgorithms.Es256, new CBAdESCwtClaims(TestClock.CanonicalEpoch), x5t: thumbprint);

        byte[] wireBytes = await SignAndSerializeAsync(headers, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using CBAdESValidationResult result = await CBAdESSignatureValidation.ValidateAsync(
            wireBytes,
            CBAdESSignatureSerialization.ParseCBAdESSign1,
            CoseSerialization.BuildSigStructure,
            publicKey,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            unknownMechanismHandler: null,
            AdESBaselineLevel.BB,
            CBAdESLevelMessageImprintAdapters.BuildPayloadTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildSignatureAndReferencesTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildReferencesOnlyTimestampMessageImprintInput,
            CBAdESLevelMessageImprintAdapters.TryBuildArchiveTimestampValidationMessageImprintInput,
            BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.Failure?.Message);
        Assert.IsNotNull(result.Verified);
        Assert.IsFalse(result.Verified!.Value.IsIdentityBound, "The level-aware bare-key overload must never bind -- it is the honest BYOK primitive.");
        Assert.IsTrue(result.Verified.Value.Provenance is AssertedProvenance, "The level-aware bare-key overload's provenance must be an AssertedProvenance label.");
        Assert.AreEqual(AdESBaselineLevel.BB, result.Verified.Value.Value.Level, "The asserted facts must carry the level this call checked against.");
    }


    /// <summary>Signs <paramref name="headers"/> over a fixed attached payload and serializes the result.</summary>
    private static async Task<byte[]> SignAndSerializeAsync(CBAdESProtectedHeaders headers, PrivateKeyMemory privateKey, CancellationToken cancellationToken)
    {
        using CBAdESSignatureCreationResult creationResult = await CBAdESSignatureCreation.SignAsync(
            headers,
            new CBAdESAttachedPayloadInput(new byte[] { 0x01, 0x02, 0x03 }),
            unsignedHeaders: null,
            CBAdESSignatureSerialization.EncodeCBAdESProtectedHeader,
            CBAdESSignatureSerialization.EncodeCBAdESUnprotectedHeader,
            CoseSerialization.BuildSigStructure,
            privateKey,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        using EncodedCoseSign1 wireBytes = CoseSerialization.SerializeCoseSign1(creationResult.Message, BaseMemoryPool.Shared);

        return wireBytes.AsReadOnlySpan().ToArray();
    }
}
