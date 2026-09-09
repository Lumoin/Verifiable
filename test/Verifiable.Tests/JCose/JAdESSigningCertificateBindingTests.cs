using System;
using System.Buffers;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.JCose;

/// <summary>
/// The JAdES certificate-accepting <see cref="JAdESSignatureValidation.ValidateAsync"/> overload earns
/// <see cref="BoundProvenance"/> through <see cref="BoundProvenance.TryBindByCertificateDigestAsync"/>, and the
/// bare-<see cref="PublicKeyMemory"/> overloads stay the honest bring-your-own-key <see cref="AssertedProvenance"/>
/// primitive; the JA-A.1.1-02 trivial-PASS hole <see cref="SigningCertificateIdentification"/> otherwise takes
/// when a format never populates <see cref="SignatureFacts.SigningCertificateReferences"/> is closed by
/// <see cref="JAdESSignatureFacts.BuildSigningCertificateReferences"/>.
/// </summary>
[TestClass]
internal sealed class JAdESSigningCertificateBindingTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Positive: a JAdES signature whose protected header commits <c>x5t#S256</c> over the SAME certificate the
    /// certificate-accepting overload is handed, genuinely signed under that certificate's own key, mints a
    /// <see cref="BoundProvenance"/> — <see cref="ResolutionSource.CertificateDigest"/>,
    /// <see cref="VerificationRelationship.SignerCertificate"/>, and a <see cref="KeyId"/> equal to the
    /// independently recomputed certificate digest.
    /// </summary>
    [TestMethod]
    public async Task CertificateOverloadMintsBoundOnGenuineSignatureCommittingItsOwnDigest()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CertificateChainMaterial signer = TestCertificateChainProvider.CreateP256ChainMaterial(timeProvider);

        using DigestValue certDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.LeafDerBytes.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string expectedKeyId = Convert.ToHexStringLower(certDigest.AsReadOnlySpan());

        using DigestValue x5tDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            signer.LeafDerBytes.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256, issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch), x5tHashS256: x5tDigest);

        byte[] wireBytes = await SignAndSerializeAsync(headers, signer.LeafSigningKey, TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESValidationResult result = await JAdESSignatureValidation.ValidateAsync(
            wireBytes,
            JAdESMessageJson.TryParse,
            JAdESProtectedHeaderJson.Decode,
            JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse,
            signer.LeafDerBytes,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            httpHeadersContext: null,
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
    }


    /// <summary>
    /// Negative (the substitution this certificate-binding gate closes): the JWS signature value genuinely verifies under attacker
    /// certificate Y's own key (Y really signed it), but the protected header's own <c>x5t#S256</c> commits
    /// victim certificate X's digest — "verified under Y, signed-reference names X". The certificate-accepting
    /// overload must refuse to mint ANYTHING, never silently downgrading to an unbound label.
    /// </summary>
    [TestMethod]
    public async Task CertificateOverloadRefusesWhenTheHeaderCommitsADifferentCertificateThanTheOneItVerifiedUnder()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CertificateChainMaterial victim = TestCertificateChainProvider.CreateP256ChainMaterial(timeProvider);
        using CertificateChainMaterial attacker = TestCertificateChainProvider.CreateFreshP256ChainMaterial("attacker.example.test", timeProvider);

        using DigestValue victimDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            victim.LeafDerBytes.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256, issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch), x5tHashS256: victimDigest);

        //Genuinely signed with the ATTACKER's own key -- the JWS signature value itself verifies cleanly under
        //attacker.LeafDerBytes; only the header's own commitment lies about which certificate that is.
        byte[] wireBytes = await SignAndSerializeAsync(headers, attacker.LeafSigningKey, TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESValidationResult result = await JAdESSignatureValidation.ValidateAsync(
            wireBytes,
            JAdESMessageJson.TryParse,
            JAdESProtectedHeaderJson.Decode,
            JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse,
            attacker.LeafDerBytes,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            httpHeadersContext: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "The digest commitment mismatch must refuse the whole validation, never silently mint an unbound label.");
        Assert.IsNull(result.Verified);
        Assert.IsInstanceOfType<JAdESSigningCertificateBindingFailure>(result.Failure);
        Assert.IsNotNull(result.Headers, "The decoded facts must still be reachable through Headers even on a binding refusal.");
    }


    /// <summary>
    /// BYOK stays honest: the bare-<see cref="PublicKeyMemory"/> overload never binds, regardless of whether the
    /// protected header carries an <c>x5t#S256</c> claim — <see cref="Verified{T}.IsIdentityBound"/> is
    /// <see langword="false"/> and the provenance is an <see cref="AssertedProvenance"/> label only.
    /// </summary>
    [TestMethod]
    public async Task BareKeyOverloadStaysAssertedAndNeverBinds()
    {
        var keyPair = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PublicKeyMemory publicKey = keyPair.PublicKey;
        using PrivateKeyMemory privateKey = keyPair.PrivateKey;

        using DigestValue x5tDigest = TestDigest();
        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256, issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch), x5tHashS256: x5tDigest);

        byte[] wireBytes = await SignAndSerializeAsync(headers, privateKey, TestContext.CancellationToken).ConfigureAwait(false);

        using JAdESValidationResult result = await JAdESSignatureValidation.ValidateAsync(
            wireBytes,
            JAdESMessageJson.TryParse,
            JAdESProtectedHeaderJson.Decode,
            JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse,
            publicKey,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            dereference: null,
            dereferenceContext: null,
            externalDetachedPayload: null,
            httpHeadersContext: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.Failure?.Message);
        Assert.IsNotNull(result.Verified);
        Assert.IsFalse(result.Verified!.Value.IsIdentityBound, "The bare-key overload must never bind -- it is the honest BYOK primitive.");
        Assert.IsTrue(result.Verified.Value.Provenance is AssertedProvenance, "The bare-key overload's provenance must be an AssertedProvenance label.");
    }


    /// <summary>
    /// The JA-A.1.1-02 trivial-PASS hole closure: before <see cref="JAdESSignatureFacts.BuildSigningCertificateReferences"/>,
    /// <see cref="SignatureFacts.SigningCertificateReferences"/> stayed empty and
    /// <see cref="SigningCertificateIdentification.IdentifyAsync"/> took clause 5.2.3.4's last-paragraph
    /// no-reference-present branch, trivially PASSING with whatever candidate certificate the Driving
    /// Application supplied — even one the signature's own <c>x5t#S256</c> commitment does not name. Now that a
    /// real reference is fed, identification correctly reports INDETERMINATE/NO_SIGNING_CERTIFICATE_FOUND for a
    /// candidate whose digest does not match.
    /// </summary>
    [TestMethod]
    public async Task TrivialPassHoleIsClosedWhenCandidateCertificateDoesNotMatchTheCommittedDigest()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CertificateChainMaterial committed = TestCertificateChainProvider.CreateP256ChainMaterial(timeProvider);
        using CertificateChainMaterial candidate = TestCertificateChainProvider.CreateFreshP256ChainMaterial("mismatched.example.test", timeProvider);

        using DigestValue committedDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            committed.LeafDerBytes.AsReadOnlyMemory(), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        using var headers = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256, issuedAt: new JAdESClaimedSigningTime(TestClock.CanonicalEpoch), x5tHashS256: committedDigest);

        byte[] wireBytes = await SignAndSerializeAsync(headers, committed.LeafSigningKey, TestContext.CancellationToken).ConfigureAwait(false);

        using PkiCertificateMemory wireCarrier = ToCarrier(wireBytes);

        SignatureFormatSeam seam = JAdESSignatureFacts.CreateSeam(
            JAdESMessageJson.TryParse, JAdESProtectedHeaderJson.Decode, JAdESProtectedHeaderJson.DetectX5tPresence,
            JAdESEtsiUJson.TryParse, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder);

        using SignatureFacts facts = await seam.ExtractFacts(
            new SignatureFactsExtractionContext { SignedDataObject = wireCarrier },
            BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SignatureFactsStatus.Extracted, facts.Status);
        Assert.IsNotEmpty(facts.SigningCertificateReferences, "The x5t#S256 commitment must now populate SigningCertificateReferences -- the trivial-PASS hole this test closes.");

        SigningCertificateIdentificationResult identification = await SigningCertificateIdentification.IdentifyAsync(
            facts, candidate.LeafDerBytes, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(BuildingBlockIndication.Indeterminate, identification.Conclusion.Indication,
            "A candidate certificate whose digest does not match the signature's own commitment must no longer trivially PASS.");
        Assert.Contains(SignatureValidationSubIndication.NoSigningCertificateFound, identification.Conclusion.SubIndications);
    }


    /// <summary>Signs <paramref name="headers"/> over a fixed payload and serializes the result in Compact form.</summary>
    private static async Task<byte[]> SignAndSerializeAsync(JAdESProtectedHeaders headers, PrivateKeyMemory privateKey, CancellationToken cancellationToken)
    {
        using JAdESSignatureCreationResult creationResult = await JAdESSignatureCreation.SignAsync(
            headers,
            new JAdESAttachedPayloadInput(new byte[] { 0x01, 0x02, 0x03 }),
            unsignedHeaders: null,
            JAdESProtectedHeaderJson.Encode,
            JAdESEtsiUJson.Encode,
            TestSetup.Base64UrlEncoder,
            privateKey,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async,
            dereference: null,
            dereferenceContext: null,
            unknownMechanismHandler: null,
            BaseMemoryPool.Shared,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return JAdESSignatureCreation.Serialize(creationResult, JoseSerializationFormat.Compact, TestSetup.Base64UrlEncoder, JsonSerialize);
    }


    private static byte[] JsonSerialize(object value) => JsonSerializer.SerializeToUtf8Bytes(value);


    private static DigestValue TestDigest()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[32].CopyTo(owner.Memory);

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    /// <summary>Copies bytes into a pooled carrier standing in for the engine's <see cref="SensitiveMemory"/> Signed Data Object slot (mirrors <see cref="JAdESSignatureFactsTests"/>'s identical helper).</summary>
    private static PkiCertificateMemory ToCarrier(byte[] bytes)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}
