using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Proofs for the <see cref="Verified{T}"/> provenance kernel: the restored value-equality semantics for
/// asserted labels, the reference-payload-only guard on binding a value-type payload, and the fail-closed
/// refusals of the <see cref="BoundProvenance"/> gates.
/// </summary>
[TestClass]
internal sealed class VerifiedProvenanceTests
{
    public TestContext TestContext { get; set; } = null!;


    private sealed record TestPayload(string Content);


    /// <summary>
    /// Two <see cref="Verified{T}"/> minted with <see cref="Verified{T}.CreateAsserted"/> over the same
    /// value and the same label are equal again -- the equality <see cref="Verified{T}"/> held before it grew
    /// a <see cref="Verified{T}.Provenance"/> property, restored by giving <see cref="AssertedProvenance"/>
    /// value equality over its <see cref="VerificationProvenance.Identity"/>.
    /// </summary>
    [TestMethod]
    public void TwoAssertedVerifiedInstancesOverTheSameValueAndLabelAreEqual()
    {
        var value = new TestPayload("same-instance");

        Verified<TestPayload> first = Verified<TestPayload>.CreateAsserted(value, AssertedProvenance.OfLabel("did:example:123#key-1"));
        Verified<TestPayload> second = Verified<TestPayload>.CreateAsserted(value, AssertedProvenance.OfLabel("did:example:123#key-1"));

        Assert.AreEqual(first, second);
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode());
    }


    /// <summary>
    /// Negative half: two asserted labels naming DIFFERENT identities are not equal, so the restored value
    /// equality is over the label's content, not vacuously true for every <see cref="AssertedProvenance"/>.
    /// </summary>
    [TestMethod]
    public void TwoAssertedVerifiedInstancesOverDifferentLabelsAreNotEqual()
    {
        var value = new TestPayload("same-instance");

        Verified<TestPayload> first = Verified<TestPayload>.CreateAsserted(value, AssertedProvenance.OfLabel("did:example:123#key-1"));
        Verified<TestPayload> second = Verified<TestPayload>.CreateAsserted(value, AssertedProvenance.OfLabel("did:example:456#key-1"));

        Assert.AreNotEqual(first, second);
    }


    /// <summary>
    /// <see cref="BoundProvenance"/> KEEPS reference identity -- two independently-established bindings for
    /// the exact same value and identity are correctly NOT equal, because a bound provenance is a capability
    /// token tied to the one instance a typed gate actually witnessed, not a label.
    /// </summary>
    [TestMethod]
    public void TwoBoundVerifiedInstancesOverTheSameValueAreNotEqualCapabilityTokenSemantics()
    {
        var value = new TestPayload("same-instance");
        var claimedIdentity = new KeyId("did:example:123#key-1");

        BoundProvenance? firstProvenance = BoundProvenance.TryBindByResolvedMethod(
            claimedIdentity, "did:example:123#key-1", VerificationRelationship.Authentication, value);
        BoundProvenance? secondProvenance = BoundProvenance.TryBindByResolvedMethod(
            claimedIdentity, "did:example:123#key-1", VerificationRelationship.Authentication, value);
        Assert.IsNotNull(firstProvenance);
        Assert.IsNotNull(secondProvenance);

        Verified<TestPayload>? first = Verified<TestPayload>.TryCreateBound(value, firstProvenance!);
        Verified<TestPayload>? second = Verified<TestPayload>.TryCreateBound(value, secondProvenance!);
        Assert.IsTrue(first.HasValue);
        Assert.IsTrue(second.HasValue);

        Assert.AreNotEqual(first!.Value, second!.Value);
    }


    /// <summary>
    /// A value-type <typeparamref name="T"/>'s <see cref="Verified{T}.TryCreateBound"/> is refused
    /// explicitly, never left to fail incidentally on fresh boxing at every call.
    /// </summary>
    [TestMethod]
    public void TryCreateBoundRefusesAValueTypePayload()
    {
        object subject = 42;
        BoundProvenance? provenance = BoundProvenance.TryBindByResolvedMethod(
            new KeyId("k"), "k", VerificationRelationship.Authentication, subject);
        Assert.IsNotNull(provenance);

        Verified<int>? bound = Verified<int>.TryCreateBound(42, provenance!);

        Assert.IsFalse(bound.HasValue);
    }


    /// <summary>
    /// <see cref="BoundProvenance.TryBindByResolvedMethod"/> refuses <see langword="default"/>(<see cref="KeyId"/>)
    /// -- a null/whitespace identity can never name a principal.
    /// </summary>
    [TestMethod]
    public void TryBindByResolvedMethodRefusesADefaultIdentity()
    {
        BoundProvenance? provenance = BoundProvenance.TryBindByResolvedMethod(
            default, "did:example:123#key-1", VerificationRelationship.Authentication, new object());

        Assert.IsNull(provenance);
    }


    /// <summary>
    /// <see cref="BoundProvenance.TryBindByKeyAgreement"/> refuses <see langword="default"/>(<see cref="KeyId"/>).
    /// </summary>
    [TestMethod]
    public void TryBindByKeyAgreementRefusesADefaultIdentity()
    {
        var claimed = default(KeyId);
        BoundProvenance? provenance = BoundProvenance.TryBindByKeyAgreement(claimed, isDecryptionAuthenticated: true, claimed, new object());

        Assert.IsNull(provenance);
    }


    /// <summary>
    /// <see cref="BoundProvenance.TryBindByKeyAgreement"/> refuses when the decryption-succeeded evidence is
    /// absent, checked IN-BODY rather than inferred from having been called at all.
    /// </summary>
    [TestMethod]
    public void TryBindByKeyAgreementRefusesWhenDecryptionEvidenceIsAbsent()
    {
        var senderKeyId = new KeyId("did:example:alice#key-agreement-1");
        BoundProvenance? provenance = BoundProvenance.TryBindByKeyAgreement(
            senderKeyId, isDecryptionAuthenticated: false, senderKeyId, new object());

        Assert.IsNull(provenance);
    }


    /// <summary>
    /// <see cref="BoundProvenance.TryBindByKeyAgreement"/> refuses when the resolved sender key the
    /// ECDH-1PU step actually ran under disagrees with the claimed <c>senderKeyId</c> — the evidence is
    /// present but inconsistent.
    /// </summary>
    [TestMethod]
    public void TryBindByKeyAgreementRefusesWhenResolvedSenderKeyDisagreesWithClaimed()
    {
        BoundProvenance? provenance = BoundProvenance.TryBindByKeyAgreement(
            new KeyId("did:example:alice#key-agreement-1"),
            isDecryptionAuthenticated: true,
            new KeyId("did:example:mallory#key-agreement-1"),
            new object());

        Assert.IsNull(provenance);
    }


    /// <summary>
    /// Positive half: <see cref="BoundProvenance.TryBindByKeyAgreement"/> binds when the decryption
    /// evidence is present and the resolved sender key agrees with the claimed one.
    /// </summary>
    [TestMethod]
    public void TryBindByKeyAgreementBindsWhenEvidenceIsPresentAndConsistent()
    {
        var senderKeyId = new KeyId("did:example:alice#key-agreement-1");
        var value = new TestPayload("authcrypt-sender");
        BoundProvenance? provenance = BoundProvenance.TryBindByKeyAgreement(
            senderKeyId, isDecryptionAuthenticated: true, senderKeyId, value);

        Assert.IsNotNull(provenance);
        Assert.AreEqual(ResolutionSource.KeyAgreement, provenance!.Source);

        Verified<TestPayload>? bound = Verified<TestPayload>.TryCreateBound(value, provenance);
        Assert.IsTrue(bound.HasValue);
        Assert.IsTrue(bound!.Value.IsIdentityBound);
    }


    /// <summary>
    /// <see cref="BoundProvenance.TryBindByCertificateDigestAsync"/> refuses (returns <see langword="null"/>)
    /// a signer reference whose stored digest length disagrees with its own declared algorithm's output length,
    /// fail-closed, rather than reaching the digest recompute with a mismatched buffer size (which would
    /// otherwise throw <see cref="ArgumentException"/>).
    /// </summary>
    [TestMethod]
    public async Task TryBindByCertificateDigestAsyncRefusesAReferenceWhoseLengthDisagreesWithItsOwnAlgorithm()
    {
        IMemoryOwner<byte> certificateOwner = BaseMemoryPool.Shared.Rent(3);
        new byte[] { 0x10, 0x20, 0x30 }.CopyTo(certificateOwner.Memory.Span);
        using var certificate = new PkiCertificateMemory(certificateOwner, PkiCertificateTags.X509Certificate);

        var verification = new SignatureCryptographicVerification
        {
            Outcome = SignatureCryptographicOutcome.Verified,
            SigningCertificate = certificate
        };

        //A SHA-256 OID (32-byte output) paired with a 16-byte stored digest: internally inconsistent.
        IMemoryOwner<byte> shortDigestOwner = BaseMemoryPool.Shared.Rent(16);
        using var shortDigest = new DigestValue(shortDigestOwner, CryptoTags.Sha256Digest);
        var mismatchedReference = new SigningCertificateReference
        {
            DigestAlgorithm = AlgorithmIdentifier.Sha256,
            CertificateDigest = shortDigest,
            IsSignerReference = true
        };

        BoundProvenance? bound = await BoundProvenance.TryBindByCertificateDigestAsync(
            [mismatchedReference], verification, new object(), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(bound);
    }
}
