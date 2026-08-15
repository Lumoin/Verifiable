using System;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Construction, ownership, and dispose tests for <see cref="JAdESProtectedHeaders"/> — the JAdES
/// signed-header-set aggregate, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
/// ETSI TS 119 182-1 V1.2.1</see>, clauses 5.1 and 5.2.
/// </summary>
[TestClass]
internal sealed class JAdESProtectedHeadersTests
{
    /// <summary>Builds a fixture <see cref="DigestValue"/> — content is irrelevant, only ownership/dispose behavior matters here.</summary>
    private static DigestValue CreateDigest(byte value)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(1);
        owner.Memory.Span[0] = value;

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }


    /// <summary>Constructing with only the mandatory <c>alg</c> member leaves every optional member null.</summary>
    [TestMethod]
    public void ConstructsWithAlgorithmOnly()
    {
        using var model = new JAdESProtectedHeaders(WellKnownJwaValues.Es256);

        Assert.AreEqual(WellKnownJwaValues.Es256, model.Algorithm);
        Assert.IsNull(model.ContentType);
        Assert.IsNull(model.KeyId);
        Assert.IsNull(model.X5U);
        Assert.IsNull(model.X5tHashS256);
        Assert.IsNull(model.X5Chain);
        Assert.IsNull(model.CriticalLabels);
        Assert.IsNull(model.B64);
        Assert.IsNull(model.IssuedAt);
        Assert.IsNull(model.SigT);
        Assert.IsNull(model.X5tHashO);
        Assert.IsNull(model.SigX5ts);
        Assert.IsNull(model.SignerCommitments);
        Assert.IsNull(model.SignatureProductionPlace);
        Assert.IsNull(model.SignerAttributes);
        Assert.IsNull(model.PayloadTimestamps);
        Assert.IsNull(model.SignaturePolicyIdentifier);
        Assert.IsNull(model.SigD);
    }


    /// <summary><c>alg</c> is mandatory (JA-5.1.2-01); a <see langword="null"/>/empty value fails closed.</summary>
    [TestMethod]
    public void ConstructingWithEmptyAlgorithmThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new JAdESProtectedHeaders(string.Empty));
    }


    /// <summary>RFC 7515 §4.1.11: a present <c>crit</c> array shall not be empty; an empty array fails closed.</summary>
    [TestMethod]
    public void ConstructingWithEmptyCriticalLabelsThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new JAdESProtectedHeaders(WellKnownJwaValues.Es256, criticalLabels: []));
    }


    /// <summary>
    /// <c>iat</c> and legacy <c>sigT</c> both carry through independently, unenforced for mutual
    /// exclusivity at this model layer — a validation-layer concern (see the type remarks).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-5.1.11-01.
    /// </remarks>
    [TestMethod]
    public void ConstructsWithBothIssuedAtAndLegacySigT()
    {
        var issuedAt = new JAdESClaimedSigningTime(new DateTimeOffset(2026, 8, 6, 0, 0, 0, TimeSpan.Zero));
        var sigT = new JAdESClaimedSigningTime(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero));

        using var model = new JAdESProtectedHeaders(WellKnownJwaValues.Es256, issuedAt: issuedAt, sigT: sigT);

        Assert.AreEqual(issuedAt, model.IssuedAt);
        Assert.AreEqual(sigT, model.SigT);
    }


    /// <summary>
    /// Every clause 5.2 component model supplied constructs and carries through unchanged, exercising every
    /// aggregate member this model type carries.
    /// </summary>
    [TestMethod]
    public void ConstructsWithEveryClause52ComponentSupplied()
    {
        using DigestValue x5tHashS256 = CreateDigest(0x01);
        using DigestValue x5tHashODigest = CreateDigest(0x02);
        using DigestValue thumbprintDigestA = CreateDigest(0x03);
        using DigestValue thumbprintDigestB = CreateDigest(0x04);

        //CA2000: ownership of each disposable model below transfers into the JAdESProtectedHeaders constructor
        //call further down; disposing 'model' (via 'using') disposes them all. The 'using' locals here are
        //redundant-but-safe with that transfer — every owned Dispose here is idempotent.
        using var x5tHashO = new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-512"), x5tHashODigest);
#pragma warning disable CA2000 // Dispose objects before losing scope
        using var sigX5ts = new AdESCertificateThumbprints(
        [
            new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-256"), thumbprintDigestA),
            new AdESCertificateThumbprint(new AdESDigestAlgorithmTextIdentifier("sha-384"), thumbprintDigestB)
        ]);
#pragma warning restore CA2000 // Dispose objects before losing scope
        var signerCommitments = new AdESSignerCommitments(
        [
            new AdESCommitment(new AdESObjectIdentifier("https://example.org/commitments/proof-of-origin"))
        ]);
        var signatureProductionPlace = new AdESSignatureProductionPlace { AddressLocality = "Espoo" };
        var signerAttributes = new AdESSignerAttributes(
            claimed: [new JAdESQualifyingAttribute("text/plain", "base64url", ["role=signer"])]);
        using var payloadTimestamps = new AdESTimestampContainer([new AdESTimestampToken { Val = new byte[] { 0x30 } }]);
        using var signaturePolicyIdentifier = new AdESSignaturePolicyIdentifier(
            new AdESObjectIdentifier("https://example.org/jades/policy/1"));
        var sigD = new JAdESHttpHeadersReference(["digest"]);

        using var model = new JAdESProtectedHeaders(
            WellKnownJwaValues.Es256,
            contentType: "application/json",
            keyId: "signing-key-1",
            x5u: new Uri("https://example.org/certs/signer.pem"),
            x5tHashS256: x5tHashS256,
            x5chain: [new byte[] { 0x30, 0x82 }],
            criticalLabels: ["sigD"],
            b64: false,
            x5tHashO: x5tHashO,
            sigX5ts: sigX5ts,
            signerCommitments: signerCommitments,
            signatureProductionPlace: signatureProductionPlace,
            signerAttributes: signerAttributes,
            payloadTimestamps: payloadTimestamps,
            signaturePolicyIdentifier: signaturePolicyIdentifier,
            sigD: sigD);

        Assert.AreEqual("application/json", model.ContentType);
        Assert.AreEqual("signing-key-1", model.KeyId);
        Assert.AreEqual(new Uri("https://example.org/certs/signer.pem"), model.X5U);
        Assert.IsTrue(x5tHashS256.AsReadOnlySpan().SequenceEqual(model.X5tHashS256!.AsReadOnlySpan()));
        Assert.HasCount(1, model.X5Chain!);
        Assert.HasCount(1, model.CriticalLabels!);
        Assert.IsFalse(model.B64!.Value);
        Assert.AreSame(x5tHashO, model.X5tHashO);
        Assert.AreSame(sigX5ts, model.SigX5ts);
        Assert.AreSame(signerCommitments, model.SignerCommitments);
        Assert.AreSame(signatureProductionPlace, model.SignatureProductionPlace);
        Assert.AreSame(signerAttributes, model.SignerAttributes);
        Assert.AreSame(payloadTimestamps, model.PayloadTimestamps);
        Assert.AreSame(signaturePolicyIdentifier, model.SignaturePolicyIdentifier);
        Assert.AreSame(sigD, model.SigD);
    }


    /// <summary>
    /// <see cref="JAdESProtectedHeaders.Dispose"/> disposes every owned disposable member — including
    /// <see cref="JAdESDetachedDataObjectReference"/> arms that themselves implement <see cref="IDisposable"/>
    /// — and is safe to call more than once.
    /// </summary>
    [TestMethod]
    public void DisposeDisposesEveryOwnedMemberAndIsIdempotent()
    {
        //CA2000: ownership of 'x5tHashS256'/'sigD' (and its own owned entry) transfers into the
        //JAdESProtectedHeaders constructor below; this test's own repeated 'model.Dispose()' calls are exactly
        //what exercises the idempotency claim under test, not a leak.
#pragma warning disable CA2000 // Dispose objects before losing scope
        DigestValue x5tHashS256 = CreateDigest(0x01);
        var sigD = new JAdESObjectIdByUriReference([new JAdESReferencedDataObject("https://example.org/1")]);

        var model = new JAdESProtectedHeaders(WellKnownJwaValues.Es256, x5tHashS256: x5tHashS256, sigD: sigD);
#pragma warning restore CA2000 // Dispose objects before losing scope

        model.Dispose();
        model.Dispose();
    }
}
