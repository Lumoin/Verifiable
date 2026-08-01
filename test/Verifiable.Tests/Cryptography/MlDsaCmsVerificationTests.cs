using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Proves the managed CMS backend verifies ML-DSA signers — the quantum-resistant signature family of NIST
/// FIPS 204 — through the registered ML-DSA verification delegates, agreeing with the independent BouncyCastle
/// backend on the same independently minted structures. The managed verifier owns the CMS format and delegates
/// only the primitive, so a host's own provider carries the post-quantum mathematics exactly as it carries the
/// classical families'.
/// </summary>
[TestClass]
internal sealed class MlDsaCmsVerificationTests
{
    /// <summary>The registration qualifier of the independent BouncyCastle CMS backend.</summary>
    private const string BouncyCastleQualifier = "BouncyCastle";

    /// <summary>The authority certificate validity start, before the canonical test instant.</summary>
    private static DateTimeOffset NotBefore => TestClock.CanonicalEpoch.AddDays(-1);

    /// <summary>The authority certificate validity end, after the canonical test instant.</summary>
    private static DateTimeOffset NotAfter => TestClock.CanonicalEpoch.AddYears(1);


    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// An ML-DSA signer verifies through the managed backend for each of the three parameter sets, and the
    /// managed backend agrees with the independent BouncyCastle backend on the verified content, the signer
    /// certificate, and the signed attributes of the same structure.
    /// </summary>
    /// <param name="parameterSetOid">The ML-DSA parameter set the signer's key is minted under.</param>
    [TestMethod]
    [DataRow(WellKnownOids.MlDsa44)]
    [DataRow(WellKnownOids.MlDsa65)]
    [DataRow(WellKnownOids.MlDsa87)]
    public async Task TheManagedBackendVerifiesAnMlDsaSignerAgreeingWithTheIndependentBackend(string parameterSetOid)
    {
        using MlDsaCmsTestFactory.MlDsaSigningAuthority authority = MlDsaCmsTestFactory.MintSelfSignedAuthority(parameterSetOid, NotBefore, NotAfter);
        using CmsSignedData carrier = MlDsaCmsTestFactory.SignAsCms("the ml-dsa cross-backend content"u8, authority);

        using CmsVerifiedContent fromBouncyCastle = await ResolveBouncyCastle()(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromManaged = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        AssertEquivalent(fromBouncyCastle, fromManaged);
    }


    /// <summary>
    /// The managed backend refuses an ML-DSA signature whose stated algorithm names a different parameter set
    /// than the one the certificate key pins — the substitution shape: a genuine ML-DSA-65 structure whose
    /// <c>SignerInfo</c> signature algorithm octets are patched to ML-DSA-87 names a computation the key does
    /// not perform, and is refused by the parameter-set binding rather than resolved in the claimed set's
    /// favor.
    /// </summary>
    [TestMethod]
    public async Task TheManagedBackendRefusesAnMlDsaParameterSetSubstitution()
    {
        using MlDsaCmsTestFactory.MlDsaSigningAuthority authority = MlDsaCmsTestFactory.MintSelfSignedAuthority(WellKnownOids.MlDsa65, NotBefore, NotAfter);
        using CmsSignedData carrier = MlDsaCmsTestFactory.SignAsCms("the ml-dsa substitution fixture"u8, authority);

        //The ML-DSA-65 and ML-DSA-87 identifier value octets differ only in their last octet. The identifier
        //also occurs inside the embedded certificate; the SignerInfo signature algorithm is the LAST
        //occurrence, because the SignerInfos set closes the SignedData and nothing after the patched field
        //re-states the arc.
        ReadOnlySpan<byte> mlDsa65OidValue = WellKnownOids.MlDsa65DerValue;
        ReadOnlySpan<byte> encoded = carrier.AsReadOnlySpan();
        int lastIndex = encoded.LastIndexOf(mlDsa65OidValue);
        Assert.IsGreaterThan(0, lastIndex, "The parameter-set arc must occur in the structure for the patch to have a target.");

        byte[] patched = encoded.ToArray();
        patched[lastIndex + mlDsa65OidValue.Length - 1] = WellKnownOids.MlDsa87DerValue[^1];
        using CmsSignedData substituted = CmsSignedData.FromBytes(patched, BaseMemoryPool.Shared);

        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(
                    substituted, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "An ML-DSA signature claimed under a different parameter set than the key's must be refused.").ConfigureAwait(false);

        //The refusal is the parameter-set binding's own — the phrase appears only in the binding's message,
        //not in the unmapped-set fallback or any other failure sharing the exception type.
        Assert.Contains("equal to the certificate key's parameter set", refusal.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// The managed backend refuses an ML-DSA public key whose length contradicts its claimed parameter set —
    /// a genuine ML-DSA-44 structure whose every parameter-set identifier octet is patched to ML-DSA-65 passes
    /// the signature-to-key set binding (both now claim the same set) and is stopped by the exact FIPS 204
    /// Table 2 key-length check, before the raw bytes ever reach the registered backend whose own
    /// malformed-encoding failure would surface as an undocumented exception type.
    /// </summary>
    [TestMethod]
    public async Task TheManagedBackendRefusesAnMlDsaKeyWhoseLengthContradictsItsClaimedParameterSet()
    {
        using MlDsaCmsTestFactory.MlDsaSigningAuthority authority = MlDsaCmsTestFactory.MintSelfSignedAuthority(WellKnownOids.MlDsa44, NotBefore, NotAfter);
        using CmsSignedData carrier = MlDsaCmsTestFactory.SignAsCms("the ml-dsa key-length fixture"u8, authority);

        //Every occurrence of the ML-DSA-44 arc — the certificate's SubjectPublicKeyInfo, the certificate's own
        //two signature-algorithm statements, and the SignerInfo signature algorithm — is patched to ML-DSA-65,
        //a same-length flip of the final octet, so the structure consistently claims a parameter set whose key
        //is 1952 octets while carrying a 1312-octet key.
        ReadOnlySpan<byte> mlDsa44OidValue = WellKnownOids.MlDsa44DerValue;
        byte[] patched = carrier.AsReadOnlySpan().ToArray();
        int patchedCount = 0;
        for(int i = 0; i <= patched.Length - mlDsa44OidValue.Length; i++)
        {
            if(patched.AsSpan(i, mlDsa44OidValue.Length).SequenceEqual(mlDsa44OidValue))
            {
                patched[i + mlDsa44OidValue.Length - 1] = WellKnownOids.MlDsa65DerValue[^1];
                patchedCount++;
            }
        }

        Assert.IsGreaterThan(0, patchedCount, "The parameter-set arc must occur in the structure for the patch to have a target.");
        using CmsSignedData contradicting = CmsSignedData.FromBytes(patched, BaseMemoryPool.Shared);

        CryptographicException refusal = await Assert.ThrowsExactlyAsync<CryptographicException>(
            async () =>
            {
                using CmsVerifiedContent _ = await ManagedCmsVerification.VerifyCmsSignedDataAsync(
                    contradicting, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            },
            "A key whose length contradicts its claimed parameter set must be refused before the primitive runs.").ConfigureAwait(false);

        Assert.Contains("exactly 1952 octets", refusal.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Where the platform ships its own ML-DSA — <see cref="MLDsa.IsSupported"/> — the default backend (the
    /// platform CMS stack) verifies the same BouncyCastle-minted structure the managed backend verifies: the
    /// platform's FIPS 204 implementation checking a signature the BouncyCastle implementation produced, the
    /// one primitive-level cross-check available in-tree. Where the platform ships none, the check is
    /// inconclusive rather than silently green; the durable closure is the recorded known-answer-vector
    /// follow-up.
    /// </summary>
    [TestMethod]
    public async Task TheDefaultBackendAgreesOnAnMlDsaSignerWhereThePlatformSupportsIt()
    {
#pragma warning disable SYSLIB5006 //The platform's ML-DSA surface is experimental; probing its availability is the point of this test.
        if(!MLDsa.IsSupported)
        {
            Assert.Inconclusive("The platform ships no ML-DSA implementation; the primitive-level cross-check needs one.");
        }
#pragma warning restore SYSLIB5006

        using MlDsaCmsTestFactory.MlDsaSigningAuthority authority = MlDsaCmsTestFactory.MintSelfSignedAuthority(WellKnownOids.MlDsa65, NotBefore, NotAfter);
        using CmsSignedData carrier = MlDsaCmsTestFactory.SignAsCms("the ml-dsa platform cross-check content"u8, authority);

        using CmsVerifiedContent fromDefault = await ResolveDefault()(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using CmsVerifiedContent fromManaged = await ManagedCmsVerification.VerifyCmsSignedDataAsync(carrier, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        AssertEquivalent(fromDefault, fromManaged);
    }


    /// <summary>
    /// Asserts two verified-content results agree: the same content type, content, signer certificate, and
    /// signed attributes (by object identifier and value).
    /// </summary>
    /// <param name="reference">The independent backend's result.</param>
    /// <param name="other">The managed backend's result.</param>
    private static void AssertEquivalent(CmsVerifiedContent reference, CmsVerifiedContent other)
    {
        Assert.AreEqual(reference.ContentType, other.ContentType, "The managed backend must report the same encapsulated content type.");
        Assert.AreEqual(Convert.ToHexString(reference.Content.Span), Convert.ToHexString(other.Content.Span), "The managed backend must surface the same encapsulated content.");
        Assert.IsTrue(
            reference.SignerCertificate.AsReadOnlyMemory().Span.SequenceEqual(other.SignerCertificate.AsReadOnlyMemory().Span),
            "The managed backend must surface the same signer certificate.");

        Assert.HasCount(reference.SignedAttributes.Count, other.SignedAttributes, "The managed backend must surface the same number of signed attributes.");
        foreach(CmsSignedAttribute attribute in reference.SignedAttributes)
        {
            Assert.IsTrue(other.TryGetSignedAttribute(attribute.AttributeType, out CmsSignedAttribute? match), $"The managed backend must surface the signed attribute {attribute.AttributeType}.");
            Assert.IsTrue(attribute.AsReadOnlySpan().SequenceEqual(match!.AsReadOnlySpan()), $"The signed attribute {attribute.AttributeType} must have the same value under the managed backend.");
        }
    }


    /// <summary>
    /// Resolves the independent BouncyCastle CMS verification backend.
    /// </summary>
    /// <returns>The registered backend.</returns>
    /// <exception cref="InvalidOperationException">Thrown when nothing is registered under the qualifier.</exception>
    private static VerifyCmsSignedDataDelegate ResolveBouncyCastle() =>
        CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate), BouncyCastleQualifier)
            ?? throw new InvalidOperationException("No BouncyCastle VerifyCmsSignedDataDelegate has been registered.");


    /// <summary>
    /// Resolves the default (platform) CMS verification backend.
    /// </summary>
    /// <returns>The registered backend.</returns>
    /// <exception cref="InvalidOperationException">Thrown when nothing is registered as the default.</exception>
    private static VerifyCmsSignedDataDelegate ResolveDefault() =>
        CryptographicKeyFactory.GetFunction<VerifyCmsSignedDataDelegate>(typeof(VerifyCmsSignedDataDelegate), qualifier: null)
            ?? throw new InvalidOperationException("No default VerifyCmsSignedDataDelegate has been registered.");
}
