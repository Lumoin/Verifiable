using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Jose;

/// <summary>
/// The binding of a JWS header's algorithm to the key its signature is verified under (<see cref="JwsKeyAlgorithmBinding"/>):
/// under a verification the caller supplies, the header must name the one algorithm the verification is bound to, defined over
/// the key's type; under the registry's function for the key's tag, the one algorithm that function computes; and every
/// disagreement is refused under its own name.
/// </summary>
[TestClass]
internal sealed class JwsKeyAlgorithmBindingTests
{
    /// <summary>
    /// A P-256 key verifies ES256 and nothing else: RS256, ES384 and EdDSA over it, and a differently cased ES256, are
    /// algorithms of another key type under either judgement, even under a supplied verification bound to that very algorithm.
    /// </summary>
    [TestMethod]
    public void AnEllipticCurveKeyIsBoundToItsCurvesAlgorithmAlone()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        Assert.IsNull(JwsKeyAlgorithmBinding.JudgeSuppliedVerification(WellKnownJwaValues.Es256, publicKey, VerificationPerforming(WellKnownJwaValues.Es256)));
        Assert.IsNull(JwsKeyAlgorithmBinding.JudgeRegistryVerification(WellKnownJwaValues.Es256, publicKey));

        foreach(var algorithm in new[] { WellKnownJwaValues.Rs256, WellKnownJwaValues.Es384, WellKnownJwaValues.EdDsa, WellKnownJwaValues.Hs256, "es256" })
        {
            Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
                JwsKeyAlgorithmBinding.JudgeSuppliedVerification(algorithm, publicKey, VerificationPerforming(algorithm)), algorithm);
            Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
                JwsKeyAlgorithmBinding.JudgeRegistryVerification(algorithm, publicKey), algorithm);
        }
    }


    /// <summary>
    /// An RSA key's type carries the RSASSA-PKCS1-v1_5 and RSASSA-PSS algorithms, so a verification the caller supplies may be
    /// bound to any of them; the function the registry resolves from the key's tag verifies RS256 alone, so every other RSA
    /// algorithm is refused against it as one the verification would not perform, and ES256 as an algorithm of another key type.
    /// </summary>
    [TestMethod]
    public void AnRsaKeyIsBoundToRs256UnderTheRegistrysVerification()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        Assert.IsNull(JwsKeyAlgorithmBinding.JudgeRegistryVerification(WellKnownJwaValues.Rs256, publicKey));

        foreach(var algorithm in new[] { WellKnownJwaValues.Rs256, WellKnownJwaValues.Rs384, WellKnownJwaValues.Rs512, WellKnownJwaValues.Ps256, WellKnownJwaValues.Ps384, WellKnownJwaValues.Ps512 })
        {
            Assert.IsNull(JwsKeyAlgorithmBinding.JudgeSuppliedVerification(algorithm, publicKey, VerificationPerforming(algorithm)), algorithm);
        }

        foreach(var algorithm in new[] { WellKnownJwaValues.Rs384, WellKnownJwaValues.Rs512, WellKnownJwaValues.Ps256, WellKnownJwaValues.Ps384, WellKnownJwaValues.Ps512 })
        {
            Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmNotComputedByTheKeysVerification,
                JwsKeyAlgorithmBinding.JudgeRegistryVerification(algorithm, publicKey), algorithm);
        }

        Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
            JwsKeyAlgorithmBinding.JudgeSuppliedVerification(WellKnownJwaValues.Es256, publicKey, VerificationPerforming(WellKnownJwaValues.Es256)));
        Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
            JwsKeyAlgorithmBinding.JudgeRegistryVerification(WellKnownJwaValues.Es256, publicKey));
    }


    /// <summary>
    /// A supplied verification bound to RS256 admits a header naming RS256 over an RSA key and refuses one naming PS256, RS384,
    /// a differently cased RS256 or any other algorithm over the same key, each an algorithm of the key's type the verification
    /// never performs (RFC 8725 Section 3.1); a verification bound to PS256 refuses the RS256 header in turn.
    /// </summary>
    [TestMethod]
    public void ASuppliedVerificationIsBoundToTheAlgorithmItPerforms()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshRsa2048KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;
        var rs256Verification = VerificationPerforming(WellKnownJwaValues.Rs256);

        Assert.IsNull(JwsKeyAlgorithmBinding.JudgeSuppliedVerification(WellKnownJwaValues.Rs256, publicKey, rs256Verification));

        foreach(var algorithm in new[] { WellKnownJwaValues.Ps256, WellKnownJwaValues.Rs384, WellKnownJwaValues.Ps512, "rs256", WellKnownJwaValues.Es256 })
        {
            Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmNotPerformedByTheSuppliedVerification,
                JwsKeyAlgorithmBinding.JudgeSuppliedVerification(algorithm, publicKey, rs256Verification), algorithm);
        }

        Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmNotPerformedByTheSuppliedVerification,
            JwsKeyAlgorithmBinding.JudgeSuppliedVerification(WellKnownJwaValues.Rs256, publicKey, VerificationPerforming(WellKnownJwaValues.Ps256)));
    }


    /// <summary>An Ed25519 key is bound to EdDSA alone under either judgement.</summary>
    [TestMethod]
    public void AnEd25519KeyIsBoundToEdDsaAlone()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        Assert.IsNull(JwsKeyAlgorithmBinding.JudgeSuppliedVerification(WellKnownJwaValues.EdDsa, publicKey, VerificationPerforming(WellKnownJwaValues.EdDsa)));
        Assert.IsNull(JwsKeyAlgorithmBinding.JudgeRegistryVerification(WellKnownJwaValues.EdDsa, publicKey));
        Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
            JwsKeyAlgorithmBinding.JudgeRegistryVerification(WellKnownJwaValues.Es256, publicKey));
    }


    /// <summary>
    /// A key of a type the library names by no JWA algorithm, an ML-KEM encryption key, resolves as naming none
    /// (<see cref="JwaAlgorithmResolution.NoneNamed"/>), and every algorithm over it is one of another key type under either
    /// judgement, answered without raising; a P-256 key's tag resolves as naming ES256.
    /// </summary>
    [TestMethod]
    public void AKeyTypeNamedByNoAlgorithmResolvesAsNamingNone()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshMlKem512KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        Assert.AreEqual(JwaAlgorithmResolution.NoneNamed, CryptoFormatConversions.ResolveJwaAlgorithm(publicKey.Tag));
        Assert.AreEqual(JwaAlgorithmResolution.Named(WellKnownJwaValues.Es256), CryptoFormatConversions.ResolveJwaAlgorithm(CryptoTags.P256PublicKey));

        Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
            JwsKeyAlgorithmBinding.JudgeRegistryVerification(WellKnownJwaValues.Es256, publicKey));
        Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
            JwsKeyAlgorithmBinding.JudgeSuppliedVerification(WellKnownJwaValues.Es256, publicKey, VerificationPerforming(WellKnownJwaValues.Es256)));
    }


    /// <summary>
    /// A verification bound to <paramref name="algorithm"/> whose function verifies nothing: the binding is judged before any
    /// function runs, so only the algorithm it carries is read here.
    /// </summary>
    /// <param name="algorithm">The algorithm the verification is bound to.</param>
    /// <returns>The verification.</returns>
    private static JwsAlgorithmVerification VerificationPerforming(string algorithm) =>
        new(algorithm, static (data, signature, key, context, cancellationToken) => ValueTask.FromResult<(bool, CryptoEvent?)>((false, null)));
}
