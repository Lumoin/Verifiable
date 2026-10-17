using Verifiable.JCose;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Jose;

/// <summary>
/// The binding of a JWS header's algorithm to the key its signature is verified under (<see cref="JwsKeyAlgorithmBinding"/>):
/// each algorithm of a key's type is admitted against the key's type, only the one the registry's function for the key's tag
/// computes against that function, and every disagreement is refused under its own name.
/// </summary>
[TestClass]
internal sealed class JwsKeyAlgorithmBindingTests
{
    /// <summary>
    /// A P-256 key verifies ES256 and nothing else: RS256, ES384 and EdDSA over it are algorithms of another key type under
    /// either judgement.
    /// </summary>
    [TestMethod]
    public void AnEllipticCurveKeyIsBoundToItsCurvesAlgorithmAlone()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        Assert.IsNull(JwsKeyAlgorithmBinding.JudgeKeyType(WellKnownJwaValues.Es256, publicKey));
        Assert.IsNull(JwsKeyAlgorithmBinding.JudgeRegistryVerification(WellKnownJwaValues.Es256, publicKey));

        foreach(var algorithm in new[] { WellKnownJwaValues.Rs256, WellKnownJwaValues.Es384, WellKnownJwaValues.EdDsa, WellKnownJwaValues.Hs256, "es256" })
        {
            Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
                JwsKeyAlgorithmBinding.JudgeKeyType(algorithm, publicKey), algorithm);
            Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
                JwsKeyAlgorithmBinding.JudgeRegistryVerification(algorithm, publicKey), algorithm);
        }
    }


    /// <summary>
    /// An RSA key's type carries the RSASSA-PKCS1-v1_5 and RSASSA-PSS algorithms, so a function the caller supplies may verify
    /// any of them; the function the registry resolves from the key's tag verifies RS256 alone, so every other RSA algorithm is
    /// refused against it as one the verification would not perform, and ES256 as an algorithm of another key type.
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
            Assert.IsNull(JwsKeyAlgorithmBinding.JudgeKeyType(algorithm, publicKey), algorithm);
        }

        foreach(var algorithm in new[] { WellKnownJwaValues.Rs384, WellKnownJwaValues.Rs512, WellKnownJwaValues.Ps256, WellKnownJwaValues.Ps384, WellKnownJwaValues.Ps512 })
        {
            Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmNotComputedByTheKeysVerification,
                JwsKeyAlgorithmBinding.JudgeRegistryVerification(algorithm, publicKey), algorithm);
        }

        Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
            JwsKeyAlgorithmBinding.JudgeKeyType(WellKnownJwaValues.Es256, publicKey));
        Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
            JwsKeyAlgorithmBinding.JudgeRegistryVerification(WellKnownJwaValues.Es256, publicKey));
    }


    /// <summary>An Ed25519 key is bound to EdDSA alone under either judgement.</summary>
    [TestMethod]
    public void AnEd25519KeyIsBoundToEdDsaAlone()
    {
        var keyMaterial = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using var publicKey = keyMaterial.PublicKey;
        using var privateKey = keyMaterial.PrivateKey;

        Assert.IsNull(JwsKeyAlgorithmBinding.JudgeKeyType(WellKnownJwaValues.EdDsa, publicKey));
        Assert.IsNull(JwsKeyAlgorithmBinding.JudgeRegistryVerification(WellKnownJwaValues.EdDsa, publicKey));
        Assert.AreEqual<JwsKeyAlgorithmRefusal?>(JwsKeyAlgorithmRefusal.AlgorithmOfAnotherKeyType,
            JwsKeyAlgorithmBinding.JudgeRegistryVerification(WellKnownJwaValues.Es256, publicKey));
    }
}
