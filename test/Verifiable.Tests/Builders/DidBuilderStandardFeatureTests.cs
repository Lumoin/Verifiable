using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Builders;

/// <summary>
/// Cross-method tests that the SHARED standard DID-document construction
/// (<see cref="DidDocumentVerificationExtensions.WithStandardVerificationRelationships"/> +
/// <see cref="DidBuilderExtensions.CreateVerificationMethod"/>) produces an identical standard shape regardless
/// of method: every verification method's controller is the DID, a signing key is registered under all four
/// signing relationships, and a key-exchange (key-agreement) key is registered under <c>keyAgreement</c>. Each
/// per-method builder plugs in only its method-specific id format; these assertions are the proof that the
/// standard features stay uniform across method builders.
/// </summary>
[TestClass]
internal sealed class DidBuilderStandardFeatureTests
{
    /// <summary>The test context.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>did:key: a signing + key-exchange key set yields the standard relationships and controllers.</summary>
    [TestMethod]
    public async Task KeyDidBuilderProducesStandardFeatures()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signing = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchange = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using PublicKeyMemory signingPublic = signing.PublicKey;
        using PrivateKeyMemory signingPrivate = signing.PrivateKey;
        using PublicKeyMemory exchangePublic = exchange.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchange.PrivateKey;

        DidDocument document = await new KeyDidBuilder().BuildAsync(
            StandardKeyInputs(signingPublic, exchangePublic),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        AssertStandardFeatures(document);
    }


    /// <summary>did:web: the same key set yields the same standard relationships and controllers.</summary>
    [TestMethod]
    public async Task WebDidBuilderProducesStandardFeatures()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signing = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchange = TestKeyMaterialProvider.CreateX25519KeyMaterial();
        using PublicKeyMemory signingPublic = signing.PublicKey;
        using PrivateKeyMemory signingPrivate = signing.PrivateKey;
        using PublicKeyMemory exchangePublic = exchange.PublicKey;
        using PrivateKeyMemory exchangePrivate = exchange.PrivateKey;

        DidDocument document = await new WebDidBuilder().BuildAsync(
            StandardKeyInputs(signingPublic, exchangePublic),
            "example.com",
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        AssertStandardFeatures(document);
    }


    /// <summary>A signing Ed25519 verification method followed by a key-agreement X25519 verification method.</summary>
    /// <param name="signingKey">The Ed25519 signing public key (also derives the DID identifier).</param>
    /// <param name="exchangeKey">The X25519 key-agreement public key.</param>
    /// <returns>The ordered key-material inputs.</returns>
    private static IEnumerable<KeyMaterialInput> StandardKeyInputs(PublicKeyMemory signingKey, PublicKeyMemory exchangeKey)
    {
        return
        [
            new KeyMaterialInput { PublicKey = signingKey, VerificationMethodType = JsonWebKey2020VerificationMethodTypeInfo.Instance },
            new KeyMaterialInput { PublicKey = exchangeKey, VerificationMethodType = X25519KeyAgreementKey2020VerificationMethodTypeInfo.Instance }
        ];
    }


    /// <summary>
    /// Asserts the standard shape the shared construction guarantees: two verification methods both controlled by
    /// the DID, the signing key in all four signing relationships, and the exchange key in <c>keyAgreement</c>.
    /// </summary>
    /// <param name="document">The built DID document.</param>
    private static void AssertStandardFeatures(DidDocument document)
    {
        string did = document.Id!.ToString()!;

        Assert.IsNotNull(document.VerificationMethod);
        Assert.HasCount(2, document.VerificationMethod!);
        foreach(VerificationMethod verificationMethod in document.VerificationMethod!)
        {
            Assert.AreEqual(did, verificationMethod.Controller, "Every verification method's controller MUST be the DID.");
        }

        //The signing key (first) is registered under all four signing relationships, one entry each.
        Assert.HasCount(1, document.Authentication!);
        Assert.HasCount(1, document.AssertionMethod!);
        Assert.HasCount(1, document.CapabilityInvocation!);
        Assert.HasCount(1, document.CapabilityDelegation!);

        //The key-exchange key (second) is registered under keyAgreement, and only there.
        Assert.HasCount(1, document.KeyAgreement!);
    }
}
