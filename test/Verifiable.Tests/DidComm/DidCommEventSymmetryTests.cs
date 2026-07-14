using System.Buffers;
using System.Linq;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.DidComm;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.DidComm;

/// <summary>
/// The wave-7 DIDComm symmetry fix (contract §PKG-1 "Fix the DIDComm asymmetry"): before this wave,
/// <c>DidCommFromPriorExtensions.VerifyFromPriorAsync</c> emitted (via its own <c>InternalsVisibleTo</c>
/// access to <c>CryptographicKeyEvents.Emit</c>) while the sibling sign side
/// (<c>PackFromPriorAsync</c>/<c>PackSignedAsync</c>, which route through <c>Verifiable.JCose</c>) discarded
/// — the wave-7 scout's sharpest concrete finding (§2.3 of <c>scout-emit-surface.md</c>). Now that the JOSE
/// layer's explicit-delegate sites default to <see cref="CryptographicKeyEvents.DefaultSink"/> instead of
/// discarding, sign and verify both reach the same global <see cref="CryptographicKeyEvents.Events"/> stream
/// with no further <c>InternalsVisibleTo</c> growth — these tests prove the symmetry end to end.
/// </summary>
[TestClass]
internal sealed class DidCommEventSymmetryTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly ExchangeContext Context = new();


    /// <summary>
    /// <c>PackSignedAsync</c> (sign) and <c>UnpackSignedAsync</c> (verify) both publish to the global
    /// <see cref="CryptographicKeyEvents.Events"/> stream — the symmetry the DIDComm signed-message pair
    /// lacked before wave 7 (sign discarded via the JOSE facade, verify emitted via internal access).
    /// </summary>
    [TestMethod]
    public async Task PackSignedAndUnpackSignedBothEmitToGlobalStreamSymmetrically()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        DidDocument document = await new KeyDidBuilder().BuildAsync(
            publicKey, MultikeyVerificationMethodTypeInfo.Instance, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string did = document.Id!.Id;
        string kid = AuthenticationKid(document, did);

        var resolver = new DidResolver(DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

        var message = new DidCommMessage
        {
            Id = "wave7-symmetry-1",
            Type = "https://example.com/protocols/lets_do_lunch/1.0/proposal",
            From = did
        };

        var observer = new TestObserver<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(observer))
        {
            using DidCommSignedMessage signed = await message.PackSignedAsync(
                privateKey,
                kid,
                DidCommMessageJson.Serializer,
                DidCommSignedMessageJson.ProtectedHeaderEncoder,
                DidCommSignedMessageJson.Serializer,
                TestSetup.Base64UrlEncoder,
                Pool,
                JoseSerializationFormat.GeneralJson,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.Contains(
                (SignatureProducedEvent e) => true,
                observer.Received.OfType<SignatureProducedEvent>(),
                "PackSignedAsync (sign) must publish a SignatureProducedEvent to the global stream by default — no explicit sink is passed.");

            DidCommSignedVerificationResult result = await signed.UnpackSignedAsync(
                resolver,
                Context,
                DidCommMessageJson.Parser,
                DidCommSignedMessageJson.Parser,
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                Pool,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsVerified, $"Round trip MUST verify. Error: {result.Error}.");
            Assert.Contains(
                (VerificationCompletedEvent e) => e.Outcome == VerificationOutcome.Valid,
                observer.Received.OfType<VerificationCompletedEvent>(),
                "UnpackSignedAsync (verify) must publish a VerificationCompletedEvent to the global stream — symmetric with the sign side.");
        }
    }


    /// <summary>
    /// <c>PackFromPriorAsync</c> (sign the from_prior rotation JWT) also reaches the global stream by
    /// default — the specific asymmetry the scout named (§2.3): <c>VerifyFromPriorAsync</c> already emitted
    /// via internal access, while <c>PackFromPriorAsync</c> discarded through the JOSE facade
    /// (<c>JwtSigningExtensions.SignAsync</c>). Verified here indirectly through the signed-message unpack
    /// path carrying a <c>from_prior</c> header, which verifies the rotation as part of the same call.
    /// </summary>
    [TestMethod]
    public async Task PackFromPriorAsyncEmitsToGlobalStream()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> priorKeys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory priorPublicKey = priorKeys.PublicKey;
        using PrivateKeyMemory priorPrivateKey = priorKeys.PrivateKey;

        DidDocument priorDocument = await new KeyDidBuilder().BuildAsync(
            priorPublicKey, MultikeyVerificationMethodTypeInfo.Instance, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string priorDid = priorDocument.Id!.Id;
        string priorKid = AuthenticationKid(priorDocument, priorDid);

        var message = new DidCommMessage
        {
            Id = "wave7-symmetry-rotation",
            Type = "https://example.com/protocols/ping/1.0",
            From = "did:example:new-placeholder"
        };

        var observer = new TestObserver<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(observer))
        {
            await message.PackFromPriorAsync(
                priorDid,
                priorKid,
                priorPrivateKey,
                DateTimeOffset.FromUnixTimeSeconds(1516239022),
                JwtClaimsJson.HeaderSerializer,
                JwtClaimsJson.PayloadSerializer,
                TestSetup.Base64UrlEncoder,
                Pool,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.IsNotNull(message.FromPrior, "PackFromPriorAsync must produce a from_prior JWT.");
        Assert.Contains(
            (SignatureProducedEvent e) => true,
            observer.Received.OfType<SignatureProducedEvent>(),
            "PackFromPriorAsync must publish a SignatureProducedEvent to the global stream by default — matching VerifyFromPriorAsync's existing internal-access emission.");
    }


    /// <summary>The fully-qualified authentication verification-method id of a did:key Ed25519 document.</summary>
    private static string AuthenticationKid(DidDocument document, string did)
    {
        VerificationMethod method = document.GetLocalAuthenticationMethods()[0];

        return method.Id!.StartsWith('#') ? did + method.Id : method.Id!;
    }
}
