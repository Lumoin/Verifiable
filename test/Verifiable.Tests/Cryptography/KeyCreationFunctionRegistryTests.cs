using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Coverage for the wave-7 keygen choke point: <see cref="KeyCreationFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>
/// resolution and <see cref="CryptographicKeyEvents.CreateKeyPair"/>'s <see cref="KeyMaterialGeneratedEvent"/>
/// emission, across both software backends this project's <c>TestSetup</c> registers and both purposes the
/// registry discriminates on. Also proves the double-emission risk the wave-7 contract's design item 3
/// explicitly rejects: <see cref="CryptographicKeyFactory.CreatePrivateKey(PrivateKeyMemory, string, CryptoAlgorithm, Purpose, string?, System.Collections.Frozen.FrozenDictionary{string, object}?)"/>/
/// <see cref="CryptographicKeyFactory.CreatePublicKey(PublicKeyMemory, string, CryptoAlgorithm, Purpose, string?, System.Collections.Frozen.FrozenDictionary{string, object}?)"/>
/// binding freshly-minted material must never also emit <see cref="KeyMaterialGeneratedEvent"/>.
/// </summary>
[TestClass]
internal sealed class KeyCreationFunctionRegistryTests
{
    /// <summary>The payload signed by <see cref="MintBindSignEmitsExactlyOneKeyMaterialGeneratedEvent"/>.</summary>
    private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("KeyCreationFunctionRegistryTests payload.");


    /// <summary>
    /// <see cref="CryptographicKeyEvents.CreateKeyPair"/> for a Microsoft-backed P-256 signing key emits a
    /// <see cref="KeyMaterialGeneratedEvent"/> naming the Microsoft backend and <see cref="MaterialSemantics.Direct"/> —
    /// the CLI-consumable combination <c>CryptoProviderStartup</c> registers.
    /// </summary>
    [TestMethod]
    public void MicrosoftP256SigningEmitsKeyMaterialGeneratedEvent()
    {
        var observed = new ConcurrentQueue<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            var keys = CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Signing, BaseMemoryPool.Shared);
            using PublicKeyMemory publicKey = keys.PublicKey;
            using PrivateKeyMemory privateKey = keys.PrivateKey;

            Assert.Contains(
                (KeyMaterialGeneratedEvent e) =>
                    e.Algorithm == CryptoAlgorithm.P256
                    && e.Purpose == Purpose.Signing
                    && e.Backend == "System.Security.Cryptography"
                    && e.MaterialSemantics == MaterialSemantics.Direct,
                observed.OfType<KeyMaterialGeneratedEvent>(),
                "A KeyMaterialGeneratedEvent naming the Microsoft backend, P256, Signing, and Direct semantics must be observed.");
        }
    }


    /// <summary>
    /// <see cref="CryptographicKeyEvents.CreateKeyPair"/> for a BouncyCastle-backed Ed25519 signing key emits a
    /// <see cref="KeyMaterialGeneratedEvent"/> naming the BouncyCastle backend.
    /// </summary>
    [TestMethod]
    public void BouncyCastleEd25519SigningEmitsKeyMaterialGeneratedEvent()
    {
        var observed = new ConcurrentQueue<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            var keys = CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.Ed25519, Purpose.Signing, BaseMemoryPool.Shared);
            using PublicKeyMemory publicKey = keys.PublicKey;
            using PrivateKeyMemory privateKey = keys.PrivateKey;

            Assert.Contains(
                (KeyMaterialGeneratedEvent e) =>
                    e.Algorithm == CryptoAlgorithm.Ed25519
                    && e.Purpose == Purpose.Signing
                    && e.Backend == "Org.BouncyCastle.Cryptography"
                    && e.MaterialSemantics == MaterialSemantics.Direct,
                observed.OfType<KeyMaterialGeneratedEvent>(),
                "A KeyMaterialGeneratedEvent naming the BouncyCastle backend, Ed25519, Signing, and Direct semantics must be observed.");
        }
    }


    /// <summary>
    /// The registry discriminates on <em>both</em> axes of its <c>(CryptoAlgorithm, Purpose)</c> key: P-256
    /// <see cref="Purpose.Exchange"/> resolves to the BouncyCastle adapter even though P-256
    /// <see cref="Purpose.Signing"/> (above) resolves to Microsoft — proving purpose, not merely algorithm,
    /// selects the backend, exactly as <c>TestSetup</c>'s own doc comment states.
    /// </summary>
    [TestMethod]
    public void BouncyCastleP256ExchangeEmitsKeyMaterialGeneratedEventDistinctFromSigning()
    {
        var observed = new ConcurrentQueue<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            var keys = CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Exchange, BaseMemoryPool.Shared);
            using PublicKeyMemory publicKey = keys.PublicKey;
            using PrivateKeyMemory privateKey = keys.PrivateKey;

            Assert.Contains(
                (KeyMaterialGeneratedEvent e) =>
                    e.Algorithm == CryptoAlgorithm.P256
                    && e.Purpose == Purpose.Exchange
                    && e.Backend == "Org.BouncyCastle.Cryptography",
                observed.OfType<KeyMaterialGeneratedEvent>(),
                "A KeyMaterialGeneratedEvent naming the BouncyCastle backend and Exchange purpose must be observed for the P-256 exchange registration.");
        }
    }


    /// <summary>
    /// The registry's fallback branch throws for a deliberately-excluded combination.
    /// <c>TestSetup.InitializeKeyCreationFunctions</c>'s own doc comment states ML-KEM is excluded because
    /// <c>InitializeKeyAgreementFunctions</c> wires <c>kemDecapsulationMatcher: null</c> — no consumer can bind
    /// a minted ML-KEM key, so registering its keygen would produce an event for a key nothing downstream uses.
    /// This is a regression guard for that documented exclusion staying in force.
    /// </summary>
    [TestMethod]
    public void ResolveCreationThrowsForTheDocumentedMlKemExclusion()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            KeyCreationFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveCreation(CryptoAlgorithm.MlKem768, Purpose.Exchange));
    }


    /// <summary>
    /// Mint (<see cref="CryptographicKeyEvents.CreateKeyPair"/>), bind
    /// (<see cref="CryptographicKeyFactory.CreatePrivateKey(PrivateKeyMemory, string, CryptoAlgorithm, Purpose, string?, System.Collections.Frozen.FrozenDictionary{string, object}?)"/>/
    /// <see cref="CryptographicKeyFactory.CreatePublicKey(PublicKeyMemory, string, CryptoAlgorithm, Purpose, string?, System.Collections.Frozen.FrozenDictionary{string, object}?)"/>),
    /// then sign+verify must emit exactly ONE <see cref="KeyMaterialGeneratedEvent"/> for this key — never a
    /// second one from the bind step, which is the double-emission risk the wave-7 contract's design item 3
    /// explicitly rejects (binding methods bind both freshly-minted and loaded/stored material
    /// indistinguishably, so a bind-time emission would also mislabel every loaded key as newly generated).
    /// Uses a Brainpool curve no other test in this file mints, so the count assertion against the
    /// process-wide <see cref="CryptographicKeyEvents.Events"/> stream stays deterministic under MSTest's
    /// class-level parallelism.
    /// </summary>
    [TestMethod]
    public async Task MintBindSignEmitsExactlyOneKeyMaterialGeneratedEvent()
    {
        var observed = new ConcurrentQueue<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            var keys = CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.BrainpoolP224r1, Purpose.Signing, BaseMemoryPool.Shared);
            using PublicKeyMemory publicKeyMemory = keys.PublicKey;
            using PrivateKey privateKey = CryptographicKeyFactory.CreatePrivateKey(
                keys.PrivateKey, "wave7-double-emission-key", CryptoAlgorithm.BrainpoolP224r1, Purpose.Signing);
            using PublicKey publicKey = CryptographicKeyFactory.CreatePublicKey(
                publicKeyMemory, "wave7-double-emission-key", CryptoAlgorithm.BrainpoolP224r1, Purpose.Verification);

            using Signature signature = await privateKey.SignAsync(TestData, BaseMemoryPool.Shared).ConfigureAwait(false);
            bool isVerified = await publicKey.VerifyAsync(TestData, signature).ConfigureAwait(false);
            Assert.IsTrue(isVerified, "The mint -> bind -> sign -> verify chain must round-trip correctly.");

            int keyMaterialGeneratedCount = observed
                .OfType<KeyMaterialGeneratedEvent>()
                .Count(e => e.Algorithm == CryptoAlgorithm.BrainpoolP224r1 && e.Purpose == Purpose.Signing);
            Assert.AreEqual(1, keyMaterialGeneratedCount,
                "Mint -> bind -> sign must emit exactly one KeyMaterialGeneratedEvent: binding must never also emit one.");
        }
    }


    /// <summary>
    /// <see cref="MicrosoftKeyMaterialCreator.CreateKeysWithEvent"/> wraps <see cref="MicrosoftKeyMaterialCreator.CreateP384Keys"/>
    /// without changing that method's own signature, and packages a correctly-shaped
    /// <see cref="KeyMaterialGeneratedEvent"/> alongside the returned key pair. Tested directly, independent of
    /// the registry and the global event stream, since this adapter is a pure function.
    /// </summary>
    [TestMethod]
    public void MicrosoftAdapterPackagesKeysAndEventTogether()
    {
        (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys, CryptoEvent? evt) = MicrosoftKeyMaterialCreator.CreateKeysWithEvent(
            MicrosoftKeyMaterialCreator.CreateP384Keys, CryptoAlgorithm.P384, Purpose.Signing, BaseMemoryPool.Shared);

        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        var generated = evt as KeyMaterialGeneratedEvent;
        Assert.IsNotNull(generated, "The adapter must produce a KeyMaterialGeneratedEvent, not a null or differently-typed event.");
        Assert.AreEqual(CryptoAlgorithm.P384, generated.Algorithm);
        Assert.AreEqual(Purpose.Signing, generated.Purpose);
        Assert.AreEqual(MaterialSemantics.Direct, generated.MaterialSemantics);
        Assert.AreEqual("System.Security.Cryptography", generated.Backend);
    }


    /// <summary>
    /// <see cref="BouncyCastleKeyMaterialCreator.CreateKeysWithEvent"/> wraps
    /// <see cref="BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys"/> the same way, proving the adapter shape is
    /// shared identically across both software backends.
    /// </summary>
    [TestMethod]
    public void BouncyCastleAdapterPackagesKeysAndEventTogether()
    {
        (PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys, CryptoEvent? evt) = BouncyCastleKeyMaterialCreator.CreateKeysWithEvent(
            BouncyCastleKeyMaterialCreator.CreateMlDsa65Keys, CryptoAlgorithm.MlDsa65, Purpose.Signing, BaseMemoryPool.Shared);

        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        var generated = evt as KeyMaterialGeneratedEvent;
        Assert.IsNotNull(generated, "The adapter must produce a KeyMaterialGeneratedEvent, not a null or differently-typed event.");
        Assert.AreEqual(CryptoAlgorithm.MlDsa65, generated.Algorithm);
        Assert.AreEqual(Purpose.Signing, generated.Purpose);
        Assert.AreEqual(MaterialSemantics.Direct, generated.MaterialSemantics);
        Assert.AreEqual("Org.BouncyCastle.Cryptography", generated.Backend);
    }


    /// <summary>
    /// A minimal <see cref="IObserver{T}"/> that appends every observed event to a caller-owned queue,
    /// mirroring the <c>SignVerifyEventTests</c> precedent for observing the process-wide
    /// <see cref="CryptographicKeyEvents.Events"/> subject without a System.Reactive dependency. Uses a
    /// concurrent queue rather than a plain list: <see cref="CryptographicKeyEvents.Events"/> is a single
    /// process-wide stream, so while this observer is subscribed it also receives events emitted by whatever
    /// other test happens to be running concurrently in another MSTest class-parallel worker — a plain list
    /// being written from more than one thread at once throws "Collection was modified" out of a concurrent
    /// enumeration, exactly the race <c>CryptoEventSinkTests</c>'s own doc comment names (reproduced live
    /// this wave against <c>SignVerifyEventTests</c>'/<c>Fido2ObservedWorkloadEventTests</c>' own observers,
    /// both since fixed to the same <see cref="ConcurrentQueue{T}"/> shape this file uses from the start).
    /// </summary>
    private sealed class CollectingObserver(ConcurrentQueue<CryptoEvent> sink): IObserver<CryptoEvent>
    {
        /// <summary>No-op: this test observer never unsubscribes via completion.</summary>
        public void OnCompleted()
        {
        }


        /// <summary>No-op: the live subject never calls <see cref="IObserver{T}.OnError"/>.</summary>
        public void OnError(Exception error)
        {
        }


        /// <summary>Appends the observed event to the sink queue.</summary>
        public void OnNext(CryptoEvent value) => sink.Enqueue(value);
    }
}
