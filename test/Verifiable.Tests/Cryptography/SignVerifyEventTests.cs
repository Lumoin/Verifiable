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
/// Coverage for the <see cref="SignatureProducedEvent"/>/<see cref="VerificationCompletedEvent"/> wiring
/// through the <see cref="PrivateKey.SignAsync"/>/<see cref="PublicKey.VerifyAsync"/> choke points: the
/// widened <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/> tuple is unwrapped and the
/// carried event is emitted onto the live <see cref="CryptographicKeyEvents.Events"/> subject. Every
/// scenario constructs its <see cref="PrivateKey"/>/<see cref="PublicKey"/> with an explicit backend
/// delegate rather than the process-wide registry, so the test names exactly which backend is under
/// test regardless of what <c>TestSetup</c> registers as the default for an algorithm.
/// </summary>
[TestClass]
internal sealed class SignVerifyEventTests
{
    private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("SignVerifyEventTests payload.");


    /// <summary>
    /// <see cref="PrivateKey.SignAsync"/> over a Microsoft-backed P-256 key emits a
    /// <see cref="SignatureProducedEvent"/> naming the Microsoft backend, the P-256 algorithm, and the
    /// correct data/signature lengths.
    /// </summary>
    [TestMethod]
    public async Task MicrosoftSignAsyncEmitsSignatureProducedEvent()
    {
        var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory publicKeyMemory = keys.PublicKey;
        using PrivateKeyMemory privateKeyMemory = keys.PrivateKey;

        using PrivateKey privateKey = new(privateKeyMemory, "ms-p256-sign", MicrosoftCryptographicFunctions.SignP256Async);

        var observed = new ConcurrentQueue<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            using Signature signature = await privateKey.SignAsync(TestData, BaseMemoryPool.Shared).ConfigureAwait(false);
            int signatureLength = signature.AsReadOnlySpan().Length;

            //Matches every asserted property in one predicate rather than pulling a single element out of the
            //process-wide static subject and asserting on its properties separately: the subject is shared with
            //every other test running in parallel (MSTest parallelizes at class scope), so a second event of the
            //same CLR type — from an unrelated concurrent test — is expected and must not fail this assertion.
            Assert.Contains(
                (SignatureProducedEvent e) =>
                    e.Algorithm == CryptoAlgorithm.P256
                    && e.Backend == "System.Security.Cryptography"
                    && e.DataLength == TestData.Length
                    && e.SignatureLength == signatureLength,
                observed.OfType<SignatureProducedEvent>(),
                "A SignatureProducedEvent naming the Microsoft backend, P256, and the correct lengths must be observed.");
        }
    }


    /// <summary>
    /// <see cref="PublicKey.VerifyAsync"/> over a Microsoft-backed P-256 key emits a
    /// <see cref="VerificationCompletedEvent"/> with <see cref="VerificationOutcome.Valid"/> for a genuine
    /// signature.
    /// </summary>
    [TestMethod]
    public async Task MicrosoftVerifyAsyncEmitsVerificationCompletedEventWithValidOutcome()
    {
        var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory publicKeyMemory = keys.PublicKey;
        using PrivateKeyMemory privateKeyMemory = keys.PrivateKey;

        using PrivateKey privateKey = new(privateKeyMemory, "ms-p256-sign", MicrosoftCryptographicFunctions.SignP256Async);
        using PublicKey publicKey = new(publicKeyMemory, "ms-p256-verify", MicrosoftCryptographicFunctions.VerifyP256Async);

        using Signature signature = await privateKey.SignAsync(TestData, BaseMemoryPool.Shared).ConfigureAwait(false);

        var observed = new ConcurrentQueue<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            bool isVerified = await publicKey.VerifyAsync(TestData, signature).ConfigureAwait(false);
            Assert.IsTrue(isVerified);

            //See the sign-side test above for why this asserts via a single combined predicate rather than
            //pulling one element from the shared, process-wide static subject.
            Assert.Contains(
                (VerificationCompletedEvent e) =>
                    e.Algorithm == CryptoAlgorithm.P256
                    && e.Backend == "System.Security.Cryptography"
                    && e.Outcome == VerificationOutcome.Valid
                    && e.DataLength == TestData.Length,
                observed.OfType<VerificationCompletedEvent>(),
                "A VerificationCompletedEvent naming the Microsoft backend, P256, Valid, and the correct length must be observed.");
        }
    }


    /// <summary>
    /// <see cref="PrivateKey.SignAsync"/> over a BouncyCastle-backed Ed25519 key emits a
    /// <see cref="SignatureProducedEvent"/> naming the BouncyCastle backend and the Ed25519 algorithm.
    /// </summary>
    [TestMethod]
    public async Task BouncyCastleSignAsyncEmitsSignatureProducedEvent()
    {
        var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory publicKeyMemory = keys.PublicKey;
        using PrivateKeyMemory privateKeyMemory = keys.PrivateKey;

        using PrivateKey privateKey = new(privateKeyMemory, "bc-ed25519-sign", BouncyCastleCryptographicFunctions.SignEd25519Async);

        var observed = new ConcurrentQueue<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            using Signature signature = await privateKey.SignAsync(TestData, BaseMemoryPool.Shared).ConfigureAwait(false);
            int signatureLength = signature.AsReadOnlySpan().Length;

            Assert.Contains(
                (SignatureProducedEvent e) =>
                    e.Algorithm == CryptoAlgorithm.Ed25519
                    && e.Backend == "Org.BouncyCastle.Cryptography"
                    && e.DataLength == TestData.Length
                    && e.SignatureLength == signatureLength,
                observed.OfType<SignatureProducedEvent>(),
                "A SignatureProducedEvent naming the BouncyCastle backend, Ed25519, and the correct lengths must be observed.");
        }
    }


    /// <summary>
    /// <see cref="PublicKey.VerifyAsync"/> over a BouncyCastle-backed Ed25519 key emits a
    /// <see cref="VerificationCompletedEvent"/> with <see cref="VerificationOutcome.Valid"/> for a genuine
    /// signature.
    /// </summary>
    [TestMethod]
    public async Task BouncyCastleVerifyAsyncEmitsVerificationCompletedEventWithValidOutcome()
    {
        var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory publicKeyMemory = keys.PublicKey;
        using PrivateKeyMemory privateKeyMemory = keys.PrivateKey;

        using PrivateKey privateKey = new(privateKeyMemory, "bc-ed25519-sign", BouncyCastleCryptographicFunctions.SignEd25519Async);
        using PublicKey publicKey = new(publicKeyMemory, "bc-ed25519-verify", BouncyCastleCryptographicFunctions.VerifyEd25519Async);

        using Signature signature = await privateKey.SignAsync(TestData, BaseMemoryPool.Shared).ConfigureAwait(false);

        var observed = new ConcurrentQueue<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            bool isVerified = await publicKey.VerifyAsync(TestData, signature).ConfigureAwait(false);
            Assert.IsTrue(isVerified);

            Assert.Contains(
                (VerificationCompletedEvent e) =>
                    e.Algorithm == CryptoAlgorithm.Ed25519
                    && e.Backend == "Org.BouncyCastle.Cryptography"
                    && e.Outcome == VerificationOutcome.Valid,
                observed.OfType<VerificationCompletedEvent>(),
                "A VerificationCompletedEvent naming the BouncyCastle backend, Ed25519, and Valid must be observed.");
        }
    }


    /// <summary>
    /// A verification over a tampered payload emits a <see cref="VerificationCompletedEvent"/> with
    /// <see cref="VerificationOutcome.Invalid"/> — the security-relevant negative outcome the event
    /// stream must surface, not merely a <see langword="false"/> return value.
    /// </summary>
    [TestMethod]
    public async Task TamperedPayloadVerificationEmitsInvalidOutcome()
    {
        var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory publicKeyMemory = keys.PublicKey;
        using PrivateKeyMemory privateKeyMemory = keys.PrivateKey;

        using PrivateKey privateKey = new(privateKeyMemory, "ms-p256-sign", MicrosoftCryptographicFunctions.SignP256Async);
        using PublicKey publicKey = new(publicKeyMemory, "ms-p256-verify", MicrosoftCryptographicFunctions.VerifyP256Async);

        using Signature signature = await privateKey.SignAsync(TestData, BaseMemoryPool.Shared).ConfigureAwait(false);

        byte[] tampered = (byte[])TestData.Clone();
        tampered[0] ^= 0x01;

        var observed = new ConcurrentQueue<CryptoEvent>();
        using(CryptographicKeyEvents.Events.Subscribe(new CollectingObserver(observed)))
        {
            bool isVerified = await publicKey.VerifyAsync(tampered, signature).ConfigureAwait(false);
            Assert.IsFalse(isVerified);

            Assert.Contains(
                (VerificationCompletedEvent e) =>
                    e.Algorithm == CryptoAlgorithm.P256
                    && e.Backend == "System.Security.Cryptography"
                    && e.Outcome == VerificationOutcome.Invalid
                    && e.DataLength == tampered.Length,
                observed.OfType<VerificationCompletedEvent>(),
                "A VerificationCompletedEvent with Invalid outcome must be observed for the tampered payload.");
        }
    }


    /// <summary>
    /// A minimal <see cref="IObserver{T}"/> that appends every observed event to a caller-owned
    /// <see cref="ConcurrentQueue{T}"/>, mirroring the <c>TpmEntropyProviderTests</c> precedent for
    /// observing the process-wide <see cref="CryptographicKeyEvents.Events"/> subject without a
    /// System.Reactive dependency. A <see cref="ConcurrentQueue{T}"/> rather than a plain
    /// <see cref="List{T}"/>: the subject is shared with every concurrently running test and its dispatch
    /// makes no promise about which thread delivers, so a plain list here risks "Collection was modified"
    /// when this observer's own <c>OnNext</c> is invoked concurrently from two unrelated tests' emissions.
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
