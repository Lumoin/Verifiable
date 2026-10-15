using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Libsodium;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Every signing provider observes the cancellation its caller gives: a signing asked for under an already-cancelled
    /// token is refused as cancelled before the key is imported, and no signature octets are rented from the caller's pool; the
    /// recoverable verification its contract says observes the cancellation is refused as cancelled before it parses the key.
    /// </summary>
    [TestClass]
    internal sealed class SigningCancellationTests
    {
        /// <summary>The payload every refused signing is asked over.</summary>
        private static byte[] Payload { get; } = Encoding.UTF8.GetBytes("A payload no cancelled signing may sign.");

        /// <summary>The eight-octet terminal challenge an ISO/IEC 9796-2 signing carries as its non-recovered part.</summary>
        private static byte[] Challenge { get; } = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];


        /// <summary>The Microsoft provider's ECDSA P-256 signing signs nothing under a cancelled token.</summary>
        [TestMethod]
        public async Task MicrosoftEcdsaSigningUnderCancelledTokenSignsNothing()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertCancelledSigningSignsNothingAsync(MicrosoftCryptographicFunctionsAdapter.SignP256Async, privateKey, Payload).ConfigureAwait(false);
        }


        /// <summary>The Microsoft provider's RSA PKCS#1 v1.5 signing signs nothing under a cancelled token.</summary>
        [TestMethod]
        public async Task MicrosoftRsaPkcs1SigningUnderCancelledTokenSignsNothing()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertCancelledSigningSignsNothingAsync(MicrosoftCryptographicFunctionsAdapter.SignRsa2048Async, privateKey, Payload).ConfigureAwait(false);
        }


        /// <summary>The Microsoft provider's RSA-PSS signing signs nothing under a cancelled token.</summary>
        [TestMethod]
        public async Task MicrosoftRsaPssSigningUnderCancelledTokenSignsNothing()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertCancelledSigningSignsNothingAsync(MicrosoftCryptographicFunctionsAdapter.SignRsaSha256PssAsync, privateKey, Payload).ConfigureAwait(false);
        }


        /// <summary>The BouncyCastle provider's Ed25519 signing signs nothing under a cancelled token.</summary>
        [TestMethod]
        public async Task BouncyCastleEd25519SigningUnderCancelledTokenSignsNothing()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertCancelledSigningSignsNothingAsync(BouncyCastleCryptographicFunctionsAdapter.SignEd25519Async, privateKey, Payload).ConfigureAwait(false);
        }


        /// <summary>The BouncyCastle provider's ECDSA P-256 signing signs nothing under a cancelled token.</summary>
        [TestMethod]
        public async Task BouncyCastleEcdsaSigningUnderCancelledTokenSignsNothing()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertCancelledSigningSignsNothingAsync(BouncyCastleCryptographicFunctionsAdapter.SignP256Async, privateKey, Payload).ConfigureAwait(false);
        }


        /// <summary>The BouncyCastle provider's RSA PKCS#1 v1.5 signing signs nothing under a cancelled token.</summary>
        [TestMethod]
        public async Task BouncyCastleRsaPkcs1SigningUnderCancelledTokenSignsNothing()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertCancelledSigningSignsNothingAsync(BouncyCastleCryptographicFunctionsAdapter.SignRsa2048Async, privateKey, Payload).ConfigureAwait(false);
        }


        /// <summary>The BouncyCastle provider's RSA-PSS signing signs nothing under a cancelled token.</summary>
        [TestMethod]
        public async Task BouncyCastleRsaPssSigningUnderCancelledTokenSignsNothing()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertCancelledSigningSignsNothingAsync(BouncyCastleCryptographicFunctionsAdapter.SignRsaSha256PssAsync, privateKey, Payload).ConfigureAwait(false);
        }


        /// <summary>The BouncyCastle provider's ML-DSA-44 signing signs nothing under a cancelled token.</summary>
        [TestMethod]
        public async Task BouncyCastleMlDsaSigningUnderCancelledTokenSignsNothing()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateMlDsa44Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertCancelledSigningSignsNothingAsync(BouncyCastleCryptographicFunctionsAdapter.SignMlDsa44Async, privateKey, Payload).ConfigureAwait(false);
        }


        /// <summary>The BouncyCastle provider's ISO/IEC 9796-2 recoverable signing signs nothing under a cancelled token.</summary>
        [TestMethod]
        public async Task BouncyCastleRecoverableSigningUnderCancelledTokenSignsNothing()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertCancelledSigningSignsNothingAsync(BouncyCastleRecoverableSignatureFunctionsAdapter.SignRsaIso9796d2Async, privateKey, Challenge).ConfigureAwait(false);
        }


        /// <summary>
        /// The BouncyCastle provider's ISO/IEC 9796-2 recoverable verification observes the cancellation before it parses the key,
        /// as its contract says: under an already-cancelled token it is refused as cancelled rather than answering a verdict.
        /// </summary>
        /// <returns>A task completing once the refusal is checked.</returns>
        [TestMethod]
        public async Task BouncyCastleRecoverableVerificationUnderCancelledTokenVerifiesNothing()
        {
            var keys = BouncyCastleKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;
            using var cancellation = new CancellationTokenSource();
            await cancellation.CancelAsync().ConfigureAwait(false);

            var cancelledToken = cancellation.Token;

            _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
                await BouncyCastleRecoverableSignatureFunctions.VerifyRsaIso9796d2Async(
                    Challenge, Payload, publicKey.AsReadOnlyMemory(), TimeProvider.System, null, cancelledToken).ConfigureAwait(false)).ConfigureAwait(false);
        }


        /// <summary>The libsodium provider's Ed25519 signing signs nothing under a cancelled token.</summary>
        [TestMethod]
        public async Task LibsodiumEd25519SigningUnderCancelledTokenSignsNothing()
        {
            var keys = LibsodiumKeyMaterialCreator.CreateEd25519Keys(BaseMemoryPool.Shared);
            using var publicKey = keys.PublicKey;
            using var privateKey = keys.PrivateKey;

            await AssertCancelledSigningSignsNothingAsync(LibsodiumCryptographicFunctionsAdapter.SignEd25519Async, privateKey, Payload).ConfigureAwait(false);
        }


        /// <summary>
        /// Asks a signing function to sign under an already-cancelled token and checks the refusal is the cancellation and
        /// the pool handed in lent nothing a signature could have been written into.
        /// </summary>
        /// <param name="sign">The provider's signing function.</param>
        /// <param name="privateKey">The private key the signing is asked under.</param>
        /// <param name="dataToSign">The octets the signing is asked over.</param>
        /// <returns>A task completing once the refusal is checked.</returns>
        private static async Task AssertCancelledSigningSignsNothingAsync(SigningDelegate sign, PrivateKeyMemory privateKey, byte[] dataToSign)
        {
            using var cancellation = new CancellationTokenSource();
            await cancellation.CancelAsync().ConfigureAwait(false);

            using var meteredPool = new MeteredHousePool();
            var cancelledToken = cancellation.Token;

            _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
                await sign(privateKey.AsReadOnlyMemory(), dataToSign, meteredPool.Pool, null, cancelledToken).ConfigureAwait(false)).ConfigureAwait(false);

            Assert.AreEqual(0L, meteredPool.RentedCount, "A signing under a cancelled token must rent no signature octets.");
        }
    }
}
