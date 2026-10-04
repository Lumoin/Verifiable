using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography
{
    [TestClass]
    internal class CryptoFunctionRegistryTests
    {
        private static byte[] TestData { get; } = Encoding.UTF8.GetBytes("Hello, CryptoFunctionRegistryTests!");


        [TestMethod]
        public async ValueTask P256SignatureVerifies()
        {
            var compressedKeys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);

            var privateKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.P256, Purpose.Signing);
            var publicKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(CryptoAlgorithm.P256, Purpose.Verification);

            (Signature signature, CryptoEvent? _) = await privateKey(compressedKeys.PrivateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, context: null, cancellationToken: default)
                .ConfigureAwait(false);
            (bool isVerified, CryptoEvent? _) = await publicKey(TestData, signature.AsReadOnlyMemory(), compressedKeys.PublicKey.AsReadOnlyMemory(), context: null, cancellationToken: default)
                .ConfigureAwait(false);
            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask P256SignatureVerifiesHighestLevel()
        {
            var compressedKeys = MicrosoftKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);

            using var publicKey = CryptographicKeyFactory.CreatePublicKey(compressedKeys.PublicKey, "key-identifier", compressedKeys.PublicKey.Tag);
            using var privateKey = CryptographicKeyFactory.CreatePrivateKey(compressedKeys.PrivateKey, "key-identifier", compressedKeys.PrivateKey.Tag);
            var signature = await privateKey.SignAsync(TestData.AsMemory(), BaseMemoryPool.Shared)
                .ConfigureAwait(false);
            bool isVerified = await publicKey.VerifyAsync(TestData.AsMemory(), signature)
                .ConfigureAwait(false);

            Assert.IsTrue(isVerified);
        }


        [TestMethod]
        public async ValueTask Rsa2048SignatureVerifies()
        {
            var keys = MicrosoftKeyMaterialCreator.CreateRsa2048Keys(BaseMemoryPool.Shared);

            var privateKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.Rsa2048, Purpose.Signing);
            var publicKey = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(CryptoAlgorithm.Rsa2048, Purpose.Verification);

            (Signature signature, CryptoEvent? _) = await privateKey(keys.PrivateKey.AsReadOnlyMemory(), TestData, BaseMemoryPool.Shared, context: null, cancellationToken: default).ConfigureAwait(false);
            (bool isVerified, CryptoEvent? _) = await publicKey(TestData, signature.AsReadOnlyMemory(), keys.PublicKey.AsReadOnlyMemory(), context: null, cancellationToken: default).ConfigureAwait(false);
            Assert.IsTrue(isVerified);
        }


        /// <summary>
        /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.IsInitialized"/> is
        /// <see langword="true"/> once <c>TestSetup</c>'s module initializer has run
        /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.Initialize"/>. The
        /// process-wide <c>[ModuleInitializer]</c> runs before any test, so only the true-after state
        /// is observable here without disturbing the other tests' process-wide registration.
        /// </summary>
        [TestMethod]
        public void IsInitializedIsTrueAfterProcessWideSetup()
        {
            Assert.IsTrue(CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.IsInitialized);
        }


        /// <summary>
        /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>: "All
        /// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
        /// them fail to validate." A verifier can reject only what it is answered, so for a pair the registry's
        /// matcher serves no function for (the test matcher has a verification arm for neither X25519 nor P-256
        /// under <see cref="Purpose.Exchange"/>),
        /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.TryResolveVerification"/> answers
        /// <see langword="false"/> with no function and raises nothing, and
        /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.ResolveVerification"/>, which takes
        /// the pair as its caller's argument, throws <see cref="ArgumentException"/> naming the pair, the type a
        /// caller that resolves a presented pair through it catches to fail closed.
        /// </summary>
        /// <param name="algorithmName">The name of the algorithm of the unserved pair.</param>
        /// <param name="expectedMessage">The message the argument exception carries.</param>
        [TestMethod]
        [DataRow("X25519", "No verification function is registered for algorithm 'X25519', purpose 'Exchange' and qualifier ''.")]
        [DataRow("P256", "No verification function is registered for algorithm 'P256', purpose 'Exchange' and qualifier ''.")]
        public void UnservedPairIsNoFunctionNotAFault(string algorithmName, string expectedMessage)
        {
            CryptoAlgorithm algorithm = algorithmName switch
            {
                "X25519" => CryptoAlgorithm.X25519,
                "P256" => CryptoAlgorithm.P256,
                _ => throw new ArgumentOutOfRangeException(nameof(algorithmName), algorithmName, "No such algorithm name.")
            };

            bool isServed = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.TryResolveVerification(
                algorithm, Purpose.Exchange, out VerificationDelegate? verification);

            Assert.IsFalse(isServed);
            Assert.IsNull(verification);

            ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
                () => CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Exchange));
            Assert.AreEqual(expectedMessage, exception.Message);
        }


        /// <summary>
        /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.ResolveSigning"/> takes the pair as
        /// its caller's argument: for a pair the registry's signing matcher serves no function for (the test
        /// matcher has a signing arm for no X25519 pair), it throws <see cref="ArgumentException"/> whose message
        /// names the algorithm, the purpose and the qualifier. A signature is computed only under a function the
        /// backend serves for the algorithm; <see href="https://www.rfc-editor.org/rfc/rfc7515#section-5.1">RFC 7515
        /// Section 5.1</see>, step 5: "Compute the JWS Signature in the manner defined for the particular algorithm
        /// being used over the JWS Signing Input ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' ||
        /// BASE64URL(JWS Payload))."
        /// </summary>
        [TestMethod]
        public void UnservedSigningPairIsAnArgumentFaultNamingThePair()
        {
            ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
                () => CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(CryptoAlgorithm.X25519, Purpose.Exchange));

            Assert.AreEqual("No signing function is registered for algorithm 'X25519', purpose 'Exchange' and qualifier ''.", exception.Message);
        }
    }
}
