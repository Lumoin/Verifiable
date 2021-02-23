using DotDecentralized.Core.Did;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Xunit;

namespace DotDecentralized.Tests
{
    /// <summary>
    /// These are general purpose cryptography tests that rely on DID Core specific
    /// APIs that abstract the underlying providers.
    /// </summary>
    /// <remarks>There should not be code specific to underlying providers.</remarks>
    public class DidCryptoProviderTests
    {
        /// <summary>
        /// A test for loading and rountripping a signing and verifying event.
        /// </summary>
        /*[Fact]
        public void DidCoreCanLoadAllCryptoProvidersByReflectionSignAndVerify()
        {
            var cryptoProviders = CryptoProviderLoader.LoadCryptoProviders();
            var didCryptoProvider = new DidCryptoProvider(cryptoProviders);

            const string Algorithm = CryptographyAlgorithmConstants.EdDsa.Algorithm;
            const string Curve = CryptographyAlgorithmConstants.EdDsa.Curves.Ed25519;
            const string KeyType = CryptographyAlgorithmConstants.EdDsa.KeyType;
            var publicPrivateJwk = CryptoUtilities.GeneratePublicPrivateJwk(KeyType, Curve, new byte[] { 0x1 });
            var publicJwk = new JsonWebKey(publicPrivateJwk);
            var privateJwk = new JsonWebKey(publicPrivateJwk);
            publicJwk.D = null;
            privateJwk.X = null;

            Assert.True(didCryptoProvider.IsSupportedAlgorithm(Algorithm, publicJwk), "Unsupported algorithm was tried for public crypto provider.");
            Assert.True(didCryptoProvider.IsSupportedAlgorithm(Algorithm, privateJwk), "Unsupported algorithm was tried for private crypto provider.");

            var publicKeyWrapper = didCryptoProvider.Create(Algorithm, publicJwk);
            Assert.NotNull(publicKeyWrapper);
            Assert.True(publicKeyWrapper is AsymmetricKeyWrapper);

            var privateKeyWrapper = didCryptoProvider.Create(Algorithm, privateJwk);
            Assert.NotNull(privateKeyWrapper);
            Assert.True(privateKeyWrapper is AsymmetricKeyWrapper);

            //This string is signed by the privat key owner somewhere else...
            var testBytes = Encoding.UTF8.GetBytes("This string is the soure of some test bytes for general DID core types.");
            var signer = (AsymmetricKeyWrapper)privateKeyWrapper;
            Assert.True(signer.SignatureProvider.WillCreateSignatures, "This provider should be able to create signatures.");
            var signedTestBytes = signer.SignatureProvider.Sign(testBytes);

            //While this verifier uses the public key found in the DID document.
            var verifier = (AsymmetricKeyWrapper)publicKeyWrapper;
            Assert.False(verifier.SignatureProvider.WillCreateSignatures, "This provider should not be able to create signatures.");
            Assert.True(verifier.SignatureProvider.Verify(testBytes, signedTestBytes));
        }*/
    }
}
