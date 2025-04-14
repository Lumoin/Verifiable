using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Cryptography.Context;
using Verifiable.Core.Did;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for <see cref="VerifiableCryptoFormatConversions" />.
    /// </summary>
    [TestClass]
    public sealed class CryptoConversionTests
    {        
        [TestMethod]
        public void TestConversion1()
        {
            const string Vector1 = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

            var decodedVector1 = MultibaseSerializer.Decode(Vector1, ExactSizeMemoryPool<byte>.Shared, TestSetup.StackBase58Decoder).Memory.Span;

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(decodedVector1, MulticodecHeaders.Ed25519PublicKey, MultibaseAlgorithms.Base58Btc, TestSetup.TestBase58ArrayEncoder);
            var reEncodedVector1 = MultibaseSerializer.Encode(decodedVector1, MulticodecHeaders.Ed25519PublicKey, MultibaseAlgorithms.Base58Btc, TestSetup.TestBase58ArrayEncoder);
            Assert.AreEqual(Vector1, reEncodedVector1);

            // Call the converter using a simple inline buffer allocation delegate.
            var (algorithm, purpose, scheme, keyMaterial) = VerifiableCryptoFormatConversions.DefaultBase58ToAlgorithmConverter(Vector1, ExactSizeMemoryPool<byte>.Shared, TestSetup.StackBase58Decoder);

            // Now you can assert on these values as needed.
            Assert.AreEqual(CryptoAlgorithm.Ed25519, algorithm);
            Assert.AreEqual(Purpose.Verification, purpose);
            Assert.IsNotNull(keyMaterial);
            Assert.IsTrue(keyMaterial.Memory.Length > 0);
        }



        [TestMethod]
        public void TestConversion2()
        {
            const string Vector1 = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

            // The delegate must decode Base58 data into bytes, remove the codec header,
            // and return an IMemoryOwner<byte> containing the final bytes.
            var (algorithm, purpose, scheme, keyMaterial) = VerifiableCryptoFormatConversions.DefaultBase58ToAlgorithmConverter(Vector1, ExactSizeMemoryPool<byte>.Shared, TestSetup.StackBase58Decoder);
            
            // Now you can assert on the returned values.
            Assert.AreEqual(CryptoAlgorithm.Ed25519, algorithm);
            Assert.AreEqual(Purpose.Verification, purpose);
            Assert.IsNotNull(keyMaterial);
            Assert.IsTrue(keyMaterial.Memory.Length > 0);
        }
    }
}
