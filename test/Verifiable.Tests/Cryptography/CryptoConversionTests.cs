using SimpleBase;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for <see cref="VerifiableCryptoFormatConversions" />.
    /// </summary>
    [TestClass]
    internal sealed class CryptoConversionTests
    {
        [TestMethod]
        public void TestConversion1()
        {
            const string Vector1 = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

            static byte[] simpleBase58Decoder(ReadOnlySpan<char> source) => Base58.Bitcoin.Decode(source.ToString());

            var decodedVector1Owner = MultibaseSerializer.Decode(Vector1, codecHeaderLength: 2, simpleBase58Decoder, SensitiveMemoryPool<byte>.Shared);
            var decodedVector1 = decodedVector1Owner.Memory.Span;

            var multibaseEncodedPublicKey = MultibaseSerializer.Encode(decodedVector1, MulticodecHeaders.Ed25519PublicKey, MultibaseAlgorithms.Base58Btc, TestSetup.Base58Encoder);
            var reEncodedVector1 = MultibaseSerializer.Encode(decodedVector1, MulticodecHeaders.Ed25519PublicKey, MultibaseAlgorithms.Base58Btc, TestSetup.Base58Encoder);
            Assert.AreEqual(Vector1, reEncodedVector1);

            decodedVector1Owner.Dispose();

            //Call the converter using a simple inline buffer allocation delegate.
            var (algorithm, purpose, scheme, keyMaterial) = CryptoFormatConversions.DefaultBase58ToAlgorithmConverter(Vector1, SensitiveMemoryPool<byte>.Shared, TestSetup.Base58Decoder);

            // Now you can assert on these values as needed.
            Assert.AreEqual(CryptoAlgorithm.Ed25519, algorithm);
            Assert.AreEqual(Purpose.Verification, purpose);
            Assert.IsNotNull(keyMaterial);
            Assert.IsGreaterThan(0, keyMaterial.Memory.Length);
        }



        [TestMethod]
        public void TestConversion2()
        {
            const string Vector1 = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

            // The delegate must decode Base58 data into bytes, remove the codec header,
            // and return an IMemoryOwner<byte> containing the final bytes.
            var (algorithm, purpose, scheme, keyMaterial) = CryptoFormatConversions.DefaultBase58ToAlgorithmConverter(Vector1, SensitiveMemoryPool<byte>.Shared, TestSetup.Base58Decoder);

            // Now you can assert on the returned values.
            Assert.AreEqual(CryptoAlgorithm.Ed25519, algorithm);
            Assert.AreEqual(Purpose.Verification, purpose);
            Assert.IsNotNull(keyMaterial);
            Assert.IsGreaterThan(0, keyMaterial.Memory.Length);
        }
    }
}
