using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Cryptography
{
    /// <summary>
    /// Tests for RSA utilities.
    /// </summary>
    [TestClass]
    internal sealed class RsaUtilitiesTests
    {
        /// <summary>
        /// Test array that is wrong length for RSA encoding.
        /// </summary>
        private static byte[] WrongSizeArray1 => [];

        /// <summary>
        /// Test array that is wrong length for RSA encoding.
        /// </summary>
        private static byte[] WrongSizeArray2 => new byte[257];

        /// <summary>
        /// The RSA key lenghts DID specifications support.
        /// </summary>
        public static IEnumerable<object[]> RsaKeySizesInBits => new object[][]
        {
            [2048],
            [4096]
        };


        [TestMethod]
        public void EncodeThrowsWithCorrectMessageIfModulusNull()
        {
            //Since the argument is ReadOnlySpan<byte>, it will be converted to ReadOnlySpan<byte>.Empty automatically.
            const string ParameterName = "rsaModulusBytes";
            var exception1 = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RsaUtilities.Encode(null));
            Assert.AreEqual(ParameterName, exception1.ParamName);
        }


        [TestMethod]
        public void EncodeThrowsWithCorrectMessageIfModulusNotCorrectLength()
        {
            const string ParameterName = "rsaModulusBytes";
            var exception1 = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RsaUtilities.Encode(WrongSizeArray1));
            Assert.AreEqual(ParameterName, exception1.ParamName);
            Assert.AreEqual($"Length must be {RsaUtilities.Rsa2048ModulusLength} (RSA 2048) or {RsaUtilities.Rsa4096ModulusLength} (RSA 4096). (Parameter '{ParameterName}')", exception1.Message);

            var exception2 = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RsaUtilities.Encode(WrongSizeArray2));
            Assert.AreEqual(ParameterName, exception2.ParamName);
            Assert.AreEqual($"Length must be {RsaUtilities.Rsa2048ModulusLength} (RSA 2048) or {RsaUtilities.Rsa4096ModulusLength} (RSA 4096). (Parameter '{ParameterName}')", exception2.Message);
        }


        [TestMethod]
        public void DecodeThrowsWithCorrectMessageIfModulusNotCorrectLength()
        {
            //OI-002 widened Decode to accept either raw modulus bytes
            //(length 256 / 512) or DER-encoded modulus bytes (length 270 /
            //526). The error message enumerates all four accepted shapes;
            //inputs of any other length (including empty and 257-byte test
            //arrays) still throw ArgumentOutOfRangeException.
            const string ParameterName = "encodedRsaModulusBytes";
            const string ExpectedMessage =
                "Length must be 256 or 270 (RSA 2048), or 512 or 526 (RSA 4096). "
                + "(Parameter 'encodedRsaModulusBytes')";

            var exception1 = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RsaUtilities.Decode(WrongSizeArray1));
            Assert.AreEqual(ParameterName, exception1.ParamName);
            Assert.AreEqual(ExpectedMessage, exception1.Message);

            var exception2 = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => RsaUtilities.Decode(WrongSizeArray2));
            Assert.AreEqual(ParameterName, exception2.ParamName);
            Assert.AreEqual(ExpectedMessage, exception2.Message);
        }


        [TestMethod]
        public void DecodeAcceptsRawModulus()
        {
            //OI-002 — raw RSA-2048 modulus (256 bytes) and raw RSA-4096
            //modulus (512 bytes) round-trip through Decode unchanged.
            //Raw modulus has the MSB set per algorithm invariant; emulate
            //by filling the first byte with 0xFF.
            byte[] rawRsa2048 = new byte[RsaUtilities.Rsa2048ModulusLength];
            rawRsa2048[0] = 0xFF;
            byte[] decoded2048 = RsaUtilities.Decode(rawRsa2048);
            Assert.HasCount(RsaUtilities.Rsa2048ModulusLength, decoded2048);
            Assert.AreSequenceEqual(rawRsa2048, decoded2048);

            byte[] rawRsa4096 = new byte[RsaUtilities.Rsa4096ModulusLength];
            rawRsa4096[0] = 0xFF;
            byte[] decoded4096 = RsaUtilities.Decode(rawRsa4096);
            Assert.HasCount(RsaUtilities.Rsa4096ModulusLength, decoded4096);
            Assert.AreSequenceEqual(rawRsa4096, decoded4096);
        }


        [TestMethod]
        [DynamicData(nameof(RsaKeySizesInBits))]
        public void RsaDecodeThrowsIfNoDerPaddingByte(int keySizeInBits)
        {
            const string CatastrophicExceptionMessage = "Catastrophic error while decoding RSA modulus bytes.";
            const int PaddingByteIndex = 8;

            var keyMaterial = CreateRsaKeyMaterial(keySizeInBits);
            try
            {
                var rsaModulus = RsaUtilities.Decode(keyMaterial.PublicKey.AsReadOnlySpan());

                var encodedModulus = RsaUtilities.Encode(rsaModulus);
                encodedModulus[PaddingByteIndex] = 0x1;

                var exception = Assert.ThrowsExactly<ArgumentException>(() => RsaUtilities.Decode(RsaUtilities.Decode(encodedModulus)));
                Assert.AreEqual(CatastrophicExceptionMessage, exception.Message);
            }
            finally
            {
                keyMaterial.PublicKey.Dispose();
                keyMaterial.PrivateKey.Dispose();
            }
        }


        [TestMethod]
        [DynamicData(nameof(RsaKeySizesInBits))]
        public void RsaDecodeThrowsIfNoMsbSet(int keySizeInBits)
        {
            const string CatastrophicExceptionMessage = "Catastrophic error while decoding RSA modulus bytes.";
            const int MsbByteIndex = 9;

            var keyMaterial = CreateRsaKeyMaterial(keySizeInBits);
            try
            {
                var rsaModulus = RsaUtilities.Decode(keyMaterial.PublicKey.AsReadOnlySpan());

                var encodedModulus = RsaUtilities.Encode(rsaModulus);
                encodedModulus[MsbByteIndex] = 0x1;

                var exception = Assert.ThrowsExactly<ArgumentException>(() => RsaUtilities.Decode(RsaUtilities.Decode(encodedModulus)));
                Assert.AreEqual(CatastrophicExceptionMessage, exception.Message);
            }
            finally
            {
                keyMaterial.PublicKey.Dispose();
                keyMaterial.PrivateKey.Dispose();
            }
        }


        [TestMethod]
        [DynamicData(nameof(RsaKeySizesInBits))]
        public void RsaEncodingAndDecodingSucceeds(int keySizeInBits)
        {
            //Independent oracle: a freshly minted platform RSA key is exported through the .NET-native
            //ExportRSAPublicKey() DER path, independently of this library's RsaUtilities.Encode/Decode,
            //so the two DER encodings can be compared byte-for-byte below.
            using(var rsaKey = RSA.Create(keySizeInBits))
            {
                var rsaParameters = rsaKey.ExportParameters(includePrivateParameters: false);
                var rsaModulus = rsaParameters.Modulus!;

                var encodedModulus = RsaUtilities.Encode(rsaModulus);
                var decodedModulus = RsaUtilities.Decode(encodedModulus);
                Assert.AreSequenceEqual(rsaModulus, decodedModulus);

                //This is a bit of extra to show how to get the DER encoded public key from the platform.
                var dotNetEncoded = ExportPublicKeyAsDerEncoded(rsaKey);
                var dotNetDecoded = DecodeDerPublicKey(dotNetEncoded);
                Assert.AreSequenceEqual(encodedModulus, dotNetEncoded);
                Assert.AreSequenceEqual(rsaParameters.Modulus, dotNetDecoded.Modulus);
                Assert.AreSequenceEqual(rsaParameters.Exponent, dotNetDecoded.Exponent);
            }
        }


        [TestMethod]
        public void IsValidPublicKeyRejectsForgeryAndWeakKeys()
        {
            var keyMaterial = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
            try
            {
                byte[] modulus = RsaUtilities.Decode(keyMaterial.PublicKey.AsReadOnlySpan());

                //RSA key material minted by TestKeyMaterialProvider always carries the standard
                //65537 public exponent (RsaUtilities.DefaultExponent, "AQAB").
                byte[] exponent = [0x01, 0x00, 0x01];

                Assert.IsTrue(RsaUtilities.IsValidPublicKey(modulus, exponent), "A well-formed 2048-bit key with the standard public exponent is valid.");

                //e = 1 is the identity map: an ISO/IEC 9796-2 recovered message equals the signature, so any value "verifies".
                Assert.IsFalse(RsaUtilities.IsValidPublicKey(modulus, [0x01]), "A public exponent of 1 (the identity map) must be rejected.");

                //An even public exponent shares a factor with phi(n) and cannot be an RSA exponent.
                Assert.IsFalse(RsaUtilities.IsValidPublicKey(modulus, [0x02]), "An even public exponent must be rejected.");

                //A public exponent at least as large as the modulus is outside the valid range.
                Assert.IsFalse(RsaUtilities.IsValidPublicKey(modulus, modulus), "A public exponent not less than the modulus must be rejected.");

                //An even modulus is not a product of two odd primes.
                byte[] evenModulus = (byte[])modulus.Clone();
                evenModulus[^1] &= 0xFE;
                Assert.IsFalse(RsaUtilities.IsValidPublicKey(evenModulus, exponent), "An even modulus must be rejected.");

                //A modulus below the minimum bit length is too weak to sign; a 512-bit odd modulus with a valid exponent still fails.
                byte[] weakModulus = new byte[64];
                weakModulus[0] = 0xFF;
                weakModulus[^1] = 0x03;
                Assert.IsFalse(RsaUtilities.IsValidPublicKey(weakModulus, exponent), "A modulus below the minimum bit length must be rejected.");

                //An empty modulus or exponent is malformed.
                Assert.IsFalse(RsaUtilities.IsValidPublicKey([], exponent), "An empty modulus must be rejected.");
                Assert.IsFalse(RsaUtilities.IsValidPublicKey(modulus, []), "An empty exponent must be rejected.");
            }
            finally
            {
                keyMaterial.PublicKey.Dispose();
                keyMaterial.PrivateKey.Dispose();
            }
        }


        /// <summary>
        /// Returns key material of the size <paramref name="keySizeInBits"/> selects, matching the
        /// <see cref="RsaKeySizesInBits"/> shapes the DynamicData-driven tests exercise.
        /// </summary>
        /// <param name="keySizeInBits">The RSA modulus size in bits; 2048 or 4096.</param>
        /// <returns>RSA key material of the requested size. The caller owns and must dispose it.</returns>
        private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> CreateRsaKeyMaterial(int keySizeInBits)
        {
            return keySizeInBits == RsaUtilities.Rsa4096ModulusLength * 8
                ? TestKeyMaterialProvider.CreateRsa4096KeyMaterial()
                : TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        }


        /// <summary>
        /// This is a platform provided way to get the DER encoded public key.
        /// </summary>
        /// <param name="rsa">The RSA structure from which to export the key.</param>
        /// <returns>The RSA key in DER encoded format.</returns>
        private static byte[] ExportPublicKeyAsDerEncoded(RSA rsa)
        {
            byte[] rsaPublicKey = rsa.ExportRSAPublicKey();
            AsnWriter writer = new(AsnEncodingRules.DER);
            writer.WriteEncodedValue(rsaPublicKey);

            return writer.Encode();
        }


        /// <summary>
        /// This is a platform provided way to turn DER into raw RSA key components.
        /// </summary>
        /// <param name="rsa">The RSA structure from which to export the key.</param>
        /// <returns>The RSA key in raw format.</returns>
        private static (byte[] Modulus, byte[] Exponent)  DecodeDerPublicKey(byte[] derEncodedKey)
        {
            AsnReader reader = new(derEncodedKey, AsnEncodingRules.DER);

            AsnReader publicKeyReader = reader.ReadSequence();
            BigInteger modulus = publicKeyReader.ReadInteger();
            BigInteger exponent = publicKeyReader.ReadInteger();

            return (modulus.ToByteArray(isUnsigned: true, isBigEndian: true), exponent.ToByteArray(isUnsigned: true, isBigEndian: true));
        }
    }
}
