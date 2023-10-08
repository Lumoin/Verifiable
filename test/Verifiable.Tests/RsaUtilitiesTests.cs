using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using Verifiable.Core.Cryptography;
using Xunit;

namespace Verifiable.Core
{
    /// <summary>
    /// Tests for RSA utilities.
    /// </summary>
    public class RsaUtilitiesTests
    {
        /// <summary>
        /// Test array that is wrong length for RSA encoding.
        /// </summary>
        private static byte[] WrongSizeArray1 => Array.Empty<byte>();

        /// <summary>
        /// Test array that is wrong length for RSA encoding.
        /// </summary>
        private static byte[] WrongSizeArray2 => new byte[257];

        /// <summary>
        /// The RSA key lenghts DID specifications support.
        /// </summary>
        public static IEnumerable<object[]> RsaKeySizesInBits => new object[][]
        {
            new object[] { 2048 },
            new object[] { 4096 }            
        };


        [Fact]
        public void EncodeThrowsWithCorrectMessageIfModulusNull()
        {
            const string ParameterName = "rsaModulusBytes";
            var exception1 = Assert.Throws<ArgumentNullException>(() => RsaUtilities.Encode(null));
            Assert.Equal(ParameterName, exception1.ParamName);
        }


        [Fact]
        public void EncodeThrowsWithCorrectMessageIfModulusNotCorrectLength()
        {
            const string ParameterName = "rsaModulusBytes";
            var exception1 = Assert.Throws<ArgumentOutOfRangeException>(() => RsaUtilities.Encode(WrongSizeArray1));
            Assert.Equal(ParameterName, exception1.ParamName);
            Assert.Equal($"Length must be {RsaUtilities.Rsa2048ModulusLength} (RSA 2048) or {RsaUtilities.Rsa4096ModulusLength} (RSA 4096). (Parameter '{ParameterName}')", exception1.Message);

            var exception2 = Assert.Throws<ArgumentOutOfRangeException>(() => RsaUtilities.Encode(WrongSizeArray2));
            Assert.Equal(ParameterName, exception2.ParamName);
            Assert.Equal($"Length must be {RsaUtilities.Rsa2048ModulusLength} (RSA 2048) or {RsaUtilities.Rsa4096ModulusLength} (RSA 4096). (Parameter '{ParameterName}')", exception2.Message);
        }


        [Fact]
        public void DecodeThrowsWithCorrectMessageIfModulusNotCorrectLength()
        {
            const string ParameterName = "encodedRsaModulusBytes";
            const int Rsa2048DerEncodedBytesLength = 270;
            const int Rsa4096DerEncodedBytesLength = 526;
            var exception1 = Assert.Throws<ArgumentOutOfRangeException>(() => RsaUtilities.Decode(WrongSizeArray1));
            Assert.Equal(ParameterName, exception1.ParamName);
            Assert.Equal($"Length must be {Rsa2048DerEncodedBytesLength} (RSA 2048) or {Rsa4096DerEncodedBytesLength} (RSA 4096). (Parameter '{ParameterName}')", exception1.Message);

            var exception2 = Assert.Throws<ArgumentOutOfRangeException>(() => RsaUtilities.Decode(WrongSizeArray2));
            Assert.Equal(ParameterName, exception2.ParamName);
            Assert.Equal($"Length must be {Rsa2048DerEncodedBytesLength} (RSA 2048) or {Rsa4096DerEncodedBytesLength} (RSA 4096). (Parameter '{ParameterName}')", exception2.Message);
        }


        [Theory]
        [MemberData(nameof(RsaKeySizesInBits))]
        public void RsaDecodeThrowsIfNoDerPaddingByte(int keySizeInBits)
        {
            const string CatastrophicExceptionMessage = "Catastrophic error while decoding RSA modulus bytes.";
            const int PaddingByteIndex = 8;

            using(var rsaKey = RSA.Create(keySizeInBits))
            {
                var rsaParameters = rsaKey.ExportParameters(includePrivateParameters: false);
                var rsaModulus = rsaParameters.Modulus!;

                var encodedModulus = RsaUtilities.Encode(rsaModulus);
                encodedModulus[PaddingByteIndex] = 0x1;

                var exception = Assert.Throws<ArgumentException>(() => RsaUtilities.Decode(RsaUtilities.Decode(encodedModulus)));
                Assert.Equal(CatastrophicExceptionMessage, exception.Message);
            }
        }


        [Theory]
        [MemberData(nameof(RsaKeySizesInBits))]
        public void RsaDecodeThrowsIfNoMsbSet(int keySizeInBits)
        {
            const string CatastrophicExceptionMessage = "Catastrophic error while decoding RSA modulus bytes.";
            const int MsbByteIndex = 9;

            using(var rsaKey = RSA.Create(keySizeInBits))
            {
                var rsaParameters = rsaKey.ExportParameters(includePrivateParameters: false);
                var rsaModulus = rsaParameters.Modulus!;

                var encodedModulus = RsaUtilities.Encode(rsaModulus);
                encodedModulus[MsbByteIndex] = 0x1;

                var exception = Assert.Throws<ArgumentException>(() => RsaUtilities.Decode(RsaUtilities.Decode(encodedModulus)));
                Assert.Equal(CatastrophicExceptionMessage, exception.Message);
            }
        }

        
        [Theory]
        [MemberData(nameof(RsaKeySizesInBits))]
        public void RsaEncodingAndDecodingSucceeds(int keySizeInBits)
        {
            using(var rsaKey = RSA.Create(keySizeInBits))
            {
                var rsaParameters = rsaKey.ExportParameters(includePrivateParameters: false);                
                var rsaModulus = rsaParameters.Modulus!;

                var encodedModulus = RsaUtilities.Encode(rsaModulus);                
                var decodedModulus = RsaUtilities.Decode(encodedModulus);                              
                Assert.Equal(rsaModulus, decodedModulus);

                //This is a bit of extra to show how to get the DER encoded public key from the platform.
                var dotNetEncoded = ExportPublicKeyAsDerEncoded(rsaKey);
                var dotNetDecoded = DecodeDerPublicKey(dotNetEncoded);
                Assert.Equal(encodedModulus, dotNetEncoded);
                Assert.Equal(rsaParameters.Modulus, dotNetDecoded.Modulus);
                Assert.Equal(rsaParameters.Exponent, dotNetDecoded.Exponent);
            }
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
            AsnReader reader = new AsnReader(derEncodedKey, AsnEncodingRules.DER);
            
            AsnReader publicKeyReader = reader.ReadSequence();
            BigInteger modulus = publicKeyReader.ReadInteger();
            BigInteger exponent = publicKeyReader.ReadInteger();

            return (modulus.ToByteArray(isUnsigned: true, isBigEndian: true), exponent.ToByteArray(isUnsigned: true, isBigEndian: true));
        }
    }
}
