using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Verifiable.Core;
using Verifiable.Core.Cryptography;
using Xunit;

namespace Verifiable.Tests.DataProviders
{
    /// <summary>
    /// Test data container for RSA tests.
    /// </summary>    
    public record RsaTestData(
        int KeyLength,
        byte[] PublicKeyMulticodecHeader,
        byte[] PrivateKeyMulticodecHeader,
        string Base58BtcEncodedMulticodecHeaderPublicKey,
        string Base58BtcEncodedMulticodecHeaderPrivateKey,
        byte[] Modulus);

    /// <summary>
    ///  
    /// </summary>
    public class RsaTheoryData: TheoryData<RsaTestData>
    {
        private static readonly IList<RsaTestData> rsaKeyData = new List<RsaTestData>();

        public const int Rsa2048KeyLength = 2048;
        public const int Rsa4096KeyLength = 4096;

        /// <summary>
        /// The DID supported RSA key lengths. These are used to generate keys for testing.
        /// </summary>
        public static IList<int> RsaKeyLengthConstants => new List<int>(new[]
        {
            Rsa2048KeyLength,
            Rsa4096KeyLength,
        });


        /// <summary>
        /// Turns the human readable curve name into <see cref="Base58BtcEncodedMulticodecHeaders"/>.
        /// </summary>
        /// <param name="humanReadable">Human readable elliptic curve name.</param>
        /// <returns><see cref="Base58BtcEncodedMulticodecHeaders">public and private Base58 BTC encode multicodec value</see>.</returns>
        /// <exception cref="NotSupportedException"></exception>
        public static (string PublicKey, string PrivateKey) FromKeyLengthToBtc58EncodedHeader(int keyLength) => keyLength switch
        {
            Rsa2048KeyLength => (Base58BtcEncodedMulticodecHeaders.RsaPublicKey2048.ToString(), string.Empty),
            Rsa4096KeyLength => (Base58BtcEncodedMulticodecHeaders.RsaPublicKey4096.ToString(), string.Empty),
            _ => throw new NotSupportedException()
        };


        /// <summary>
        /// Turns the human readable curve name into <see cref="Base58BtcEncodedMulticodecHeaders"/>.
        /// </summary>
        /// <param name="humanReadable">Human readable elliptic curve name.</param>
        /// <returns><see cref="Base58BtcEncodedMulticodecHeaders">public and private Base58 BTC encode multicodec value</see>.</returns>
        /// <exception cref="NotSupportedException"></exception>
        public static (byte[] PublicKeyHeader, byte[] PrivateKeyHeader) FromKeyLengthToMultiCodecHeader(int keyLength) => keyLength switch
        {
            Rsa2048KeyLength => (MulticodecHeaders.RsaPublicKey.ToArray(), Array.Empty<byte>()),
            Rsa4096KeyLength => (MulticodecHeaders.RsaPublicKey.ToArray(), Array.Empty<byte>()),
            _ => throw new NotSupportedException()
        };


        static RsaTheoryData()
        {
            foreach(int keyLength in RsaKeyLengthConstants)
            {
                var rsaKey = GenerateRsaTestKeyMaterial(keyLength);
                rsaKeyData.Add(rsaKey);
            }
        }

        public RsaTheoryData()
        {
            foreach(var td in rsaKeyData)
            {
                Add(td);
            }
        }

        private static RsaTestData GenerateRsaTestKeyMaterial(int keyLength)
        {            
            using(var key = RSA.Create(keyLength))
            {
                var parameters = key.ExportParameters(includePrivateParameters: true);
                var modulus = parameters.Modulus!;
                var encodedModulus = RsaUtilities.Encode(modulus);

                var btc58Headers = FromKeyLengthToBtc58EncodedHeader(keyLength);
                var multiCodecHeaders = FromKeyLengthToMultiCodecHeader(keyLength);

                return new RsaTestData(
                    keyLength,
                    multiCodecHeaders.PublicKeyHeader,
                    multiCodecHeaders.PrivateKeyHeader,
                    btc58Headers.PublicKey,
                    btc58Headers.PrivateKey,
                    modulus);
            }
        }
    }
}
