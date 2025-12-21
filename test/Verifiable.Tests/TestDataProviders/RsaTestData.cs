using System.Security.Cryptography;
using Verifiable.Cryptography;

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
    /// RSA theory data generator for MSTest DynamicData.
    /// </summary>
    public static class RsaTheoryData
    {
        public const int Rsa2048KeyLength = 2048;
        public const int Rsa4096KeyLength = 4096;

        /// <summary>
        /// The DID supported RSA key lengths. These are used to generate keys for testing.
        /// </summary>
        public static int[] RsaKeyLengthConstants => [ Rsa2048KeyLength, Rsa4096KeyLength ];

        /// <summary>
        /// Turns the RSA key length into <see cref="Base58BtcEncodedMulticodecHeaders"/>.
        /// </summary>
        /// <param name="keyLength">The RSA key length.</param>
        /// <returns><see cref="Base58BtcEncodedMulticodecHeaders">Public and private Base58 BTC encoded multicodec values</see>.</returns>
        /// <exception cref="NotSupportedException"></exception>
        public static (string PublicKey, string PrivateKey) FromKeyLengthToBtc58EncodedHeader(int keyLength) => keyLength switch
        {
            Rsa2048KeyLength => (Base58BtcEncodedMulticodecHeaders.RsaPublicKey2048.ToString(), string.Empty),
            Rsa4096KeyLength => (Base58BtcEncodedMulticodecHeaders.RsaPublicKey4096.ToString(), string.Empty),
            _ => throw new NotSupportedException()
        };

        /// <summary>
        /// Turns the RSA key length into <see cref="Base58BtcEncodedMulticodecHeaders"/>.
        /// </summary>
        /// <param name="keyLength">The RSA key length.</param>
        /// <returns><see cref="Base58BtcEncodedMulticodecHeaders">Public and private Base58 BTC encoded multicodec headers</see>.</returns>
        /// <exception cref="NotSupportedException"></exception>
        public static (byte[] PublicKeyHeader, byte[] PrivateKeyHeader) FromKeyLengthToMultiCodecHeader(int keyLength) => keyLength switch
        {
            Rsa2048KeyLength => (MulticodecHeaders.RsaPublicKey.ToArray(), []),
            Rsa4096KeyLength => (MulticodecHeaders.RsaPublicKey.ToArray(), []),
            _ => throw new NotSupportedException()
        };

        /// <summary>
        /// Provides the RSA test data for MSTest DynamicData.
        /// </summary>
        /// <returns>An IEnumerable of object arrays containing RSA test data.</returns>
        public static IEnumerable<object[]> GetRsaTestData()
        {
            foreach(int keyLength in RsaKeyLengthConstants)
            {
                var rsaKey = GenerateRsaTestKeyMaterial(keyLength);
                yield return new object[] { rsaKey };
            }
        }

        /// <summary>
        /// Generates RSA test key material based on key length.
        /// </summary>
        /// <param name="keyLength">The key length.</param>
        /// <returns>An <see cref="RsaTestData"/> instance.</returns>
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
