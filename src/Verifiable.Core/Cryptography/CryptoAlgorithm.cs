using System;
using System.Collections.Generic;
using System.Linq;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// This record represents different cryptographic algorithms that are used to generate key material.
    /// Each algorithm is represented by an integer constant.
    /// </summary>
    public sealed class CryptoAlgorithm
    {
        /// <summary>
        /// Secp256k1.
        /// Corresponds to <see cref="MulticodecHeaders.Secp256k1PublicKey"/> when used
        /// with <see cref="Purpose.Public"/>, and <see cref="WellKnownJwaValues.Es256k1"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Secp256k1 { get; } = new CryptoAlgorithm(0);

        /// <summary>
        /// BLS12-381 in the G1 field.
        /// Corresponds to <see cref="MulticodecHeaders.Bls12381G1PublicKey"/>  when used
        /// with <see cref="Purpose.Public"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in<see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Bls12381G1 { get; } = new CryptoAlgorithm(1);

        /// <summary>
        /// BLS12-381 in the G2 field.
        /// Corresponds to <see cref="MulticodecHeaders.Bls12381G2PublicKey"/>  when used
        /// with <see cref="Purpose.Public"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Bls12381G2 { get; } = new CryptoAlgorithm(2);

        /// <summary>
        /// Curve25519.
        /// Corresponds to <see cref="MulticodecHeaders.X25519PublicKey"/>  when used
        /// with <see cref="Purpose.Public"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm X25519 { get; } = new CryptoAlgorithm(3);

        /// <summary>
        /// Ed25519.
        /// Corresponds to <see cref="MulticodecHeaders.Ed25519PublicKey"/> and <see cref="WellKnownJwaValues.EdDsa"/>  when used
        /// with <see cref="Purpose.Public"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Ed25519 { get; } = new CryptoAlgorithm(4);

        /// <summary>
        /// BLS12-381 in the G1 and G2 fields.
        /// Corresponds to <see cref="MulticodecHeaders.Bls12381G1G2PublicKey"/>  when used
        /// with <see cref="Purpose.Public"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Bls12381G1G2 { get; } = new CryptoAlgorithm(5);

        /// <summary>
        /// P-256.
        /// Corresponds to <see cref="MulticodecHeaders.P256PublicKey"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/> when used
        /// with <see cref="Purpose.Public"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm P256 { get; } = new CryptoAlgorithm(6);

        /// <summary>
        /// P-384.
        /// Corresponds to <see cref="MulticodecHeaders.P384PublicKey"/>  when used
        /// with <see cref="Purpose.Public"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm P384 { get; } = new CryptoAlgorithm(7);

        /// <summary>
        /// P-512.
        /// Corresponds to <see cref="MulticodecHeaders.P521PublicKey"/>  when used
        /// with <see cref="Purpose.Public"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm P521 { get; } = new CryptoAlgorithm(8);

        /// <summary>
        /// RSA 2048.
        /// Corresponds to <see cref="MulticodecHeaders.RsaPublicKey"/>  when used
        /// with <see cref="Purpose.Public"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Rsa2048 { get; } = new CryptoAlgorithm(9);

        /// <summary>
        /// RSA 4096.
        /// Corresponds to <see cref="MulticodecHeaders.RsaPublicKey"/>  when used
        /// with <see cref="Purpose.Public"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Rsa4096 { get; } = new CryptoAlgorithm(10);


        /// <summary>
        /// Windows Platform encryption provider.
        /// </summary>        
        /// </remarks>
        public static CryptoAlgorithm WindowsPlatformEncrypted { get; } = new CryptoAlgorithm(11);

        private static List<CryptoAlgorithm> algorithms = new List<CryptoAlgorithm>(new[] { Rsa2048 });

        public static IReadOnlyList<CryptoAlgorithm> Algorithms => algorithms.AsReadOnly();

        public int Algorithm { get; }

        private CryptoAlgorithm(int algorithm)
        {
            Algorithm = algorithm;
        }

        public static CryptoAlgorithm Create(int algorithm)
        {
            if(algorithms.Any(p => p.Algorithm == algorithm))
            {
                throw new ArgumentException("Code already exists.");
            }

            var newAlgorithm = new CryptoAlgorithm(algorithm);
            algorithms.Add(newAlgorithm);

            return newAlgorithm;
        }
    }
}
