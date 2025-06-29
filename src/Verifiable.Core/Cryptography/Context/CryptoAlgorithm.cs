using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;


namespace Verifiable.Core.Cryptography.Context
{
    [AttributeUsage(AttributeTargets.Property, Inherited = false, AllowMultiple = false)]
    public sealed class CryptoAlgorithmRegistrationAttribute: Attribute
    {
    }


    /// <summary>
    /// This record represents different cryptographic algorithms that are used to generate key material.
    /// Each algorithm is represented by an integer constant.
    /// </summary>
    /// <remarks>
    /// This class is part of a structured tagging mechanism designed to clearly
    /// define cryptographic contexts without relying on OIDs, JWT values, or other
    /// identifiers that could be ambiguous over time or need extensive parsing. This works in
    /// conjunction with <see cref="EncodingScheme"/> and <see cref="Purpose"/>
    /// to provide a comprehensive framework for representing and manipulating
    /// cryptographic material.
    /// </remarks>
    [DebuggerDisplay("{CryptoAlgorithmNames.GetName(this),nq}")]
    public readonly struct CryptoAlgorithm: IEquatable<CryptoAlgorithm>
    {
        /// <summary>
        /// Secp256k1.
        /// Corresponds to <see cref="MulticodecHeaders.Secp256k1PublicKey"/> when used
        /// with <see cref="Purpose.Verification"/>, and <see cref="WellKnownJwaValues.Es256k1"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        [CryptoAlgorithmRegistration]
        public static CryptoAlgorithm Secp256k1 { get; } = new CryptoAlgorithm(0);

        /// <summary>
        /// BLS12-381 in the G1 field.
        /// Corresponds to <see cref="MulticodecHeaders.Bls12381G1PublicKey"/>  when used
        /// with <see cref="Purpose.Verification"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in<see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Bls12381G1 { get; } = new CryptoAlgorithm(1);

        /// <summary>
        /// BLS12-381 in the G2 field.
        /// Corresponds to <see cref="MulticodecHeaders.Bls12381G2PublicKey"/>  when used
        /// with <see cref="Purpose.Verification"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Bls12381G2 { get; } = new CryptoAlgorithm(2);

        /// <summary>
        /// Curve25519.
        /// Corresponds to <see cref="MulticodecHeaders.X25519PublicKey"/>  when used
        /// with <see cref="Purpose.Verification"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm X25519 { get; } = new CryptoAlgorithm(3);

        /// <summary>
        /// Ed25519.
        /// Corresponds to <see cref="MulticodecHeaders.Ed25519PublicKey"/> and <see cref="WellKnownJwaValues.EdDsa"/>  when used
        /// with <see cref="Purpose.Verification"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Ed25519 { get; } = new CryptoAlgorithm(4);

        /// <summary>
        /// BLS12-381 in the G1 and G2 fields.
        /// Corresponds to <see cref="MulticodecHeaders.Bls12381G1G2PublicKey"/>  when used
        /// with <see cref="Purpose.Verification"/>.
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
        /// with <see cref="Purpose.Verification"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm P256 { get; } = new CryptoAlgorithm(6);

        /// <summary>
        /// P-384.
        /// Corresponds to <see cref="MulticodecHeaders.P384PublicKey"/>  when used
        /// with <see cref="Purpose.Verification"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm P384 { get; } = new CryptoAlgorithm(7);

        /// <summary>
        /// P-512.
        /// Corresponds to <see cref="MulticodecHeaders.P521PublicKey"/>  when used
        /// with <see cref="Purpose.Verification"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm P521 { get; } = new CryptoAlgorithm(8);

        /// <summary>
        /// RSA 2048.
        /// Corresponds to <see cref="MulticodecHeaders.RsaPublicKey"/>  when used
        /// with <see cref="Purpose.Verification"/>.
        /// </summary>
        /// <remarks>
        /// Purpose (e.g. public or private key) is defined in <see cref="Purpose"/>.
        /// Encoding method is defined in <see cref="EncodingScheme"/>.
        /// </remarks>
        public static CryptoAlgorithm Rsa2048 { get; } = new CryptoAlgorithm(9);

        /// <summary>
        /// RSA 4096.
        /// Corresponds to <see cref="MulticodecHeaders.RsaPublicKey"/>  when used
        /// with <see cref="Purpose.Verification"/>.
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

        private static List<CryptoAlgorithm> algorithms = new([Rsa2048]);

        public static IReadOnlyList<CryptoAlgorithm> Algorithms => algorithms.AsReadOnly();

        public int Algorithm { get; }

        public static CryptoAlgorithm Create(int algorithm)
        {
            for(int i = 0; i < algorithms.Count; ++i)
            {
                if(algorithms[i].Algorithm == algorithm)
                {
                    throw new ArgumentException("Code already exists.");
                }
            }

            var newAlgorithm = new CryptoAlgorithm(algorithm);
            algorithms.Add(newAlgorithm);

            return newAlgorithm;
        }


        /// <ihertidoc />
        public override string ToString() => CryptoAlgorithmNames.GetName(this);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(CryptoAlgorithm other)
        {
            return Algorithm == other.Algorithm;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? o) => o is CryptoAlgorithm cryptoAlgorithm && Equals(cryptoAlgorithm);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in CryptoAlgorithm cryptoAlgorithm1, in CryptoAlgorithm cryptoAlgorithm2) => Equals(cryptoAlgorithm1, cryptoAlgorithm2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in CryptoAlgorithm cryptoAlgorithm1, in CryptoAlgorithm cryptoAlgorithm2) => !Equals(cryptoAlgorithm1, cryptoAlgorithm2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in object cryptoAlgorithm1, in CryptoAlgorithm cryptoAlgorithm2) => Equals(cryptoAlgorithm1, cryptoAlgorithm2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in CryptoAlgorithm cryptoAlgorithm1, in object cryptoAlgorithm2) => Equals(cryptoAlgorithm1, cryptoAlgorithm2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in object cryptoAlgorithm1, in CryptoAlgorithm cryptoAlgorithm2) => !Equals(cryptoAlgorithm1, cryptoAlgorithm2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in CryptoAlgorithm cryptoAlgorithm1, in object cryptoAlgorithm2) => !Equals(cryptoAlgorithm1, cryptoAlgorithm2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            return base.GetHashCode();

        }

        private CryptoAlgorithm(int algorithm)
        {
            Algorithm = algorithm;
        }
    }


    public static class CryptoAlgorithmNames
    {
        public static string GetName(CryptoAlgorithm algorithm) => GetName(algorithm.Algorithm);


        public static string GetName(int algorithm) => algorithm switch
        {
            var a when a == CryptoAlgorithm.Secp256k1.Algorithm => nameof(CryptoAlgorithm.Secp256k1),
            var a when a == CryptoAlgorithm.Bls12381G1.Algorithm => nameof(CryptoAlgorithm.Bls12381G1),
            var a when a == CryptoAlgorithm.Bls12381G2.Algorithm => nameof(CryptoAlgorithm.Bls12381G2),
            var a when a == CryptoAlgorithm.X25519.Algorithm => nameof(CryptoAlgorithm.X25519),
            var a when a == CryptoAlgorithm.Ed25519.Algorithm => nameof(CryptoAlgorithm.Ed25519),
            var a when a == CryptoAlgorithm.Bls12381G1G2.Algorithm => nameof(CryptoAlgorithm.Bls12381G1G2),
            var a when a == CryptoAlgorithm.P256.Algorithm => nameof(CryptoAlgorithm.P256),
            var a when a == CryptoAlgorithm.P384.Algorithm => nameof(CryptoAlgorithm.P384),
            var a when a == CryptoAlgorithm.P521.Algorithm => nameof(CryptoAlgorithm.P521),
            var a when a  == CryptoAlgorithm.Rsa2048.Algorithm => nameof(CryptoAlgorithm.Rsa2048),
            var a when a  == CryptoAlgorithm.Rsa4096.Algorithm => nameof(CryptoAlgorithm.Rsa4096),
            var a when a  == CryptoAlgorithm.WindowsPlatformEncrypted.Algorithm => nameof(CryptoAlgorithm.WindowsPlatformEncrypted),
            _ => $"Unknown ({algorithm})"
        };
    }
}
