using System;

namespace Verifiable.Core
{
    /// <summary>
    /// These are headers for multicodec header values when they are Base58 encoded in BTC flavor.
    /// </summary>
    public static class Base58BtcEncodedMulticodecHeaders
	{                        
        /// <summary>
        /// Corresponds to <see cref="MulticodecHeaders.Secp256k1PublicKey"/> in Base58 BTC encoding.
        /// </summary>        
        public static ReadOnlySpan<char> Secp256k1PublicKey => "zQ3s";
        
		/// <summary>
		/// Corresponds to <see cref="MulticodecHeaders.Bls12381G2PublicKey"/> in Base58 BTC encoding.
		/// </summary>		
		public static ReadOnlySpan<char> Bls12381G2PublicKey => "zUC7";

		/// <summary>
		/// Corresponds to <see cref="MulticodecHeaders.X25519PublicKey"/> in Base58 BTC encoding.
		/// </summary>		
		public static ReadOnlySpan<char> X25519PublicKey => "z6LS";

        /// <summary>
		/// Corresponds to <see cref="MulticodecHeaders.X25519PrivateKey"/> in Base58 BTC encoding.
		/// </summary>		
		public static ReadOnlySpan<char> X25519PrivateKey => "z3we";
        
		/// <summary>
		/// Corresponds to <see cref="MulticodecHeaders.Ed25519PublicKey"/> in Base58 BTC encoding.
		/// </summary>
		public static ReadOnlySpan<char> Ed25519PublicKey => "z6Mk";

        /// <summary>
		/// Corresponds to <see cref="MulticodecHeaders.Ed25519PrivateKey"/> in Base58 BTC encoding.
		/// </summary>
        public static ReadOnlySpan<char> Ed25519PrivateKey => "z3u2";
		
		/// <summary>
		/// Corresponds to <see cref="MulticodecHeaders.P256PublicKey"/> in Base58 BTC encoding.
		/// </summary>		
		public static ReadOnlySpan<char> P256PublicKey => "zDn";

		/// <summary>
		/// Corresponds to <see cref="MulticodecHeaders.P384PublicKey"/> in Base58 BTC encoding.
		/// </summary>		
		public static ReadOnlySpan<char> P384PublicKey => "z82";

		/// <summary>
		/// Corresponds to <see cref="MulticodecHeaders.P521PublicKey"/> in Base58 BTC encoding.
		/// </summary>		
		public static ReadOnlySpan<char> P521PublicKey => "z2J9";

		/// <summary>
		/// Corresponds to <see cref="MulticodecHeaders.RsaPublicKey"/> in RSA 2048 bit Base58 BTC encoding.
		/// </summary>
		public static ReadOnlySpan<char> RsaPublicKey2048 => "z4MX";

		/// <summary>
		/// Corresponds to <see cref="MulticodecHeaders.RsaPublicKey"/> in RSA 4096 bit Base58 BTC encoding.
		/// </summary>
		public static ReadOnlySpan<char> RsaPublicKey4096 => "zgg";


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is Secp256k1 public key.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the Secp256k1 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsSecp256k1PublicKey(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, Secp256k1PublicKey);


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is BLS12-381 G2 public key.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the BLS12-381 G2 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsBls12381G2PublicKey(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, Bls12381G2PublicKey);


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is X25519 public key.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the X25519 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsX25519PublicKey(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, X25519PublicKey);


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is X25519 private key.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the X25519 private key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsX25519PrivateKey(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, X25519PrivateKey);


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is Ed25519 public key.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the Ed25519 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsEd25519PublicKey(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, Ed25519PublicKey);


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is Ed25519 private key.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the Ed25519 private key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsEd25519PrivateKey(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, Ed25519PrivateKey);


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is P256 public key.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the P256 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsP256PublicKey(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, P256PublicKey);


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is P384 public key.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the P384 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsP384PublicKey(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, P384PublicKey);


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is P521 public key.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the P521 public key header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsP521PublicKey(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, P521PublicKey);


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is RSA public key (2048-bit).
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the RSA public key (2048-bit) header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsRsaPublicKey2048(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, RsaPublicKey2048);


        /// <summary>
        /// Returns a value that indicates if the Base58 BTC encoded material is RSA public key (4096-bit).
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the RSA public key (4096-bit) header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsRsaPublicKey4096(ReadOnlySpan<char> base58Material) => IsBase58Header(base58Material, RsaPublicKey4096);


        /// <summary>
        /// Returns the equivalent static instance of the provided Base58 BTC encoded material, or the original if none match.
        /// This conversion is optional but allows for performance optimizations.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <returns>The equivalent static instance if one matches; otherwise, the original.</returns>
        public static ReadOnlySpan<char> GetCanonicalizedHeader(ReadOnlySpan<char> base58Material) => base58Material switch
        {
            _ when IsSecp256k1PublicKey(base58Material) => Secp256k1PublicKey,
            _ when IsBls12381G2PublicKey(base58Material) => Bls12381G2PublicKey,
            _ when IsBase58Header(base58Material, X25519PublicKey) => X25519PublicKey,
            _ when IsBase58Header(base58Material, X25519PrivateKey) => X25519PrivateKey,
            _ when IsBase58Header(base58Material, Ed25519PublicKey) => Ed25519PublicKey,
            _ when IsBase58Header(base58Material, Ed25519PrivateKey) => Ed25519PrivateKey,
            _ when IsBase58Header(base58Material, P256PublicKey) => P256PublicKey,
            _ when IsBase58Header(base58Material, P384PublicKey) => P384PublicKey,
            _ when IsBase58Header(base58Material, P521PublicKey) => P521PublicKey,
            _ when IsBase58Header(base58Material, RsaPublicKey2048) => RsaPublicKey2048,
            _ when IsBase58Header(base58Material, RsaPublicKey4096) => RsaPublicKey4096,
            _ => base58Material
        };


        /// <summary>
        /// Returns a value that indicates if two Base58 BTC encoded headers are equal.
        /// </summary>
        /// <param name="headerA">The first Base58 BTC encoded header to compare.</param>
        /// <param name="headerB">The second Base58 BTC encoded header to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the headers are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(ReadOnlySpan<char> headerA, ReadOnlySpan<char> headerB) => headerA.SequenceEqual(headerB);


        /// <summary>
        /// Returns a value that indicates if the provided material matches the specified Base58 BTC encoded multicodec header.
        /// </summary>
        /// <param name="base58Material">The Base58 BTC encoded material to evaluate.</param>
        /// <param name="header">The Base58 BTC encoded header to compare against.</param>
        /// <returns>
        /// <see langword="true" /> if the material matches the specified header; otherwise, <see langword="false" />.
        /// </returns>
        public static bool IsBase58Header(ReadOnlySpan<char> base58Material, ReadOnlySpan<char> header) => base58Material.SequenceEqual(header);
    }
}
