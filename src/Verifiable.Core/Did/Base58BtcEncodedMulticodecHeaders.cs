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
    }
}
