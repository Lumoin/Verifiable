using System;
using System.Security.Cryptography;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Provides convenience methods to initialize cryptographic providers with DID-specific key formats.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class wraps <see cref="CryptoLibrary.InitializeProviders"/> and provides a simpler API
    /// that automatically configures encoders and decoders for well-known DID key formats such as
    /// <see cref="PublicKeyMultibase"/> and <see cref="PublicKeyJwk"/>.
    /// </para>
    /// <para>
    /// For more control over encoder and decoder selection, use
    /// <see cref="CryptoLibrary.InitializeProviders"/> directly.
    /// </para>
    /// </remarks>
    public static class DidCryptoInitializer
    {
        /// <summary>
        /// Initializes the cryptographic providers with default configuration for DID key formats.
        /// </summary>
        /// <param name="base58BtcEncoder">The Base58 BTC encoder delegate.</param>
        /// <param name="base58BtcDecoder">The Base58 BTC decoder delegate.</param>
        /// <param name="sha256Implementation">The SHA-256 hash function implementation.</param>
        /// <remarks>
        /// <para>
        /// This method configures encoders and decoders for the following key formats:
        /// </para>
        /// <list type="bullet">
        /// <item><description><see cref="PublicKeyMultibase"/> - uses Base58 BTC encoding.</description></item>
        /// <item><description><see cref="PublicKeyJwk"/> - uses Base64 URL encoding (via the provided encoder).</description></item>
        /// </list>
        /// </remarks>
        public static void Initialize(EncodeDelegate base58BtcEncoder, DecodeDelegate base58BtcDecoder, HashFunction sha256Implementation)
        {
            CryptoLibrary.InitializeProviders(
                CreateEncoderSelector(base58BtcEncoder),
                CreateDecoderSelector(base58BtcDecoder),
                CreateHashFunctionSelector(sha256Implementation));
        }


        private static EncoderSelector CreateEncoderSelector(EncodeDelegate base58BtcEncoder)
        {
            return keyFormatType => keyFormatType switch
            {
                //TODO: Here base58BtcEncoder for PublicKeyJwk works because it's not actually used. It's just a placeholder when
                //the default key format creator is used.
                Type kt when kt == WellKnownKeyFormats.PublicKeyMultibase => base58BtcEncoder,
                Type kt when kt == WellKnownKeyFormats.PublicKeyJwk => base58BtcEncoder,
                _ => throw new ArgumentException($"No encoder available for key format: {keyFormatType}.")
            };
        }


        private static DecoderSelector CreateDecoderSelector(DecodeDelegate base58BtcDecoder)
        {
            return keyFormatType => keyFormatType switch
            {
                //TODO: Here base58BtcDecoder for PublicKeyJwk works because it's not actually used. It's just a placeholder when
                //the default key format creator is used.
                Type kt when kt == WellKnownKeyFormats.PublicKeyMultibase => base58BtcDecoder,
                Type kt when kt == WellKnownKeyFormats.PublicKeyJwk => base58BtcDecoder,
                _ => throw new ArgumentException($"No decoder available for key format: {keyFormatType}.")
            };
        }


        private static HashFunctionSelector CreateHashFunctionSelector(HashFunction sha256Implementation)
        {
            return hashAlgorithm =>
            {
                if(hashAlgorithm.Equals(HashAlgorithmName.SHA256))
                {
                    return sha256Implementation;
                }

                throw new ArgumentException($"No hash function available for hash algorithm: {hashAlgorithm}.");
            };
        }
    }
}