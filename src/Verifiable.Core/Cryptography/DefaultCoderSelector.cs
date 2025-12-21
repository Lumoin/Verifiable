using System;
using System.Security.Cryptography;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Delegate that selects an encoder based on a given key format type.
    /// </summary>
    /// <param name="keyFormatType">The type of the key format.</param>
    /// <returns>An encoding delegate for the specified format.</returns>
    public delegate EncodeDelegate EncoderSelector(Type keyFormatType);

    /// <summary>
    /// Delegate that selects a decoder based on a given key format type.
    /// </summary>
    /// <param name="keyFormatType">The type of the key format.</param>
    /// <returns>A decoding delegate for the specified format.</returns>
    public delegate DecodeDelegate DecoderSelector(Type keyFormatType);


    /// <summary>
    /// Provides a way to select the correct encoder or decoder for a given key format type.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Key formats often require specific encoding strategies to correctly transform cryptographic
    /// key material into a suitable format. The <see cref="DefaultCoderSelector"/> allows developers
    /// to specify a function that selects the appropriate encoder or decoder based on the key format type.
    /// </para>
    /// <para>
    /// This class must be initialized before use by calling <see cref="CryptoLibrary.InitializeProviders"/>.
    /// </para>
    /// <para>
    /// Not all key formats require an encoder. The encoder selector function should throw for
    /// key formats that are not supported.
    /// </para>
    /// </remarks>
    public static class DefaultCoderSelector
    {
        /// <summary>
        /// Gets or sets a delegate that selects an encoder based on a given key format type.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The delegate receives the type of the key format and returns a delegate that can
        /// perform the required encoding operation.
        /// </para>
        /// <para>
        /// This property must be set to a valid delegate before it is used. If it is not set,
        /// an <see cref="InvalidOperationException"/> will be thrown when it is accessed.
        /// </para>
        /// </remarks>
        public static EncoderSelector SelectEncoder { get; set; } = (Type keyFormatType) =>
        {
            throw new InvalidOperationException($"The {nameof(SelectEncoder)} delegate has not been initialized. Please initialize it by using the {nameof(CryptoLibrary.InitializeProviders)} method before using it.");
        };

        /// <summary>
        /// Gets or sets a delegate that selects a decoder based on a given key format type.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The delegate receives the type of the key format and returns a delegate that can
        /// perform the required decoding operation.
        /// </para>
        /// <para>
        /// This property must be set to a valid delegate before it is used. If it is not set,
        /// an <see cref="InvalidOperationException"/> will be thrown when it is accessed.
        /// </para>
        /// </remarks>
        public static DecoderSelector SelectDecoder { get; set; } = (Type keyFormatType) =>
        {
            throw new InvalidOperationException($"The {nameof(SelectDecoder)} delegate has not been initialized. Please initialize it by using the {nameof(CryptoLibrary.InitializeProviders)} method before using it.");
        };
    }


    /// <summary>
    /// Delegate that computes a hash of the input data.
    /// </summary>
    /// <param name="input">The data to hash.</param>
    /// <returns>The hash of the input data.</returns>
    public delegate byte[] HashFunction(byte[] input);

    /// <summary>
    /// Delegate that selects a hash function based on a given hash algorithm.
    /// </summary>
    /// <param name="hashAlgorithm">The hash algorithm to use.</param>
    /// <returns>A hash function for the specified algorithm.</returns>
    public delegate HashFunction HashFunctionSelector(HashAlgorithmName hashAlgorithm);


    /// <summary>
    /// Provides a way to select the correct hash function for a given hash algorithm.
    /// </summary>
    public static class DefaultHashFunctionSelector
    {
        /// <summary>
        /// Gets or sets a delegate that selects a hash function based on a given hash algorithm.
        /// </summary>
        public static HashFunctionSelector Select { get; set; } = (HashAlgorithmName hashAlgorithm) =>
        {
            if(hashAlgorithm.Equals(HashAlgorithmName.SHA256))
            {
                return SHA256.HashData;
            }
            else
            {
                throw new ArgumentException($"No hash function available for hash algorithm: {hashAlgorithm}.");
            }
        };
    }


    /// <summary>
    /// Provides methods to initialize cryptographic providers.
    /// </summary>
    public static class CryptoLibrary
    {
        /// <summary>
        /// Initializes the cryptographic providers with the specified selectors.
        /// </summary>
        /// <param name="encoderSelector">A delegate that selects encoders based on key format type.</param>
        /// <param name="decoderSelector">A delegate that selects decoders based on key format type.</param>
        /// <param name="hashFunctionSelector">A delegate that selects hash functions based on algorithm.</param>
        public static void InitializeProviders(EncoderSelector encoderSelector, DecoderSelector decoderSelector, HashFunctionSelector hashFunctionSelector)
        {
            DefaultCoderSelector.SelectEncoder = encoderSelector;
            DefaultCoderSelector.SelectDecoder = decoderSelector;
            DefaultHashFunctionSelector.Select = hashFunctionSelector;
        }
    }
}