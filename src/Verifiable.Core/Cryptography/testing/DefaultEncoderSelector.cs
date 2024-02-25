using System;
using System.Security.Cryptography;
using Verifiable.Core;

namespace Verifiable.Cryptography
{
    public delegate BufferAllocationEncodeDelegate EncoderSelector(Type keyFormatType);

    /// <summary>
    /// <para>Provides a way to select the correct encoder for a given key format type in the context of 
    /// decentralized identifiers (DIDs) and verifiable credentials.</para>
    /// 
    /// <para>Key formats often require specific encoding strategies to correctly transform cryptographic 
    /// key material into a suitable format for use in DID and verifiable credentials systems. The 
    /// <see cref="DefaultEncoderSelector"/> allows developers to specify a function that selects the 
    /// appropriate encoder based on the key format type.</para>
    /// 
    /// <para>This class must be initialized before use by using the <see cref="CryptoLibrary.InitializeProviders"/>.</para>
    /// 
    /// <para>Not all key formats will require an encoder. The encoder selector function should return null 
    /// for key formats that do not require encoding.</para>
    /// </summary>
    public static class DefaultEncoderSelector
    {
        /// <summary>
        /// <para>Gets or sets a delegate that selects an encoder based on a given key format type.
        /// If the format type is known to <c>Verifiable</c>, it is enumerated in <see cref="WellKnownKeyFormats"/>.
        /// </para>
        /// 
        /// <para>The delegate receives the type of the key format and returns a delegate that can 
        /// perform the required encoding operation. If the key format does not require encoding, 
        /// the delegate should return null.</para>
        /// 
        /// <para>This property must be set to a valid delegate before it is used. If it is not set, 
        /// an <see cref="InvalidOperationException"/> will be thrown when it is accessed.</para>
        /// </summary>
        public static EncoderSelector Select { get; set; } = (Type keyFormatType) =>
        {
            throw new InvalidOperationException($"The {nameof(Select)} delegate has not been initialized. Please initialize it by using the {nameof(CryptoLibrary.InitializeProviders)} method before using it.");
        };
    }



    public delegate byte[] HashFunction(byte[] input);
    public delegate HashFunction HashFunctionSelector(HashAlgorithmName hashAlgorithm);

    public static class DefaultHashFunctionSelector
    {
        public static HashFunctionSelector Select { get; set; } = (HashAlgorithmName hashAlgorithm) =>
        {
            if(hashAlgorithm.Equals(HashAlgorithmName.SHA256))
            {
                return SHA256.HashData;
            }
            else
            {
                throw new ArgumentException($"No hash function available for hash algorithm: {hashAlgorithm}");
            }
        };
    };


    public static class CryptoLibrary
    {
        public static void InitializeProviders(BufferAllocationEncodeDelegate base58BtcEncoder, HashFunction sha256Implementation)
        {
            InitializerProviders(keyFormatType =>
            {
                //TODO: Here base58BtcEncoder for PublicKeyJwk works because it's not actually used. It's just a placeholder when
                //MultibaseSerializer.DefaultKeyFormatCreator is used to create default key format.
                return keyFormatType switch
                {
                    var kt when keyFormatType == WellKnownKeyFormats.PublicKeyMultibase => base58BtcEncoder,
                    var kt when keyFormatType == WellKnownKeyFormats.PublicKeyBase58 => base58BtcEncoder,
                    var kt when keyFormatType == WellKnownKeyFormats.PublicKeyJwk => base58BtcEncoder,
                    _ => throw new ArgumentException($"No encoder available for key format: {keyFormatType}")
                };
            },
            hashAlgorithm =>
            {
                if(hashAlgorithm.Equals(HashAlgorithmName.SHA256))
                {
                    return sha256Implementation;
                }
                else
                {
                    throw new ArgumentException($"No hash function available for hash algorithm: {hashAlgorithm}");
                }
            });
        }


        public static void InitializerProviders(EncoderSelector encoderSelector, HashFunctionSelector hashFunctionSelector)
        {
            DefaultEncoderSelector.Select = encoderSelector;
            DefaultHashFunctionSelector.Select = hashFunctionSelector;
        }
    }
}
