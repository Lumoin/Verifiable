using System;
using System.Collections.Generic;
using Verifiable.Core.Cryptography.Context;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// A type for tagging data with additional out-of-band information.
    /// </summary>
    /// <param name="Data">The metadata associated with the tag.</param>
    /// <remarks>
    /// The Tag is not tightly bound to the data, such as a cryptographic key material. 
    /// Instead, it provides metadata to assist in managing otherwise opaque data blocks. 
    /// This could include identifiers, storage locations (like a trusted platform module or database), 
    /// or data format specifications (such as whether an EC public key is compressed).
    /// Despite the provided metadata, all inputs should be validated.
    /// </remarks>    
    public record Tag(IReadOnlyDictionary<Type, object> Data)
    {
        /// <summary>
        /// And empty tag.
        /// </summary>
        public static Tag Empty { get; } = new(new Dictionary<Type, object>());

        public static Tag P256PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P256,
            [typeof(Purpose)] = Purpose.Public,
            [typeof(EncodingScheme)] = EncodingScheme.EcCompressed
        });

        public static Tag P256PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P256,
            [typeof(Purpose)] = Purpose.Private,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag P384PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P384,
            [typeof(Purpose)] = Purpose.Public,
            [typeof(EncodingScheme)] = EncodingScheme.EcCompressed
        });

        public static Tag P384PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P384,
            [typeof(Purpose)] = Purpose.Private,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag P521PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P521,
            [typeof(Purpose)] = Purpose.Public,
            [typeof(EncodingScheme)] = EncodingScheme.EcCompressed
        });

        public static Tag P521PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P521,
            [typeof(Purpose)] = Purpose.Private,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag Secp256k1PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Secp256k1,
            [typeof(Purpose)] = Purpose.Public,
            [typeof(EncodingScheme)] = EncodingScheme.EcCompressed
        });

        public static Tag Secp256k1PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Secp256k1,
            [typeof(Purpose)] = Purpose.Private,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag Rsa2048PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Rsa2048,
            [typeof(Purpose)] = Purpose.Public,
            [typeof(EncodingScheme)] = EncodingScheme.Der
        });

        public static Tag Rsa2048PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Rsa2048,
            [typeof(Purpose)] = Purpose.Private,
            [typeof(EncodingScheme)] = EncodingScheme.Der
        });

        public static Tag Rsa4096PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Rsa4096,
            [typeof(Purpose)] = Purpose.Public,
            [typeof(EncodingScheme)] = EncodingScheme.Der
        });

        public static Tag Rsa4096PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Rsa4096,
            [typeof(Purpose)] = Purpose.Private,
            [typeof(EncodingScheme)] = EncodingScheme.Der
        });

        public static Tag Ed25519PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Ed25519,
            [typeof(Purpose)] = Purpose.Public,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag Ed25519PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Ed25519,
            [typeof(Purpose)] = Purpose.Private,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag Ed25519Signature { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Ed25519,
            [typeof(Purpose)] = Purpose.Signature,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });


        public static Tag X25519PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.X25519,
            [typeof(Purpose)] = Purpose.Exchange,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag X25519PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.X25519,
            [typeof(Purpose)] = Purpose.Private,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag WindowsPlatformEncrypted { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.WindowsPlatformEncrypted,
            [typeof(Purpose)] = Purpose.Encryption,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });



        /// <summary>
        /// Gets the value associated with the specified key in the Tag data.
        /// </summary>
        /// <param name="key">The key of the value to get.</param>
        /// <returns>The value associated with the specified key. If the specified key is not found, 
        /// a get operation throws a <see cref="KeyNotFoundException"/>.</returns>
        public object this[Type key] => Data[key];
    }
}
