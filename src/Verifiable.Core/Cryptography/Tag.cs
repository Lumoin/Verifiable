using System;
using System.Collections.Generic;
using System.Diagnostics;
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
    [DebuggerDisplay("{DebuggerView,nq}")]
    public record Tag(IReadOnlyDictionary<Type, object> Data)
    {
        /// <summary>
        /// And empty tag.
        /// </summary>
        public static Tag Empty { get; } = new(new Dictionary<Type, object>());


        /// <summary>
        /// Retrieves a value from the tag, inferring the key from the generic type.
        /// </summary>
        /// <typeparam name="T">The type of the value to retrieve.</typeparam>
        /// <returns>The value associated with the type key, cast to the specified type.</returns>
        /// <exception cref="InvalidCastException">Thrown if the value cannot be cast to the specified type.</exception>
        /// <exception cref="KeyNotFoundException">Thrown if the key is not found in the dictionary.</exception>
        public T Get<T>()
        {
            Type key = typeof(T);
            if(!Data.TryGetValue(key, out object? value))
            {
                throw new KeyNotFoundException($"Key '{key}' was not found in the tag's data.");
            }

            if(value is not T typedValue)
            {
                throw new InvalidCastException($"Value for key '{key}' is not of type '{typeof(T)}'.");
            }

            return typedValue;
        }

        public static Tag P256PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P256,
            [typeof(Purpose)] = Purpose.Verification,
            [typeof(EncodingScheme)] = EncodingScheme.EcCompressed
        });

        public static Tag P256PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P256,
            [typeof(Purpose)] = Purpose.Signing,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag P256Signature { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P256,
            [typeof(Purpose)] = Purpose.Signature,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag P384PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P384,
            [typeof(Purpose)] = Purpose.Verification,
            [typeof(EncodingScheme)] = EncodingScheme.EcCompressed
        });

        public static Tag P384PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P384,
            [typeof(Purpose)] = Purpose.Signing,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag P384Signature { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P384,
            [typeof(Purpose)] = Purpose.Signature,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag P521PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P521,
            [typeof(Purpose)] = Purpose.Verification,
            [typeof(EncodingScheme)] = EncodingScheme.EcCompressed
        });

        public static Tag P521PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P521,
            [typeof(Purpose)] = Purpose.Signing,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag P521Signature { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P521,
            [typeof(Purpose)] = Purpose.Signature,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag Secp256k1PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Secp256k1,
            [typeof(Purpose)] = Purpose.Verification,
            [typeof(EncodingScheme)] = EncodingScheme.EcCompressed
        });

        public static Tag Secp256k1PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Secp256k1,
            [typeof(Purpose)] = Purpose.Signing,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag Secp256k1Signature { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Secp256k1,
            [typeof(Purpose)] = Purpose.Signature,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag Rsa2048PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Rsa2048,
            [typeof(Purpose)] = Purpose.Verification,
            [typeof(EncodingScheme)] = EncodingScheme.Der
        });

        public static Tag Rsa2048PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Rsa2048,
            [typeof(Purpose)] = Purpose.Signing,
            [typeof(EncodingScheme)] = EncodingScheme.Pkcs1
        });

        public static Tag Rsa4096PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Rsa4096,
            [typeof(Purpose)] = Purpose.Verification,
            [typeof(EncodingScheme)] = EncodingScheme.Der
        });

        public static Tag Rsa4096PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Rsa4096,
            [typeof(Purpose)] = Purpose.Signing,
            [typeof(EncodingScheme)] = EncodingScheme.Pkcs1
        });

        public static Tag Ed25519PublicKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Ed25519,
            [typeof(Purpose)] = Purpose.Verification,
            [typeof(EncodingScheme)] = EncodingScheme.Raw
        });

        public static Tag Ed25519PrivateKey { get; } = new(new Dictionary<Type, object>
        {
            [typeof(CryptoAlgorithm)] = CryptoAlgorithm.Ed25519,
            [typeof(Purpose)] = Purpose.Signing,
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
            [typeof(Purpose)] = Purpose.Signing,
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


        /// <inheritdoc />
        public override string ToString() => TagString;


        /// <summary>
        /// Debugging view of the Tag.
        /// </summary>
        private string DebuggerView
        {
            get
            {
                try
                {
                    return TagString;
                }
                catch
                {
                    return "Tag: (incomplete).";
                }
            }
        }


        private string TagString => $"Tag: Alg={Get<CryptoAlgorithm>()}, Purpose={Get<Purpose>()}, Encoding={Get<EncodingScheme>()}.";
    }
}
