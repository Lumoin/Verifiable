using System;
using System.ComponentModel;
using System.Diagnostics;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents a public key encoded in Base58 format.
    /// </summary>
    /// <remarks>
    /// Base58 encoding is a binary-to-text encoding scheme that uses a 58-character alphabet
    /// designed to avoid visually similar characters (0, O, I, l) and non-alphanumeric characters,
    /// making it more human-friendly for manual entry and verification. This encoding is commonly
    /// used in cryptocurrency applications and some DID methods for representing cryptographic
    /// key material in a compact, readable format.
    /// </remarks>
    [DebuggerDisplay("PublicKeyBase58({Key,nq})")]
    [Obsolete("Use PublicKeyMultibase instead, as it is more versatile and widely supported in DID contexts.")]
    public class PublicKeyBase58: KeyFormat
    {
        /// <summary>
        /// The Base58-encoded public key string.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This property contains the complete Base58-encoded representation of the public key
        /// using the standard Base58 alphabet. The encoding provides a compact representation
        /// of binary key material while avoiding characters that might be confusing when
        /// manually transcribed or displayed.
        /// </para>
        /// <para>
        /// The Base58 alphabet consists of the following 58 characters:
        /// <c>123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz</c>
        /// </para>
        /// <para>
        /// Unlike multibase encoding, Base58 format typically does not include prefix
        /// characters to identify the encoding scheme, as the encoding is implicit from
        /// the context in which it is used. The exact structure and length of the
        /// Base58 string depends on the specific cryptographic algorithm and key type.
        /// </para>
        /// <para>
        /// Example Base58-encoded Ed25519 public key:
        /// <c>H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV</c>
        /// </para>
        /// <para>
        /// Example Base58-encoded secp256k1 public key:
        /// <c>4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM</c>
        /// </para>
        /// </remarks>
        public string Key { get; set; }


        /// <summary>
        /// Initializes a new instance of the <see cref="PublicKeyBase58"/> class with the specified key.
        /// </summary>
        /// <param name="key">The Base58-encoded public key string.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This constructor performs basic validation to ensure the key parameter is not null,
        /// but does not validate the format or content of the Base58 string. Format validation
        /// is typically performed by cryptographic decoding functions when the key material
        /// is actually used for cryptographic operations.
        /// </para>
        /// <para>
        /// The provided key should be a valid Base58 string containing only characters from
        /// the Base58 alphabet. The length should be appropriate for the specific cryptographic
        /// algorithm being used, though this varies based on the key type and any additional
        /// encoding layers that may be present.
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// //Create a PublicKeyBase58 with an Ed25519 key.
        /// var base58Key = new PublicKeyBase58("H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV");
        ///
        /// //Create a PublicKeyBase58 with a secp256k1 key.
        /// var secp256k1Key = new PublicKeyBase58("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM");
        /// </code>
        /// </example>
        public PublicKeyBase58(string key)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            Key = key;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(KeyFormat? other)
        {
            if(other is not PublicKeyBase58 base58)
            {
                return false;
            }

            if(ReferenceEquals(this, base58))
            {
                return true;
            }

            return string.Equals(Key, base58.Key, StringComparison.Ordinal);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            return Key.GetHashCode(StringComparison.InvariantCulture);
        }
    }
}