using System;
using System.ComponentModel;
using System.Diagnostics;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents a public key encoded in hexadecimal format.
    /// </summary>
    /// <remarks>
    /// Hexadecimal encoding provides a straightforward representation of binary key material
    /// using base-16 encoding with characters 0-9 and A-F (case insensitive). This format
    /// is commonly used in cryptographic applications for its simplicity and readability
    /// while maintaining a direct correspondence to the underlying binary data.
    /// </remarks>
    [DebuggerDisplay("PublicKeyHex({Key,nq})")]
    [Obsolete("Use PublicKeyMultibase or PublicKeyJwk instead. Hexadecimal keys are not recommended for new implementations.")]
    public class PublicKeyHex: KeyFormat
    {
        /// <summary>
        /// The hexadecimal-encoded public key string.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This property contains the complete hexadecimal representation of the public key
        /// using base-16 encoding. The string should contain only valid hexadecimal characters
        /// (0-9, A-F, a-f) representing the raw public key bytes.
        /// </para>
        /// <para>
        /// The format does not include any prefix indicators (such as "0x") and represents
        /// the key material directly. The exact structure and length of the hexadecimal
        /// string depends on the specific cryptographic algorithm and key type being used.
        /// </para>
        /// <para>
        /// Example hexadecimal-encoded Ed25519 public key (32 bytes = 64 hex characters):
        /// <c>d75a980182b10ab7d54bfed3c964071a0ee172f3daa62325af021a68f707511a</c>
        /// </para>
        /// <para>
        /// Example hexadecimal-encoded secp256k1 public key (compressed, 33 bytes = 66 hex characters):
        /// <c>0258a8b9a7e3c5c24a8b9d6e5f4c3b2a1908f7e6d5c4b3a2918e7d6c5b4a39281</c>
        /// </para>
        /// </remarks>
        public string Key { get; set; }


        /// <summary>
        /// Initializes a new instance of the <see cref="PublicKeyHex"/> class with the specified key.
        /// </summary>
        /// <param name="key">The hexadecimal-encoded public key string.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This constructor performs basic validation to ensure the key parameter is not null,
        /// but does not validate the format or content of the hexadecimal string. Format validation
        /// is typically performed by cryptographic conversion functions when the key material
        /// is actually used for cryptographic operations.
        /// </para>
        /// <para>
        /// The provided key should be a valid hexadecimal string containing only characters
        /// 0-9, A-F, or a-f. The length should be appropriate for the specific cryptographic
        /// algorithm being used (typically an even number of characters representing whole bytes).
        /// </para>
        /// </remarks>
        /// <example>
        /// <code>
        /// //Create a PublicKeyHex with an Ed25519 key.
        /// var hexKey = new PublicKeyHex("d75a980182b10ab7d54bfed3c964071a0ee172f3daa62325af021a68f707511a");
        ///
        /// //Create a PublicKeyHex with a secp256k1 compressed public key.
        /// var secp256k1Key = new PublicKeyHex("0258a8b9a7e3c5c24a8b9d6e5f4c3b2a1908f7e6d5c4b3a2918e7d6c5b4a39281");
        /// </code>
        /// </example>
        public PublicKeyHex(string key)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            Key = key;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(KeyFormat? other)
        {
            if(other is not PublicKeyHex hex)
            {
                return false;
            }

            if(ReferenceEquals(this, hex))
            {
                return true;
            }

            return string.Equals(Key, hex.Key, StringComparison.OrdinalIgnoreCase);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            return Key.GetHashCode(StringComparison.InvariantCultureIgnoreCase);
        }
    }
}