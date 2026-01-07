using System;
using System.ComponentModel;
using System.Diagnostics;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents a public key encoded using the multibase specification.
    /// </summary>
    /// <remarks>
    /// Multibase encoding provides a self-describing format for binary data,
    /// where the first character indicates the encoding scheme used. This format
    /// is commonly used in DID documents for compact representation of cryptographic
    /// key material while maintaining human readability and avoiding ambiguity
    /// about the encoding format.
    /// </remarks>
    [DebuggerDisplay("PublicKeyMultibase({Key,nq})")]
    public class PublicKeyMultibase: KeyFormat
    {
        /// <summary>
        /// The multibase-encoded public key string.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This property contains the complete multibase-encoded representation of the public key,
        /// including both the encoding indicator and the key material. The format follows the
        /// multibase specification where the first character indicates the encoding scheme:
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>z</c> - Base58 Bitcoin encoding (most common in DID contexts)</description></item>
        /// <item><description><c>f</c> - Base16 (hexadecimal) encoding</description></item>
        /// <item><description><c>b</c> - Base32 encoding</description></item>
        /// <item><description><c>m</c> - Base64 encoding</description></item>
        /// </list>
        /// <para>
        /// The remaining characters after the encoding indicator represent the actual key material,
        /// which typically includes both a multicodec header (identifying the key type and format)
        /// and the raw public key bytes.
        /// </para>
        /// <para>
        /// Example multibase-encoded Ed25519 public key:
        /// <c>z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK</c>
        /// where 'z' indicates Base58 Bitcoin encoding and the remainder contains the multicodec
        /// header and Ed25519 public key material.
        /// </para>
        /// </remarks>
        public string Key { get; set; }


        /// <summary>
        /// Initializes a new instance of the <see cref="PublicKeyMultibase"/> class with the specified key.
        /// </summary>
        /// <param name="key">The multibase-encoded public key string.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This constructor performs basic validation to ensure the key parameter is not null,
        /// but does not validate the format or content of the multibase string. Format validation
        /// is typically performed by cryptographic conversion functions when the key material
        /// is actually used for cryptographic operations.
        /// </para>
        /// <para>
        /// The provided key should be a valid multibase-encoded string that includes:
        /// </para>
        /// <list type="number">
        /// <item><description>A multibase encoding indicator as the first character</description></item>
        /// <item><description>A multicodec header identifying the key type and format</description></item>
        /// <item><description>The actual public key material in the specified encoding</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// //Create a PublicKeyMultibase with an Ed25519 key.
        /// var multibaseKey = new PublicKeyMultibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        ///
        /// //Create a PublicKeyMultibase with a secp256k1 key.
        /// var secp256k1Key = new PublicKeyMultibase("zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme");
        /// </code>
        /// </example>
        public PublicKeyMultibase(string key)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            Key = key;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(KeyFormat? other)
        {
            if(other is not PublicKeyMultibase multibase)
            {
                return false;
            }

            if(ReferenceEquals(this, multibase))
            {
                return true;
            }

            return string.Equals(Key, multibase.Key, StringComparison.Ordinal);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            return Key.GetHashCode(StringComparison.InvariantCulture);
        }
    }
}
