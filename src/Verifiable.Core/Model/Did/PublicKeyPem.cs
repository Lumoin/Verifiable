using System;
using System.ComponentModel;
using System.Diagnostics;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Represents a public key encoded in PEM (Privacy-Enhanced Mail) format.
    /// </summary>
    /// <remarks>
    /// PEM format is a widely-used standard for encoding cryptographic keys and certificates.
    /// It uses Base64 encoding wrapped with header and footer lines to create a text-based
    /// representation of binary key material. This format is human-readable and commonly
    /// supported across different cryptographic libraries and tools.
    /// </remarks>
    [DebuggerDisplay("PublicKeyPem({Key,nq})")]
    [Obsolete("Use PublicKeyJwk or PublicKeyMultibase instead for new implementations.")]
    public class PublicKeyPem: KeyFormat
    {
        /// <summary>
        /// The PEM-encoded public key string.
        /// </summary>
        /// <remarks>
        /// <para>
        /// This property contains the complete PEM-formatted representation of the public key,
        /// including the header and footer delimiters and the Base64-encoded key material.
        /// The format follows the standard PEM structure with appropriate boundary markers.
        /// </para>
        /// <para>
        /// A typical PEM-encoded public key has the following structure:
        /// </para>
        /// <code>
        /// -----BEGIN PUBLIC KEY-----
        /// [Base64-encoded key material]
        /// -----END PUBLIC KEY-----
        /// </code>
        /// <para>
        /// For specific key types, the header and footer may include algorithm-specific text:
        /// </para>
        /// <list type="bullet">
        /// <item><description><c>-----BEGIN PUBLIC KEY-----</c> - Generic public key (SubjectPublicKeyInfo format)</description></item>
        /// <item><description><c>-----BEGIN RSA PUBLIC KEY-----</c> - RSA-specific public key</description></item>
        /// <item><description><c>-----BEGIN EC PUBLIC KEY-----</c> - Elliptic Curve public key</description></item>
        /// </list>
        /// <para>
        /// The PEM format is particularly useful for interoperability with standard cryptographic
        /// tools and libraries, as it provides a standardized way to represent key material
        /// in a text format that can be easily stored, transmitted, and processed.
        /// </para>
        /// </remarks>
        public string Key { get; set; }


        /// <summary>
        /// Initializes a new instance of the <see cref="PublicKeyPem"/> class with the specified key.
        /// </summary>
        /// <param name="key">The PEM-encoded public key string.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="key"/> is null.</exception>
        /// <remarks>
        /// <para>
        /// This constructor performs basic validation to ensure the key parameter is not null,
        /// but does not validate the format or content of the PEM string. Format validation
        /// is typically performed by cryptographic parsing functions when the key material
        /// is actually used for cryptographic operations.
        /// </para>
        /// <para>
        /// The provided key should be a valid PEM-formatted string that includes:
        /// </para>
        /// <list type="number">
        /// <item><description>Appropriate BEGIN and END header/footer lines</description></item>
        /// <item><description>Valid Base64-encoded key material between the headers</description></item>
        /// <item><description>Proper line endings and formatting</description></item>
        /// </list>
        /// </remarks>
        /// <example>
        /// <code>
        /// //Create a PublicKeyPem with a generic public key.
        /// var pemKey = new PublicKeyPem(@"-----BEGIN PUBLIC KEY-----
        /// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L
        /// 2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QQ==
        /// -----END PUBLIC KEY-----");
        ///
        /// //Create a PublicKeyPem with an RSA public key.
        /// var rsaKey = new PublicKeyPem(@"-----BEGIN RSA PUBLIC KEY-----
        /// MIIBCgKCAQEA4f7jGC8Y4A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8
        /// QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8QY4Y8A8L2Y9XZGx8
        /// QIDAQAB
        /// -----END RSA PUBLIC KEY-----");
        /// </code>
        /// </example>
        public PublicKeyPem(string key)
        {
            ArgumentNullException.ThrowIfNull(key, nameof(key));
            Key = key;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals(KeyFormat? other)
        {
            if(other is not PublicKeyPem pem)
            {
                return false;
            }

            if(ReferenceEquals(this, pem))
            {
                return true;
            }

            return string.Equals(Key, pem.Key, StringComparison.Ordinal);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            return Key.GetHashCode(StringComparison.InvariantCulture);
        }
    }
}