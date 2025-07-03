using System;
using Verifiable.Core.Cryptography;
using Verifiable.Core.Did.CryptographicSuites;

namespace Verifiable.Core.Builders
{
    /// <summary>
    /// Represents the build state for constructing <c>did:key</c> DID documents.
    /// This state is passed between transformation functions during the fold/aggregate process
    /// and contains all the information needed to construct a <c>did:key</c> DID document.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The build state follows the <c>did:key</c> specification where the DID identifier is derived
    /// from the public key material using multibase encoding with Base58-BTC and appropriate
    /// multicodec headers for the key type.
    /// </para>
    /// <para>
    /// This struct implements value equality semantics where two build states are considered
    /// equal if they contain the same encoded key, equivalent public key material, and the same
    /// cryptographic suite.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var buildState = new KeyDidBuildState
    /// {
    ///     EncodedKey = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    ///     PublicKey = publicKeyMemory,
    ///     Suite = JsonWebKey2020.DefaultInstance
    /// };
    /// </code>
    /// </example>
    public readonly struct KeyDidBuildState: IEquatable<KeyDidBuildState>
    {
        /// <summary>
        /// Gets the Base58-encoded public key that forms the identifier portion of the <c>did:key</c>.
        /// This encoded key is used in the DID identifier and as the fragment identifier
        /// for the verification method.
        /// </summary>
        /// <remarks>
        /// The encoding follows the multibase format with Base58-BTC encoding and includes
        /// the appropriate multicodec header for the key type. For example, Ed25519 keys
        /// use the 0xed01 multicodec header, resulting in identifiers that start with "z6Mk".
        /// </remarks>
        /// <example>
        /// For an Ed25519 key: <c>"z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"</c>
        /// </example>
        public string EncodedKey { get; init; }

        /// <summary>
        /// Gets the original public key material used to create this DID document.
        /// This includes the raw key bytes and associated metadata such as algorithm,
        /// purpose, and encoding scheme information.
        /// </summary>
        /// <remarks>
        /// The public key memory contains both the key material and rich metadata
        /// through the Tag system, allowing the builder to make appropriate decisions
        /// about key format representation and cryptographic operations.
        /// </remarks>
        public PublicKeyMemory PublicKey { get; init; }

        /// <summary>
        /// Gets the cryptographic suite that determines how the public key is represented
        /// in the verification method of the DID document.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Common crypto suites for <c>did:key</c> include:
        /// </para>
        /// <list type="bullet">
        /// <item><description><see cref="JsonWebKey2020"/> - Represents keys in JWK format</description></item>
        /// <item><description><see cref="Multikey"/> - Represents keys in multibase format</description></item>
        /// <item><description><see cref="Ed25519VerificationKey2020"/> - Ed25519-specific representation</description></item>
        /// </list>
        /// </remarks>
        public VerificationMethodTypeInfo VerificationMethodTypeInfo { get; init; }


        /// <summary>
        /// Determines whether the specified <see cref="KeyDidBuildState"/> is equal to the current instance.
        /// Two build states are considered equal if they have the same encoded key, equivalent public key material,
        /// and the same cryptographic suite.
        /// </summary>
        /// <param name="other">The build state to compare with the current instance.</param>
        /// <returns><c>true</c> if the specified build state is equal to the current instance; otherwise, <c>false</c>.</returns>
        /// <remarks>
        /// This method implements value equality semantics. Public key equality is determined by
        /// the <see cref="PublicKeyMemory.Equals(PublicKeyMemory)"/> method, which compares
        /// both the key material and associated metadata.
        /// </remarks>
        public bool Equals(KeyDidBuildState other)
        {
            return EncodedKey == other.EncodedKey
                && PublicKey.Equals(other.PublicKey)
                && Equals(VerificationMethodTypeInfo, other.VerificationMethodTypeInfo);
        }


        /// <summary>
        /// Determines whether the specified object is equal to the current instance.
        /// </summary>
        /// <param name="obj">The object to compare with the current instance.</param>
        /// <returns><c>true</c> if the specified object is a <see cref="KeyDidBuildState"/> and is equal to the current instance; otherwise, <c>false</c>.</returns>
        public override bool Equals(object? obj)
        {
            return obj is KeyDidBuildState other && Equals(other);
        }


        /// <summary>
        /// Returns the hash code for this instance.
        /// </summary>
        /// <returns>A 32-bit signed integer that is the hash code for this instance.</returns>
        /// <remarks>
        /// The hash code is computed from the encoded key, public key, and crypto suite
        /// to ensure consistent hashing behavior for equal instances.
        /// </remarks>
        public override int GetHashCode()
        {
            return HashCode.Combine(EncodedKey, PublicKey, VerificationMethodTypeInfo);
        }


        /// <summary>
        /// Determines whether two specified instances of <see cref="KeyDidBuildState"/> are equal.
        /// </summary>
        /// <param name="left">The first build state to compare.</param>
        /// <param name="right">The second build state to compare.</param>
        /// <returns><c>true</c> if the two build states are equal; otherwise, <c>false</c>.</returns>
        public static bool operator ==(KeyDidBuildState left, KeyDidBuildState right)
        {
            return left.Equals(right);
        }


        /// <summary>
        /// Determines whether two specified instances of <see cref="KeyDidBuildState"/> are not equal.
        /// </summary>
        /// <param name="left">The first build state to compare.</param>
        /// <param name="right">The second build state to compare.</param>
        /// <returns><c>true</c> if the two build states are not equal; otherwise, <c>false</c>.</returns>
        public static bool operator !=(KeyDidBuildState left, KeyDidBuildState right)
        {
            return !left.Equals(right);
        }
    }
}
