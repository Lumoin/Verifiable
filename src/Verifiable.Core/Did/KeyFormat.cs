using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Did
{
    /// <summary>
    /// Abstract base class that serves as a marker for different key format representations used in DID documents.
    /// This class defines the contract for how cryptographic key material can be encoded and stored within
    /// verification methods, enabling support for multiple standardized key formats.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The KeyFormat class hierarchy provides a type-safe way to represent different encodings of the same
    /// underlying cryptographic key material. Each concrete implementation corresponds to a specific
    /// standardized format for representing public keys in DID documents and related specifications.
    /// </para>
    /// <para>
    /// Common key format implementations include:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <see cref="PublicKeyJwk"/> - Represents keys using the JSON Web Key (JWK) format as defined in RFC 7517.
    /// This format is widely used in JWT and OAuth ecosystems and provides comprehensive metadata about the key.
    /// </description></item>
    /// <item><description>
    /// <see cref="PublicKeyMultibase"/> - Represents keys using multibase encoding, which provides a compact,
    /// self-describing format that includes both the encoding scheme and the key material in a single string.
    /// </description></item>
    /// </list>
    /// <para>
    /// The key format is typically selected based on the cryptographic suite specified in the verification method's
    /// <c>Type</c> property. For example, "JsonWebKey2020" type verification methods use <see cref="PublicKeyJwk"/>,
    /// while "Multikey" type verification methods use <see cref="PublicKeyMultibase"/>.
    /// </para>
    /// <para>
    /// All key formats must implement value-based equality to ensure that verification methods with identical
    /// key material are considered equal regardless of object identity. This is essential for proper operation
    /// of DID document comparison, caching, and resolution operations.
    /// </para>
    /// <para>
    /// For more information about key formats in DID documents, see the
    /// <see href="https://www.w3.org/TR/did-core/#key-types-and-formats">DID Core specification</see>.
    /// </para>
    /// </remarks>
    public abstract class KeyFormat: IEquatable<KeyFormat>
    {
        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public abstract bool Equals(KeyFormat? other);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? obj) => obj is KeyFormat keyFormat && Equals(keyFormat);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(KeyFormat? format1, KeyFormat? format2)
        {
            if(format1 is null)
            {
                return format2 is null;
            }

            return format1.Equals(format2);
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(KeyFormat? format1, KeyFormat? format2) => !(format1 == format2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(object? format1, KeyFormat? format2) => format1 is KeyFormat f && f == format2;


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(KeyFormat? format1, object? format2) => format2 is KeyFormat f && format1 == f;


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(object? format1, KeyFormat? format2) => !(format1 == format2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(KeyFormat? format1, object? format2) => !(format1 == format2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public abstract override int GetHashCode();
    }
}
