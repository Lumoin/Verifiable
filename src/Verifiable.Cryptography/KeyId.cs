using System.Diagnostics;

namespace Verifiable.Cryptography;

/// <summary>
/// A semantic identifier for a specific key instance, stored as an entry in a
/// <see cref="Tag"/> alongside type metadata such as <see cref="CryptoAlgorithm"/>
/// and <see cref="Purpose"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Tag"/> describes <em>what kind</em> of key a piece of memory is.
/// <see cref="KeyId"/> identifies <em>which specific</em> key it is. Two freshly
/// generated P-256 exchange keys share the same <see cref="Tag"/> but have distinct
/// <see cref="KeyId"/> values once one is assigned.
/// </para>
/// <para>
/// Keys are anonymous at creation time. An identifier is assigned at the latest when
/// the key must outlive a single request — for example when the private key scalar is
/// stored so that a future HTTP request can reload it to decrypt a response. The form of
/// the identifier depends entirely on the application:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       A UUID or database row key for keys stored in a local secret store.
///     </description>
///   </item>
///   <item>
///     <description>
///       A KMS key ARN or key alias for keys held in a cloud key management service.
///     </description>
///   </item>
///   <item>
///     <description>
///       A DID key identifier (<c>did:key:z6Mk…</c>) for keys whose identity is derived
///       from the public key bytes via multibase/multicodec encoding, as produced by
///       <see cref="CryptoFormatConversions"/> in <c>Verifiable.JCose</c>.
///     </description>
///   </item>
///   <item>
///     <description>
///       A JWK <c>kid</c> value for keys distributed in a JWKS endpoint, where the
///       identifier is assigned by the key owner rather than derived from the bytes.
///     </description>
///   </item>
/// </list>
/// <para>
/// The library never interprets or validates the value — it is opaque to all library
/// code and meaningful only to the application's key resolver. The library propagates
/// the identifier through flow state records (e.g., <c>DecryptionKeyId</c>) so that a
/// subsequent HTTP request can call the resolver to obtain the live key material.
/// </para>
/// <para>
/// To attach a <see cref="KeyId"/> to existing key material use <see cref="Tag.With{T}"/>:
/// </para>
/// <code>
/// PrivateKeyMemory withId = new(
///     keyMaterialOwner,
///     existingKey.Tag.With(new KeyId("urn:uuid:3f2504e0-...")));
/// </code>
/// </remarks>
[DebuggerDisplay("KeyId={Value}")]
public readonly struct KeyId: IEquatable<KeyId>
{
    /// <summary>
    /// The raw identifier value. Opaque to the library; meaningful to the application's
    /// key resolver.
    /// </summary>
    public string Value { get; }


    /// <summary>
    /// Initialises a <see cref="KeyId"/> with the specified identifier value.
    /// </summary>
    /// <param name="value">The identifier value. Must not be null or whitespace.</param>
    public KeyId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }


    /// <inheritdoc />
    public bool Equals(KeyId other) => string.Equals(Value, other.Value, StringComparison.Ordinal);


    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is KeyId other && Equals(other);


    /// <inheritdoc />
    public override int GetHashCode() => Value.GetHashCode(StringComparison.Ordinal);


    /// <inheritdoc />
    public override string ToString() => Value;


    public static bool operator ==(KeyId left, KeyId right) => left.Equals(right);

    public static bool operator !=(KeyId left, KeyId right) => !(left == right);


    /// <summary>
    /// Implicitly converts a <see cref="string"/> to a <see cref="KeyId"/>.
    /// Enables concise assignment at call sites that already hold a string identifier.
    /// </summary>
    public static implicit operator KeyId(string value) => new(value);


    /// <summary>
    /// Implicitly converts a <see cref="KeyId"/> to its underlying <see cref="string"/> value.
    /// </summary>
    public static implicit operator string(KeyId kid) => kid.Value;
}
