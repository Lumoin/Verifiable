using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Identifies the role an entity plays in an OpenID Federation 1.0
/// hierarchy per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.1">Federation §5.1</see>
/// and
/// <see href="https://openid.net/specs/openid-federation-wallet-1_0.html#section-6">Federation Wallet 1.0 §6</see>.
/// </summary>
/// <remarks>
/// <para>
/// Standard Entity Type Identifiers are short strings (e.g.
/// <c>openid_relying_party</c>, <c>federation_entity</c>); application-
/// defined ones can be either short strings or URLs per Federation §5.1.
/// The string form flows directly into the <c>metadata</c> object's
/// per-type sub-objects (one key per entity type the subject plays).
/// </para>
/// <para>
/// Library-shipped well-known instances live on
/// <see cref="WellKnownEntityTypeIdentifiers"/>; applications register
/// custom identifiers via the constructor.
/// </para>
/// </remarks>
[DebuggerDisplay("{Value,nq}")]
public readonly struct EntityTypeIdentifier: IEquatable<EntityTypeIdentifier>
{
    /// <summary>
    /// The identifier value. Canonical identity; equality and hashing
    /// compare on this string with <see cref="StringComparison.Ordinal"/>.
    /// </summary>
    public string Value { get; }


    /// <summary>
    /// Constructs an Entity Type Identifier from its string form.
    /// </summary>
    /// <param name="value">The identifier. Required to be non-null and non-whitespace; can be either a short identifier (e.g. <c>openid_relying_party</c>) or an absolute URL per Federation §5.1.</param>
    /// <exception cref="ArgumentException">When <paramref name="value"/> is null or whitespace.</exception>
    public EntityTypeIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }


    /// <inheritdoc/>
    public bool Equals(EntityTypeIdentifier other) =>
        string.Equals(Value, other.Value, StringComparison.Ordinal);


    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is EntityTypeIdentifier other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode() =>
        Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);


    /// <inheritdoc/>
    public override string ToString() => Value ?? string.Empty;


    /// <summary>Equality operator.</summary>
    public static bool operator ==(EntityTypeIdentifier left, EntityTypeIdentifier right) => left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(EntityTypeIdentifier left, EntityTypeIdentifier right) => !left.Equals(right);
}
