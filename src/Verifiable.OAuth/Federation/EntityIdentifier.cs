using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Identifies an entity in an OpenID Federation 1.0 hierarchy by its
/// Entity Identifier per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3">Federation §3</see>.
/// </summary>
/// <remarks>
/// <para>
/// Entity Identifiers are absolute URLs. They appear as the <c>iss</c> and
/// <c>sub</c> claims of Entity Statements, in <c>authority_hints</c>, in
/// federation document fetch URLs, and elsewhere across the protocol.
/// Equality and hashing are ordinal string comparison on the URL value.
/// </para>
/// <para>
/// Value type wrapping <see cref="string"/> rather than <see cref="Uri"/>
/// to match the wire-format identifier discipline shared with
/// <see cref="Server.CapabilityIdentifier"/> and
/// <see cref="Server.IdentifierPurpose"/>: the identifier flows opaquely
/// into telemetry / audit / metadata documents and the round-trip cost of
/// <see cref="Uri"/> normalisation is unnecessary. Construction validates
/// absolute-URL shape via <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("{Value,nq}")]
public readonly struct EntityIdentifier: IEquatable<EntityIdentifier>
{
    /// <summary>
    /// The absolute-URL value identifying this entity. Canonical identity;
    /// equality and hashing compare on this string with
    /// <see cref="StringComparison.Ordinal"/>.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Entity Identifiers flow opaquely into Federation metadata documents and telemetry; routing through System.Uri adds no value and incurs normalisation cost.")]
    public string Value { get; }


    /// <summary>
    /// Constructs an Entity Identifier from an absolute-URL string.
    /// </summary>
    /// <param name="value">The absolute URL. Required to be non-null, non-whitespace, and a valid absolute URL per <see cref="Uri.TryCreate(string, UriKind, out Uri)"/>.</param>
    /// <exception cref="ArgumentException">When <paramref name="value"/> is null, whitespace, or not an absolute URL.</exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "Entity Identifiers flow opaquely into Federation metadata documents and telemetry; routing through System.Uri adds no value and incurs normalisation cost.")]
    public EntityIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if(!Uri.TryCreate(value, UriKind.Absolute, out _))
        {
            throw new ArgumentException(
                $"Entity Identifier must be an absolute URL; got '{value}'.",
                nameof(value));
        }

        Value = value;
    }


    /// <inheritdoc/>
    public bool Equals(EntityIdentifier other) =>
        string.Equals(Value, other.Value, StringComparison.Ordinal);


    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is EntityIdentifier other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode() =>
        Value is null ? 0 : StringComparer.Ordinal.GetHashCode(Value);


    /// <inheritdoc/>
    public override string ToString() => Value ?? string.Empty;


    /// <summary>Equality operator.</summary>
    public static bool operator ==(EntityIdentifier left, EntityIdentifier right) => left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(EntityIdentifier left, EntityIdentifier right) => !left.Equals(right);
}
