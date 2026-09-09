using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.Federation;

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
    /// Constructs an Entity Identifier from an absolute-URL string. Per the
    /// Entity Identifier definition in OpenID Federation 1.0 §1.2, the value
    /// MUST be an https URL with a host component and MUST NOT contain query
    /// or fragment components (port and path components are permitted).
    /// </summary>
    /// <param name="value">The Entity Identifier. Required to be non-null, non-whitespace, an absolute https URL with a host, and free of query and fragment components.</param>
    /// <exception cref="ArgumentException">When <paramref name="value"/> is null, whitespace, not an absolute URL, not https, lacks a host, or carries a query or fragment.</exception>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "Entity Identifiers flow opaquely into Federation metadata documents and telemetry; routing through System.Uri adds no value and incurs normalisation cost.")]
    public EntityIdentifier(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if(!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri))
        {
            throw new ArgumentException(
                $"Entity Identifier must be an absolute URL; got '{value}'.",
                nameof(value));
        }

        //§1.2: Entity Identifiers use the https scheme. Restricting the scheme also
        //closes the cross-platform Uri.TryCreate trap whereby a scheme-relative or
        //path-only value is accepted as a non-http(s) absolute URL on some platforms.
        if(!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"Entity Identifier must use the https scheme; got '{value}'.",
                nameof(value));
        }

        //§1.2: Entity Identifiers have a host component.
        if(string.IsNullOrEmpty(uri.Host))
        {
            throw new ArgumentException(
                $"Entity Identifier must contain a host component; got '{value}'.",
                nameof(value));
        }

        //§1.2: Entity Identifiers MUST NOT contain query or fragment components.
        if(!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException(
                $"Entity Identifier must not contain query or fragment components; got '{value}'.",
                nameof(value));
        }

        Value = value;
    }


    /// <summary>
    /// Attempts to construct an Entity Identifier from an arbitrary string, failing closed rather than
    /// throwing when the value is not a well-formed identifier — the shape a DCQL <c>openid_federation</c>
    /// <c>trusted_authorities</c> value needs, since an unparseable value simply matches nothing rather than
    /// aborting evaluation (OpenID for Verifiable Presentations 1.0, Section 6.1.1.3).
    /// </summary>
    /// <param name="value">The candidate identifier text.</param>
    /// <param name="identifier">The parsed identifier when <paramref name="value"/> satisfies OpenID Federation 1.0 §1.2's Entity Identifier shape; <see langword="default"/> otherwise.</param>
    /// <returns><see langword="true"/> when parsing succeeds; otherwise <see langword="false"/>.</returns>
    public static bool TryCreate(string? value, out EntityIdentifier identifier)
    {
        identifier = default;
        if(!IsWellFormedEntityIdentifier(value, out Uri? uri))
        {
            return false;
        }

        identifier = new EntityIdentifier(value!);

        return true;
    }


    /// <summary>
    /// Reports whether <paramref name="value"/> satisfies OpenID Federation 1.0 §1.2's Entity Identifier
    /// shape: an absolute https URL with a host, carrying no query or fragment component.
    /// </summary>
    /// <param name="value">The candidate identifier text.</param>
    /// <param name="uri">The parsed <see cref="Uri"/> when <paramref name="value"/> is at least an absolute URL; <see langword="null"/> otherwise.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> qualifies; otherwise <see langword="false"/>.</returns>
    private static bool IsWellFormedEntityIdentifier(string? value, out Uri? uri)
    {
        uri = null;
        if(string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if(!Uri.TryCreate(value, UriKind.Absolute, out uri))
        {
            return false;
        }

        bool isHttps = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal);
        bool hasHost = !string.IsNullOrEmpty(uri.Host);
        bool hasNoQueryOrFragment = string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment);

        return isHttps && hasHost && hasNoQueryOrFragment;
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
