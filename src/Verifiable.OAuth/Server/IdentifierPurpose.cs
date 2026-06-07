using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Identifies the purpose for which an identifier is being generated.
/// Threaded through <see cref="GenerateIdentifierDelegate"/> so application
/// implementations can dispatch on purpose — different formats per
/// purpose, deterministic replay-read for certain purposes, audit logging
/// for all, etc. URN-shaped strings per the scheme
/// <c>urn:verifiable:identifier-purpose:&lt;namespace&gt;:&lt;name&gt;</c>; the URN
/// is the canonical identity and the only field that participates in
/// equality.
/// </summary>
/// <remarks>
/// <para>
/// Same "dynamic value type" extensibility shape as
/// <see cref="CapabilityIdentifier"/>: predefined purposes for every
/// identifier site the library ships live on
/// <see cref="WellKnownIdentifierPurposes"/>; applications register
/// custom purposes via <see cref="Create(string)"/>. Federation and
/// downstream tracks add their own purposes either as additional
/// well-known entries or as application-registered URNs.
/// </para>
/// <para>
/// Mirrors the existing <see cref="CapabilityIdentifier"/> design: URN-
/// shaped string, ordinal equality, no integer-code compatibility
/// property, no <c>ToString</c> indirection through a names-lookup
/// class. The URN itself is what flows into telemetry and audit logs.
/// </para>
/// </remarks>
[DebuggerDisplay("{Urn,nq}")]
public readonly struct IdentifierPurpose: IEquatable<IdentifierPurpose>
{
    /// <summary>
    /// The URN-shaped string identifying this purpose. Canonical identity;
    /// equality and hashing compare on this string with
    /// <see cref="StringComparison.Ordinal"/>.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "URN identifiers are string-compared and emitted opaquely into telemetry/audit logs; routing through System.Uri adds no value.")]
    public string Urn { get; }


    private IdentifierPurpose(string urn)
    {
        Urn = urn;
    }


    /// <summary>
    /// Registers a purpose identifier from an arbitrary URN-shaped string.
    /// Use for application-defined purposes that aren't covered by the
    /// library's <see cref="WellKnownIdentifierPurposes"/> set.
    /// </summary>
    /// <param name="urn">
    /// The URN-shaped identifier, e.g.
    /// <c>urn:example:identifier-purpose:my-app:audit_trail_id</c>.
    /// Required to be non-null and non-whitespace; the library does not
    /// enforce the <c>urn:verifiable:identifier-purpose:...</c> prefix
    /// on application identifiers, only on its own well-known set.
    /// </param>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "URN identifiers are string-compared and emitted opaquely into telemetry/audit logs; routing through System.Uri adds no value.")]
    public static IdentifierPurpose Create(string urn)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(urn);
        return new IdentifierPurpose(urn);
    }


    /// <inheritdoc/>
    public bool Equals(IdentifierPurpose other) =>
        string.Equals(Urn, other.Urn, StringComparison.Ordinal);


    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is IdentifierPurpose other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode() =>
        Urn is null ? 0 : StringComparer.Ordinal.GetHashCode(Urn);


    /// <inheritdoc/>
    public override string ToString() => Urn ?? string.Empty;


    /// <summary>Equality operator.</summary>
    public static bool operator ==(IdentifierPurpose left, IdentifierPurpose right) => left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(IdentifierPurpose left, IdentifierPurpose right) => !left.Equals(right);
}
