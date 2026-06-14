using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Server;

/// <summary>
/// Identifies a capability an Authorization Server can offer to a registered
/// client. Identifiers are URN-shaped strings per the scheme
/// <c>urn:verifiable:capability:&lt;namespace&gt;:&lt;name&gt;</c>; the URN is the
/// canonical identity and the only field that participates in equality.
/// </summary>
/// <remarks>
/// <para>
/// Same "dynamic value type" extensibility shape as
/// <see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>: predefined
/// values for every protocol the library ships live on
/// <see cref="WellKnownCapabilityIdentifiers"/>; applications register
/// custom identifiers via <see cref="Create(string)"/>. Federation
/// sub-capabilities, OID4VCI roles, AuthZEN profiles, and any future
/// downstream-track capabilities land as additional well-known instances
/// or as application-registered URNs without further infrastructure work.
/// </para>
/// <para>
/// The URN form flows directly into Discovery / Federation metadata via
/// the per-capability wire-name mapping, so the identifier registered
/// in code stays traceable to the identifier the relying party observes.
/// </para>
/// </remarks>
[DebuggerDisplay("{Urn,nq}")]
public readonly struct CapabilityIdentifier: IEquatable<CapabilityIdentifier>
{
    /// <summary>
    /// The URN-shaped string identifying this capability. Canonical identity;
    /// equality and hashing compare on this string with
    /// <see cref="StringComparison.Ordinal"/>.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "URN identifiers are string-compared and serialised into Discovery metadata as opaque strings; routing through System.Uri adds no value.")]
    public string Urn { get; }


    private CapabilityIdentifier(string urn)
    {
        Urn = urn;
    }


    /// <summary>
    /// Registers a capability identifier from an arbitrary URN-shaped string.
    /// Use for application-defined capabilities that aren't covered by the
    /// library's <see cref="WellKnownCapabilityIdentifiers"/> set.
    /// </summary>
    /// <param name="urn">
    /// The URN-shaped identifier, e.g.
    /// <c>urn:example:capability:my-app:custom_flow</c>. Required to be
    /// non-null and non-whitespace; the library does not enforce the
    /// <c>urn:verifiable:capability:...</c> prefix on application identifiers,
    /// only on its own well-known set.
    /// </param>
    [SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
        Justification = "URN identifiers are string-compared and serialised into Discovery metadata as opaque strings; routing through System.Uri adds no value.")]
    public static CapabilityIdentifier Create(string urn)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(urn);
        return new CapabilityIdentifier(urn);
    }


    /// <inheritdoc/>
    public bool Equals(CapabilityIdentifier other) =>
        string.Equals(Urn, other.Urn, StringComparison.Ordinal);


    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is CapabilityIdentifier other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode() =>
        Urn is null ? 0 : StringComparer.Ordinal.GetHashCode(Urn);


    /// <inheritdoc/>
    public override string ToString() => Urn ?? string.Empty;


    /// <summary>Equality operator.</summary>
    public static bool operator ==(CapabilityIdentifier left, CapabilityIdentifier right) => left.Equals(right);


    /// <summary>Inequality operator.</summary>
    public static bool operator !=(CapabilityIdentifier left, CapabilityIdentifier right) => !left.Equals(right);
}
