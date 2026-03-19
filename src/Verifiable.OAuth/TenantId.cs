using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// A semantic identifier for a tenant whose authorization-server configuration
/// and key inventory the library operates against. Opaque to the library;
/// meaningful only to the application's tenant resolver and registration store.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="TenantId"/> names the entity the library loads
/// <see cref="ClientRegistration"/> for when handling a request. The string form
/// is produced by the application's request-routing layer from whatever signal
/// identifies the tenant in that deployment:
/// </para>
/// <list type="bullet">
///   <item><description>URL path segment (<c>/connect/{segment}/...</c>).</description></item>
///   <item><description>Subdomain (<c>tenant-a.issuer.example.com</c>).</description></item>
///   <item><description>HTTP header (<c>X-Tenant-Id</c>).</description></item>
///   <item><description>Client certificate subject or SAN for mTLS-authenticated requests.</description></item>
///   <item><description>A claim in an upstream-issued JWT.</description></item>
///   <item><description>A combination of the above.</description></item>
/// </list>
/// <para>
/// The library does not parse or validate the value. It is passed opaquely into
/// the registration resolver and propagated through flow state so that every
/// protocol decision made for the tenant carries the tenant's identity explicitly.
/// </para>
/// <para>
/// <strong>Relationship to <see cref="Verifiable.Cryptography.KeyId"/></strong>
/// </para>
/// <para>
/// <see cref="TenantId"/> identifies the organization operating an authorization
/// server. <see cref="Verifiable.Cryptography.KeyId"/> identifies a specific key
/// within (or used by) a tenant. A tenant typically has many keys across multiple
/// usage contexts and rotation states.
/// </para>
/// </remarks>
[DebuggerDisplay("TenantId={Value}")]
public readonly struct TenantId: IEquatable<TenantId>
{
    /// <summary>
    /// The raw identifier value. Opaque to the library; meaningful to the
    /// application's resolver and registration store.
    /// </summary>
    public string Value { get; }


    /// <summary>
    /// Initialises a <see cref="TenantId"/> with the specified identifier value.
    /// </summary>
    /// <param name="value">The identifier value. Must not be null or whitespace.</param>
    public TenantId(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Value = value;
    }


    /// <inheritdoc />
    public bool Equals(TenantId other) => string.Equals(Value, other.Value, StringComparison.Ordinal);


    /// <inheritdoc />
    public override bool Equals(object? obj) => obj is TenantId other && Equals(other);


    /// <inheritdoc />
    public override int GetHashCode() => Value.GetHashCode(StringComparison.Ordinal);


    /// <inheritdoc />
    public override string ToString() => Value;


    public static bool operator ==(TenantId left, TenantId right) => left.Equals(right);


    public static bool operator !=(TenantId left, TenantId right) => !(left == right);


    /// <summary>
    /// Implicitly converts a <see cref="string"/> to a <see cref="TenantId"/>.
    /// </summary>
    public static implicit operator TenantId(string value) => new(value);


    /// <summary>
    /// Implicitly converts a <see cref="TenantId"/> to its underlying
    /// <see cref="string"/> value.
    /// </summary>
    public static implicit operator string(TenantId tenantId) => tenantId.Value;
}
