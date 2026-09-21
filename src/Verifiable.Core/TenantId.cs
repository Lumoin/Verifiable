using System.Diagnostics;

namespace Verifiable.Core;

/// <summary>
/// A semantic identifier for a tenant whose authorization-server configuration
/// and key inventory the library operates against. Opaque to the library;
/// meaningful only to the application's tenant resolver and registration store.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="TenantId"/> names the entity the library loads
/// <c>ClientRecord</c> for when handling a request. The string form
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
/// <strong>A tenant has two identifiers, and this is the internal one.</strong> Everything the
/// library stores for a tenant — registrations, flow state, correlation keys, key inventories — hangs
/// off <see cref="TenantId"/>, so it must stay stable for the tenant's whole life. The tenant's public
/// face is <see cref="TenantHandle"/>: the value bound into its URLs and issuer identifier and shown
/// on telemetry. Keeping the two apart is what lets an operator give a tenant a fresh public
/// identifier — after a key compromise, a reorganisation, a move to a custom domain — without
/// orphaning a single stored record, and what keeps the storage key off every wire and log line.
/// </para>
/// <para>
/// <strong>The key never leaves the process through the library.</strong> It is passed to the
/// application's own delegates and compared and stored, but no span tag, wire body, token claim,
/// metadata document or delivered diagnostic carries it, and <see cref="ToString"/> and the debugger
/// display below deliberately show nothing of <see cref="Value"/>, so a log template that formats a
/// <see cref="TenantId"/> prints nothing correlatable. A site that genuinely needs the key reads
/// <see cref="Value"/> explicitly.
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
[DebuggerDisplay("TenantId Length={Value.Length}")]
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


    /// <summary>
    /// Returns a fixed, non-identifying representation. <see cref="Value"/> is the storage key and
    /// never renders through this member; read <see cref="Value"/> explicitly at sites that need it.
    /// </summary>
    public override string ToString() => nameof(TenantId);


    /// <summary>Compares two tenant identifiers for equality by their ordinal <see cref="Value"/>.</summary>
    /// <param name="left">The first tenant identifier.</param>
    /// <param name="right">The second tenant identifier.</param>
    /// <returns><see langword="true"/> when <paramref name="left"/> and <paramref name="right"/> carry the same value.</returns>
    public static bool operator ==(TenantId left, TenantId right) => left.Equals(right);


    /// <summary>Compares two tenant identifiers for inequality by their ordinal <see cref="Value"/>.</summary>
    /// <param name="left">The first tenant identifier.</param>
    /// <param name="right">The second tenant identifier.</param>
    /// <returns><see langword="true"/> when <paramref name="left"/> and <paramref name="right"/> carry different values.</returns>
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
