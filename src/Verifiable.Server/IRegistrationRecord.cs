using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// The host-generic projection of a registration record the dispatch host reads:
/// the tenant the registration belongs to, the stable client identifier used for
/// telemetry, and the capability set that gates which endpoint candidates enter the
/// per-request chain.
/// </summary>
/// <remarks>
/// <para>
/// The dispatch host scopes storage and routing by these three members alone.
/// Protocol families carry their own richer registration shape (signing keys,
/// redirect URIs, policy profile, protocol metadata) on a derived type and reach
/// it by downcasting at the family seams; the host itself depends only on this
/// projection so the registration carrier stays free of any single family's vocabulary.
/// </para>
/// <para>
/// <see cref="CapabilityIdentifier"/> is the same value type the endpoint candidates
/// and the per-request chain filter use, so the capability set a registration exposes
/// here is directly comparable to the candidate capabilities the builders emit.
/// </para>
/// </remarks>
public interface IRegistrationRecord
{
    /// <summary>
    /// The stable client identifier. Surfaced on dispatch telemetry so traces and
    /// audit records carry the registration the request resolved to.
    /// </summary>
    string ClientId { get; }

    /// <summary>
    /// The tenant the registration belongs to. The host threads it through every
    /// storage seam so tenant isolation is enforced at the storage boundary.
    /// </summary>
    TenantId TenantId { get; }

    /// <summary>
    /// The tenant's public identifier, as distinct from <see cref="TenantId"/>, the internal key the
    /// stores hang off: the value bound into the tenant's URLs and issuer identifier, and the only
    /// tenant-shaped value the host writes to an exported span or delivers in a registration event
    /// (see <see cref="Verifiable.Core.TenantHandle"/> for why a tenant carries two). <see langword="null"/>
    /// when the application assigned none, in which case the dispatch host emits no tenant-shaped tag
    /// for this registration's requests rather than falling back to <see cref="TenantId"/>.
    /// </summary>
    TenantHandle? TenantHandle { get; }

    /// <summary>
    /// The capabilities the registration is allowed to exercise. The per-request
    /// chain build drops endpoint candidates whose capability is not in this set
    /// before any matcher runs.
    /// </summary>
    IReadOnlySet<CapabilityIdentifier> AllowedCapabilities { get; }
}
