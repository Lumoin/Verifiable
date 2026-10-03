using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// Resolves the per-request capability set active for a given registration.
/// Consulted once per request for the registration
/// <see cref="ServerIntegration.LoadRegistrationAsync"/> answers, by
/// the dispatcher's chain build, and once more for
/// the registration <see cref="ServerIntegration.MaterializeRegistrationAsync"/>
/// answers when that is another reference of the loaded registration's type,
/// its answer then held to the capabilities resolved for the loaded
/// registration, to attenuate
/// <see cref="IRegistrationRecord.AllowedCapabilities"/> down to whatever subset
/// the deployment considers active for this request. The request is served
/// under the library's own immutable copy of an answer, so a set changed after
/// it is handed back does not change that copy. The copy is made by walking the
/// registration's own <see cref="IRegistrationRecord.AllowedCapabilities"/>
/// (or the bound, for a materialized registration) and asking the answer for
/// each capability, so a capability an answer holds beyond them is not served:
/// an answer can only narrow what the registration allows.
/// </summary>
/// <remarks>
/// <para>
/// The static registration capability set
/// (<see cref="IRegistrationRecord.AllowedCapabilities"/>) describes what the
/// registration <em>can</em> host. This delegate is the per-request layer that
/// answers what is <em>active right now</em> — the integration point for
/// CAEP/RISC signal consumption, feature flags, maintenance windows, and any
/// other deployment-driven attenuation.
/// </para>
/// <para>
/// The library default returns
/// <see cref="IRegistrationRecord.AllowedCapabilities"/> unchanged.
/// </para>
/// </remarks>
/// <param name="registration">The registration whose active capabilities are being resolved.</param>
/// <param name="context">The per-request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The capabilities active for this request. Only those within <see cref="IRegistrationRecord.AllowedCapabilities"/>
/// are served; a capability beyond them is left out of the set the request is served under.
/// </returns>
public delegate ValueTask<IReadOnlySet<CapabilityIdentifier>> ResolveCapabilitiesDelegate(
    IRegistrationRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
