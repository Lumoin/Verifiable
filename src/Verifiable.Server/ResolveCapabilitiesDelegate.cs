using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// Resolves the per-request capability set active for a given registration.
/// Consulted once per request by
/// <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/> to attenuate
/// <see cref="IRegistrationRecord.AllowedCapabilities"/> down to whatever subset
/// the deployment considers active for this request.
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
/// <returns>The capabilities active for this request. Must be a subset of <see cref="IRegistrationRecord.AllowedCapabilities"/>.</returns>
public delegate ValueTask<IReadOnlySet<CapabilityIdentifier>> ResolveCapabilitiesDelegate(
    IRegistrationRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
