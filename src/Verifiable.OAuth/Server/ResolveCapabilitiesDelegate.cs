namespace Verifiable.OAuth.Server;

/// <summary>
/// Resolves the per-request capability set active for a given
/// <see cref="ClientRecord"/>. Consulted once per request by
/// <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/> to attenuate
/// <see cref="ClientRecord.AllowedCapabilities"/> down to whatever subset
/// the deployment considers active for this request.
/// </summary>
/// <remarks>
/// <para>
/// The static registration capability set (<see cref="ClientRecord.AllowedCapabilities"/>)
/// describes what the registration <em>can</em> host. This delegate is the
/// per-request layer that answers what is <em>active right now</em> — the
/// integration point for CAEP/RISC signal consumption, feature flags,
/// maintenance windows, and any other deployment-driven attenuation.
/// </para>
/// <para>
/// The library default is <see cref="DefaultCapabilityResolver.ResolveAsync"/>
/// which returns <see cref="ClientRecord.AllowedCapabilities"/> unchanged.
/// </para>
/// </remarks>
/// <param name="registration">The registration whose active capabilities are being resolved.</param>
/// <param name="context">The per-request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The capabilities active for this request. Must be a subset of <see cref="ClientRecord.AllowedCapabilities"/>.</returns>
public delegate ValueTask<IReadOnlySet<ServerCapabilityName>> ResolveCapabilitiesDelegate(
    ClientRecord registration,
    RequestContext context,
    CancellationToken cancellationToken);
