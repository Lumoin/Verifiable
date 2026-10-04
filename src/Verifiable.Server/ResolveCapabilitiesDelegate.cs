using Verifiable.Core;

namespace Verifiable.Server;

/// <summary>
/// Resolves the per-request capability set active for a given registration.
/// Consulted by the dispatcher's chain build for the registration the
/// dispatcher loaded, when the configuration holds an endpoint builder, and
/// once more, for a request an endpoint of that chain matches, for the
/// registration <see cref="ServerIntegration.MaterializeRegistrationAsync"/>
/// answers in its place when that is another reference of a type the loaded
/// registration's type admits and the request's context holds the set that
/// chain build wrote (a context without it is answered <c>500</c>
/// <c>server_error</c> before a second resolution), its answer then held to
/// the capabilities resolved for the loaded registration, to attenuate
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
/// <para>
/// The context this delegate receives for a materialized registration carries
/// the set the request is served under, which the dispatcher's chain build
/// wrote for the loaded registration and the answer is held to. This delegate
/// is the application's code: code that removes that entry from the context
/// and builds a chain on it has rewritten the request's context, which is the
/// application's own act.
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
