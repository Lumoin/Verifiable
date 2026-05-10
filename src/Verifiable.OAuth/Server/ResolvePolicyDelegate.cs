namespace Verifiable.OAuth.Server;

/// <summary>
/// Resolves the per-request policy values for a registration and populates
/// them on the request context bag at dispatch entry.
/// </summary>
/// <remarks>
/// <para>
/// The dispatcher invokes this delegate exactly once per request, after the
/// tenant has been resolved and the registration loaded but before any
/// matcher executes. The implementation reads
/// <see cref="ClientRegistration.ProfileName"/> (or any other application
/// signal) and writes the corresponding <see cref="PolicyContextKeys"/>
/// entries on <paramref name="context"/> via the typed extensions in
/// <see cref="PolicyRequestContextExtensions"/>. Matchers, validators, and
/// token producers downstream read those values by getting the typed
/// extension property.
/// </para>
/// <para>
/// The library ships a default implementation in
/// <see cref="PolicyProfiles.DefaultResolvePolicyAsync"/> that dispatches on
/// the registration's <see cref="ClientRegistration.ProfileName"/> across
/// the three named profiles <c>strict</c>, <c>haip</c>, and <c>rfc6749</c>.
/// Applications that need custom policy resolution wire their own delegate.
/// </para>
/// </remarks>
/// <param name="registration">The registration whose policy is being resolved.</param>
/// <param name="context">The per-request context bag to populate.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask ResolvePolicyDelegate(
    ClientRegistration registration,
    RequestContext context,
    CancellationToken cancellationToken);
