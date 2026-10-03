using Verifiable.Core;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Library-provided default implementation of the issuer-resolution logic
/// behind <see cref="ResolveIssuerDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// Applied by every call site in the library when
/// <see cref="Verifiable.Server.ServerIntegration.ResolveIssuerAsync"/> is not set.
/// Applications that set that delegate bypass this helper entirely; the
/// library never second-guesses an application-supplied resolver.
/// </para>
/// <para>
/// Resolution order:
/// </para>
/// <list type="number">
///   <item>
///     <description>
///       <see cref="ClientRecord.IssuerUri"/> — the declared canonical
///       URL for the tenant. Used as-is when set. Suitable for deployments
///       where the tenant's authorization-server URL is stable and known at
///       registration time.
///     </description>
///   </item>
///   <item>
///     <description>
///       <c>ExchangeContextServerExtensions.Issuer</c> — a request-scoped URI
///       populated by the ASP.NET skin from the incoming request's scheme and
///       host. Used when the registration does not declare an issuer,
///       accommodating deployments where the URL is derived per-request from
///       the reverse proxy's forwarded host. A value derived from an unvalidated
///       <c>Host</c> or forwarded header lets a client assertion made for another
///       authorization server match the accepted audience, so the application
///       pins the issuer to configuration.
///     </description>
///   </item>
///   <item>
///     <description>
///       Neither set — throws <see cref="InvalidOperationException"/>. A token
///       or metadata document without <c>iss</c> is not valid under RFC 9068
///       or OIDC Discovery, so the request fails rather than emitting a
///       non-conformant response.
///     </description>
///   </item>
/// </list>
/// </remarks>
internal static class DefaultIssuerResolver
{
    /// <summary>
    /// Resolves the issuer URI for a given registration and request context
    /// using the registration → context → throw fallback chain.
    /// </summary>
    /// <param name="registration">The registration for the current request.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="cancellationToken">Cancellation token (unused by the default but present for delegate compatibility).</param>
    /// <returns>The authoritative issuer URI for this request.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when neither <see cref="ClientRecord.IssuerUri"/> nor
    /// <c>ExchangeContextServerExtensions.Issuer</c> is set, or when the
    /// resolved value fails the RFC 9207 §2 / RFC 8414 §2 issuer-identifier shape
    /// (<see cref="IssuerIdentifier.Parse"/>) — an https URL
    /// with no query or fragment component.
    /// </exception>
    public static ValueTask<Uri> ResolveAsync(
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        ValueTask.FromResult(Resolve(registration, context));


    /// <summary>
    /// The resolution of <see cref="ResolveAsync"/>, which completes without waiting, for a caller that composes
    /// its answer synchronously: the registration's issuer, else the context's, each checked by
    /// <see cref="IssuerIdentifier.Parse"/>.
    /// </summary>
    /// <param name="registration">The registration for the current request.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <returns>The authoritative issuer URI for this request.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when neither source names an issuer, or when the resolved value fails the issuer-identifier shape.
    /// </exception>
    public static Uri Resolve(ClientRecord registration, ExchangeContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        if(registration.IssuerUri is not null)
        {
            return ValidatedIssuerShape(registration.IssuerUri, registration);
        }

        Uri? contextIssuer = context.Issuer;
        if(contextIssuer is not null)
        {
            return ValidatedIssuerShape(contextIssuer, registration);
        }

        throw new InvalidOperationException(
            $"Cannot resolve issuer URI: registration '{registration.ClientId}' has no " +
            $"{nameof(ClientRecord.IssuerUri)} set and the request context does not " +
            "carry an Issuer URI. Either declare the canonical URL on the registration, or " +
            "have the ASP.NET skin populate the issuer on every request, or supply a custom " +
            $"{nameof(ResolveIssuerDelegate)} via {nameof(EndpointServer)}.{nameof(EndpointServer.Integration)}.{nameof(AuthorizationServerIntegration.ResolveIssuerAsync)}.");
    }


    /// <summary>
    /// Enforces <see cref="IssuerIdentifier.Parse"/> on a
    /// candidate issuer before it becomes the value this resolver returns. Applied
    /// to both the <see cref="ClientRecord.IssuerUri"/> and
    /// <c>ExchangeContextServerExtensions.Issuer</c> sources so every caller
    /// of this default resolver — discovery metadata and the RFC 9207 <c>iss</c>
    /// redirect parameter alike — emits a conformant issuer identifier.
    /// </summary>
    private static Uri ValidatedIssuerShape(Uri issuer, ClientRecord registration)
    {
        if(!IssuerIdentifier.Parse(issuer.OriginalString).IsSuccess)
        {
            throw new InvalidOperationException(
                $"Issuer identifier '{issuer}' configured for registration '{registration.ClientId}' does " +
                "not satisfy RFC 9207 §2 / RFC 8414 §2: it MUST be a URL using the https scheme with no " +
                "query or fragment component.");
        }

        return issuer;
    }
}
