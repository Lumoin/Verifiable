using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Library-provided default implementation of the issuer-resolution logic
/// behind <see cref="ResolveIssuerDelegate"/>.
/// </summary>
/// <remarks>
/// <para>
/// Applied by every call site in the library when
/// <see cref="AuthorizationServerOptions.ResolveIssuerAsync"/> is not set.
/// Applications that set that delegate bypass this helper entirely; the
/// library never second-guesses an application-supplied resolver.
/// </para>
/// <para>
/// Resolution order:
/// </para>
/// <list type="number">
///   <item>
///     <description>
///       <see cref="ClientRegistration.IssuerUri"/> — the declared canonical
///       URL for the tenant. Used as-is when set. Suitable for deployments
///       where the tenant's authorization-server URL is stable and known at
///       registration time.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="RequestContextExtensions.Issuer"/> — a request-scoped URI
///       populated by the ASP.NET skin from the incoming request's scheme and
///       host. Used when the registration does not declare an issuer,
///       accommodating deployments where the URL is derived per-request from
///       the reverse proxy's forwarded host.
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
[DebuggerDisplay("DefaultIssuerResolver")]
public static class DefaultIssuerResolver
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
    /// Thrown when neither <see cref="ClientRegistration.IssuerUri"/> nor
    /// <see cref="RequestContextExtensions.Issuer"/> is set.
    /// </exception>
    public static ValueTask<Uri> ResolveAsync(
        ClientRegistration registration,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        if(registration.IssuerUri is not null)
        {
            return ValueTask.FromResult(registration.IssuerUri);
        }

        Uri? contextIssuer = context.Issuer;
        if(contextIssuer is not null)
        {
            return ValueTask.FromResult(contextIssuer);
        }

        throw new InvalidOperationException(
            $"Cannot resolve issuer URI: registration '{registration.ClientId}' has no " +
            $"{nameof(ClientRegistration.IssuerUri)} set and the request context does not " +
            "carry an Issuer URI. Either declare the canonical URL on the registration, or " +
            "have the ASP.NET skin populate the issuer on every request, or supply a custom " +
            $"{nameof(ResolveIssuerDelegate)} via {nameof(AuthorizationServerOptions)}.{nameof(AuthorizationServerOptions.ResolveIssuerAsync)}.");
    }
}
