namespace Verifiable.OAuth.Server;

/// <summary>
/// Resolves the authorization server's issuer identifier for a given
/// <see cref="ClientRegistration"/> and <see cref="RequestContext"/>.
/// </summary>
/// <remarks>
/// <para>
/// The issuer identifier (<c>iss</c>) is the case-sensitive URL by which the
/// authorization server advertises itself to wallets, resource servers, and
/// relying parties. It appears in the discovery document, in signed request
/// objects, and as the <c>iss</c> claim of every access token and ID token.
/// Consumers fetch <c>{iss}/.well-known/openid-configuration</c> and the JWKS
/// at the advertised path to verify signatures — so the value returned here
/// must be the URL at which the authorization server is actually reachable
/// for the caller that initiated this request.
/// </para>
/// <para>
/// <strong>Style B — cross-cutting single-value resolver.</strong>
/// This delegate is one of the library's cross-cutting resolvers: a single
/// scalar value looked up identically by several endpoints. Contrast with
/// per-token-type issuance hooks (Style A) that assemble coupled claim sets
/// for a specific token type. The issuer is shared across endpoints, so it
/// lives outside any token-specific hook.
/// </para>
/// <para>
/// The library ships <see cref="DefaultIssuerResolver"/> as the default
/// implementation. It reads <see cref="ClientRegistration.IssuerUri"/> first,
/// then falls back to <see cref="RequestContextExtensions.Issuer"/> set by
/// the ASP.NET skin, and throws when neither is available. Applications that
/// need per-caller, per-region, or dynamically-resolved issuer URIs set this
/// delegate on <see cref="AuthorizationServerOptions.ResolveIssuerAsync"/>
/// to supply their own logic. The returned URI is treated as authoritative;
/// no further normalisation is performed by the library.
/// </para>
/// </remarks>
/// <param name="registration">The registration for the current request.</param>
/// <param name="context">The per-request context bag.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The authoritative issuer URI for this request.</returns>
public delegate ValueTask<Uri> ResolveIssuerDelegate(
    ClientRegistration registration,
    RequestContext context,
    CancellationToken cancellationToken);
