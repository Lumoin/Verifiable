namespace Verifiable.OAuth.Server;

/// <summary>
/// Resolves the <c>aud</c> claim audience(s) for an RFC 9068 access token at
/// issuance time.
/// </summary>
/// <remarks>
/// <para>
/// Invoked by <see cref="Rfc9068AccessTokenProducer"/> on every token-endpoint
/// request that emits an access token. The delegate inspects the resolved
/// <see cref="IssuanceContext"/> — typically the granted scope — and returns
/// the list of resource-server identifiers the token grants access to per
/// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 §2.2</see>.
/// </para>
/// <para>
/// The library ships
/// <see cref="Rfc9068AccessTokenProducer.DefaultResolveAccessTokenAudienceAsync"/>
/// as a default; that default reads from
/// <see cref="ClientRecord.ScopeToAudience"/>. Applications that need
/// dynamic, tenant-aware, or registration-store-derived audience resolution
/// supply their own delegate via
/// <see cref="AuthorizationServerIntegration.ResolveAccessTokenAudienceAsync"/>.
/// </para>
/// <para>
/// Returning <see langword="null"/> or an empty list signals "no audience
/// resolved": the producer then writes the issuer, the value the token's <c>iss</c>
/// takes, as the token's one audience, the default resource indicator
/// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-3">RFC 9068 Section 3</see>
/// requires: "If the request does not include a "resource" parameter, the authorization
/// server MUST use a default resource indicator in the "aud" claim." Every access token the
/// producer writes therefore carries <c>aud</c>
/// (<see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 Section 2.2</see>: "aud
/// REQUIRED - as defined in Section 4.1.3 of [RFC7519].").
/// </para>
/// <para>
/// An answer that holds an entry that is null, empty or white space only names no resource:
/// the token request fails with 500 <c>server_error</c> and the description
/// <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/>, and no token of the request is
/// issued. The token endpoint holds the issued access token's <c>aud</c> to this before it is
/// signed, after the application's claim contributors have run.
/// </para>
/// <para>
/// The audiences answered are the token's whole <c>aud</c>: the issuer is not added to them.
/// This Authorization Server's own resources, UserInfo and the OID4VCI Credential, Deferred
/// Credential and Notification endpoints, refuse a token whose <c>aud</c> does not contain the
/// issuer (<see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>),
/// so a deployment whose clients call those resources with a token this delegate audiences
/// elsewhere answers the issuer among that token's audiences.
/// </para>
/// <para>
/// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2.3">RFC 9068 Section 2.2.3</see>: "All the
/// individual scope strings in the "scope" claim MUST have meaning for the resources indicated in the "aud"
/// claim." Which scopes have meaning at which resource is the deployment's knowledge, stated through this
/// delegate or <see cref="ClientRecord.ScopeToAudience"/>;
/// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-3">RFC 9068 Section 3</see>: "The mechanism through
/// which scopes are associated with default resource indicator values is outside the scope of this
/// specification." The issuer is the default of last resort and fits the scopes of the issuer's own resources.
/// </para>
/// </remarks>
/// <param name="registration">The client registration the token is issued for.</param>
/// <param name="context">The per-request issuance context — scope, subject, client id.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The resolved audiences, or <see langword="null"/> when none could be
/// resolved. The producer writes the audiences as a JSON array, a single audience
/// included, the general form of
/// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 Section 4.1.3</see>.
/// </returns>
public delegate ValueTask<IReadOnlyList<string>?> ResolveAccessTokenAudienceDelegate(
    ClientRecord registration,
    IssuanceContext context,
    CancellationToken cancellationToken);
