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
/// resolved." The producer's behaviour on null/empty depends on the active
/// <see cref="AccessTokenAudPolicy"/>: <c>Required</c> raises
/// <see cref="InvalidOperationException"/>; <c>Optional</c> emits no
/// <c>aud</c> claim; <c>Suppressed</c> never emits regardless.
/// </para>
/// </remarks>
/// <param name="registration">The client registration the token is issued for.</param>
/// <param name="context">The per-request issuance context — scope, subject, client id.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The resolved audiences, or <see langword="null"/> when none could be
/// resolved. Multiple audiences are emitted as a JSON array per
/// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see>;
/// a single audience is emitted as a JSON string.
/// </returns>
public delegate ValueTask<IReadOnlyList<string>?> ResolveAccessTokenAudienceDelegate(
    ClientRecord registration,
    IssuanceContext context,
    CancellationToken cancellationToken);
