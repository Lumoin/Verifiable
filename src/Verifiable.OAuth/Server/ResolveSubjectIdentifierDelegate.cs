using Verifiable.Core;
namespace Verifiable.OAuth.Server;

/// <summary>
/// Maps an authenticated end-user identifier to the subject identifier the
/// server emits in tokens for a given <see cref="ClientRecord"/>. Used by
/// ID Token issuance and the UserInfo endpoint to honour OIDC
/// <c>subject_type</c> per OIDC Core §8 — public subjects are the
/// end-user identifier as-is; pairwise subjects are a per-sector hash so a
/// single subject appears under different identifiers to different relying
/// parties.
/// </summary>
/// <remarks>
/// <para>
/// The library default is
/// <see cref="DefaultSubjectIdentifierResolver.PublicAsync"/> which returns
/// the end-user identifier unchanged. Pairwise deployments wire a
/// <see cref="ResolveSubjectIdentifierDelegate"/> that computes the per-
/// sector hash (typically <c>SHA-256(sector_identifier_uri ‖ sub ‖ salt)</c>).
/// </para>
/// <para>
/// Phase 9h adds the slot structurally so Phase A's UserInfo wiring does
/// not have to revisit <see cref="AuthorizationServerIntegration"/>. The
/// slot is not yet read by any token producer in 9h.
/// </para>
/// </remarks>
/// <param name="endUserId">The authenticated end-user identifier (typically <see cref="ExchangeContextServerExtensions.SubjectId"/>).</param>
/// <param name="registration">The registration the token is being issued for.</param>
/// <param name="context">The per-request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The subject identifier to emit in the token's <c>sub</c> claim.</returns>
public delegate ValueTask<string> ResolveSubjectIdentifierDelegate(
    string endUserId,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
