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
/// <see cref="Pipeline.DefaultSubjectIdentifierResolver.PublicAsync"/> which returns
/// the end-user identifier unchanged. Pairwise deployments wire a
/// <see cref="ResolveSubjectIdentifierDelegate"/> that computes the per-
/// sector hash (typically <c>SHA-256(sector_identifier_uri ‖ sub ‖ salt)</c>).
/// </para>
/// <para>
/// A structural slot the UserInfo wiring resolves the subject identifier
/// through, without requiring changes to
/// <see cref="AuthorizationServerIntegration"/>. The slot is not read by
/// any token producer.
/// </para>
/// <para>
/// For the life of one grant, the application returns the SAME value for the same
/// <paramref name="endUserId"/> and <paramref name="registration"/> on every call this delegate
/// answers — the initial issuance and every later refresh alike — because
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">OpenID
/// Connect Core 1.0 §12.2</see> requires a refreshed ID Token's <c>sub</c> Claim Value to "be the
/// same as in the ID Token issued when the original authentication occurred." The library does not
/// store the emitted <c>sub</c> to enforce this; the application's own resolution (a stable
/// end-user identifier, or a deterministic pairwise hash of one) is what makes it hold.
/// </para>
/// </remarks>
/// <param name="endUserId">The authenticated end-user identifier (typically the <see cref="ExchangeContext"/>'s <c>SubjectId</c> extension property).</param>
/// <param name="registration">The registration the token is being issued for.</param>
/// <param name="context">The per-request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The subject identifier to emit in the token's <c>sub</c> claim.</returns>
public delegate ValueTask<string> ResolveSubjectIdentifierDelegate(
    string endUserId,
    ClientRecord registration,
    ExchangeContext context,
    CancellationToken cancellationToken);
