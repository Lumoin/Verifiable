using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// Pre-defined <see cref="ClaimId"/> instances for JWT token claim validation.
/// </summary>
/// <remarks>
/// <para>
/// Codes 800–899 are reserved for JWT registered claim checks defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc7519">RFC 7519</see> and the
/// security requirements from
/// <see href="https://www.rfc-editor.org/rfc/rfc9700">RFC 9700</see>.
/// Codes 850–869 cover scope validation.
/// Codes 870–899 cover request-side pre-send checks.
/// </para>
/// </remarks>
public static class OAuthTokenClaimIds
{
    //JWT registered claim presence checks — RFC 7519 §4.1, codes 800–819.

    /// <summary>
    /// The <c>iss</c> (issuer) claim is present and non-empty.
    /// Required per <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1">RFC 7519 §4.1.1</see>.
    /// </summary>
    public static ClaimId IssPresent { get; } = ClaimId.Create(800, "IssPresent");

    /// <summary>
    /// The <c>iss</c> value exactly matches the expected issuer identifier.
    /// Required for mix-up attack defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>
    /// and exact string comparison per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.3">RFC 8414 §3.3</see>.
    /// </summary>
    public static ClaimId IssMatchesExpected { get; } = ClaimId.Create(801, "IssMatchesExpected");

    /// <summary>
    /// The <c>sub</c> (subject) claim is present and non-empty.
    /// Required in ID Tokens per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
    /// </summary>
    public static ClaimId SubPresent { get; } = ClaimId.Create(802, "SubPresent");

    /// <summary>
    /// The <c>aud</c> (audience) claim is present per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see>.
    /// </summary>
    public static ClaimId AudPresent { get; } = ClaimId.Create(803, "AudPresent");

    /// <summary>
    /// The <c>aud</c> value contains the expected client identifier.
    /// Tokens not intended for this client must be rejected per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see>.
    /// </summary>
    public static ClaimId AudContainsExpectedClient { get; } = ClaimId.Create(804, "AudContainsExpectedClient");

    /// <summary>
    /// The <c>exp</c> (expiration time) claim is present per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 §4.1.4</see>.
    /// </summary>
    public static ClaimId ExpPresent { get; } = ClaimId.Create(805, "ExpPresent");

    /// <summary>
    /// The token has not expired — the current time is before <c>exp</c> allowing
    /// for configured clock skew.
    /// </summary>
    public static ClaimId TokenNotExpired { get; } = ClaimId.Create(806, "TokenNotExpired");

    /// <summary>
    /// The <c>nbf</c> (not before) claim is present per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">RFC 7519 §4.1.5</see>.
    /// </summary>
    public static ClaimId NbfPresent { get; } = ClaimId.Create(807, "NbfPresent");

    /// <summary>
    /// The current time is at or after <c>nbf</c>, allowing for clock skew.
    /// </summary>
    public static ClaimId TokenNotBeforeValid { get; } = ClaimId.Create(808, "TokenNotBeforeValid");

    /// <summary>
    /// The <c>iat</c> (issued at) claim is present per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">RFC 7519 §4.1.6</see>.
    /// </summary>
    public static ClaimId IatPresent { get; } = ClaimId.Create(809, "IatPresent");

    /// <summary>
    /// The <c>iat</c> value is not in the future beyond clock skew tolerance.
    /// Tokens issued in the future indicate a misconfigured server or a replay attempt.
    /// </summary>
    public static ClaimId IatNotInFuture { get; } = ClaimId.Create(810, "IatNotInFuture");

    /// <summary>
    /// The <c>jti</c> (JWT ID) claim is present per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 §4.1.7</see>.
    /// Required by FAPI 2.0 and HAIP 1.0 for replay prevention.
    /// </summary>
    public static ClaimId JtiPresent { get; } = ClaimId.Create(811, "JtiPresent");

    /// <summary>
    /// The <c>jti</c> value has not been seen before in the replay cache.
    /// Duplicate <c>jti</c> values indicate a token replay attack per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.2">RFC 9700 §2.2</see>.
    /// </summary>
    public static ClaimId JtiNotReplayed { get; } = ClaimId.Create(812, "JtiNotReplayed");

    //ID Token specific checks — OIDC Core 1.0 §2, codes 820–839.

    /// <summary>
    /// The <c>nonce</c> claim is present in the ID Token when a nonce was sent
    /// in the authorization request per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
    /// </summary>
    public static ClaimId NoncePresentInIdToken { get; } = ClaimId.Create(820, "NoncePresentInIdToken");

    /// <summary>
    /// The <c>nonce</c> value in the ID Token matches the nonce sent in the
    /// authorization request. A mismatch indicates a replay or injection attempt.
    /// </summary>
    public static ClaimId NonceMatchesRequest { get; } = ClaimId.Create(821, "NonceMatchesRequest");

    /// <summary>
    /// The <c>auth_time</c> claim satisfies the maximum authentication age
    /// constraint when <c>max_age</c> was requested per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>.
    /// </summary>
    public static ClaimId AuthTimeSatisfiesMaxAge { get; } = ClaimId.Create(822, "AuthTimeSatisfiesMaxAge");

    /// <summary>
    /// The <c>acr</c> (Authentication Context Class Reference) satisfies the
    /// requested <c>acr_values</c> constraint per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
    /// </summary>
    public static ClaimId AcrSatisfiesRequest { get; } = ClaimId.Create(823, "AcrSatisfiesRequest");

    //Token lifetime range checks — codes 840–849.

    /// <summary>
    /// The difference between <c>exp</c> and <c>nbf</c> (or <c>iat</c>) does not
    /// exceed the maximum permitted lifetime. Excessively long-lived tokens increase
    /// the window for replay attacks per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.2">RFC 9700 §2.2</see>.
    /// FAPI 2.0 / HAIP 1.0 require JAR <c>exp - nbf</c> ≤ 60 seconds.
    /// </summary>
    public static ClaimId TokenLifetimeWithinMaximum { get; } = ClaimId.Create(840, "TokenLifetimeWithinMaximum");

    //Scope validation checks — codes 850–869.

    /// <summary>
    /// The <c>scope</c> parameter or claim is present and non-empty.
    /// </summary>
    public static ClaimId ScopePresent { get; } = ClaimId.Create(850, "ScopePresent");

    /// <summary>
    /// The <c>scope</c> contains <c>openid</c>, confirming that OIDC authentication
    /// was requested per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>.
    /// </summary>
    public static ClaimId ScopeContainsOpenId { get; } = ClaimId.Create(851, "ScopeContainsOpenId");

    /// <summary>
    /// The granted <c>scope</c> does not include values that were not requested.
    /// An authorization server that expands scope beyond what was requested violates
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>.
    /// </summary>
    public static ClaimId ScopeDoesNotExceedRequested { get; } = ClaimId.Create(852, "ScopeDoesNotExceedRequested");

    //Outbound request pre-send checks — codes 870–899.

    /// <summary>
    /// The request contains a <c>state</c> parameter for CSRF protection per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public static ClaimId RequestContainsState { get; } = ClaimId.Create(870, "RequestContainsState");

    /// <summary>
    /// The request contains a <c>redirect_uri</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>.
    /// </summary>
    public static ClaimId RequestContainsRedirectUri { get; } = ClaimId.Create(871, "RequestContainsRedirectUri");

    /// <summary>
    /// The request contains a <c>code_challenge</c>, ensuring PKCE is active and
    /// a PKCE downgrade attack cannot succeed per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>.
    /// </summary>
    public static ClaimId RequestContainsCodeChallenge { get; } = ClaimId.Create(872, "RequestContainsCodeChallenge");

    /// <summary>
    /// The <c>code_challenge_method</c> is <c>S256</c>.
    /// The plain method must not be used per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>.
    /// </summary>
    public static ClaimId RequestCodeChallengeMethodIsS256 { get; } = ClaimId.Create(873, "RequestCodeChallengeMethodIsS256");
}