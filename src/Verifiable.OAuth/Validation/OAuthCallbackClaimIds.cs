using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// Pre-defined <see cref="ClaimId"/> instances for OAuth 2.0 authorization callback
/// and request body validation.
/// </summary>
/// <remarks>
/// <para>
/// Codes 700–799 are reserved for OAuth 2.0 callback and flow validation checks.
/// Each entry maps to a specific security requirement from the following specifications:
/// </para>
/// <list type="bullet">
///   <item><description><see href="https://www.rfc-editor.org/rfc/rfc6749">RFC 6749</see> — OAuth 2.0 Authorization Framework.</description></item>
///   <item><description><see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</see> — Proof Key for Code Exchange (PKCE).</description></item>
///   <item><description><see href="https://www.rfc-editor.org/rfc/rfc9126">RFC 9126</see> — Pushed Authorization Requests (PAR).</description></item>
///   <item><description><see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see> — Authorization Server Issuer Identification.</description></item>
///   <item><description><see href="https://www.rfc-editor.org/rfc/rfc9700">RFC 9700</see> — OAuth 2.0 Security Best Current Practice.</description></item>
/// </list>
/// </remarks>
public static class OAuthCallbackClaimIds
{
    //Callback parameter presence checks — codes 700–709.

    /// <summary>
    /// The <c>code</c> parameter is present in the callback.
    /// Required per <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see>.
    /// </summary>
    public static ClaimId CallbackCodePresent { get; } = ClaimId.Create(700, "CallbackCodePresent");

    /// <summary>
    /// The <c>state</c> parameter is present in the callback.
    /// Required for CSRF defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public static ClaimId CallbackStatePresent { get; } = ClaimId.Create(701, "CallbackStatePresent");

    /// <summary>
    /// The <c>iss</c> parameter is present in the callback.
    /// Required for mix-up attack defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    public static ClaimId CallbackIssPresent { get; } = ClaimId.Create(702, "CallbackIssPresent");

    //RFC 9700 §4.4 — Mix-Up Attack mitigations — codes 710–719.

    /// <summary>
    /// The <c>iss</c> value in the callback matches the expected authorization server issuer.
    /// Failure indicates a potential mix-up attack per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    public static ClaimId IssuerMatchesExpected { get; } = ClaimId.Create(710, "IssuerMatchesExpected");

    //RFC 9700 §4.7 — CSRF mitigations — codes 720–729.

    /// <summary>
    /// The <c>state</c> value in the callback matches an active flow state.
    /// Failure indicates a CSRF attempt per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public static ClaimId StateMatchesActiveFlow { get; } = ClaimId.Create(720, "StateMatchesActiveFlow");

    /// <summary>
    /// The flow state has not expired at the time of the callback.
    /// Expired states must be rejected to prevent replay of stale authorization codes.
    /// </summary>
    public static ClaimId FlowStateNotExpired { get; } = ClaimId.Create(721, "FlowStateNotExpired");

    //RFC 9700 §4.5 — Authorization Code Injection mitigations — codes 730–739.

    /// <summary>
    /// The PAR request body contains a <c>code_challenge</c> parameter.
    /// Its absence would allow PKCE downgrade per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>.
    /// </summary>
    public static ClaimId ParBodyContainsCodeChallenge { get; } = ClaimId.Create(730, "ParBodyContainsCodeChallenge");

    /// <summary>
    /// The token request body contains a <c>code_verifier</c> parameter.
    /// Its absence when a <c>code_challenge</c> was registered indicates an injection attempt per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.5">RFC 9700 §4.5</see>.
    /// </summary>
    public static ClaimId TokenRequestContainsCodeVerifier { get; } = ClaimId.Create(731, "TokenRequestContainsCodeVerifier");

    //RFC 9700 §4.8 — PKCE Downgrade mitigations — codes 740–749.

    /// <summary>
    /// The <c>code_challenge_method</c> parameter value is <c>S256</c>.
    /// The plain method must not be used per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>
    /// and HAIP 1.0.
    /// </summary>
    public static ClaimId CodeChallengeMethodIsS256 { get; } = ClaimId.Create(740, "CodeChallengeMethodIsS256");
}