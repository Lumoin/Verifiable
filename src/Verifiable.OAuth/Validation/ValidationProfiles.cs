using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// Pre-built <see cref="ClaimDelegate{TInput}"/> lists for all validation points,
/// composable via <see cref="ClaimIssuer{TInput}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each method returns a mutable <see cref="IList{T}"/> the application can extend
/// with custom rules before passing to a <see cref="ClaimIssuer{TInput}"/>.
/// Adding a new protocol flow means adding methods here — not new files.
/// </para>
/// <para>
/// Example: extending HAIP 1.0 VP verification with a custom trust framework check.
/// </para>
/// <code>
/// var rules = ValidationProfiles.Haip10SdJwtRules();
/// rules.Add(new ClaimDelegate&lt;ValidationContext&gt;(
///     MyChecks.CheckTrustFramework,
///     [MyClaimIds.TrustFrameworkValid]));
///
/// var verifier = new ClaimIssuer&lt;ValidationContext&gt;(
///     "vp-verifier", rules, timeProvider);
/// </code>
/// </remarks>
public static class ValidationProfiles
{
    /// <summary>
    /// RFC 6749 with PKCE callback validation rules.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<ValidationContext>> CallbackRfc6749WithPkceRules() =>
        new List<ClaimDelegate<ValidationContext>>
        {
            new(ValidationChecks.CheckCallbackCodePresent,
                [ValidationClaimIds.CallbackCodePresent]),

            new(ValidationChecks.CheckCallbackStatePresent,
                [ValidationClaimIds.CallbackStatePresent]),

            new(ValidationChecks.CheckCallbackStateMatchesFlow,
                [ValidationClaimIds.StateMatchesActiveFlow]),

            new(ValidationChecks.CheckCallbackFlowNotExpired,
                [ValidationClaimIds.FlowStateNotExpired]),
        };


    /// <summary>
    /// HAIP 1.0 / FAPI 2.0 callback validation rules. Adds <c>iss</c> parameter
    /// checks for mix-up attack defense per RFC 9207.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<ValidationContext>> CallbackHaip10Rules() =>
        new List<ClaimDelegate<ValidationContext>>
        {
            new(ValidationChecks.CheckCallbackCodePresent,
                [ValidationClaimIds.CallbackCodePresent]),

            new(ValidationChecks.CheckCallbackStatePresent,
                [ValidationClaimIds.CallbackStatePresent]),

            new(ValidationChecks.CheckCallbackIssPresent,
                [ValidationClaimIds.CallbackIssPresent]),

            new(ValidationChecks.CheckCallbackIssuerMatches,
                [ValidationClaimIds.IssuerMatchesExpected]),

            new(ValidationChecks.CheckCallbackStateMatchesFlow,
                [ValidationClaimIds.StateMatchesActiveFlow]),

            new(ValidationChecks.CheckCallbackFlowNotExpired,
                [ValidationClaimIds.FlowStateNotExpired]),
        };



    /// <summary>
    /// PAR request body validation rules: <c>state</c>, <c>redirect_uri</c>,
    /// <c>code_challenge</c> presence, and <c>code_challenge_method = S256</c>.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<ValidationContext>> ParRequestRules() =>
        new List<ClaimDelegate<ValidationContext>>
        {
            new(ValidationChecks.CheckRequestStatePresent,
                [ValidationClaimIds.RequestContainsState]),

            new(ValidationChecks.CheckRequestRedirectUriPresent,
                [ValidationClaimIds.RequestContainsRedirectUri]),

            new(ValidationChecks.CheckRequestCodeChallengePresent,
                [ValidationClaimIds.RequestContainsCodeChallenge]),

            new(ValidationChecks.CheckRequestCodeChallengeMethodIsS256,
                [ValidationClaimIds.RequestCodeChallengeMethodIsS256]),
        };



    /// <summary>
    /// HAIP 1.0 verification rules for SD-JWT VC presentations.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<ValidationContext>> Haip10SdJwtRules() =>
        new List<ClaimDelegate<ValidationContext>>
        {
            new(ValidationChecks.CheckKbJwtSignature,
                [ValidationClaimIds.KbJwtSignatureValid]),

            new(ValidationChecks.CheckKbJwtNonce,
                [ValidationClaimIds.KbJwtNonceMatchesRequest]),

            new(ValidationChecks.CheckKbJwtAud,
                [ValidationClaimIds.KbJwtAudMatchesClientId]),

            new(ValidationChecks.CheckKbJwtIatNotInFuture,
                [ValidationClaimIds.KbJwtIatNotInFuture]),

            new(ValidationChecks.CheckKbJwtIatNotTooOld,
                [ValidationClaimIds.KbJwtIatNotTooOld]),

            new(ValidationChecks.CheckCredentialSignature,
                [ValidationClaimIds.CredentialSignatureValid]),

            new(ValidationChecks.CheckSdHash,
                [ValidationClaimIds.SdHashMatchesPresentation]),
        };


    /// <summary>
    /// HAIP 1.0 verification rules for mdoc presentations. KB-JWT checks are
    /// omitted (mdoc uses device authentication). Session transcript replaces
    /// <c>sd_hash</c>.
    /// </summary>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<ValidationContext>> Haip10MdocRules() =>
        new List<ClaimDelegate<ValidationContext>>
        {
            new(ValidationChecks.CheckCredentialSignature,
                [ValidationClaimIds.CredentialSignatureValid]),

            new(ValidationChecks.CheckSessionTranscript,
                [ValidationClaimIds.SessionTranscriptValid]),
        };
}
