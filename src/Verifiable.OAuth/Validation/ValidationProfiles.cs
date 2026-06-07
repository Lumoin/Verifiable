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

            new(ValidationChecks.CheckKbJwtTransactionDataHashes,
                [ValidationClaimIds.KbJwtTransactionDataHashesMatchRequest]),

            new(ValidationChecks.CheckDcqlSatisfaction,
                [ValidationClaimIds.DcqlSatisfied]),

            new(ValidationChecks.CheckNoOverDisclosure,
                [ValidationClaimIds.NoOverDisclosure]),

            new(ValidationChecks.CheckDisclosureSaltLength,
                [ValidationClaimIds.DisclosureSaltLength]),

            new(ValidationChecks.CheckSaltReuse,
                [ValidationClaimIds.SaltNotReused]),
        };


    /// <summary>
    /// HAIP 1.0 verification rules for ISO mdoc (<c>mso_mdoc</c>) presentations.
    /// </summary>
    /// <remarks>
    /// mdoc carries no KB-JWT and no <c>sd_hash</c>; the holder binding is the
    /// device COSE_Sign1 over the OID4VP <c>SessionTranscript</c>, which binds
    /// <c>client_id</c>/<c>response_uri</c>/<c>nonce</c> cryptographically. So
    /// the rule set is the credential (issuer-auth + MSO digest binding)
    /// signature plus the session-transcript device signature — the KB-JWT and
    /// <c>sd_hash</c> axes the SD-JWT profile checks are not applicable.
    /// </remarks>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<ValidationContext>> Haip10MdocRules() =>
        new List<ClaimDelegate<ValidationContext>>
        {
            new(ValidationChecks.CheckCredentialSignature,
                [ValidationClaimIds.CredentialSignatureValid]),

            new(ValidationChecks.CheckSessionTranscript,
                [ValidationClaimIds.SessionTranscriptValid]),

            new(ValidationChecks.CheckDcqlSatisfaction,
                [ValidationClaimIds.DcqlSatisfied]),

            new(ValidationChecks.CheckNoOverDisclosure,
                [ValidationClaimIds.NoOverDisclosure]),
        };


    /// <summary>
    /// HAIP 1.0 verification rules for SD-CWT (<c>dc+sd-cwt</c>) presentations.
    /// </summary>
    /// <remarks>
    /// The holder binding is the SD-CWT Key Binding Token (KBT); its signature and
    /// <c>aud</c>/<c>iat</c>/<c>cnonce</c> map onto the same key-binding axes the SD-JWT
    /// KB-JWT fills, so the KB-JWT checks apply unchanged. SD-CWT carries no
    /// <c>sd_hash</c> and no SessionTranscript, so those checks are omitted.
    /// </remarks>
    /// <returns>A mutable list the application can extend.</returns>
    public static IList<ClaimDelegate<ValidationContext>> Haip10SdCwtRules() =>
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

            new(ValidationChecks.CheckDcqlSatisfaction,
                [ValidationClaimIds.DcqlSatisfied]),

            new(ValidationChecks.CheckNoOverDisclosure,
                [ValidationClaimIds.NoOverDisclosure]),

            new(ValidationChecks.CheckDisclosureSaltLength,
                [ValidationClaimIds.DisclosureSaltLength]),

            new(ValidationChecks.CheckSaltReuse,
                [ValidationClaimIds.SaltNotReused]),
        };
}
