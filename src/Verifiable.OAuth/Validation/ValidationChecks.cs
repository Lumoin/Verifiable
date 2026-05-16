using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// Validation check functions for OAuth 2.0 callback handling, JAR audience
/// validation, and OID4VP SD-JWT KB-JWT / credential signature verification.
/// Each function matches the <see cref="ClaimDelegateAsync{TInput}"/> signature
/// for composition via <see cref="ClaimIssuer{TInput}"/>.
/// </summary>
/// <remarks>
/// <para>
/// Adding a new protocol flow (CIBA, Federation, OID4VCI) means adding methods
/// here — not new files. Every check takes its context type and returns
/// <see cref="List{T}"/> of <see cref="Claim"/>.
/// </para>
/// </remarks>
public static class ValidationChecks
{
    /// <summary>
    /// Checks that the <c>code</c> parameter is present in the callback fields.
    /// </summary>
    public static ValueTask<List<Claim>> CheckCallbackCodePresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.Fields!.ContainsKey(OAuthRequestParameters.Code)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.CallbackCodePresent, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>state</c> parameter is present in the callback fields.
    /// </summary>
    public static ValueTask<List<Claim>> CheckCallbackStatePresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.Fields!.ContainsKey(OAuthRequestParameters.State)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.CallbackStatePresent, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>iss</c> parameter is present in the callback fields.
    /// Required for mix-up attack defense per RFC 9207.
    /// </summary>
    public static ValueTask<List<Claim>> CheckCallbackIssPresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.Fields!.ContainsKey(OAuthRequestParameters.Iss)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.CallbackIssPresent, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>iss</c> value matches the expected issuer.
    /// Exact string comparison per RFC 8414 §3.3.
    /// </summary>
    public static ValueTask<List<Claim>> CheckCallbackIssuerMatches(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        bool issPresent = context.Fields!.TryGetValue(OAuthRequestParameters.Iss, out string? iss);
        ClaimOutcome outcome = issPresent
            && string.Equals(iss, context.FlowState!.ExpectedIssuer, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.IssuerMatchesExpected, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>state</c> value matches the loaded flow state.
    /// </summary>
    public static ValueTask<List<Claim>> CheckCallbackStateMatchesFlow(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        bool statePresent = context.Fields!.TryGetValue(OAuthRequestParameters.State, out string? state);
        ClaimOutcome outcome = statePresent
            && string.Equals(state, context.FlowState!.FlowId, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.StateMatchesActiveFlow, outcome)]);
    }


    /// <summary>
    /// Checks that the flow state has not expired.
    /// </summary>
    public static ValueTask<List<Claim>> CheckCallbackFlowNotExpired(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.Now <= context.FlowState!.ExpiresAt
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.FlowStateNotExpired, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>aud</c> claim contains the expected issuer URL.
    /// Handles both single-string and array representations per RFC 7519 §4.1.3.
    /// Used for JAR <c>aud</c> validation per RFC 9101 §10.2.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenAudContainsExpectedIssuer(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(context.TokenClaims!.TryGetValue(WellKnownJwtClaimNames.Aud, out object? aud))
        {
            outcome = aud switch
            {
                string single => string.Equals(single, context.ExpectedIssuer, StringComparison.Ordinal)
                    ? ClaimOutcome.Success
                    : ClaimOutcome.Failure,
                IEnumerable<object> array => array.Any(item =>
                    item is string s && string.Equals(s, context.ExpectedIssuer, StringComparison.Ordinal))
                    ? ClaimOutcome.Success
                    : ClaimOutcome.Failure,
                _ => ClaimOutcome.Failure
            };
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.AudContainsExpectedIssuer, outcome)]);
    }


    /// <summary>
    /// Checks that the KB-JWT <c>nonce</c> matches the nonce from the authorization request.
    /// Conformance test: <c>VP1FinalVerifierInvalidKbJwtNonce</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckKbJwtNonce(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.KbJwtNonce is not null
            && string.Equals(context.KbJwtNonce, context.ExpectedNonce, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.KbJwtNonceMatchesRequest, outcome)]);
    }


    /// <summary>
    /// Checks that the KB-JWT <c>aud</c> matches the Verifier's client identifier.
    /// Conformance test: <c>VP1FinalVerifierInvalidKbJwtAud</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckKbJwtAud(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.KbJwtAud is not null
            && string.Equals(context.KbJwtAud, context.ExpectedClientId, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.KbJwtAudMatchesClientId, outcome)]);
    }


    /// <summary>
    /// Checks that the KB-JWT <c>iat</c> is not in the future.
    /// Conformance test: <c>VP1FinalVerifierKbJwtIatInFuture</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckKbJwtIatNotInFuture(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.KbJwtIat.HasValue
            && context.KbJwtIat.Value <= context.Now.Add(context.ClockSkew)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.KbJwtIatNotInFuture, outcome)]);
    }


    /// <summary>
    /// Checks that the KB-JWT <c>iat</c> is not too far in the past.
    /// Conformance test: <c>VP1FinalVerifierKbJwtIatInPast</c>.
    /// </summary>
    /// <remarks>
    /// Reads the freshness window from the per-request policy
    /// (<see cref="Verifiable.OAuth.Server.PolicyRequestContextExtensions.KbJwtMaxAgeWindow"/>)
    /// when populated; otherwise falls back to the legacy
    /// <see cref="ValidationContext.MaxAge"/> field. Closes audit Finding 7
    /// (KB-JWT <c>iat</c>-too-old window has no library default).
    /// </remarks>
    public static ValueTask<List<Claim>> CheckKbJwtIatNotTooOld(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        TimeSpan maxAge = context.Context?.KbJwtMaxAgeWindow ?? context.MaxAge;

        ClaimOutcome outcome = context.KbJwtIat.HasValue
            && context.KbJwtIat.Value >= context.Now.Subtract(maxAge)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.KbJwtIatNotTooOld, outcome)]);
    }


    /// <summary>
    /// Records the outcome of KB-JWT signature verification.
    /// Conformance test: <c>VP1FinalVerifierInvalidKbJwtSignature</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckKbJwtSignature(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(
                ValidationClaimIds.KbJwtSignatureValid,
                context.KbJwtSignatureValid ? ClaimOutcome.Success : ClaimOutcome.Failure)]);
    }


    /// <summary>
    /// Records the outcome of credential issuer signature verification.
    /// Conformance test: <c>VP1FinalVerifierInvalidCredentialSignature</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckCredentialSignature(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(
                ValidationClaimIds.CredentialSignatureValid,
                context.CredentialSignatureValid ? ClaimOutcome.Success : ClaimOutcome.Failure)]);
    }


    /// <summary>
    /// Records the outcome of <c>sd_hash</c> verification.
    /// Conformance test: <c>VP1FinalVerifierInvalidSdHash</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckSdHash(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(
                ValidationClaimIds.SdHashMatchesPresentation,
                context.SdHashValid ? ClaimOutcome.Success : ClaimOutcome.Failure)]);
    }
}
