using Verifiable.Core.Assessment;
using Verifiable.JCose;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// All validation check functions for OAuth 2.0, OID4VP, and related protocols.
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
    /// Checks that the request contains a <c>state</c> parameter for CSRF protection.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRequestStatePresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.Fields!.TryGetValue(OAuthRequestParameters.State, out string? state)
            && !string.IsNullOrEmpty(state)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.RequestContainsState, outcome)]);
    }


    /// <summary>
    /// Checks that the request contains a <c>redirect_uri</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRequestRedirectUriPresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.Fields!.TryGetValue(OAuthRequestParameters.RedirectUri, out string? uri)
            && !string.IsNullOrEmpty(uri)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.RequestContainsRedirectUri, outcome)]);
    }


    /// <summary>
    /// Checks that the request contains a <c>code_challenge</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRequestCodeChallengePresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.Fields!.TryGetValue(OAuthRequestParameters.CodeChallenge, out string? challenge)
            && !string.IsNullOrEmpty(challenge)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.RequestContainsCodeChallenge, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>code_challenge_method</c> is <c>S256</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckRequestCodeChallengeMethodIsS256(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.Fields!.TryGetValue(OAuthRequestParameters.CodeChallengeMethod, out string? method)
            && string.Equals(method, OAuthRequestParameters.CodeChallengeMethodS256, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.RequestCodeChallengeMethodIsS256, outcome)]);
    }



    /// <summary>
    /// Checks that the <c>iss</c> claim is present and non-empty.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenIssPresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.TokenClaims!.TryGetValue(WellKnownJwtClaims.Iss, out object? iss)
            && iss is string issStr
            && !string.IsNullOrEmpty(issStr)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.IssPresent, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>iss</c> value matches the expected issuer.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenIssMatchesExpected(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        bool issPresent = context.TokenClaims!.TryGetValue(WellKnownJwtClaims.Iss, out object? iss)
            && iss is string issStr
            && !string.IsNullOrEmpty(issStr);

        ClaimOutcome outcome = issPresent
            && string.Equals((string)iss!, context.ExpectedIssuer, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.IssMatchesExpected, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>sub</c> claim is present and non-empty.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenSubPresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.TokenClaims!.TryGetValue(WellKnownJwtClaims.Sub, out object? sub)
            && sub is string subStr
            && !string.IsNullOrEmpty(subStr)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.SubPresent, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>aud</c> claim is present.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenAudPresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.TokenClaims!.ContainsKey(WellKnownJwtClaims.Aud)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.AudPresent, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>aud</c> value contains the expected client identifier.
    /// Handles both single-string and array representations per RFC 7519 §4.1.3.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenAudContainsClient(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(context.TokenClaims!.TryGetValue(WellKnownJwtClaims.Aud, out object? aud))
        {
            outcome = aud switch
            {
                string single => string.Equals(single, context.ExpectedClientId, StringComparison.Ordinal)
                    ? ClaimOutcome.Success
                    : ClaimOutcome.Failure,
                IEnumerable<object> array => array.Any(item =>
                    item is string s && string.Equals(s, context.ExpectedClientId, StringComparison.Ordinal))
                    ? ClaimOutcome.Success
                    : ClaimOutcome.Failure,
                _ => ClaimOutcome.Failure
            };
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.AudContainsExpectedClient, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>exp</c> claim is present.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenExpPresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.TokenClaims!.ContainsKey(WellKnownJwtClaims.Exp)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.ExpPresent, outcome)]);
    }


    /// <summary>
    /// Checks that the token has not expired.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenNotExpired(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(context.TokenClaims!.TryGetValue(WellKnownJwtClaims.Exp, out object? expValue)
            && TryGetUnixTime(expValue, out long expSeconds))
        {
            DateTimeOffset expiry = DateTimeOffset.FromUnixTimeSeconds(expSeconds);
            outcome = context.Now <= expiry + context.ClockSkew
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.TokenNotExpired, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>iat</c> claim is present.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenIatPresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.TokenClaims!.ContainsKey(WellKnownJwtClaims.Iat)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.IatPresent, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>iat</c> value is not in the future beyond clock skew.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenIatNotInFuture(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(context.TokenClaims!.TryGetValue(WellKnownJwtClaims.Iat, out object? iatValue)
            && TryGetUnixTime(iatValue, out long iatSeconds))
        {
            DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(iatSeconds);
            outcome = issuedAt <= context.Now + context.ClockSkew
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.IatNotInFuture, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>jti</c> claim is present.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenJtiPresent(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.TokenClaims!.TryGetValue(WellKnownJwtClaims.Jti, out object? jti)
            && jti is string jtiStr
            && !string.IsNullOrEmpty(jtiStr)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.JtiPresent, outcome)]);
    }


    /// <summary>
    /// Checks that the <c>jti</c> has not been seen before.
    /// </summary>
    public static ValueTask<List<Claim>> CheckTokenJtiNotReplayed(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(context.SeenJtiValues is not null
            && context.TokenClaims!.TryGetValue(WellKnownJwtClaims.Jti, out object? jti)
            && jti is string jtiStr
            && !string.IsNullOrEmpty(jtiStr))
        {
            outcome = !context.SeenJtiValues.Contains(jtiStr)
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.JtiNotReplayed, outcome)]);
    }



    /// <summary>
    /// Checks that the JWE <c>enc</c> header is in the set of allowed algorithms.
    /// </summary>
    public static ValueTask<List<Claim>> CheckJweEncAlgorithm(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.JweEncAlgorithm is not null
            && context.AllowedEncAlgorithms!.Any(a =>
                string.Equals(a, context.JweEncAlgorithm, StringComparison.Ordinal))
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.JweEncAlgorithmAllowed, outcome)]);
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
    public static ValueTask<List<Claim>> CheckKbJwtIatNotTooOld(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.KbJwtIat.HasValue
            && context.KbJwtIat.Value >= context.Now.Subtract(context.MaxAge)
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


    /// <summary>
    /// Records the outcome of session transcript verification for mdoc presentations.
    /// Conformance test: <c>VP1FinalVerifierInvalidSessionTranscript</c>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckSessionTranscript(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(
                ValidationClaimIds.SessionTranscriptValid,
                context.SessionTranscriptValid ? ClaimOutcome.Success : ClaimOutcome.Failure)]);
    }



    private static bool TryGetUnixTime(object value, out long seconds)
    {
        seconds = 0;
        return value switch
        {
            long l => (seconds = l) >= 0,
            int i => (seconds = i) >= 0,
            double d => (seconds = (long)d) >= 0,
            string s => long.TryParse(s, out seconds),
            _ => false
        };
    }
}
