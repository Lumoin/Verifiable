using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
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

        ClaimOutcome outcome = context.Fields!.ContainsKey(OAuthRequestParameterNames.Code)
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

        ClaimOutcome outcome = context.Fields!.ContainsKey(OAuthRequestParameterNames.State)
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

        ClaimOutcome outcome = context.Fields!.ContainsKey(OAuthRequestParameterNames.Iss)
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

        bool issPresent = context.Fields!.TryGetValue(OAuthRequestParameterNames.Iss, out string? iss);
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

        bool statePresent = context.Fields!.TryGetValue(OAuthRequestParameterNames.State, out string? state);
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
    /// <remarks>
    /// Reads the clock-skew tolerance from the per-request policy
    /// (<see cref="Verifiable.OAuth.Server.PolicyExchangeContextExtensions.ClockSkewToleranceOverride"/>)
    /// when populated — so a deployment's profile governs the leeway per flow —
    /// otherwise falls back to the <see cref="ValidationContext.ClockSkew"/> field.
    /// Mirrors how <see cref="CheckKbJwtIatNotTooOld"/> resolves its window.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckKbJwtIatNotInFuture(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        TimeSpan clockSkew = context.Context?.ClockSkewToleranceOverride ?? context.ClockSkew;

        ClaimOutcome outcome = context.KbJwtIat.HasValue
            && context.KbJwtIat.Value <= context.Now.Add(clockSkew)
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
    /// (<see cref="Verifiable.OAuth.Server.PolicyExchangeContextExtensions.KbJwtMaxAgeWindow"/>)
    /// when populated; otherwise falls back to the legacy
    /// <see cref="ValidationContext.KbJwtMaxAge"/> field. Enforces a library
    /// default for the KB-JWT <c>iat</c>-too-old window.
    /// </remarks>
    public static ValueTask<List<Claim>> CheckKbJwtIatNotTooOld(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        TimeSpan maxAge = context.Context?.KbJwtMaxAgeWindow ?? context.KbJwtMaxAge;

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


    /// <summary>
    /// Records the outcome of the mdoc device-signature verification over the
    /// verifier-reconstructed <c>SessionTranscript</c>. The transcript
    /// reconstruction and the signature check happen in
    /// <see cref="Oid4Vp.Server.MdocVpTokenVerification"/>; this check only
    /// surfaces the resulting boolean, mirroring <see cref="CheckSdHash"/>.
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


    /// <summary>
    /// Records whether the presentation satisfies the DCQL query — every claim
    /// the credential query requested is present in the extracted claims. The
    /// derivation (comparing the query's requested leaf identifiers against the
    /// extracted claims) happens in the verify step
    /// (<see cref="Oid4Vp.HaipOid4VpVerifierExecutor"/>); this check only
    /// surfaces the resulting boolean, mirroring <see cref="CheckSessionTranscript"/>.
    /// </summary>
    public static ValueTask<List<Claim>> CheckDcqlSatisfaction(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(
                ValidationClaimIds.DcqlSatisfied,
                context.DcqlSatisfied ? ClaimOutcome.Success : ClaimOutcome.Failure)]);
    }


    /// <summary>
    /// Records whether the presentation stayed within the DCQL query's requested
    /// claims (data minimization). The over-disclosure derivation (a disclosed
    /// claim the query did not request) happens in the verify step
    /// (<see cref="Oid4Vp.HaipOid4VpVerifierExecutor"/>) and is surfaced via
    /// <see cref="ValidationContext.DcqlOverDisclosed"/>; enforcement is gated by
    /// the per-request policy
    /// (<see cref="Verifiable.OAuth.Server.PolicyExchangeContextExtensions.EnforceNoOverDisclosure"/>,
    /// default enforce). When enforcement is disabled the check passes regardless,
    /// leaving the over-disclosure signal available for audit/telemetry.
    /// </summary>
    public static ValueTask<List<Claim>> CheckNoOverDisclosure(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        bool enforce = context.Context?.EnforceNoOverDisclosure ?? true;

        ClaimOutcome outcome = !enforce || !context.DcqlOverDisclosed
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.NoOverDisclosure, outcome)]);
    }


    /// <summary>
    /// Records whether the presentation's disclosure salts meet the recommended minimum length. The
    /// shortest observed salt length is surfaced via
    /// <see cref="ValidationContext.MinimumDisclosureSaltLengthBytes"/> by the verify step; this check
    /// compares it against <see cref="Verifiable.Cryptography.Salt.RecommendedByteLength"/>. Enforcement
    /// is opt-in (<see cref="Verifiable.OAuth.Server.PolicyExchangeContextExtensions.EnforceMinimumSaltLength"/>,
    /// default observe): when enforcement is off the check always passes, leaving the length signal
    /// available for audit/telemetry; RFC 9901 §9.3 RECOMMENDS rather than mandates the length, so
    /// observe is the principled default.
    /// </summary>
    public static ValueTask<List<Claim>> CheckDisclosureSaltLength(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        bool enforce = context.Context?.EnforceMinimumSaltLength ?? false;
        bool belowRecommended = context.MinimumDisclosureSaltLengthBytes is int length
            && length < Salt.RecommendedByteLength;

        ClaimOutcome outcome = !enforce || !belowRecommended
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.DisclosureSaltLength, outcome)]);
    }


    /// <summary>
    /// Records whether the presentation reused a disclosure salt. The reuse signal
    /// (<see cref="ValidationContext.SaltReused"/>) is derived in the verify step against the
    /// application's salt-reuse store and is only ever set when a store was wired, so a detected reuse
    /// always fails — the opt-in, enforce-when-wired posture of DPoP-JTI replay (no separate policy gate).
    /// When no store is wired the signal is <see langword="false"/> and the check passes.
    /// </summary>
    public static ValueTask<List<Claim>> CheckSaltReuse(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.SaltReused
            ? ClaimOutcome.Failure
            : ClaimOutcome.Success;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.SaltNotReused, outcome)]);
    }


    /// <summary>
    /// Checks the KB-JWT <c>transaction_data_hashes</c> against the Verifier's
    /// expectation per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4">OID4VP 1.0 §8.4</see>.
    /// Success when both sides are absent (no transaction_data sent) or the
    /// two arrays are positionally equal; failure for any mismatch.
    /// </summary>
    public static ValueTask<List<Claim>> CheckKbJwtTransactionDataHashes(
        ValidationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = TransactionDataHashesEqual(
            context.KbJwtTransactionDataHashes,
            context.ExpectedTransactionDataHashes)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>(
            [new Claim(ValidationClaimIds.KbJwtTransactionDataHashesMatchRequest, outcome)]);
    }


    private static bool TransactionDataHashesEqual(
        IReadOnlyList<string>? left, IReadOnlyList<string>? right)
    {
        bool leftEmpty = left is null || left.Count == 0;
        bool rightEmpty = right is null || right.Count == 0;
        if(leftEmpty && rightEmpty)
        {
            return true;
        }

        if(leftEmpty || rightEmpty)
        {
            return false;
        }

        if(left!.Count != right!.Count)
        {
            return false;
        }

        for(int i = 0; i < left.Count; i++)
        {
            if(!string.Equals(left[i], right[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }
}
