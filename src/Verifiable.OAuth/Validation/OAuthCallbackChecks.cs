using Verifiable.Core.Assessment;

namespace Verifiable.OAuth.Validation;


/// <summary>
/// Individual callback validation check functions.
/// </summary>
/// <remarks>
/// These are the building blocks used by <see cref="OAuthCallbackValidators"/>.
/// Callers composing a custom <see cref="ValidateCallbackDelegate"/> can call these
/// directly, adding or omitting checks as their profile requires.
/// </remarks>
public static class OAuthCallbackChecks
{
    /// <summary>
    /// Checks that the <c>code</c> parameter is present in the callback fields.
    /// </summary>
    public static void CheckCodePresent(
        IReadOnlyDictionary<string, string> fields,
        List<Claim> claims)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(claims);

        ClaimOutcome outcome = fields.ContainsKey(OAuthRequestParameters.Code)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;
        claims.Add(new Claim(OAuthCallbackClaimIds.CallbackCodePresent, outcome));
    }


    /// <summary>
    /// Checks that the <c>state</c> parameter is present in the callback fields.
    /// </summary>
    public static void CheckStatePresent(
        IReadOnlyDictionary<string, string> fields,
        List<Claim> claims)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(claims);

        ClaimOutcome outcome = fields.ContainsKey(OAuthRequestParameters.State)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;
        claims.Add(new Claim(OAuthCallbackClaimIds.CallbackStatePresent, outcome));
    }


    /// <summary>
    /// Checks that the <c>iss</c> parameter is present in the callback fields.
    /// Required for HAIP 1.0 and FAPI 2.0 mix-up attack defense per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9207">RFC 9207</see>.
    /// </summary>
    public static void CheckIssPresent(
        IReadOnlyDictionary<string, string> fields,
        List<Claim> claims)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(claims);

        ClaimOutcome outcome = fields.ContainsKey(OAuthRequestParameters.Iss)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;
        claims.Add(new Claim(OAuthCallbackClaimIds.CallbackIssPresent, outcome));
    }


    /// <summary>
    /// Checks that the <c>iss</c> value exactly matches the expected issuer stored in
    /// the flow state. Exact string comparison is required per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.3">RFC 8414 §3.3</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.4">RFC 9700 §4.4</see>.
    /// </summary>
    public static void CheckIssuerMatches(
        IReadOnlyDictionary<string, string> fields,
        OAuthFlowState flowState,
        List<Claim> claims)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(flowState);
        ArgumentNullException.ThrowIfNull(claims);

        bool issPresent = fields.TryGetValue(OAuthRequestParameters.Iss, out string? iss);
        ClaimOutcome outcome = issPresent
            && string.Equals(iss, flowState.ExpectedIssuer, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;
        claims.Add(new Claim(OAuthCallbackClaimIds.IssuerMatchesExpected, outcome));
    }


    /// <summary>
    /// Checks that the <c>state</c> value corresponds to the loaded flow state.
    /// A mismatch indicates either a CSRF attempt or a state lookup failure.
    /// </summary>
    public static void CheckStateMatchesFlow(
        IReadOnlyDictionary<string, string> fields,
        OAuthFlowState flowState,
        List<Claim> claims)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(flowState);
        ArgumentNullException.ThrowIfNull(claims);

        bool statePresent = fields.TryGetValue(OAuthRequestParameters.State, out string? state);
        ClaimOutcome outcome = statePresent
            && string.Equals(state, flowState.FlowId, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;
        claims.Add(new Claim(OAuthCallbackClaimIds.StateMatchesActiveFlow, outcome));
    }


    /// <summary>
    /// Checks that the flow state has not expired at the time of the callback.
    /// </summary>
    public static void CheckFlowNotExpired(
        OAuthFlowState flowState,
        TimeProvider timeProvider,
        List<Claim> claims)
    {
        ArgumentNullException.ThrowIfNull(flowState);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(claims);

        ClaimOutcome outcome = timeProvider.GetUtcNow() <= flowState.ExpiresAt
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;
        claims.Add(new Claim(OAuthCallbackClaimIds.FlowStateNotExpired, outcome));
    }
}