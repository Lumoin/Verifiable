using System;
using System.Collections.Generic;
using Verifiable.Core.Assessment;
using Verifiable.OAuth;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// Static functions for validating outbound OAuth 2.0 request fields before they are
/// sent to the authorization server.
/// </summary>
/// <remarks>
/// <para>
/// Pre-send validation catches configuration mistakes — missing PKCE parameters,
/// absent state, wrong challenge method — before a network round-trip is made.
/// Each function appends one or more <see cref="Claim"/> instances to the supplied
/// list; the caller inspects failures and decides whether to abort the request.
/// </para>
/// <para>
/// These checks complement <see cref="OAuthCallbackChecks"/>, which validate the
/// inbound callback, and <see cref="OAuthTokenChecks"/>, which validate received
/// tokens. Together they cover the full request-response lifecycle.
/// </para>
/// </remarks>
public static class OAuthRequestChecks
{
    /// <summary>
    /// Checks that the request fields include a <c>state</c> parameter.
    /// <c>state</c> is required for CSRF protection per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.7">RFC 9700 §4.7</see>.
    /// </summary>
    public static void CheckStatePresent(
        IReadOnlyDictionary<string, string> fields,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = fields.TryGetValue(OAuthRequestParameters.State, out string? state)
            && !string.IsNullOrEmpty(state)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.RequestContainsState, outcome));
    }


    /// <summary>
    /// Checks that the request fields include a <c>redirect_uri</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2">RFC 6749 §3.1.2</see>.
    /// </summary>
    public static void CheckRedirectUriPresent(
        IReadOnlyDictionary<string, string> fields,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = fields.TryGetValue(OAuthRequestParameters.RedirectUri, out string? uri)
            && !string.IsNullOrEmpty(uri)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.RequestContainsRedirectUri, outcome));
    }


    /// <summary>
    /// Checks that the request fields include a <c>code_challenge</c>. Its absence
    /// would allow a PKCE downgrade attack per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.8">RFC 9700 §4.8</see>.
    /// </summary>
    public static void CheckCodeChallengePresent(
        IReadOnlyDictionary<string, string> fields,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = fields.TryGetValue(OAuthRequestParameters.CodeChallenge, out string? challenge)
            && !string.IsNullOrEmpty(challenge)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.RequestContainsCodeChallenge, outcome));
    }


    /// <summary>
    /// Checks that the <c>code_challenge_method</c> is <c>S256</c>.
    /// The plain method must not be used per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>
    /// and HAIP 1.0.
    /// </summary>
    public static void CheckCodeChallengeMethodIsS256(
        IReadOnlyDictionary<string, string> fields,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = fields.TryGetValue(OAuthRequestParameters.CodeChallengeMethod, out string? method)
            && string.Equals(method, OAuthRequestParameters.CodeChallengeMethodS256, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.RequestCodeChallengeMethodIsS256, outcome));
    }


    /// <summary>
    /// Runs all mandatory pre-send checks for a PAR request body: <c>state</c>,
    /// <c>redirect_uri</c>, <c>code_challenge</c> presence, and
    /// <c>code_challenge_method = S256</c>.
    /// </summary>
    /// <param name="fields">The encoded PAR request body fields.</param>
    /// <param name="results">The list to append all claims to.</param>
    public static void CheckParRequestBody(
        IReadOnlyDictionary<string, string> fields,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(results);

        CheckStatePresent(fields, results);
        CheckRedirectUriPresent(fields, results);
        CheckCodeChallengePresent(fields, results);
        CheckCodeChallengeMethodIsS256(fields, results);
    }
}