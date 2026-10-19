using System.Diagnostics.CodeAnalysis;
using Verifiable.JCose;
using Verifiable.OAuth.Jar;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Projection from a <see cref="JarVerified"/> result into the typed
/// <see cref="AuthCodeRequestObject"/> the AuthCode JAR matchers consume.
/// </summary>
/// <remarks>
/// <para>
/// The projection only reads claims; it does not re-validate signature or
/// timing — those are <see cref="JarVerification.VerifyAsync"/>'s job and
/// already complete by the time a <see cref="JarVerified"/> exists.
/// </para>
/// <para>
/// Required claims map to <see cref="JwtClaimReaders.RequireClaim"/>;
/// missing or wrong-typed claims raise <see cref="FormatException"/>. The
/// caller (the matcher's <c>BuildInputAsync</c>) catches that exception and
/// maps it to a 400 response with <see cref="OAuthErrors.InvalidRequestObject"/>.
/// A registered client whose JAR omits <see cref="OAuthRequestParameterNames.ResponseType"/>,
/// <see cref="OAuthRequestParameterNames.RedirectUri"/>, or any other RFC 9101 §4
/// required claim is the bug being surfaced; the exception path is the right
/// shape for that.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "C# 13 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class AuthCodeRequestObjectExtensions
{
    extension(JarVerified verified)
    {
        /// <summary>
        /// Projects this verified JAR's claims into a typed
        /// <see cref="AuthCodeRequestObject"/>. The method claim is optional per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>:
        /// "OPTIONAL, defaults to "plain" if not present in the request".
        /// The endpoint method gate refuses that default with <c>invalid_request</c>.
        /// </summary>
        /// <param name="rawAuthorizationDetails">
        /// The verbatim RFC 9396 <c>authorization_details</c> array text the caller re-sliced
        /// from the verified payload, or <see langword="null"/> when absent. Passed in rather
        /// than read from the parsed claims because the carried value must be the exact signed
        /// text, not a reserialisation.
        /// </param>
        /// <returns>The typed projection.</returns>
        /// <exception cref="FormatException">
        /// Thrown when an RFC 9101 §4 required claim is missing or has the
        /// wrong runtime type, or when <c>redirect_uri</c> is not an absolute
        /// <see cref="Uri"/>.
        /// </exception>
        public AuthCodeRequestObject ProjectAuthCode(string? rawAuthorizationDetails = null)
        {
            ArgumentNullException.ThrowIfNull(verified);

            var claims = verified.Claims;

            string clientId = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameterNames.ClientId);
            string responseType = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameterNames.ResponseType);
            string redirectUriString = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameterNames.RedirectUri);
            //Scope is optional in the projection; required-ness is a policy
            //axis (policy.ScopeRequiredOnRequest) enforced at the matcher.
            string scope = JwtClaimReaders.OptionalClaim(claims, OAuthRequestParameterNames.Scope) ?? string.Empty;
            string state = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameterNames.State);
            string nonce = JwtClaimReaders.RequireClaim(claims, WellKnownJwtClaimNames.Nonce);
            string codeChallenge = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameterNames.CodeChallenge);
            string? codeChallengeMethod = JwtClaimReaders.OptionalClaim(
                claims, OAuthRequestParameterNames.CodeChallengeMethod);

            if(!Uri.TryCreate(redirectUriString, UriKind.Absolute, out Uri? redirectUri))
            {
                throw new FormatException(
                    $"JAR '{OAuthRequestParameterNames.RedirectUri}' claim is not a valid absolute URI: '{redirectUriString}'.");
            }

            string? iss = JwtClaimReaders.OptionalClaim(claims, WellKnownJwtClaimNames.Iss);
            string? aud = JwtClaimReaders.OptionalClaim(claims, WellKnownJwtClaimNames.Aud);
            string? jti = JwtClaimReaders.OptionalClaim(claims, WellKnownJwtClaimNames.Jti);

            //RFC 9470 §4 step-up parameters carried in the request object. acr_values is a
            //string; max_age is a non-negative integer (OIDC Core §3.1.2.1) — a present but
            //malformed value is surfaced as invalid_request_object like any other JAR defect.
            string? acrValues = JwtClaimReaders.OptionalClaim(claims, OAuthRequestParameterNames.AcrValues);
            string? prompt = JwtClaimReaders.OptionalClaim(claims, OAuthRequestParameterNames.Prompt);
            string? responseMode = JwtClaimReaders.OptionalClaim(claims, OAuthRequestParameterNames.ResponseMode);

            //OID4VCI 1.0 §5.1.3 issuer_state and RFC 8707 resource: read verbatim. issuer_state is
            //surfaced to the decision seam as UNTRUSTED — §5.1.3 forbids the issuer from assuming it
            //originated here — so the projection neither validates nor interprets it.
            string? issuerState = JwtClaimReaders.OptionalClaim(claims, OAuthRequestParameterNames.IssuerState);
            string? resource = ReadResourceClaim(claims);
            int? maxAge = null;
            if(claims.TryGetValue(OAuthRequestParameterNames.MaxAge, out object? maxAgeClaim))
            {
                if(!JwtClaimReaders.TryToInt64(maxAgeClaim, out long maxAgeValue)
                    || maxAgeValue < 0 || maxAgeValue > int.MaxValue)
                {
                    throw new FormatException(
                        $"JAR '{OAuthRequestParameterNames.MaxAge}' claim must be a non-negative integer.");
                }

                maxAge = (int)maxAgeValue;
            }

            return new AuthCodeRequestObject
            {
                ClientId = clientId,
                ResponseType = responseType,
                RedirectUri = redirectUri,
                Scope = scope,
                State = state,
                Nonce = nonce,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod,
                Iat = verified.Iat,
                Nbf = verified.Nbf,
                Exp = verified.Exp,
                Iss = iss,
                Aud = aud,
                Jti = jti,
                AcrValues = acrValues,
                MaxAge = maxAge,
                Prompt = prompt,
                AuthorizationDetails = rawAuthorizationDetails,
                ResponseMode = responseMode,
                IssuerState = issuerState,
                Resource = resource
            };
        }
    }


    /// <summary>
    /// A sentinel returned for a JAR <c>resource</c> claim that is present but does not parse to
    /// either RFC 8707 section 2.1 wire shape, or that parses to the shape but carries a blank,
    /// non-string, or whitespace-bearing element. Deliberately shaped to fail
    /// <see cref="ResourceIndicator.Parse"/> (it carries a fragment,
    /// which RFC 8707 section 2 forbids) so the SAME downstream <c>ValidateResourceIndicatorsShape</c>
    /// gate every other malformed resource value goes through rejects this one too, with
    /// <c>invalid_target</c> rather than a distinct parse-time error code.
    /// </summary>
    private static string MalformedResourceClaimSentinel { get; } = "urn:invalid-resource-claim#malformed";


    /// <summary>
    /// Reads the RFC 8707 <c>resource</c> claim per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 section 2.1</see>:
    /// "a single &quot;resource&quot; parameter value is represented as a JSON string while multiple values are
    /// represented as an array of strings." Reads the claim's own runtime value directly, admitting
    /// every shape <see cref="JwsAccessTokenValidator.ReadStringOrStringArray"/> admits for the identical
    /// RFC 7519 section 4.1.3 <c>aud</c> wire alternative, and like it filtering no
    /// element away: a JSON string is the single value; a JSON array is the multiple-value form only
    /// when it is non-empty and every element is itself a non-empty, whitespace-free JSON string
    /// (RFC 8707 section 2.1: "multiple values are represented as an array of strings"); any other
    /// shape, and any array element that is not such a string (a blank string, a number, a nested
    /// value), is malformed. A resource indicator is one absolute URI (RFC 3986 section 2 /
    /// Appendix A's ABNF forbids a raw space inside one), so an element that already carries
    /// whitespace is not "several indicators sent as one" to recover by splitting; it is malformed.
    /// A malformed claim returns <see cref="MalformedResourceClaimSentinel"/>, carrying the defect
    /// through to the existing shape gate instead of dropping it silently. Each accepted element is
    /// folded with <see cref="ResourceIndicator.ComparisonKey"/> before the set is
    /// space-joined into the convention <c>ParseResourceIndicators</c> recovers at every other seam
    /// (PAR/authorize query strings, the token-exchange grant).
    /// </summary>
    private static string? ReadResourceClaim(IReadOnlyDictionary<string, object?> claims)
    {
        if(!claims.TryGetValue(OAuthRequestParameterNames.Resource, out object? raw))
        {
            return null;
        }

        if(raw is string single)
        {
            return string.IsNullOrEmpty(single) || single.Any(char.IsWhiteSpace)
                ? MalformedResourceClaimSentinel
                : ResourceIndicator.Parse(single).Match(static value => value.ComparisonKey, _ => single);
        }

        if(raw is IEnumerable<object> elements)
        {
            List<string> folded = [];
            foreach(object element in elements)
            {
                if(element is not string value || string.IsNullOrEmpty(value) || value.Any(char.IsWhiteSpace))
                {
                    return MalformedResourceClaimSentinel;
                }

                folded.Add(ResourceIndicator.Parse(value).Match(static indicator => indicator.ComparisonKey, _ => value));
            }

            return folded.Count == 0 ? MalformedResourceClaimSentinel : string.Join(' ', folded);
        }

        return MalformedResourceClaimSentinel;
    }
}
