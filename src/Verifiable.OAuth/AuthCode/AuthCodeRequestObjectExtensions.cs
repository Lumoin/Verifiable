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
        /// <see cref="AuthCodeRequestObject"/>.
        /// </summary>
        /// <returns>The typed projection.</returns>
        /// <exception cref="FormatException">
        /// Thrown when an RFC 9101 §4 required claim is missing or has the
        /// wrong runtime type, or when <c>redirect_uri</c> is not an absolute
        /// <see cref="Uri"/>.
        /// </exception>
        public AuthCodeRequestObject ProjectAuthCode()
        {
            ArgumentNullException.ThrowIfNull(verified);

            IReadOnlyDictionary<string, object> claims = verified.Claims;

            string clientId = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameterNames.ClientId);
            string responseType = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameterNames.ResponseType);
            string redirectUriString = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameterNames.RedirectUri);
            //Scope is optional in the projection; required-ness is a policy
            //axis (policy.ScopeRequiredOnRequest) enforced at the matcher.
            string scope = JwtClaimReaders.OptionalClaim(claims, OAuthRequestParameterNames.Scope) ?? string.Empty;
            string state = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameterNames.State);
            string nonce = JwtClaimReaders.RequireClaim(claims, WellKnownJwtClaimNames.Nonce);
            string codeChallenge = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameterNames.CodeChallenge);
            string codeChallengeMethod = JwtClaimReaders.RequireClaim(
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
                MaxAge = maxAge
            };
        }
    }
}
