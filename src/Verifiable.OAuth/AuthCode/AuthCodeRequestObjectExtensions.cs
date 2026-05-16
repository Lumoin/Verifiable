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
/// A registered client whose JAR omits <see cref="OAuthRequestParameters.ResponseType"/>,
/// <see cref="OAuthRequestParameters.RedirectUri"/>, or any other RFC 9101 §4
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

            string clientId = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameters.ClientId);
            string responseType = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameters.ResponseType);
            string redirectUriString = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameters.RedirectUri);
            //Scope is optional in the projection; required-ness is a policy
            //axis (policy.ScopeRequiredOnRequest) enforced at the matcher.
            string scope = JwtClaimReaders.OptionalClaim(claims, OAuthRequestParameters.Scope) ?? string.Empty;
            string state = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameters.State);
            string nonce = JwtClaimReaders.RequireClaim(claims, WellKnownJwtClaimNames.Nonce);
            string codeChallenge = JwtClaimReaders.RequireClaim(claims, OAuthRequestParameters.CodeChallenge);
            string codeChallengeMethod = JwtClaimReaders.RequireClaim(
                claims, OAuthRequestParameters.CodeChallengeMethod);

            if(!Uri.TryCreate(redirectUriString, UriKind.Absolute, out Uri? redirectUri))
            {
                throw new FormatException(
                    $"JAR '{OAuthRequestParameters.RedirectUri}' claim is not a valid absolute URI: '{redirectUriString}'.");
            }

            string? iss = JwtClaimReaders.OptionalClaim(claims, WellKnownJwtClaimNames.Iss);
            string? aud = JwtClaimReaders.OptionalClaim(claims, WellKnownJwtClaimNames.Aud);
            string? jti = JwtClaimReaders.OptionalClaim(claims, WellKnownJwtClaimNames.Jti);

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
                Jti = jti
            };
        }
    }
}
