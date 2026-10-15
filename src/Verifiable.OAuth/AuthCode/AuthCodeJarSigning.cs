using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.AuthCode;

/// <summary>
/// Builds and signs an AuthCode JAR (JWT Authorization Request) per
/// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>.
/// </summary>
/// <remarks>
/// <para>
/// The JAR carries the Authorization Request claims as JWT payload, signed by
/// the client. The Authorization Server validates the signature, projects the
/// payload into <see cref="AuthCodeRequestObject"/>, and threads the
/// PKCE/scope/redirect_uri claims through to its PAR or Authorize handler.
/// </para>
/// <para>
/// Composes <see cref="JwtHeaderExtensions.ForJar"/> for the protected header
/// (with <c>typ = oauth-authz-req+jwt</c> per RFC 9101 §4) and
/// <see cref="JwtSigningExtensions.SignAsync(UnsignedJwt, PrivateKeyMemory, JwtHeaderSerializer, JwtPayloadSerializer, EncodeDelegate, BaseMemoryPool, CancellationToken)"/> for the JWS — the same JCose
/// composition pattern used by OID4VP JAR signing, token issuance, and the
/// Verifier attestation pipeline.
/// </para>
/// </remarks>
public static class AuthCodeJarSigning
{
    /// <summary>
    /// Signs an AuthCode JAR carrying the supplied request claims.
    /// </summary>
    /// <param name="requestObject">The AuthCode-shaped claim set to sign as the JAR payload.</param>
    /// <param name="signingKey">The client's JAR signing key. Tag determines the JWS <c>alg</c>.</param>
    /// <param name="signingKeyId">The <c>kid</c> header parameter value.</param>
    /// <param name="headerSerializer">Serialises the JAR protected header to UTF-8 JSON bytes.</param>
    /// <param name="payloadSerializer">Serialises the JAR payload claims to UTF-8 JSON bytes.</param>
    /// <param name="base64UrlEncoder">Base64url encoder for compact JWS serialisation.</param>
    /// <param name="memoryPool">Memory pool for transient signing buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact-serialised JAR (<c>header.payload.signature</c>).</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "JwsMessage is disposed via the using statement before the method returns; the returned string is independent of the message.")]
    public static async ValueTask<string> SignAsync(
        AuthCodeRequestObject requestObject,
        PrivateKeyMemory signingKey,
        string signingKeyId,
        JwtHeaderSerializer headerSerializer,
        JwtPayloadSerializer payloadSerializer,
        EncodeDelegate base64UrlEncoder,
        BaseMemoryPool memoryPool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestObject);
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(signingKeyId);
        ArgumentNullException.ThrowIfNull(headerSerializer);
        ArgumentNullException.ThrowIfNull(payloadSerializer);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeaderExtensions.ForJar(algorithm, signingKeyId);
        JwtPayload payload = BuildPayload(requestObject);

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            headerSerializer,
            payloadSerializer,
            base64UrlEncoder,
            memoryPool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, base64UrlEncoder);
    }


    /// <summary>
    /// Projects request parameters into signed claims, which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-4">RFC 9101 §4</see> defines as the
    /// authorization request parameters: "The parameters are represented as the JWT Claims of the
    /// object." The method is optional per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>:
    /// "OPTIONAL, defaults to "plain" if not present in the request". The <c>scope</c> claim is signed
    /// only when <see cref="AuthCodeRequestObject.Scope"/> names a value: RFC 6749 §3.1 treats a
    /// parameter sent without a value as omitted, and §3.3 leaves the default for an omitted scope to
    /// the authorization server, so a blank scope signs no claim rather than an empty one. The
    /// <c>resource</c> claim is signed only when <see cref="AuthCodeRequestObject.Resource"/> names
    /// an indicator, in the shape
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2.1">RFC 8707 §2.1</see> gives it:
    /// "For an authorization request sent as a JSON Web Token (JWT), such as when using the JWT
    /// Secured Authorization Request [JWT-SAR], a single "resource" parameter value is represented as
    /// a JSON string while multiple values are represented as an array of strings." The <c>dpop_jkt</c> claim is
    /// signed, as a JSON string, when <see cref="AuthCodeRequestObject.DpopJkt"/> names a value:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-3">RFC 9126 Section 3</see>, "All other request
    /// parameters, i.e., those pertaining to the authorization request itself, MUST appear as claims of the JWT
    /// representing the authorization request", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-4">RFC 9101 Section 4</see>, "Parameter names and
    /// string values MUST be included as JSON strings."
    /// </summary>
    /// <param name="requestObject">The request object whose parameters become the claims.</param>
    /// <returns>The claims to sign.</returns>
    private static JwtPayload BuildPayload(AuthCodeRequestObject requestObject)
    {
        JwtPayload payload = new(capacity: 16)
        {
            [OAuthRequestParameterNames.ClientId] = requestObject.ClientId,
            [OAuthRequestParameterNames.ResponseType] = requestObject.ResponseType,
            [OAuthRequestParameterNames.RedirectUri] = requestObject.RedirectUri.ToString()
        };

        if(!string.IsNullOrWhiteSpace(requestObject.Scope))
        {
            payload[OAuthRequestParameterNames.Scope] = requestObject.Scope;
        }

        if(!string.IsNullOrWhiteSpace(requestObject.Resource))
        {
            string[] indicators = requestObject.Resource.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            payload[OAuthRequestParameterNames.Resource] = indicators switch
            {
                [string single] => single,
                _ => indicators
            };
        }

        payload[OAuthRequestParameterNames.State] = requestObject.State;
        payload[WellKnownJwtClaimNames.Nonce] = requestObject.Nonce;
        payload[OAuthRequestParameterNames.CodeChallenge] = requestObject.CodeChallenge;
        payload[WellKnownJwtClaimNames.Iat] = requestObject.Iat.ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Nbf] = requestObject.Nbf.ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = requestObject.Exp.ToUnixTimeSeconds();

        if(requestObject.CodeChallengeMethod is string method)
        {
            payload[OAuthRequestParameterNames.CodeChallengeMethod] = method;
        }

        if(requestObject.Iss is string iss)
        {
            payload[WellKnownJwtClaimNames.Iss] = iss;
        }

        if(requestObject.Aud is string aud)
        {
            payload[WellKnownJwtClaimNames.Aud] = aud;
        }

        if(requestObject.Jti is string jti)
        {
            payload[WellKnownJwtClaimNames.Jti] = jti;
        }

        if(requestObject.DpopJkt is string dpopJkt)
        {
            payload[OAuthRequestParameterNames.DpopJkt] = dpopJkt;
        }

        return payload;
    }
}
