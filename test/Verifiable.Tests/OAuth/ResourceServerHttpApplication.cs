using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Maps inbound HTTP requests for the test resource server to the
/// validator composition. Parallel of
/// <see cref="AuthorizationServerHttpApplication"/>; minimal mapping
/// layer, no DI container, no middleware pipeline. Hosts a single
/// <c>/protected</c> endpoint that exercises
/// <see cref="JwsAccessTokenValidator"/> and (for DPoP-bound tokens)
/// <see cref="DpopProofValidator"/>.
/// </summary>
[DebuggerDisplay("ResourceServerHttpApplication")]
internal sealed class ResourceServerHttpApplication: IHttpApplication<HttpContext>
{
    private const string BearerScheme = "Bearer";
    private const string DpopScheme = "DPoP";

    private readonly ResourceServerIntegration integration;
    private readonly VerificationDelegate verifySignature;


    public ResourceServerHttpApplication(
        ResourceServerIntegration integration,
        VerificationDelegate verifySignature)
    {
        ArgumentNullException.ThrowIfNull(integration);
        ArgumentNullException.ThrowIfNull(verifySignature);
        this.integration = integration;
        this.verifySignature = verifySignature;
    }


    public HttpContext CreateContext(IFeatureCollection contextFeatures) =>
        new DefaultHttpContext(contextFeatures);


    public async Task ProcessRequestAsync(HttpContext context)
    {
        try
        {
            await ProcessRequestCoreAsync(context).ConfigureAwait(false);
        }
        catch(Exception ex)
        {
            //Tests rely on seeing the failure reason; production hosts would
            //surface this through telemetry rather than the response body.
            context.Response.StatusCode = 500;
            context.Response.ContentType = "text/plain";
            byte[] body = System.Text.Encoding.UTF8.GetBytes(
                $"Handler threw: {ex.GetType().FullName}: {ex.Message}\n{ex.StackTrace}");
            await context.Response.Body.WriteAsync(body).ConfigureAwait(false);
        }
    }


    private async Task ProcessRequestCoreAsync(HttpContext context)
    {
        if(!string.Equals(context.Request.Path, "/protected", StringComparison.Ordinal))
        {
            context.Response.StatusCode = 404;
            return;
        }

        if(!TryExtractAuthorization(context.Request, out string scheme, out string? accessToken))
        {
            await Write401Async(context, BearerScheme, "invalid_token",
                "Authorization header is missing or malformed.").ConfigureAwait(false);
            return;
        }

        ExchangeContext ExchangeContext = new();

        JwsAccessTokenValidationResult tokenResult = await JwsAccessTokenValidator.ValidateAsync(
            accessToken!,
            integration.TrustedIssuer.OriginalString,
            integration.ExpectedAudience,
            integration.ResolveVerificationKeyAsync,
            verifySignature,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            integration.TimeProvider,
            BaseMemoryPool.Shared,
            integration.AccessTokenIatSkew,
            tenantId: default,
            ExchangeContext,
            expectedAuthorizedParty: null,
            context.RequestAborted).ConfigureAwait(false);

        if(!tokenResult.IsSuccess)
        {
            await Write401Async(context, BearerScheme, "invalid_token",
                tokenResult.FailureDescription ?? "Access token validation failed.").ConfigureAwait(false);
            return;
        }

        JwsAccessTokenClaims claims = tokenResult.Claims!;

        if(claims.Confirmation is { JwkThumbprint: not null } confirmation)
        {
            if(!string.Equals(scheme, DpopScheme, StringComparison.Ordinal))
            {
                await Write401Async(context, DpopScheme, "invalid_token",
                    "Access token is DPoP-bound but was presented under Bearer scheme.")
                    .ConfigureAwait(false);
                return;
            }

            if(!TryExtractDpopProof(context.Request, out string? proofJwt))
            {
                await Write401Async(context, DpopScheme, "invalid_dpop_proof",
                    "DPoP header is missing.").ConfigureAwait(false);
                return;
            }

            string requestUrl = BuildRequestUrl(context.Request);

            DpopProofValidationRequest proofRequest = new()
            {
                Proof = proofJwt!,
                HttpMethod = context.Request.Method,
                HttpUrl = requestUrl,
                AccessToken = accessToken,
                NonceRequired = false
            };

            DpopProofValidationResult proofResult = await DpopProofValidator.ValidateAsync(
                proofRequest,
                verifySignature,
                DpopTestSupport.Parser,
                TestSetup.Base64UrlEncoder,
                TestSetup.Base64UrlDecoder,
                integration.TimeProvider,
                BaseMemoryPool.Shared,
                integration.DpopFreshnessWindow,
                context.RequestAborted).ConfigureAwait(false);

            if(!proofResult.IsSuccess)
            {
                await Write401Async(context, DpopScheme, "invalid_dpop_proof",
                    $"DPoP proof validation failed: {proofResult.FailureReason}.")
                    .ConfigureAwait(false);
                return;
            }

            if(!string.Equals(proofResult.JwkThumbprint, confirmation.JwkThumbprint, StringComparison.Ordinal))
            {
                await Write401Async(context, DpopScheme, "invalid_dpop_proof",
                    "DPoP proof thumbprint does not match the access token's cnf.jkt binding.")
                    .ConfigureAwait(false);
                return;
            }

            if(integration.IsDpopProofJtiSeenAsync is not null
                && integration.PersistDpopProofJtiAsync is not null)
            {
                string jti = proofResult.Claims!.Jti;
                bool replayed = await integration.IsDpopProofJtiSeenAsync(
                    jti, ExchangeContext, context.RequestAborted).ConfigureAwait(false);
                if(replayed)
                {
                    await Write401Async(context, DpopScheme, "invalid_dpop_proof",
                        "DPoP proof jti has been seen previously.").ConfigureAwait(false);
                    return;
                }

                DateTimeOffset expiresAt = integration.TimeProvider.GetUtcNow()
                    + integration.DpopFreshnessWindow;
                await integration.PersistDpopProofJtiAsync(
                    jti, expiresAt, ExchangeContext, context.RequestAborted).ConfigureAwait(false);
            }
        }

        await WriteClaimsAsync(context, claims).ConfigureAwait(false);
    }


    public void DisposeContext(HttpContext context, Exception? exception) { }


    private static bool TryExtractAuthorization(
        HttpRequest request, out string scheme, out string? token)
    {
        scheme = string.Empty;
        token = null;

        if(!request.Headers.TryGetValue("Authorization", out var values) || values.Count == 0)
        {
            return false;
        }

        string header = values[0]!;
        int sep = header.IndexOf(' ', StringComparison.Ordinal);
        if(sep <= 0 || sep == header.Length - 1)
        {
            return false;
        }

        scheme = header[..sep];
        token = header[(sep + 1)..];
        return !string.IsNullOrEmpty(token)
            && (string.Equals(scheme, BearerScheme, StringComparison.Ordinal)
                || string.Equals(scheme, DpopScheme, StringComparison.Ordinal));
    }


    private static bool TryExtractDpopProof(HttpRequest request, out string? proof)
    {
        if(request.Headers.TryGetValue("DPoP", out var values)
            && values.Count > 0
            && !string.IsNullOrEmpty(values[0]))
        {
            proof = values[0];
            return true;
        }
        proof = null;
        return false;
    }


    private static string BuildRequestUrl(HttpRequest request) =>
        $"{request.Scheme}://{request.Host}{request.Path}";


    private static Task Write401Async(
        HttpContext context, string scheme, string error, string description)
    {
        context.Response.StatusCode = 401;
        string challenge = $"{scheme} realm=\"protected\", error=\"{error}\", error_description=\"{description}\"";
        context.Response.Headers.Append("WWW-Authenticate", challenge);
        return Task.CompletedTask;
    }


    private static async Task WriteClaimsAsync(HttpContext context, JwsAccessTokenClaims claims)
    {
        Dictionary<string, object?> body = new(StringComparer.Ordinal)
        {
            ["sub"] = claims.Subject,
            ["iss"] = claims.Issuer,
            ["aud"] = claims.Audience,
            ["iat"] = claims.IssuedAt.ToUnixTimeSeconds(),
            ["exp"] = claims.Expiration.ToUnixTimeSeconds(),
        };
        if(claims.NotBefore is not null) { body["nbf"] = claims.NotBefore.Value.ToUnixTimeSeconds(); }
        if(claims.Scope is not null) { body["scope"] = claims.Scope; }
        if(claims.ClientId is not null) { body["client_id"] = claims.ClientId; }
        if(claims.JwtId is not null) { body["jti"] = claims.JwtId; }
        if(claims.Confirmation?.JwkThumbprint is { } jkt)
        {
            body["cnf"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["jkt"] = jkt
            };
        }

        byte[] json = JsonSerializer.SerializeToUtf8Bytes(body);
        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.Body.WriteAsync(json, context.RequestAborted).ConfigureAwait(false);
    }
}
