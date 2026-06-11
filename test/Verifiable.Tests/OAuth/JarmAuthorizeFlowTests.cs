using System.Buffers;
using System.Collections.Immutable;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Jarm;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// JWT-secured authorization responses (JARM / FAPI 2.0 Message Signing §5.4) driven
/// through the real dispatch pipeline: the <c>response_mode</c> pushed at PAR is
/// authoritative, the authorize success and error responses ride a signed JWT the
/// client validates with <see cref="JarmResponseValidation"/>, and the code carried
/// inside the JWT exchanges at the token endpoint.
/// </summary>
[TestClass]
internal sealed class JarmAuthorizeFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://jarm.client.test";

    private static readonly Uri ClientBaseUri = new("https://jarm.client.test");

    private static readonly Uri RedirectUri = new("https://client.example.com/callback");

    private const string SubjectId = "urn:uuid:end-user-42";

    private const string RequestState = "S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw";

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static readonly string[] AllowedAlgorithms = [WellKnownJwaValues.Es256];

    private static readonly ImmutableHashSet<CapabilityIdentifier> AuthCodeCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization);

    private static readonly JwtPayloadDeserializer PayloadDeserializer =
        static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("Payload JSON parsed to null.");


    [TestMethod]
    public async Task ResponseModeJwtCarriesCodeInSignedResponseThatExchangesAtToken()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJarmClient(host);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        ServerHttpResponse authorizeResponse = await RunParAuthorizeAsync(
            host, material, pkce, JarmResponseModes.Jwt).ConfigureAwait(false);

        //response_type=code resolves the jwt shortcut to query.jwt — a 302 whose
        //query carries ONLY the response parameter; the code never appears in clear.
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.IsNotNull(authorizeResponse.Location);
        Assert.Contains("?response=", authorizeResponse.Location);
        Assert.DoesNotContain("code=", authorizeResponse.Location);
        Assert.DoesNotContain("state=", authorizeResponse.Location);

        string responseJwt = ExtractResponseJwt(authorizeResponse.Location!, '?');
        JarmResponseValidationResult result = await ValidateAsync(
            responseJwt, material).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.Code);
        Assert.AreEqual(RequestState, result.State);

        //The code inside the signed response is a working authorization code.
        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeAuthorizationCode,
            [OAuthRequestParameterNames.Code] = result.Code!,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
    }


    [TestMethod]
    public async Task FormPostJwtModeReturnsAutoSubmittingHtml()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJarmClient(host);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        ServerHttpResponse authorizeResponse = await RunParAuthorizeAsync(
            host, material, pkce, JarmResponseModes.FormPostJwt).ConfigureAwait(false);

        Assert.AreEqual(200, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.Contains($"action=\"{RedirectUri.OriginalString}\"", authorizeResponse.Body);
        Assert.Contains("name=\"response\"", authorizeResponse.Body);

        string marker = "name=\"response\" value=\"";
        int start = authorizeResponse.Body.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        int end = authorizeResponse.Body.IndexOf('"', start);
        string responseJwt = authorizeResponse.Body[start..end];

        JarmResponseValidationResult result = await ValidateAsync(
            responseJwt, material).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.IsNotNull(result.Code);
    }


    [TestMethod]
    public async Task FrontChannelResponseModeInjectionIsIgnored()
    {
        //RFC 9101 §6.3 via RFC 9126 §4: only the pushed parameters are used. A
        //response_mode injected on the front-channel authorize request must not turn a
        //plain redirect into (or out of) a JWT-secured response.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJarmClient(host);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        ServerHttpResponse authorizeResponse = await RunParAuthorizeAsync(
            host, material, pkce, parResponseMode: null,
            frontChannelResponseMode: JarmResponseModes.Jwt).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.IsNotNull(authorizeResponse.Location);
        Assert.Contains("code=", authorizeResponse.Location);
        Assert.DoesNotContain("response=", authorizeResponse.Location);
    }


    [TestMethod]
    public async Task DeniedAuthorizeWrapsErrorParametersInSignedResponse()
    {
        //JARM §2.1: the JWT carries the response parameters even for an error response.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJarmClient(host);
        host.Server.Integration.EvaluateAuthorizationRequestAsync =
            (evaluation, registration, context, ct) => ValueTask.FromResult(
                AuthorizationRequestDecision.Deny(AuthorizationDenialReason.AccessDenied));

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        ServerHttpResponse authorizeResponse = await RunParAuthorizeAsync(
            host, material, pkce, JarmResponseModes.Jwt).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.IsNotNull(authorizeResponse.Location);
        Assert.Contains("?response=", authorizeResponse.Location);
        Assert.DoesNotContain("error=", authorizeResponse.Location);

        string responseJwt = ExtractResponseJwt(authorizeResponse.Location!, '?');
        JarmResponseValidationResult result = await ValidateAsync(
            responseJwt, material).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid);
        Assert.AreEqual(OAuthErrors.AccessDenied, result.Error);
        Assert.AreEqual(RequestState, result.State);
        Assert.IsNull(result.Code);
    }


    [TestMethod]
    public async Task JarmRequestWithoutResponseSigningKeyIsRejectedAtPar()
    {
        await using TestHostShell host = new(TimeProvider);
        //A baseline client WITHOUT an AuthorizationResponseSigning key.
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        RequestFields parFields = BuildParFields(pkce, JarmResponseModes.Jwt);

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, parResponse.StatusCode, parResponse.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, parResponse.Body);
    }


    [TestMethod]
    public async Task DiscoveryAdvertisesJarmOnlyWithResponseSigningKey()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse unkeyed = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, unkeyed.StatusCode, unkeyed.Body);
        Assert.DoesNotContain("response_modes_supported", unkeyed.Body,
            "Without a response-signing key the JARM modes must not be advertised.");
        Assert.DoesNotContain("authorization_signing_alg_values_supported", unkeyed.Body);

        EnableJarmSigning(host, material);

        ServerHttpResponse keyed = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, keyed.StatusCode, keyed.Body);
        Assert.Contains(JarmResponseModes.QueryJwt, keyed.Body);
        Assert.Contains(JarmResponseModes.FormPostJwt, keyed.Body);
        Assert.Contains("authorization_signing_alg_values_supported", keyed.Body);
        Assert.Contains(WellKnownJwaValues.Es256, keyed.Body);
    }


    /// <summary>
    /// Registers a PAR/auth-code client and adds an
    /// <see cref="KeyUsageContext.AuthorizationResponseSigning"/> key set reusing the
    /// registration's signing key, so the host's resolvers find it by id.
    /// </summary>
    private static VerifierKeyMaterial RegisterJarmClient(TestHostShell host)
    {
        VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        EnableJarmSigning(host, material);

        return material;
    }


    private static void EnableJarmSigning(TestHostShell host, VerifierKeyMaterial material)
    {
        host.UpdateSigningKeys(
            material.Registration.TenantId.Value,
            material.Registration.SigningKeys.ToImmutableDictionary().Add(
                KeyUsageContext.AuthorizationResponseSigning,
                new SigningKeySet { Current = [material.SigningKeyId] }));
    }


    private static RequestFields BuildParFields(PkceParameters pkce, string? responseMode)
    {
        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = RequestState
        };

        if(responseMode is not null)
        {
            parFields[OAuthRequestParameterNames.ResponseMode] = responseMode;
        }

        return parFields;
    }


    private async ValueTask<ServerHttpResponse> RunParAuthorizeAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        PkceParameters pkce,
        string? parResponseMode,
        string? frontChannelResponseMode = null)
    {
        string segment = material.Registration.TenantId.Value;

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            BuildParFields(pkce, parResponseMode), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);

        string marker = "\"request_uri\":\"";
        int start = parResponse.Body.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        int end = parResponse.Body.IndexOf('"', start);
        string requestUri = parResponse.Body[start..end];

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };

        if(frontChannelResponseMode is not null)
        {
            authorizeFields[OAuthRequestParameterNames.ResponseMode] = frontChannelResponseMode;
        }

        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);

        return await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async ValueTask<JarmResponseValidationResult> ValidateAsync(
        string responseJwt, VerifierKeyMaterial material)
    {
        ResolveJarmVerificationKeyDelegate resolver = (_, _, _) =>
            ValueTask.FromResult<PublicKeyMemory?>(material.SigningPublicKey);

        return await JarmResponseValidation.ValidateAsync(
            responseJwt,
            material.Registration.IssuerUri!.OriginalString,
            ClientId,
            AllowedAlgorithms,
            TimeProvider.GetUtcNow(),
            resolver,
            PayloadDeserializer,
            TestSetup.Base64UrlDecoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async ValueTask<ServerHttpResponse> DispatchDiscoveryAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string ExtractResponseJwt(string location, char separator)
    {
        string marker = $"{separator}response=";
        int start = location.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        int end = location.IndexOf('&', start);
        string encoded = end < 0 ? location[start..] : location[start..end];

        return Uri.UnescapeDataString(encoded);
    }
}
