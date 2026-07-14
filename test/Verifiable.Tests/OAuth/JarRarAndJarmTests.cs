using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Jarm;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 9396 <c>authorization_details</c> and JARM <c>response_mode</c> carried INSIDE signed
/// Request Objects (RFC 9101), driven through the real dispatch pipeline: the JAR-PAR and
/// JAR-by-value authorize paths run the same shape validation, servability gate, carry, and
/// signed-response minting the bare PAR/direct paths run — the signed request is not a side
/// door around either feature.
/// </summary>
[TestClass]
internal sealed class JarRarAndJarmTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://wallet.client.test";
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");
    private const string SubjectId = "urn:uuid:end-user-42";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string RequestState = "state-jar-rar-01";

    private static readonly string[] AllowedAlgorithms = [WellKnownJwaValues.Es256];

    private static readonly ImmutableHashSet<CapabilityIdentifier> JarCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadDeserializer PayloadDeserializer =
        static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("Payload JSON parsed to null.");


    /// <summary>
    /// JAR-by-value: the <c>authorization_details</c> array signed into the Request Object is
    /// the value the token grant resolves — the seam receives the parsed details and the token
    /// response advertises the minted <c>credential_identifiers</c>, exactly like the bare path.
    /// </summary>
    [TestMethod]
    public async Task JarByValueAuthorizationDetailsReachTheTokenGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJarClient(host);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        IReadOnlyList<CredentialAuthorizationDetail>? seenDetails = null;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) =>
            {
                seenDetails = details;

                return ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                [
                    new GrantedCredentialAuthorization
                    {
                        CredentialConfigurationId = details[0].CredentialConfigurationId!,
                        CredentialIdentifiers = ["CivilEngineeringDegree-2026"]
                    }
                ]));
            };

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        Dictionary<string, object> claims = BuildJarClaims(material, pkce);
        claims[OAuthRequestParameterNames.AuthorizationDetails] = DetailsArray(ConfigurationId);

        string compactJar = await SignJarAsync(material, claims).ConfigureAwait(false);
        ServerHttpResponse authorizeResponse = await DispatchJarByValueAsync(
            host, material, compactJar).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        string code = ExtractQueryValue(authorizeResponse.Location!, "code");

        ServerHttpResponse tokenResponse = await ExchangeCodeAsync(
            host, material, code, pkce).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);
        JsonElement details = doc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(1, details.GetArrayLength());
        Assert.AreEqual(ConfigurationId,
            details[0].GetProperty("credential_configuration_id").GetString());
        Assert.AreEqual("CivilEngineeringDegree-2026",
            details[0].GetProperty("credential_identifiers")[0].GetString());

        Assert.IsNotNull(seenDetails);
        Assert.AreEqual(ConfigurationId, seenDetails![0].CredentialConfigurationId);
    }


    /// <summary>
    /// JAR-PAR: <c>authorization_details</c> AND a JARM <c>response_mode</c> signed into the
    /// pushed Request Object ride the carry to the authorize endpoint — the code arrives inside
    /// a signed JWT response the client validates, and the code inside it exchanges for tokens
    /// whose <c>authorization_details</c> resolve from the signed request's value.
    /// </summary>
    [TestMethod]
    public async Task JarParCarriesDetailsAndJarmResponseModeThroughTheFlow()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJarClient(host);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        //OID4VCI 1.0 §13.10: keep the plain-bearer credential token within the long-lived
        //threshold ("Long-lived Access Tokens giving access to Credentials MUST not be issued
        //unless sender-constrained"; lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            static (details, subject, registration, context, ct) =>
                ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                [
                    new GrantedCredentialAuthorization
                    {
                        CredentialConfigurationId = details[0].CredentialConfigurationId!,
                        CredentialIdentifiers = [$"{details[0].CredentialConfigurationId}-dataset-1"]
                    }
                ]));

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        Dictionary<string, object> claims = BuildJarClaims(material, pkce);
        claims[OAuthRequestParameterNames.AuthorizationDetails] = DetailsArray(ConfigurationId);
        claims[OAuthRequestParameterNames.ResponseMode] = JarmResponseModes.Jwt;

        string compactJar = await SignJarAsync(material, claims).ConfigureAwait(false);

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeJarPar, "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.Request] = compactJar,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);

        string marker = "\"request_uri\":\"";
        int start = parResponse.Body.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
        string requestUri = parResponse.Body[start..parResponse.Body.IndexOf('"', start)];

        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeAuthorize,
            WellKnownHttpMethods.Get,
            new RequestFields
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RequestUri] = requestUri
            },
            authorizeContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //The JARM mode signed into the pushed request governs the response shape.
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.IsNotNull(authorizeResponse.Location);
        Assert.Contains("?response=", authorizeResponse.Location);
        Assert.DoesNotContain("code=", authorizeResponse.Location);

        string responseJwt = Uri.UnescapeDataString(
            ExtractQueryValue(authorizeResponse.Location, "response"));
        ResolveJarmVerificationKeyDelegate resolver = (_, _, _) =>
            ValueTask.FromResult<PublicKeyMemory?>(material.SigningPublicKey);
        JarmResponseValidationResult jarmResult = await JarmResponseValidation.ValidateAsync(
            responseJwt, material.Registration.IssuerUri!.OriginalString, ClientId,
            AllowedAlgorithms, TimeProvider.GetUtcNow(), resolver, PayloadDeserializer,
            TestSetup.Base64UrlDecoder, Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(jarmResult.IsValid);
        Assert.AreEqual(RequestState, jarmResult.State);
        Assert.IsNotNull(jarmResult.Code);

        ServerHttpResponse tokenResponse = await ExchangeCodeAsync(
            host, material, jarmResult.Code!, pkce).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);
        JsonElement details = doc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(ConfigurationId,
            details[0].GetProperty("credential_configuration_id").GetString());
    }


    /// <summary>
    /// §5.1.1 shape enforcement holds inside signed requests too: an unsupported authorization
    /// details type signed into the JAR is refused with <c>invalid_authorization_details</c>.
    /// </summary>
    [TestMethod]
    public async Task MalformedJarAuthorizationDetailsAreRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJarClient(host);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        Dictionary<string, object> claims = BuildJarClaims(material, pkce);
        claims[OAuthRequestParameterNames.AuthorizationDetails] = new List<object>
        {
            new Dictionary<string, object>
            {
                ["type"] = "payment_initiation",
                ["amount"] = "1000"
            }
        };

        string compactJar = await SignJarAsync(material, claims).ConfigureAwait(false);
        ServerHttpResponse response = await DispatchJarByValueAsync(
            host, material, compactJar).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, response.Body);
    }


    /// <summary>
    /// The JARM servability gate holds inside signed requests too: a <c>response_mode</c>
    /// requesting a JWT-secured response is refused at receipt when no response-signing key is
    /// configured — never a silent fallback to a plain redirect.
    /// </summary>
    [TestMethod]
    public async Task JarmResponseModeInJarWithoutSigningKeyIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        //A JAR-capable client WITHOUT an AuthorizationResponseSigning key.
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, JarCapabilities, PolicyProfile.Rfc6749WithPkce);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        Dictionary<string, object> claims = BuildJarClaims(material, pkce);
        claims[OAuthRequestParameterNames.ResponseMode] = JarmResponseModes.Jwt;

        string compactJar = await SignJarAsync(material, claims).ConfigureAwait(false);
        ServerHttpResponse response = await DispatchJarByValueAsync(
            host, material, compactJar).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body);
    }


    /// <summary>
    /// RFC 9101 §10.2 / RFC 9700 §4: the SAME signed JAR presented twice within its validity
    /// window is rejected on the second presentation by the shared <c>(issuer, jti)</c>
    /// correlation store (the test host wires it for <c>FlowKind.JtiReplay</c>) — and a JAR
    /// without a <c>jti</c> (OPTIONAL per RFC 9101 §4) keeps working, since there is nothing
    /// to consume. The default <see cref="JtiReplayPolicy.OptionalIfStorePresent"/> consults
    /// the store because it is present.
    /// </summary>
    [TestMethod]
    public async Task ReplayedJarJtiIsRejectedByTheCorrelationStore()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterJarClient(host);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        Dictionary<string, object> claims = BuildJarClaims(material, pkce);
        claims[WellKnownJwtClaimNames.Jti] = "jar-jti-001";
        string compactJar = await SignJarAsync(material, claims).ConfigureAwait(false);

        ServerHttpResponse first = await DispatchJarByValueAsync(
            host, material, compactJar).ConfigureAwait(false);
        Assert.AreEqual((int)HttpStatusCode.Found, first.StatusCode, first.Body);

        ServerHttpResponse replayed = await DispatchJarByValueAsync(
            host, material, compactJar).ConfigureAwait(false);
        Assert.AreEqual((int)HttpStatusCode.BadRequest, replayed.StatusCode, replayed.Body);
        Assert.Contains(OAuthErrors.InvalidRequestObject, replayed.Body);

        //A jti-less JAR carries nothing to consume — repeat presentations stay accepted.
        PkceParameters jtilessPkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        string jtilessJar = await SignJarAsync(
            material, BuildJarClaims(material, jtilessPkce)).ConfigureAwait(false);

        ServerHttpResponse jtilessFirst = await DispatchJarByValueAsync(
            host, material, jtilessJar).ConfigureAwait(false);
        ServerHttpResponse jtilessSecond = await DispatchJarByValueAsync(
            host, material, jtilessJar).ConfigureAwait(false);
        Assert.AreEqual((int)HttpStatusCode.Found, jtilessFirst.StatusCode, jtilessFirst.Body);
        Assert.AreEqual((int)HttpStatusCode.Found, jtilessSecond.StatusCode, jtilessSecond.Body);
    }


    /// <summary>
    /// Registers a JAR-capable client whose single key serves JAR signing, token issuance, and
    /// JARM response signing — the host resolvers find it by id for every usage.
    /// </summary>
    private static VerifierKeyMaterial RegisterJarClient(TestHostShell host)
    {
        VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, JarCapabilities);

        host.UpdateSigningKeys(
            material.Registration.TenantId.Value,
            material.Registration.SigningKeys.ToImmutableDictionary()
                .Add(KeyUsageContext.JarSigning,
                    new SigningKeySet { Current = [material.SigningKeyId] })
                .Add(KeyUsageContext.AuthorizationResponseSigning,
                    new SigningKeySet { Current = [material.SigningKeyId] }));

        return material;
    }


    private Dictionary<string, object> BuildJarClaims(VerifierKeyMaterial material, PkceParameters pkce)
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = ClientId,
            [WellKnownJwtClaimNames.Aud] = material.Registration.IssuerUri!.ToString(),
            [WellKnownJwtClaimNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.State] = RequestState,
            [WellKnownJwtClaimNames.Nonce] = "nonce-jar-rar-01",
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Nbf] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = (now + TimeSpan.FromSeconds(30)).ToUnixTimeSeconds()
        };
    }


    private static List<object> DetailsArray(string configurationId) =>
    [
        new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["type"] = "openid_credential",
            ["credential_configuration_id"] = configurationId
        }
    ];


    private async Task<string> SignJarAsync(
        VerifierKeyMaterial material, IReadOnlyDictionary<string, object> claims)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(material.SigningPrivateKey.Tag);
        JwtHeader header = new()
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.OauthAuthzReqJwt
        };

        JwtPayload payload = new();
        foreach(KeyValuePair<string, object> entry in claims)
        {
            payload[entry.Key] = entry.Value;
        }

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage signed = await unsigned.SignAsync(
            material.SigningPrivateKey,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(signed, TestSetup.Base64UrlEncoder);
    }


    private async ValueTask<ServerHttpResponse> DispatchJarByValueAsync(
        TestHostShell host, VerifierKeyMaterial material, string compactJar)
    {
        ExchangeContext context = new();
        context.SetSubjectId(SubjectId);

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize,
            "GET",
            new RequestFields
            {
                [OAuthRequestParameterNames.Request] = compactJar,
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            context,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async ValueTask<ServerHttpResponse> ExchangeCodeAsync(
        TestHostShell host, VerifierKeyMaterial material, string code, PkceParameters pkce)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeToken, "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
            },
            new ExchangeContext(),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string ExtractQueryValue(string location, string name)
    {
        string marker = $"{name}=";
        int start = location.IndexOf(marker, StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, start, $"Location must carry '{name}'. Got: {location}");
        start += marker.Length;
        int end = location.IndexOf('&', start);

        return Uri.UnescapeDataString(end < 0 ? location[start..] : location[start..end]);
    }
}
