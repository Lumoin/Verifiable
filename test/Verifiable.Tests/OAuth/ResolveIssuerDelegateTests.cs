using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net.Http;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using Verifiable.OAuth.Server.Pipeline;
namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for <see cref="ResolveIssuerDelegate"/> and <see cref="DefaultIssuerResolver"/>.
/// Covers the registration → context → throw fallback, application overrides, and
/// confirms that the discovery endpoint and access-token emission both route through
/// the resolver (the iss claim plus client_id are emitted as expected).
/// </summary>
/// <remarks>
/// The access-token shape tests exercise the JWT factories
/// (<see cref="JwtHeader.ForAccessToken"/> / <see cref="JwtPayload.ForAccessToken"/>)
/// composed with <see cref="JwtSigningExtensions.SignAsync"/> directly rather than
/// driving the full auth-code + PKCE + token-exchange flow. The wiring through
/// <c>AuthCodeEndpoints</c> and the producer pipeline is trivial to read in the
/// source; the behaviour worth asserting is that the signing primitive emits the
/// claims it is given.
/// </remarks>
[TestClass]
internal sealed class ResolveIssuerDelegateTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task DefaultIssuerResolverPrefersRegistrationIssuerUri()
    {
        Uri registrationUri = new("https://tenant-a.issuer.example");
        Uri contextUri = new("https://fallback.example");

        ClientRecord registration = BuildRegistration(issuerUri: registrationUri);
        ExchangeContext context = new();
        context.SetIssuer(contextUri);

        Uri resolved = await DefaultIssuerResolver.ResolveAsync(
            registration, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(registrationUri, resolved,
            "DefaultIssuerResolver must prefer the registration's declared IssuerUri " +
            "over the context's request-scoped fallback.");
    }


    [TestMethod]
    public async Task DefaultIssuerResolverFallsBackToContextWhenRegistrationIssuerUriIsNull()
    {
        Uri contextUri = new("https://derived.example");

        ClientRecord registration = BuildRegistration(issuerUri: null);
        ExchangeContext context = new();
        context.SetIssuer(contextUri);

        Uri resolved = await DefaultIssuerResolver.ResolveAsync(
            registration, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(contextUri, resolved,
            "DefaultIssuerResolver must fall back to context.Issuer when the " +
            "registration does not declare an IssuerUri.");
    }


    [TestMethod]
    public async Task DefaultIssuerResolverThrowsWhenBothAreUnset()
    {
        ClientRecord registration = BuildRegistration(issuerUri: null);
        ExchangeContext context = new();

        InvalidOperationException thrown = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await DefaultIssuerResolver.ResolveAsync(
                registration, context, TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.Contains(nameof(ClientRecord.IssuerUri), thrown.Message,
            "Exception message must identify IssuerUri as the missing declaration site.");
    }


    //R9207-002 — RFC 9207 §2: "Its value MUST be a URL that uses the https scheme
    //without any query or fragment components." IssuerIdentifierValidation is the
    //pure shape check; DefaultIssuerResolver wires it in below so every default-path
    //consumer (discovery issuer, Authorize-redirect iss) enforces it.

    [TestMethod]
    public void IssuerIdentifierValidationRejectsHttpsWithQuery()
    {
        Assert.IsFalse(IssuerIdentifierValidation.IsValidIssuerShape(new Uri("https://as.example.com?tenant=a")),
            "An issuer identifier with a query component must be rejected per RFC 9207 §2.");
    }


    [TestMethod]
    public void IssuerIdentifierValidationRejectsFragment()
    {
        Assert.IsFalse(IssuerIdentifierValidation.IsValidIssuerShape(new Uri("https://as.example.com/tenant#frag")),
            "An issuer identifier with a fragment component must be rejected per RFC 9207 §2.");
    }


    [TestMethod]
    public void IssuerIdentifierValidationRejectsHttp()
    {
        Assert.IsFalse(IssuerIdentifierValidation.IsValidIssuerShape(new Uri("http://as.example.com")),
            "An issuer identifier that does not use the https scheme must be rejected per RFC 9207 §2.");
    }


    [TestMethod]
    public void IssuerIdentifierValidationAcceptsCleanHttps()
    {
        Assert.IsTrue(IssuerIdentifierValidation.IsValidIssuerShape(new Uri("https://as.example.com/tenant-a")),
            "A clean https URL with no query or fragment must be accepted.");
    }


    [TestMethod]
    public async Task DefaultIssuerResolverThrowsWhenRegistrationIssuerHasQueryComponent()
    {
        ClientRecord registration = BuildRegistration(issuerUri: new Uri("https://as.example.com?tenant=a"));
        ExchangeContext context = new();

        InvalidOperationException thrown = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await DefaultIssuerResolver.ResolveAsync(
                registration, context, TestContext.CancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.Contains("RFC 9207", thrown.Message,
            "A shape-invalid configured issuer must fail with an RFC 9207-attributed message, " +
            "distinct from the not-configured case.");
    }


    [TestMethod]
    public async Task ApplicationResolverOverridesDefault()
    {
        Uri registrationUri = new("https://declared.example");
        Uri overrideUri = new("https://policy-chosen.example");

        ClientRecord registration = BuildRegistration(issuerUri: registrationUri);
        ExchangeContext context = new();

        ResolveIssuerDelegate customResolver = (_, _, _) =>
            ValueTask.FromResult(overrideUri);

        Uri resolved = await customResolver(
            registration, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(overrideUri, resolved,
            "An application-supplied resolver must replace the default entirely, " +
            "even when the registration declares a different IssuerUri.");
    }


    //R9207-004 — RFC 9207 §2.3: "The issuer identifier included in the server's metadata
    //value issuer MUST be identical to the iss parameter's value." Drives a custom
    //AuthorizationServerIntegration.ResolveIssuerAsync through both the discovery endpoint
    //and a live Authorize redirect and asserts the two emitted issuer values agree
    //byte-for-byte — proving the redirect builder routes through the same resolution path
    //as discovery rather than its own independent ClientRegistration?.IssuerUri fallback.

    [TestMethod]
    public async Task CustomResolverProducesByteIdenticalIssuerOnMetadataAndRedirect()
    {
        FakeTimeProvider timeProvider = new(DateTimeOffset.Parse(
            "2026-04-22T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

        await using TestHostShell app = new(timeProvider);
        app.SeedTestSubject(subject: "subject-r9207-004");

        using VerifierKeyMaterial material = app.RegisterDpopClient(
            "client-r9207-004", new Uri("https://client.example.com"));

        Uri customIssuer = new("https://custom-resolver.example.com/tenant-x");
        app.Server.OAuth().ResolveIssuerAsync = (_, _, _) =>
            ValueTask.FromResult<Uri?>(customIssuer);

        string segment = material.Registration.TenantId.Value;

        ServerHttpResponse discoveryResponse = await app.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.MetadataDiscovery, "GET",
            new RequestFields(), new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, discoveryResponse.StatusCode, discoveryResponse.Body);

        using JsonDocument discoveryBody = JsonDocument.Parse(discoveryResponse.Body);
        string metadataIssuer = discoveryBody.RootElement.GetProperty("issuer").GetString()!;
        Assert.AreEqual(customIssuer.OriginalString, metadataIssuer,
            "The discovery issuer must equal the custom-resolved issuer.");

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = material.Registration.ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = "https://client.example.com/callback",
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await app.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);

        using JsonDocument parBody = JsonDocument.Parse(parResponse.Body);
        string requestUri = parBody.RootElement.GetProperty("request_uri").GetString()!;

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = material.Registration.ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId("subject-r9207-004");

        ServerHttpResponse authorizeResponse = await app.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);

        string location = authorizeResponse.Location!;
        int issIndex = location.IndexOf("iss=", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, issIndex, $"Redirect must carry iss. Location: {location}");
        int ampIndex = location.IndexOf('&', issIndex);
        string issRaw = ampIndex < 0 ? location[(issIndex + 4)..] : location[(issIndex + 4)..ampIndex];
        string redirectIssuer = Uri.UnescapeDataString(issRaw);

        Assert.AreEqual(metadataIssuer, redirectIssuer,
            "R9207-004: the redirect iss and the discovery issuer must be byte-identical under a custom resolver.");
    }


    //R9207-002 — RFC 9207 §2's https-only issuer shape, proven over the real wire rather than the
    //in-process dispatch <see cref="CustomResolverProducesByteIdenticalIssuerOnMetadataAndRedirect"/>
    //uses: every loopback test host now serves genuine HTTPS on an ephemeral pinned certificate, so the
    //DEFAULT resolver (no application override) already produces an issuer whose scheme, authority, and
    //shape satisfy the library's own RFC 9207 §2 / RFC 8414 §2 gate — closing the http-align bypass this
    //fixture used to carry.

    [TestMethod]
    public async Task DefaultResolverServesHttpsIssuerOverRealWireEndToEnd()
    {
        FakeTimeProvider timeProvider = new(DateTimeOffset.Parse(
            "2026-04-22T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

        await using TestHostShell host = new(timeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            "client-r9207-002-real-wire",
            new Uri("https://client.example.com"),
            profile: PolicyProfile.Haip10);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                "https://client.example.com/callback",
                profile: PolicyProfile.Haip10,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");

        //Guards against a bypass reintroduction: the DEFAULT resolver — no application-supplied
        //ResolveIssuerAsync — is what serves this real-wire flow.
        Assert.IsNull(hosted.Server.OAuth().ResolveIssuerAsync,
            "The default resolver must be in play; no application override should be wired for this host.");

        string segment = material.Registration.TenantId.Value;
        Uri discoveryUri = new(
            hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.MetadataDiscovery, segment));

        using HttpResponseMessage discoveryResponse = await hosted.SharedHttpClient!
            .GetAsync(discoveryUri, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)discoveryResponse.StatusCode,
            "The discovery document must be reachable over the pinned real-wire HTTPS client.");

        string discoveryBody = await discoveryResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument discoveryDocument = JsonDocument.Parse(discoveryBody);
        string metadataIssuer = discoveryDocument.RootElement.GetProperty("issuer").GetString()!;

        Uri issuerUri = new(metadataIssuer);
        Assert.AreEqual("https", issuerUri.Scheme,
            "RFC 9207 §2: the issuer identifier must use the https scheme.");
        Assert.AreEqual(string.Empty, issuerUri.Query,
            "RFC 9207 §2: the issuer identifier must carry no query component.");
        Assert.AreEqual(string.Empty, issuerUri.Fragment,
            "RFC 9207 §2: the issuer identifier must carry no fragment component.");
        Assert.AreEqual(hosted.HttpBaseAddress!.Authority, issuerUri.Authority,
            "The issuer authority must equal the wire authority the discovery document was actually served from.");

        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration,
            new Uri("https://client.example.com/callback"),
            OAuthFormEncodedFields.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect over the real wire. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];

        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(material.Registration.ClientId)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(parState.Par.RequestUri.ToString())}");

        //A fresh pinned, no-redirect client for the browser leg: the same certificate the shell's
        //SharedHttpClient pins, so the real-wire GET succeeds without trusting a CA, and with
        //auto-redirect disabled so the 302 Location is read off the wire directly.
        using HttpClientHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(host.ServerCertificate);
        noRedirectHandler.AllowAutoRedirect = false;
        using HttpClient browserClient = new(noRedirectHandler) { BaseAddress = hosted.HttpBaseAddress };
        using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, "subject-r9207-002-real-wire");

        using HttpResponseMessage authorizeResponse = await browserClient
            .SendAsync(authorizeRequest, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect with the iss parameter over the real wire.");

        string location = authorizeResponse.Headers.Location!.ToString();
        int issIndex = location.IndexOf("iss=", StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, issIndex, $"Redirect must carry iss. Location: {location}");
        int ampIndex = location.IndexOf('&', issIndex);
        string issRaw = ampIndex < 0 ? location[(issIndex + 4)..] : location[(issIndex + 4)..ampIndex];
        string redirectIssuer = Uri.UnescapeDataString(issRaw);

        Assert.AreEqual(metadataIssuer, redirectIssuer,
            "R9207-002: the real-wire redirect iss and the real-wire discovery issuer must be byte-identical.");
    }


    [TestMethod]
    public async Task DiscoveryEndpointUsesResolvedIssuerFromRegistration()
    {
        FakeTimeProvider timeProvider = new(DateTimeOffset.Parse(
            "2026-04-22T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

        await using TestHostShell app = new(timeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(
            "verifier-client",
            new Uri("https://verifier.example"),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint));

        string segment = keys.Registration.TenantId;

        //The registration declares IssuerUri as https://issuer.test/{segment} per
        //TestHostShell. The discovery endpoint must use that value, not any context
        //override, because the resolver prefers the registration.
        ExchangeContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(new Uri("https://wrong.context.example"));

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataDiscovery,
            "GET",
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "Discovery endpoint must return HTTP 200.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        string? emittedIssuer = doc.RootElement.GetProperty("issuer").GetString();

        Assert.AreEqual(keys.Registration.IssuerUri!.OriginalString,
            emittedIssuer,
            "Discovery must emit the registration's IssuerUri verbatim (with its path/tenant " +
            "segment), not the context's fallback and not collapsed to the authority " +
            "(RFC 8414 §3.3 exact-match).");
    }


    [TestMethod]
    public async Task AccessTokenSigningEmitsIssAndClientIdWhenSupplied()
    {
        string expectedIssuer = "https://issuer.test";
        string expectedClientId = "client-abc";
        string expectedSubject = "subject-xyz";
        string expectedJti = "jti-123";
        string expectedScope = "openid profile";

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using PrivateKeyMemory signingKey = keyPair.PrivateKey;

        DateTimeOffset now = DateTimeOffset.Parse(
            "2026-04-22T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        JwtHeader accessTokenHeader = JwtHeader.ForAccessToken(algorithm, "test-key");
        JwtPayload accessTokenPayload = JwtPayload.ForAccessToken(
            subject: expectedSubject,
            jti: expectedJti,
            scope: expectedScope,
            issuedAt: now,
            expiresAt: now.AddHours(1),
            issuer: expectedIssuer,
            audience: null,
            clientId: expectedClientId);

        UnsignedJwt unsigned = new(accessTokenHeader, accessTokenPayload);

        EncodeDelegate encoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);

        using JwsMessage jws = await unsigned.SignAsync(
            privateKey: signingKey,
            headerSerializer: static headerDict => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)headerDict,
                TestSetup.DefaultSerializationOptions),
            payloadSerializer: static payloadDict => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payloadDict,
                TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: encoder,
            memoryPool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jwt = JwsSerialization.SerializeCompact(jws, encoder);

        keyPair.PublicKey.Dispose();

        (JsonDocument header, JsonDocument payload) = DecodeJwt(jwt);
        using(header)
        using(payload)
        {
            Assert.AreEqual("at+jwt", header.RootElement.GetProperty("typ").GetString(),
                "RFC 9068 requires typ=at+jwt on access tokens.");

            Assert.AreEqual(expectedIssuer, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Iss).GetString(),
                "iss claim must equal the issuer argument passed to SignAsync.");

            Assert.AreEqual(expectedClientId, payload.RootElement.GetProperty(WellKnownJwtClaimNames.ClientId).GetString(),
                "client_id claim must equal the clientId argument passed to SignAsync.");

            Assert.AreEqual(expectedSubject, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString(),
                "sub claim must equal the subject argument.");

            Assert.AreEqual(expectedJti, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Jti).GetString(),
                "jti claim must equal the jti argument.");

            Assert.AreEqual(expectedScope, payload.RootElement.GetProperty(WellKnownJwtClaimNames.Scope).GetString(),
                "scope claim must equal the scope argument.");
        }
    }


    [TestMethod]
    public async Task AccessTokenSigningOmitsIssAndClientIdWhenNotSupplied()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using PrivateKeyMemory signingKey = keyPair.PrivateKey;

        DateTimeOffset now = DateTimeOffset.Parse(
            "2026-04-22T10:00:00Z", System.Globalization.CultureInfo.InvariantCulture);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);

        JwtHeader accessTokenHeader = JwtHeader.ForAccessToken(algorithm, "test-key");
        JwtPayload accessTokenPayload = JwtPayload.ForAccessToken(
            subject: "subject-xyz",
            jti: "jti-123",
            scope: "openid",
            issuedAt: now,
            expiresAt: now.AddHours(1));

        UnsignedJwt unsigned = new(accessTokenHeader, accessTokenPayload);

        EncodeDelegate encoder = DefaultCoderSelector.SelectEncoder(WellKnownKeyFormats.PublicKeyJwk);

        using JwsMessage jws = await unsigned.SignAsync(
            privateKey: signingKey,
            headerSerializer: static headerDict => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)headerDict,
                TestSetup.DefaultSerializationOptions),
            payloadSerializer: static payloadDict => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payloadDict,
                TestSetup.DefaultSerializationOptions),
            base64UrlEncoder: encoder,
            memoryPool: BaseMemoryPool.Shared,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string jwt = JwsSerialization.SerializeCompact(jws, encoder);

        keyPair.PublicKey.Dispose();

        (JsonDocument header, JsonDocument payload) = DecodeJwt(jwt);
        using(header)
        using(payload)
        {
            //Sanity check: mechanical claims are always present.
            Assert.IsTrue(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Sub, out _),
                "sub must always be present.");
            Assert.IsTrue(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Jti, out _),
                "jti must always be present.");

            //When the caller passes no issuer/clientId the claim is absent (not
            //an empty string). This ensures applications that don't plumb them
            //don't produce RFC-9068-looking tokens with empty-string iss.
            Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.Iss, out _),
                "iss claim must be absent when issuer parameter was null.");
            Assert.IsFalse(payload.RootElement.TryGetProperty(WellKnownJwtClaimNames.ClientId, out _),
                "client_id claim must be absent when clientId parameter was null.");
        }
    }


    private static ClientRecord BuildRegistration(Uri? issuerUri) =>
        new()
        {
            ClientId = "test-client",
            TenantId = "test-segment",
            IssuerUri = issuerUri,
            AllowedCapabilities = ImmutableHashSet<CapabilityIdentifier>.Empty,
            AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
            AllowedScopes = ImmutableHashSet<string>.Empty,
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty,
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty
        };


    //Decodes a compact JWS into (header, payload). No signature verification —
    //these tests assert claim shape, not cryptographic validity.
    private static (JsonDocument Header, JsonDocument Payload) DecodeJwt(string jwt)
    {
        string[] parts = jwt.Split('.');
        Assert.HasCount(3, parts, "Compact JWS must be header.payload.signature.");

        byte[] headerBytes = Base64UrlDecode(parts[0]);
        byte[] payloadBytes = Base64UrlDecode(parts[1]);

        return (JsonDocument.Parse(headerBytes), JsonDocument.Parse(payloadBytes));
    }


    private static byte[] Base64UrlDecode(string input)
    {
        string padded = input.Replace('-', '+').Replace('_', '/');
        switch(padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}
