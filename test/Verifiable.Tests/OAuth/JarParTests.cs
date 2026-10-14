using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;


/// <summary>
/// Tests for the JAR-PAR matcher in <c>AuthCodeEndpoints.BuildJarPar</c>.
/// Covers RFC 9101 + RFC 9126 + RFC 9700 §4.6 substitution defenses, FAPI 2.0
/// timing constraints, capability gating, disjointness with the PKCE PAR matcher,
/// and the happy path.
/// </summary>
[TestClass]
internal sealed class JarParTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private const string ClientId = "https://client.example.com";
    private const string DefaultState = "state-jar-par-01";
    private const string DefaultNonce = "nonce-jar-par-01";
    private static Uri ClientBaseUri { get; } = new("https://client.example.com");
    private static Uri RegisteredRedirectUri { get; } = new("https://client.example.com/callback");

    private static ImmutableHashSet<CapabilityIdentifier> JarParCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);

    private static ImmutableHashSet<CapabilityIdentifier> ParOnlyCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization);

    private static ImmutableHashSet<CapabilityIdentifier> JarOnlyCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest);


    [TestMethod]
    public async Task AcceptsValidJarParAndIssuesRequestUriHandle()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode,
            $"Expected 201 Created from JAR-PAR happy path (RFC 9126 §2.2). Body: {response.Body}");
        Assert.AreEqual("application/json", response.ContentType);
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal,
            $"Response body must contain request_uri. Got: {response.Body}");
        Assert.Contains("\"expires_in\":", response.Body, StringComparison.Ordinal,
            $"Response body must contain expires_in. Got: {response.Body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.1">RFC 9126 §2.1</see>: "the
    /// "request_uri" authorization request parameter defined in Section 4 of [RFC9101] ... MUST NOT
    /// be provided" on a pushed authorization request. An otherwise valid, fully signed JAR-PAR body
    /// is refused for presenting one alongside the request object, before that object is ever
    /// verified — the JAR-PAR body must not be able to reach a signature check, let alone mint a
    /// <c>request_uri</c> handle, by carrying one of its own.
    /// </summary>
    [TestMethod]
    public async Task RejectsJarParPresentingRequestUri()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = compactJar,
                [OAuthRequestParameterNames.RequestUri] = "urn:ietf:params:oauth:request_uri:arbitrary"
            }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        AssertErrorCode(body, OAuthErrors.InvalidRequest);
        Assert.DoesNotContain("\"request_uri\":", body, StringComparison.Ordinal,
            "A pushed request presenting request_uri must never itself mint one.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.2">RFC 9101 section 6.2</see>: "If the key
    /// is not associated with the client or if signature validation fails, the authorization server
    /// MUST return an "invalid_request_object" error to the client in response to the authorization
    /// request." A verification-key resolver that holds the registration's request-object key only for
    /// ID Tokens answers nothing when asked under <see cref="KeyUsageContext.JarSigning"/>, so no key
    /// associated with the client verifies the request object: a signed request object pushed to the
    /// pushed authorization request endpoint over the wire is answered 400 <c>invalid_request_object</c>
    /// with the fixed description "No verification key is available for the request object.", never a
    /// server fault, mints no <c>request_uri</c>, and the body names no key identifier.
    /// </summary>
    [TestMethod]
    public async Task PushedRequestObjectWhoseKeyTheResolverDoesNotHoldIsRefusedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);
        KeyId jarKeyId = material.Registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.Cryptography.VerificationKeyResolver = (keyId, usage, tenantId, ctx, ct) =>
                ValueTask.FromResult(
                    usage == KeyUsageContext.IdTokenIssuance && hosted.VerificationKeys.TryGetValue(keyId, out PublicKeyMemory? key)
                        ? key : null);
        }).ConfigureAwait(false);

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_request_object", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual(
            "No verification key is available for the request object.",
            document.RootElement.GetProperty("error_description").GetString());
        Assert.IsFalse(document.RootElement.TryGetProperty("request_uri", out _), "A refused pushed request mints no request_uri.");
        Assert.DoesNotContain(jarKeyId.Value, body, StringComparison.Ordinal, "The refusal names no key identifier.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519, Section 4.1.7</see>: "The "jti"
    /// value is a case-sensitive string." This library refuses a request object <c>jti</c> holding a character of the
    /// Unicode general category Cc before the replay store is read or written, since the application's store may not
    /// hold such a character; the character rule is this library's policy, not a rule of a specification. A signed
    /// request object whose <c>jti</c> holds U+0001, pushed to the pushed authorization request endpoint over the
    /// wire, is answered 400 <c>invalid_request_object</c> with the description that names both causes, mints no
    /// <c>request_uri</c>, and the store observation records no flow-state store call. A request object with an
    /// ordinary <c>jti</c> is then accepted with 201, and the observation sees the replay guard read, save, read back
    /// and claim its record. U+0000 never reaches the replay guard: the payload's well-formedness pass refuses it
    /// first (<see cref="APushedRequestObjectWhoseJtiCarriesAnEscapedNullCharacterIsRefusedAsMalformedAsync"/>).
    /// </summary>
    [TestMethod]
    public async Task APushedRequestObjectWhoseJtiCarriesAControlCharacterIsRefusedBeforeAnyStoreCallAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> refusedClaims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        refusedClaims[WellKnownJwtClaimNames.Jti] = string.Concat("jti-", ((char)0x0001).ToString(), "-value");
        string refusedJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, refusedClaims, TestContext.CancellationToken).ConfigureAwait(false);

        int beforeRefusal = hosted.StorageObservations.Count;
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = refusedJar
            }, TestContext.CancellationToken).ConfigureAwait(false);
        List<string> refusalOperations = [.. hosted.StorageObservations.Skip(beforeRefusal).Select(static entry => entry.Operation)];

        Assert.AreEqual(400, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_request_object", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual(
            "The JAR jti is too long or carries a character the replay guard cannot store.",
            document.RootElement.GetProperty("error_description").GetString());
        Assert.IsFalse(document.RootElement.TryGetProperty("request_uri", out _), "A refused pushed request mints no request_uri.");
        Assert.IsEmpty(refusalOperations,
            $"The refused jti must never reach the store; it observed: {string.Join(", ", refusalOperations)}.");

        Dictionary<string, object> acceptedClaims = OAuthJarFixtures.BuildBaseClaims(
            material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        acceptedClaims[WellKnownJwtClaimNames.Jti] = "jti-ordinary-value";
        string acceptedJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, acceptedClaims, TestContext.CancellationToken).ConfigureAwait(false);

        int beforeAcceptance = hosted.StorageObservations.Count;
        (int acceptedStatusCode, string acceptedBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = acceptedJar
            }, TestContext.CancellationToken).ConfigureAwait(false);
        List<string> acceptanceOperations = [.. hosted.StorageObservations.Skip(beforeAcceptance).Select(static entry => entry.Operation)];

        Assert.AreEqual(201, acceptedStatusCode, acceptedBody);
        Assert.IsTrue(HostedAuthorizationServer.IsReplayGuardFirstUseObserved(acceptanceOperations),
            $"The store observation must see the replay guard's read, save, read-back and claim; it observed: {string.Join(", ", acceptanceOperations)}.");
    }


    /// <summary>
    /// A signed request object whose <c>jti</c> holds U+0000, which its payload can carry only as the escape
    /// <c>\u0000</c>, is refused by the payload's well-formedness pass
    /// (<see cref="Verifiable.JCose.JwkJsonReader.IsWellFormedJsonDocument"/>), before any claim is read and before
    /// any store call: pushed over the wire it is answered 400 <c>invalid_request_object</c> naming the payload,
    /// mints no <c>request_uri</c>, and the store observation records nothing.
    /// </summary>
    [TestMethod]
    public async Task APushedRequestObjectWhoseJtiCarriesAnEscapedNullCharacterIsRefusedAsMalformedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        Dictionary<string, object> refusedClaims = OAuthJarFixtures.BuildBaseClaims(
            material, TimeProvider.GetUtcNow(), ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        refusedClaims[WellKnownJwtClaimNames.Jti] = string.Concat("jti-", ((char)0x0000).ToString(), "-value");
        string refusedJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, refusedClaims, TestContext.CancellationToken).ConfigureAwait(false);

        int beforeRefusal = hosted.StorageObservations.Count;
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = refusedJar
            }, TestContext.CancellationToken).ConfigureAwait(false);
        List<string> refusalOperations = [.. hosted.StorageObservations.Skip(beforeRefusal).Select(static entry => entry.Operation)];

        Assert.AreEqual(400, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_request_object", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual(
            "JAR payload is not well-formed JSON, or carries a duplicate claim name.",
            document.RootElement.GetProperty("error_description").GetString());
        Assert.IsFalse(document.RootElement.TryGetProperty("request_uri", out _), "A refused pushed request mints no request_uri.");
        Assert.IsEmpty(refusalOperations,
            $"The refused request object must never reach the store; it observed: {string.Join(", ", refusalOperations)}.");
    }


    [TestMethod]
    public async Task RejectsJarWithMissingOuterClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce), TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Outer client_id deliberately absent — the helper must short-circuit
        //before resolving the verification key.
        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, outerClientId: null, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequest);
        Assert.Contains("Missing outer client_id", response.Body, StringComparison.Ordinal,
            $"Response should mention missing outer client_id. Got: {response.Body}");
    }


    [TestMethod]
    public async Task RejectsJarWithOuterClientIdMismatchingJarClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce), TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Outer client_id mismatches both the registration and the JAR's inner
        //value. RFC 9700 §4.6 substitution defense rejects with invalid_request
        //before signature verification.
        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, "https://attacker.example.com",
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequest);
        Assert.Contains("Outer client_id", response.Body, StringComparison.Ordinal,
            $"Response should mention outer client_id mismatch. Got: {response.Body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request." A pushed authorization request
    /// carrying a signed request object, sent over the wire with an outer <c>client_id=</c> with no value beside
    /// the registration's <c>client_id</c>, names the one client identifier and is served: 201 with a
    /// <c>request_uri</c>.
    /// </summary>
    [TestMethod]
    public async Task AnEmptyOuterClientIdBesideTheClientIdIsTheOneIdentifierAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset issuedAt = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, issuedAt, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.ClientId, string.Empty),
                new(OAuthRequestParameterNames.ClientId, ClientId),
                new(OAuthRequestParameterNames.Request, compactJar)
            ], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsTrue(document.RootElement.TryGetProperty("request_uri", out _), "A served pushed request mints a request_uri.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2">RFC 6749 Section 3.2</see>: "Request and
    /// response parameters MUST NOT be included more than once." A pushed authorization request carrying a signed
    /// request object, sent over the wire with the registration's <c>client_id</c> twice as its outer parameter, is
    /// refused 400 <c>invalid_request</c> with the description of a repeated client authentication parameter, the
    /// code <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see> names for a
    /// request that repeats a parameter, and mints no <c>request_uri</c>.
    /// </summary>
    [TestMethod]
    public async Task ARepeatedOuterClientIdIsAnInvalidRequestAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset issuedAt = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, issuedAt, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.ClientId, ClientId),
                new(OAuthRequestParameterNames.ClientId, ClientId),
                new(OAuthRequestParameterNames.Request, compactJar)
            ], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(
            "{\"error\":\"invalid_request\",\"error_description\":\"The request repeats a client authentication parameter.\"}",
            body);
    }


    [TestMethod]
    public async Task RejectsJarSignedWithDifferentClientKey()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        //Sign the JAR with an unrelated keypair while the registration's
        //JarSigning slot still references the original verification key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory attackerPrivate = attackerKeys.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarWithKeyAsync(
            attackerPrivate, OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithIssuerNotMatchingClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        //RFC 9101 §10.2 — iss must equal client_id.
        claims[WellKnownJwtClaimNames.Iss] = "https://impostor.example.com";

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarCarryingSubClaim()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        //OpenID Federation 1.0 §12.1.1.1 — a Request Object MUST NOT carry a sub
        //claim. Here sub equals iss/client_id, the exact private_key_jwt
        //client-assertion shape the prohibition guards against; the matcher must
        //reject it rather than let the object double as client authentication.
        claims[WellKnownJwtClaimNames.Sub] = ClientId;

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithMissingIssuer()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.Iss);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithWrongAudience()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        claims[WellKnownJwtClaimNames.Aud] = "https://different-issuer.example.com/";

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithMissingAudience()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.Aud);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithAudEqualToClientIdRatherThanIssuer()
    {
        //RFC 9101 §10.2 + RFC 9700 §4.2 reading: aud must equal the AS issuer
        //URL, not the client_id. The "EUDI/Microsoft" reading where aud = client_id
        //is rejected by the library.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        claims[WellKnownJwtClaimNames.Aud] = ClientId;

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithExpiredExp()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset signedAt = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, signedAt, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        //Advance the clock past exp + clock skew (skew is 60s, JAR lifetime is 60s).
        TimeProvider.Advance(TimeSpan.FromMinutes(5));

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithNbfInFuture()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        DateTimeOffset farFuture = now + TimeSpan.FromMinutes(10);
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        //Push nbf well past the clock-skew tolerance window (60s default).
        claims[WellKnownJwtClaimNames.Nbf] = farFuture.ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Exp] = (farFuture + TimeSpan.FromSeconds(30)).ToUnixTimeSeconds();
        claims[WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds();

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithLifetimeExceedingPolicyCeiling()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        //Default policy ceiling for AuthCode JAR lifetime is 60 seconds.
        claims[WellKnownJwtClaimNames.Exp] = (now + TimeSpan.FromMinutes(5)).ToUnixTimeSeconds();

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithWrongTypHeader()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarWithCustomTypAsync(
            material.SigningPrivateKey,
            "JWT",
            OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarWithRedirectUriNotInRegistration()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        claims[OAuthRequestParameterNames.RedirectUri] = "https://attacker.example.com/steal";

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    /// <summary>
    /// A verified JAR with a plain transformation receives the unsupported-method error per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">RFC 7636 §4.4.1</see>:
    /// "authorization error response with "error" value set to "invalid_request"."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 §6.3</see> sends
    /// parameter errors "as specified in Section 5.2 of [RFC6749]", yielding a direct JSON error.
    /// </summary>
    [TestMethod]
    public async Task RejectsJarWithCodeChallengeMethodPlain()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        claims[OAuthRequestParameterNames.CodeChallengeMethod] = "plain";
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// An absent method requests the refused plain transformation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>:
    /// "OPTIONAL, defaults to "plain" if not present in the request".
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">§4.4.1</see> requires
    /// "authorization error response with "error" value set to "invalid_request"."
    /// </summary>
    [TestMethod]
    public async Task RejectsJarWithAbsentCodeChallengeMethod()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.CodeChallengeMethod);
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// A verified JAR with a plain transformation receives the unsupported-method error per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">RFC 7636 §4.4.1</see>:
    /// "authorization error response with "error" value set to "invalid_request"."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 §6.3</see> sends
    /// parameter errors "as specified in Section 5.2 of [RFC6749]", yielding a direct JSON error.
    /// </summary>
    [TestMethod]
    public async Task RejectsJarWithCodeChallengeMethodPlainAtEphemeralLoopbackPort()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);
        using System.Net.Sockets.Socket socket = new(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Tcp);
        socket.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        int port = Assert.IsInstanceOfType<System.Net.IPEndPoint>(socket.LocalEndPoint).Port;
        Uri loopbackRedirectUri = new($"http://127.0.0.1:{port}/cb");

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, loopbackRedirectUri, DefaultState, DefaultNonce);
        claims[OAuthRequestParameterNames.CodeChallengeMethod] = "plain";
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// An absent method requests the refused plain transformation per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>:
    /// "OPTIONAL, defaults to "plain" if not present in the request".
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.4.1">§4.4.1</see> requires
    /// "authorization error response with "error" value set to "invalid_request"."
    /// </summary>
    [TestMethod]
    public async Task RejectsJarWithAbsentCodeChallengeMethodAtEphemeralLoopbackPort()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        await host.SetRedirectUrisAndAuthMethodAsync(
            material, ImmutableHashSet.Create(new Uri("http://127.0.0.1/cb")), tokenEndpointAuthMethod: null).ConfigureAwait(false);
        using System.Net.Sockets.Socket socket = new(
            System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream,
            System.Net.Sockets.ProtocolType.Tcp);
        socket.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 0));
        int port = Assert.IsInstanceOfType<System.Net.IPEndPoint>(socket.LocalEndPoint).Port;
        Uri loopbackRedirectUri = new($"http://127.0.0.1:{port}/cb");

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, loopbackRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.CodeChallengeMethod);
        claims[OAuthRequestParameterNames.CodeChallenge] = new string('a', 43);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, StatusCode, Body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidRequest}\"", Body, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task RejectsJarMissingClientId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.ClientId);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingResponseType()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.ResponseType);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingRedirectUri()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.RedirectUri);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingScope()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.Scope);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingState()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.State);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingNonce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.Nonce);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingCodeChallenge()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(OAuthRequestParameterNames.CodeChallenge);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task RejectsJarMissingExp()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        _ = claims.Remove(WellKnownJwtClaimNames.Exp);

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode);
        AssertErrorCode(response, OAuthErrors.InvalidRequestObject);
    }


    [TestMethod]
    public async Task JarParMatcherAbsentWhenJwtSecuredAuthorizationRequestCapabilityNotAllowed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, ParOnlyCapabilities).ConfigureAwait(false);

        EndpointChain chain = await host.GetEndpointsAsync(material.Registration, []).ConfigureAwait(false);

        bool hasJarPar = chain.Any(e => string.Equals(
            e.Name, "AuthCode.JarPar", StringComparison.Ordinal));
        Assert.IsFalse(hasJarPar,
            "JAR-PAR endpoint must not appear when JwtSecuredAuthorizationRequest is not allowed.");
    }


    [TestMethod]
    public async Task JarParMatcherAbsentWhenPushedAuthorizationCapabilityNotAllowed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarOnlyCapabilities).ConfigureAwait(false);

        EndpointChain chain = await host.GetEndpointsAsync(material.Registration, []).ConfigureAwait(false);

        bool hasJarPar = chain.Any(e => string.Equals(
            e.Name, "AuthCode.JarPar", StringComparison.Ordinal));
        Assert.IsFalse(hasJarPar,
            "JAR-PAR endpoint must not appear when PushedAuthorization is not allowed.");
    }


    [TestMethod]
    public async Task BuildParStillAcceptsPureCodeChallengeRequestAfterDisjointnessFix()
    {
        //Disjointness regression: a registration with PAR but no JAR capability
        //must still accept a pure PKCE PAR body (code_challenge + S256 method,
        //no 'request' parameter) and produce a request_uri.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, ParOnlyCapabilities).ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = "abcdEFGHijklMNOPqrstUVWXyz0123456789-_AAA",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RegisteredRedirectUri.ToString(),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };

        ExchangeContext context = [];
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode,
            $"Pure PKCE PAR must still succeed. Body: {response.Body}");
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal,
            $"PKCE PAR response must contain request_uri. Got: {response.Body}");
    }


    [TestMethod]
    public async Task RejectsRequestWithBothCodeChallengeAndRequestParameter()
    {
        //RFC 9101 Section 6.3: outer parameters must be ignored when a JAR is present.
        //The matcher routing puts a body carrying 'request' onto the JAR-PAR
        //matcher regardless of any outer code_challenge. Confirm the response
        //is a JAR validation outcome (200 happy path here), not the PKCE one.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce), TestContext.CancellationToken)
            .ConfigureAwait(false);

        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            //Outer PKCE fields the JAR matcher must ignore.
            [OAuthRequestParameterNames.CodeChallenge] = "outer-challenge-should-be-ignored",
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256
        };

        ExchangeContext context = [];
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            fields,
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The JAR matcher took over: response is a JAR-shaped success
        //(request_uri + expires_in), proving routing chose the JAR path.
        Assert.AreEqual(201, response.StatusCode,
            $"Body with both 'request' and 'code_challenge' must route to the JAR matcher. Body: {response.Body}");
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal,
            $"JAR happy path body must contain request_uri. Got: {response.Body}");
    }


    [TestMethod]
    public async Task AcceptsJarWithAudAsArrayContainingIssuer()
    {
        //RFC 7519 §4.1.3 permits aud as either a single string or an array of
        //strings. CheckTokenAudContainsExpectedIssuer accepts both shapes; the
        //matcher's ValidateJarAudienceAsync runs the check against verified.Claims
        //(the raw payload dictionary) — not the projected
        //AuthCodeRequestObject.Aud which is single-string only. This test
        //exercises the array form by replacing the default string aud claim
        //with an array that contains the expected issuer URL alongside two
        //unrelated entries.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, JarParCapabilities).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(material, now, ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);

        string expectedAud = material.Registration.IssuerUri!.ToString();
        claims[WellKnownJwtClaimNames.Aud] = new[]
        {
            "https://unrelated-aud.example",
            expectedAud,
            "https://another-unrelated.example"
        };

        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material, claims, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchJarParAsync(
            host, material, compactJar, ClientId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode,
            $"JAR with aud as array containing the issuer must be accepted. Body: {response.Body}");
        Assert.Contains("\"request_uri\":", response.Body, StringComparison.Ordinal,
            $"Array-form aud happy path must produce a JAR-PAR success body. Got: {response.Body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 §2</see>: "the rules
    /// for client authentication as defined in [RFC6749] for token endpoint requests ... apply for
    /// the PAR endpoint as well" — a confidential registration's signed JAR push with no
    /// credentials at all is refused with the token endpoint's own <c>401 invalid_client</c>
    /// answer, before the JAR is verified, before the replay store is touched, and before a
    /// <c>request_uri</c> handle is generated.
    /// </summary>
    [TestMethod]
    public async Task RejectsConfidentialJarParWithNoCredentials()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ConfidentialClientId, ConfidentialClientBaseUri, JarParCapabilities).ConfigureAwait(false);
        await DeclareConfidentialJarParClientAsync(host, material).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ConfidentialClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ConfidentialClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            },
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, statusCode, body);
        AssertErrorCode(body, OAuthErrors.InvalidClient);
        Assert.DoesNotContain("\"request_uri\":", body, StringComparison.Ordinal,
            $"An authentication failure must not have generated a request_uri handle. Got: {body}");
    }


    /// <summary>
    /// The same requirement as <see cref="RejectsConfidentialJarParWithNoCredentials"/> against a
    /// wrong <c>client_secret_basic</c> secret — a foreign credential, not merely an absent one.
    /// </summary>
    [TestMethod]
    public async Task RejectsConfidentialJarParWithWrongBasicSecret()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ConfidentialClientId, ConfidentialClientBaseUri, JarParCapabilities).ConfigureAwait(false);
        await DeclareConfidentialJarParClientAsync(host, material).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ConfidentialClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(
            ConfidentialClientId, Encoding.UTF8.GetBytes("a-foreign-secret-nobody-registered"));

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ConfidentialClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            },
            headers, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, statusCode, body);
        AssertErrorCode(body, OAuthErrors.InvalidClient);
        Assert.DoesNotContain("\"request_uri\":", body, StringComparison.Ordinal,
            $"An authentication failure must not have generated a request_uri handle. Got: {body}");
    }


    /// <summary>
    /// The positive control for <see cref="RejectsConfidentialJarParWithNoCredentials"/> and
    /// <see cref="RejectsConfidentialJarParWithWrongBasicSecret"/>: the registration's own
    /// <c>client_secret_basic</c> secret authenticates the pushed request and the JAR still issues
    /// its <c>request_uri</c> handle.
    /// </summary>
    [TestMethod]
    public async Task AcceptsConfidentialJarParWithValidBasicSecret()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ConfidentialClientId, ConfidentialClientBaseUri, JarParCapabilities).ConfigureAwait(false);
        await DeclareConfidentialJarParClientAsync(host, material).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string compactJar = await OAuthJarFixtures.BuildSignedJarAsync(
            material,
            OAuthJarFixtures.BuildBaseClaims(material, now, ConfidentialClientId, RegisteredRedirectUri, DefaultState, DefaultNonce),
            TestContext.CancellationToken).ConfigureAwait(false);

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(
            ConfidentialClientId, Encoding.UTF8.GetBytes(ConfidentialClientSecret));

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ClientId] = ConfidentialClientId,
                [OAuthRequestParameterNames.Request] = compactJar
            },
            headers, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, statusCode, body);
        Assert.Contains("\"request_uri\":", body, StringComparison.Ordinal, $"Got: {body}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-3">RFC 9126 Section 3</see>: "All other request
    /// parameters, i.e., those pertaining to the authorization request itself, MUST appear as claims of the JWT
    /// representing the authorization request.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 Section 6.3</see>: "The authorization
    /// server MUST only use the parameters in the Request Object, even if the same parameter is provided in the query
    /// parameter." A pushed Request Object whose <c>dpop_jkt</c> claim is the thumbprint of one DPoP key, sent in a
    /// body whose own <c>dpop_jkt</c> names another DPoP key, binds its code to the claim
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: "If they do not
    /// match, it MUST reject the request."): the code is refused 400 <c>invalid_grant</c> under a proof by the DPoP key
    /// the body named and redeemed under a proof by the DPoP key the claim named.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectDpopJktBindsTheCodeAndTheOuterOneIsNotReadAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        string otherThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(other.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, boundThumbprint).ConfigureAwait(false);

        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar),
            new(OAuthRequestParameterNames.DpopJkt, otherThumbprint)
        ], dpopProof: null, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, pushed.StatusCode, pushed.Body);
        string code = await AuthorizePushedAsync(host, segment, pushed.Body).ConfigureAwait(false);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, bound.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        (int otherStatusCode, string otherBody) = await RedeemAsync(host, segment, code, pkce, other.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(otherStatusCode, otherBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        (int boundStatusCode, string boundBody) = await RedeemAsync(host, segment, code, pkce, bound.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(boundStatusCode, boundBody, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 Section 6.3</see>: "The authorization
    /// server MUST extract the set of authorization request parameters from the Request Object value. ... The
    /// authorization server then validates the request, as specified in OAuth 2.0 [RFC6749].", and "If the Client ID
    /// check or the request validation fails, then the authorization server MUST return an error to the client in
    /// response to the authorization request, as specified in Section 5.2 of [RFC6749] (OAuth 2.0)."; the value of
    /// <c>dpop_jkt</c> (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>) "is
    /// the JWK Thumbprint [RFC7638] of the proof-of-possession public key using the SHA-256 hash function". At an
    /// authorization server that verifies DPoP proofs, a pushed Request Object whose <c>dpop_jkt</c> claim is a JSON
    /// number, no string at all, is an invalid Request Object
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 Section 7</see>: "The request parameter
    /// contains an invalid Request Object.") refused 400 <c>invalid_request_object</c>, and one whose claim is a string
    /// that is no thumbprint is refused 400 <c>invalid_request</c>; no <c>request_uri</c> is issued for either.
    /// </summary>
    /// <param name="dpopJktClaim">The value of the <c>dpop_jkt</c> claim.</param>
    /// <param name="expectedError">The <c>error</c> of the refusal.</param>
    /// <param name="expectedDescription">The <c>error_description</c> of the refusal.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(7, "invalid_request_object", "JAR 'dpop_jkt' claim is not a string.", DisplayName = "a JSON number")]
    [DataRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "invalid_request", "dpop_jkt is not a JWK SHA-256 Thumbprint.",
        DisplayName = "a 42-character string")]
    public async Task RequestObjectDpopJktThatIsNoThumbprintIsRefusedAsync(
        object dpopJktClaim, string expectedError, string expectedDescription)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, dpopJktClaim).ConfigureAwait(false);

        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ], dpopProof: null, TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(pushed.StatusCode, pushed.Body, 400, expectedError, expectedDescription);
        Assert.DoesNotContain("\"request_uri\":", pushed.Body, StringComparison.Ordinal, pushed.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 Section 6.3</see>: "The authorization
    /// server MUST extract the set of authorization request parameters from the Request Object value.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: "Use of the dpop_jkt
    /// authorization request parameter is OPTIONAL." At an authorization server that verifies DPoP proofs, a pushed
    /// Request Object whose <c>dpop_jkt</c> claim is the empty string is read as one without the claim: it is answered
    /// 201, and its code, bound to no DPoP key, redeemed with no <c>DPoP</c> field issues a Bearer access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectEmptyDpopJktIsReadAsOmittedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, string.Empty).ConfigureAwait(false);

        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ], dpopProof: null, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, pushed.StatusCode, pushed.Body);

        string code = await AuthorizePushedAsync(host, segment, pushed.Body).ConfigureAwait(false);
        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(statusCode, body, "Bearer", expectedJwkThumbprint: null);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 Section 5</see> passes the authorization
    /// request parameters as claims of a Request Object sent by value, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 Section 6.3</see>: "If the Client ID
    /// check or the request validation fails, then the authorization server MUST return an error to the client in
    /// response to the authorization request, as specified in Section 5.2 of [RFC6749] (OAuth 2.0)."; the value of
    /// <c>dpop_jkt</c> (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>) is
    /// "the JWK Thumbprint [RFC7638] of the proof-of-possession public key using the SHA-256 hash function". At an
    /// authorization server that verifies DPoP proofs, a Request Object passed by value whose <c>dpop_jkt</c> claim is a
    /// JSON number is an invalid Request Object
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 Section 7</see>) refused in place, 400
    /// <c>invalid_request_object</c>, and one whose claim is a string that is no thumbprint is refused in place, 400
    /// <c>invalid_request</c>, each with no redirect.
    /// </summary>
    /// <param name="dpopJktClaim">The value of the <c>dpop_jkt</c> claim.</param>
    /// <param name="expectedError">The <c>error</c> of the refusal.</param>
    /// <param name="expectedDescription">The <c>error_description</c> of the refusal.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(7, "invalid_request_object", "JAR 'dpop_jkt' claim is not a string.", DisplayName = "a JSON number")]
    [DataRow("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "invalid_request", "dpop_jkt is not a JWK SHA-256 Thumbprint.",
        DisplayName = "a 42-character string")]
    public async Task RequestObjectByValueDpopJktThatIsNoThumbprintIsRefusedAsync(
        object dpopJktClaim, string expectedError, string expectedDescription)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, dpopJktClaim).ConfigureAwait(false);

        using HttpResponseMessage response = await SendRequestObjectByValueAsync(host, segment, compactJar).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError((int)response.StatusCode, body, 400, expectedError, expectedDescription);
        Assert.IsNull(response.Headers.Location, "The refusal is answered in place.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>: "Parameters sent
    /// without a value MUST be treated as if they were omitted from the request.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 Section 5</see>, which passes the
    /// authorization request parameters as claims of a Request Object sent by value, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: "Use of the dpop_jkt
    /// authorization request parameter is OPTIONAL." At an authorization server that verifies DPoP proofs, a Request
    /// Object passed by value whose <c>dpop_jkt</c> claim is the empty string is read as one without the claim: it is
    /// answered by a redirect carrying a code, and the code, bound to no DPoP key, redeemed with no <c>DPoP</c> field
    /// issues a Bearer access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectByValueEmptyDpopJktIsReadAsOmittedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, string.Empty).ConfigureAwait(false);

        using HttpResponseMessage response = await SendRequestObjectByValueAsync(host, segment, compactJar).ConfigureAwait(false);
        string code = DpopCodeBindingWire.ReadCode((int)response.StatusCode, response.Headers.Location);

        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(statusCode, body, "Bearer", expectedJwkThumbprint: null);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>: "The authorization
    /// server MUST ignore unrecognized request parameters.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 Section 6.3</see>: "The authorization
    /// server MUST extract the set of authorization request parameters from the Request Object value." An
    /// authorization server that verifies no DPoP proof recognizes no <c>dpop_jkt</c>: a pushed Request Object whose
    /// <c>dpop_jkt</c> claim is a string of 42 characters, which is no JWK SHA-256 Thumbprint, is answered 201, and its
    /// code redeemed with no <c>DPoP</c> field issues a Bearer access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectDpopJktIsIgnoredWhereTheServerVerifiesNoDpopProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: false).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").ConfigureAwait(false);

        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ], dpopProof: null, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, pushed.StatusCode, pushed.Body);

        string code = await AuthorizePushedAsync(host, segment, pushed.Body).ConfigureAwait(false);
        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(statusCode, body, "Bearer", expectedJwkThumbprint: null);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 Section 3.1</see>: "The authorization
    /// server MUST ignore unrecognized request parameters.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 Section 5</see>, which passes the
    /// authorization request parameters as claims of a Request Object, and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">Section 6.3</see>: "The authorization server MUST
    /// extract the set of authorization request parameters from the Request Object value." An authorization server
    /// that verifies no DPoP proof recognizes no <c>dpop_jkt</c>: a Request Object passed by value whose
    /// <c>dpop_jkt</c> claim is a string of 42 characters, which is no JWK SHA-256 Thumbprint, is answered by a redirect
    /// carrying a code and no <c>error</c>, and the code redeemed with no <c>DPoP</c> field issues a Bearer access
    /// token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectByValueDpopJktIsIgnoredWhereTheServerVerifiesNoDpopProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: false).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").ConfigureAwait(false);

        using HttpResponseMessage response = await SendRequestObjectByValueAsync(host, segment, compactJar).ConfigureAwait(false);
        string code = DpopCodeBindingWire.ReadCode((int)response.StatusCode, response.Headers.Location);
        string location = response.Headers.Location!.ToString();
        Assert.IsNull(TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Error), location);

        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(statusCode, body, "Bearer", expectedJwkThumbprint: null);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-4">RFC 9101 Section 4</see>: "The parameters are
    /// represented as the JWT Claims of the object. Parameter names and string values MUST be included as JSON
    /// strings.", with <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 Section 6.3</see>: "If
    /// the Client ID check or the request validation fails, then the authorization server MUST return an error to the
    /// client in response to the authorization request, as specified in Section 5.2 of [RFC6749] (OAuth 2.0)." Even
    /// at an authorization server that verifies no DPoP proof, a pushed Request Object whose <c>dpop_jkt</c> claim is
    /// a JSON number carries a string parameter as no JSON string and is an invalid Request Object
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 Section 7</see>: "The request parameter
    /// contains an invalid Request Object."): it is refused 400 <c>invalid_request_object</c> and no
    /// <c>request_uri</c> is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectNonStringDpopJktIsMalformedWhereTheServerVerifiesNoDpopProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: false).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, 7).ConfigureAwait(false);

        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ], dpopProof: null, TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(pushed.StatusCode, pushed.Body, 400, "invalid_request_object", "JAR 'dpop_jkt' claim is not a string.");
        Assert.DoesNotContain("\"request_uri\":", pushed.Body, StringComparison.Ordinal, pushed.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-4">RFC 9101 Section 4</see>: "The parameters are
    /// represented as the JWT Claims of the object. Parameter names and string values MUST be included as JSON
    /// strings.", with <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 Section 6.3</see>: "If
    /// the Client ID check or the request validation fails, then the authorization server MUST return an error to the
    /// client in response to the authorization request, as specified in Section 5.2 of [RFC6749] (OAuth 2.0)." Even
    /// at an authorization server that verifies no DPoP proof, a Request Object passed by value whose <c>dpop_jkt</c>
    /// claim is a JSON number carries a string parameter as no JSON string and is an invalid Request Object
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9101#section-7">RFC 9101 Section 7</see>): it is refused in place,
    /// 400 <c>invalid_request_object</c>, with no redirect.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectByValueNonStringDpopJktIsMalformedWhereTheServerVerifiesNoDpopProofAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: false).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, 7).ConfigureAwait(false);

        using HttpResponseMessage response = await SendRequestObjectByValueAsync(host, segment, compactJar).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError((int)response.StatusCode, body, 400, "invalid_request_object", "JAR 'dpop_jkt' claim is not a string.");
        Assert.IsNull(response.Headers.Location, "The refusal is answered in place.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10.1">RFC 9449 Section 10.1</see>: "If both
    /// mechanisms are used at the same time, the authorization server MUST reject the request if the JWK Thumbprint in
    /// dpop_jkt does not match the public key in the DPoP header." A pushed Request Object whose <c>dpop_jkt</c> claim
    /// is the thumbprint of one DPoP key, sent with a valid proof by another DPoP key carrying the supplied nonce, is
    /// refused with the token endpoint's error format
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2.3">RFC 9126 Section 2.3</see>) as a malformed
    /// request (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>
    /// <c>invalid_request</c>), and no <c>request_uri</c> is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectDpopJktBesideAProofUnderAnotherKeyIsAnInvalidRequestAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, boundThumbprint).ConfigureAwait(false);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, other.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        string otherProof = await DpopCodeBindingWire.BuildPushedRequestProofAsync(
            host, segment, other.Key, nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        HttpResponseData response = await DpopCodeBindingWire.PushAsync(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ], otherProof, TestContext.CancellationToken).ConfigureAwait(false);

        DpopCodeBindingWire.AssertError(response.StatusCode, response.Body, 400, "invalid_request", "dpop_jkt does not match the DPoP proof's public key.");
        Assert.DoesNotContain("\"request_uri\":", response.Body, StringComparison.Ordinal, response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 Section 5</see>: "The client MAY send the
    /// parameters included in the Request Object duplicated in the query parameters as well for backward
    /// compatibility, etc. However, the authorization server supporting this specification MUST only use the
    /// parameters included in the Request Object.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-10">RFC 9449 Section 10</see>: "When a token request
    /// is received, the authorization server computes the JWK Thumbprint of the proof-of-possession public key in the
    /// DPoP proof and verifies that it matches the dpop_jkt parameter value in the authorization request. If they do not
    /// match, it MUST reject the request." A Request Object passed by value whose <c>dpop_jkt</c> claim is the
    /// thumbprint of one DPoP key, sent in a query whose own <c>dpop_jkt</c> names another DPoP key, is answered with a
    /// code bound to the claim: the code is refused 400 <c>invalid_grant</c> under a proof by the DPoP key the query
    /// named and redeemed under a proof by the DPoP key the claim named.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectByValueDpopJktBindsTheCodeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey bound = new();
        using FreshDpopKey other = new();
        string boundThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(bound.Key, TestContext.CancellationToken).ConfigureAwait(false);
        string otherThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(other.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, boundThumbprint).ConfigureAwait(false);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment,
            [
                new(OAuthRequestParameterNames.ClientId, ClientId),
                new(OAuthRequestParameterNames.Request, compactJar),
                new(OAuthRequestParameterNames.DpopJkt, otherThumbprint)
            ]), CodeBindingSubject, TestContext.CancellationToken).ConfigureAwait(false);
        string code = DpopCodeBindingWire.ReadCode((int)response.StatusCode, response.Headers.Location);
        string nonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, segment, ClientId, bound.Key, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        (int otherStatusCode, string otherBody) = await RedeemAsync(host, segment, code, pkce, other.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertError(otherStatusCode, otherBody, 400, "invalid_grant", "The authorization code is unknown, expired, or already used.");

        (int boundStatusCode, string boundBody) = await RedeemAsync(host, segment, code, pkce, bound.Key, nonce).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(boundStatusCode, boundBody, "DPoP", boundThumbprint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 Section 5</see>: "The client MAY send the
    /// parameters included in the Request Object duplicated in the query parameters as well for backward
    /// compatibility, etc. However, the authorization server supporting this specification MUST only use the
    /// parameters included in the Request Object.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 Section 6.3</see>: "The authorization
    /// server MUST only use the parameters in the Request Object, even if the same parameter is provided in the query
    /// parameter." At an authorization server that verifies DPoP proofs, a Request Object passed by value that carries
    /// no <c>dpop_jkt</c> claim, sent in a query whose own <c>dpop_jkt</c> names a DPoP key, is answered by a redirect
    /// carrying a code and no <c>error</c>; the code is bound to no DPoP key, and redeemed with no <c>DPoP</c> field it
    /// issues a Bearer access token carrying no <c>cnf</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectByValueWithoutDpopJktIsNotBoundByTheOuterOneAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey outer = new();
        string outerThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(outer.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, dpopJktClaim: null).ConfigureAwait(false);

        using HttpResponseMessage response = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment,
            [
                new(OAuthRequestParameterNames.ClientId, ClientId),
                new(OAuthRequestParameterNames.Request, compactJar),
                new(OAuthRequestParameterNames.DpopJkt, outerThumbprint)
            ]), CodeBindingSubject, TestContext.CancellationToken).ConfigureAwait(false);
        string code = DpopCodeBindingWire.ReadCode((int)response.StatusCode, response.Headers.Location);
        string location = response.Headers.Location!.ToString();
        Assert.IsNull(TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Error), location);

        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(statusCode, body, "Bearer", expectedJwkThumbprint: null);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-3">RFC 9126 Section 3</see>: "All other request
    /// parameters, i.e., those pertaining to the authorization request itself, MUST appear as claims of the JWT
    /// representing the authorization request.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9101#section-6.3">RFC 9101 Section 6.3</see>: "The authorization
    /// server MUST only use the parameters in the Request Object, even if the same parameter is provided in the query
    /// parameter.", and <see href="https://www.rfc-editor.org/rfc/rfc9101#section-5">RFC 9101 Section 5</see>: "the
    /// authorization server supporting this specification MUST only use the parameters included in the Request
    /// Object." At an authorization server that verifies DPoP proofs, a pushed Request Object that carries no
    /// <c>dpop_jkt</c> claim, sent in a body whose own <c>dpop_jkt</c> names a DPoP key, is answered 201; the code the
    /// authorization request by <c>request_uri</c> leads to is bound to no DPoP key, and redeemed with no <c>DPoP</c>
    /// field it issues a Bearer access token carrying no <c>cnf</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task RequestObjectAtTheParEndpointWithoutDpopJktIsNotBoundByTheOuterOneAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterCodeBindingJarClientAsync(host, isDpopWired: true).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        using FreshDpopKey outer = new();
        string outerThumbprint = await ResourceDpopProofs.ComputeJwkThumbprintAsync(outer.Key, TestContext.CancellationToken).ConfigureAwait(false);
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
        string compactJar = await BuildCodeBindingJarAsync(material, pkce, dpopJktClaim: null).ConfigureAwait(false);

        HttpResponseData pushed = await DpopCodeBindingWire.PushAsync(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar),
            new(OAuthRequestParameterNames.DpopJkt, outerThumbprint)
        ], dpopProof: null, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, pushed.StatusCode, pushed.Body);

        string code = await AuthorizePushedAsync(host, segment, pushed.Body).ConfigureAwait(false);
        (int statusCode, string body) = await RedeemAsync(host, segment, code, pkce, key: null, nonce: null).ConfigureAwait(false);
        DpopCodeBindingWire.AssertIssued(statusCode, body, "Bearer", expectedJwkThumbprint: null);
    }


    /// <summary>The authenticated-session stand-in of the code binding rows' authorize GETs.</summary>
    private static string CodeBindingSubject { get; } = "subject-jar-code-binding";


    /// <summary>
    /// The capabilities of the code binding rows' registration: the authorization code grant, pushed authorization
    /// requests, Request Objects pushed or passed by value at the authorization endpoint, and OpenID Connect for the
    /// <c>openid</c> scope the Request Objects carry.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> CodeBindingJarCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect);


    /// <summary>
    /// Registers a public client that both signs Request Objects and is issued access tokens, under a profile that does
    /// not itself require DPoP (<see cref="PolicyProfile.Rfc6749WithPkce"/>): its access-token signing key is listed
    /// also under <see cref="KeyUsageContext.JarSigning"/>, the authorization server's DPoP verification is wired when
    /// <paramref name="isDpopWired"/>, the listener is started, and the registration's issuer is aligned to the
    /// listener's authority, the authority a proof's <c>htu</c> is judged against and the audience a Request Object
    /// names.
    /// </summary>
    /// <param name="host">The fixture the client is registered on.</param>
    /// <param name="isDpopWired">Whether the authorization server verifies DPoP proofs.</param>
    /// <returns>The registration's key material.</returns>
    private async Task<VerifierKeyMaterial> RegisterCodeBindingJarClientAsync(TestHostShell host, bool isDpopWired)
    {
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, CodeBindingJarCapabilities).ConfigureAwait(false);
        ClientRecord updated = await host.UpdateAsync(material, previous =>
        {
            Dictionary<KeyUsageContext, SigningKeySet> signingKeys = new(previous.SigningKeys)
            {
                [KeyUsageContext.JarSigning] = new SigningKeySet { Current = [material.SigningKeyId] }
            };

            return previous with
            {
                SigningKeys = signingKeys
            };
        }, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        if(isDpopWired)
        {
            _ = await host.EnableDpopAsync().ConfigureAwait(false);
        }

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", updated);

        return material;
    }


    /// <summary>
    /// Signs a Request Object of the base claims carrying <paramref name="pkce"/>'s S256 challenge and the
    /// <c>dpop_jkt</c> claim <paramref name="dpopJktClaim"/>, written as the JSON value of its runtime type, or no
    /// <c>dpop_jkt</c> claim at all when it is <see langword="null"/>.
    /// </summary>
    /// <param name="material">The registration signing the Request Object.</param>
    /// <param name="pkce">The PKCE pair whose challenge the Request Object carries.</param>
    /// <param name="dpopJktClaim">The value of the <c>dpop_jkt</c> claim, or <see langword="null"/> to carry none.</param>
    /// <returns>The compact Request Object.</returns>
    private async Task<string> BuildCodeBindingJarAsync(VerifierKeyMaterial material, PkceParameters pkce, object? dpopJktClaim)
    {
        Dictionary<string, object> claims = OAuthJarFixtures.BuildBaseClaims(
            material, TimeProvider.GetUtcNow(), ClientId, RegisteredRedirectUri, DefaultState, DefaultNonce);
        claims[OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge;
        if(dpopJktClaim is not null)
        {
            claims[OAuthRequestParameterNames.DpopJkt] = dpopJktClaim;
        }

        return await OAuthJarFixtures.BuildSignedJarAsync(material, claims, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Sends a Request Object by value at the authorization endpoint over the real wire, without following a redirect.</summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="compactJar">The Request Object.</param>
    /// <returns>The authorize response; the caller disposes it.</returns>
    private Task<HttpResponseMessage> SendRequestObjectByValueAsync(TestHostShell host, string segment, string compactJar) =>
        RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(host, RawAuthCodeWirePushers.ComposeAuthorizeUri(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new(OAuthRequestParameterNames.Request, compactJar)
        ]), CodeBindingSubject, TestContext.CancellationToken);


    /// <summary>Completes a pushed request at the authorization endpoint and reads its code.</summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="parBody">The 201 body of the pushed request.</param>
    /// <returns>The authorization code.</returns>
    private async Task<string> AuthorizePushedAsync(TestHostShell host, string segment, string parBody)
    {
        (Uri? location, int statusCode) = await RawAuthCodeWirePushers.AuthorizePushedRequestAsync(
            host, segment, ClientId, CodeBindingSubject, parBody, [], TestContext.CancellationToken).ConfigureAwait(false);

        return DpopCodeBindingWire.ReadCode(statusCode, location);
    }


    /// <summary>
    /// Redeems <paramref name="code"/> with <paramref name="pkce"/>'s verifier, carrying a fresh proof by
    /// <paramref name="key"/> with <paramref name="nonce"/>, or no <c>DPoP</c> field when <paramref name="key"/> is
    /// <see langword="null"/>.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="code">The authorization code.</param>
    /// <param name="pkce">The PKCE pair whose verifier the redemption carries.</param>
    /// <param name="key">The DPoP key that signs the proof, or <see langword="null"/> for no proof.</param>
    /// <param name="nonce">The proof's <c>nonce</c>.</param>
    /// <returns>The response's status code and body.</returns>
    private async Task<(int StatusCode, string Body)> RedeemAsync(
        TestHostShell host, string segment, string code, PkceParameters pkce, DpopKey? key, string? nonce)
    {
        string? proof = key switch
        {
            null => null,
            _ => await DpopCodeBindingWire.BuildTokenProofAsync(
                host, segment, key, nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false)
        };

        return await RawAuthCodeWirePushers.RedeemCodeAsync(
            host, segment, ClientId, code, pkce.EncodedVerifier, RegisteredRedirectUri.ToString(), proof,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private const string ConfidentialClientId = "https://confidential-jar-par.client.test";
    private const string ConfidentialClientSecret = "s3cret-of-the-confidential-jar-par-client";
    private static Uri ConfidentialClientBaseUri { get; } = new(ConfidentialClientId);


    /// <summary>
    /// Declares <paramref name="material"/>'s registration as a <c>client_secret_basic</c>
    /// confidential client and wires the host's <c>ValidateClientCredentialsAsync</c> to check the
    /// <c>Authorization: Basic</c> header against <see cref="ConfidentialClientSecret"/> — the one
    /// place a JAR-PAR confidential fixture attaches credentials, mirroring how
    /// <see cref="AuthCodeFlowDriver"/> gives the plain pushed request its declared credentials.
    /// </summary>
    private static async Task DeclareConfidentialJarParClientAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        _ = await host.SetTokenEndpointAuthMethodAsync(material, ClientAuthenticationMethod.ClientSecretBasic).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ClientAuthenticationMethodsSupported =
                [ClientAuthenticationMethod.None, ClientAuthenticationMethod.ClientSecretBasic];
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ConfidentialClientSecret));
        }).ConfigureAwait(false);
    }


    //Helpers — JAR construction and dispatch.

    private static async ValueTask<ServerHttpResponse> DispatchJarParAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string compactJar,
        string? outerClientId,
        CancellationToken cancellationToken)
    {
        RequestFields fields = new()
        {
            [OAuthRequestParameterNames.Request] = compactJar
        };

        if(outerClientId is not null)
        {
            fields[OAuthRequestParameterNames.ClientId] = outerClientId;
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar,
            "POST",
            fields,
            [],
            cancellationToken).ConfigureAwait(false);
    }


    private static void AssertErrorCode(ServerHttpResponse response, string expectedCode) =>
        AssertErrorCode(response.Body, expectedCode);


    private static void AssertErrorCode(string body, string expectedCode)
    {
        string expectedFragment = $"\"error\":\"{expectedCode}\"";
        Assert.Contains(expectedFragment, body, StringComparison.Ordinal,
            $"Expected error '{expectedCode}' in response body. Got: {body}");
    }
}
