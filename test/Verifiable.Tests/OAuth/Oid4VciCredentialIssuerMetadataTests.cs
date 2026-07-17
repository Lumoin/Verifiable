using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Server-side OID4VCI 1.0 §12.2 Credential Issuer Metadata, driven through the real dispatch
/// pipeline. The Wallet GETs the §12.2.2 well-known document; the library derives
/// <c>credential_issuer</c> + <c>credential_endpoint</c> (REQUIRED, off the chain) +
/// <c>nonce_endpoint</c> and merges the application's
/// <see cref="ContributeCredentialIssuerMetadataDelegate"/> catalog over them, optionally
/// embedding <c>signed_metadata</c>. Mirrors the RFC 9728 Protected Resource Metadata shape.
/// </summary>
[TestClass]
internal sealed class Oid4VciCredentialIssuerMetadataTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The Credential Issuer client identifier registered for the metadata tests.</summary>
    private const string ClientId = "https://issuer.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static readonly Uri ClientBaseUri = new("https://issuer.client.test");

    /// <summary>The supported Credential Configuration identifier the catalog advertises.</summary>
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";

    /// <summary>
    /// The full capability set: the metadata endpoint, plus the Credential and Nonce Endpoints
    /// whose URLs the metadata document derives off the chain.
    /// </summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> MetadataCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint);


    /// <summary>
    /// A wired Credential Issuer Metadata endpoint returns the §12.2.4 document: the derived
    /// <c>credential_issuer</c> / <c>credential_endpoint</c> / <c>nonce_endpoint</c> off the
    /// chain plus the application's <c>credential_configurations_supported</c> catalog and
    /// <c>authorization_servers</c>.
    /// </summary>
    [TestMethod]
    public async Task ServesDerivedEndpointsAndContributedCatalog()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(BuildContribution(segment));

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.ContentType);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement root = doc.RootElement;

        //§12.2.4 credential_issuer MUST equal the identifier the well-known URL is inserted into.
        Assert.AreEqual($"https://issuer.test/{segment}",
            root.GetProperty("credential_issuer").GetString());

        //credential_endpoint (REQUIRED) and nonce_endpoint derived off the chain.
        Assert.AreEqual($"https://issuer.test/connect/{segment}/credential",
            root.GetProperty("credential_endpoint").GetString());
        Assert.AreEqual($"https://issuer.test/connect/{segment}/nonce",
            root.GetProperty("nonce_endpoint").GetString());

        //authorization_servers contributed by the application.
        JsonElement authServers = root.GetProperty("authorization_servers");
        Assert.AreEqual(JsonValueKind.Array, authServers.ValueKind);
        Assert.AreEqual($"https://issuer.test/{segment}", authServers[0].GetString());

        //credential_configurations_supported (REQUIRED) with the contributed config tree.
        JsonElement configs = root.GetProperty("credential_configurations_supported");
        Assert.IsTrue(configs.TryGetProperty(ConfigurationId, out JsonElement config),
            "The contributed Credential Configuration must be present.");
        Assert.AreEqual("dc+sd-jwt", config.GetProperty("format").GetString());
        Assert.AreEqual("ES256",
            config.GetProperty("proof_types_supported").GetProperty("jwt")
                .GetProperty("proof_signing_alg_values_supported")[0].GetString());
    }


    /// <summary>
    /// §12.2.4 marks <c>credential_configurations_supported</c> REQUIRED: an empty contribution
    /// still emits the member (as an empty object) rather than omitting it.
    /// </summary>
    [TestMethod]
    public async Task CredentialConfigurationsSupportedIsAlwaysEmitted()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(CredentialIssuerMetadataContribution.Empty);

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement configs = doc.RootElement.GetProperty("credential_configurations_supported");
        Assert.AreEqual(JsonValueKind.Object, configs.ValueKind);
        Assert.IsEmpty(configs.EnumerateObject(),
            "An empty contribution emits credential_configurations_supported as an empty object.");
    }


    /// <summary>
    /// §12.2.3: when the signer seam is wired, the assembled claim set (carrying the same derived
    /// and contributed values) is embedded as <c>signed_metadata</c>.
    /// </summary>
    [TestMethod]
    public async Task SignedMetadataEmbedsTheAssembledClaimSet()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(BuildContribution(segment));

        const string signedJwt = "eyJ0eXAiOiJvcGVuaWR2Y2ktaXNzdWVyLW1ldGFkYXRhK2p3dCJ9.eyJzdWIiOiJpc3MifQ.sig";
        JwtPayload? seenClaims = null;
        host.Server.OAuth().SignCredentialIssuerMetadataAsync =
            (metadata, registration, context, ct) =>
            {
                seenClaims = metadata;

                return ValueTask.FromResult<string?>(signedJwt);
            };

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(signedJwt, doc.RootElement.GetProperty("signed_metadata").GetString());

        //The signer received the same values the plain document carries (so they cannot diverge).
        Assert.IsNotNull(seenClaims);
        Assert.AreEqual($"https://issuer.test/{segment}",
            seenClaims!.TryGetValue("credential_issuer", out object? iss) ? iss as string : null);
        Assert.AreEqual($"https://issuer.test/connect/{segment}/credential",
            seenClaims.TryGetValue("credential_endpoint", out object? ce) ? ce as string : null);
        Assert.IsTrue(seenClaims.TryGetValue("credential_configurations_supported", out _),
            "The signed claim set must carry credential_configurations_supported.");
    }


    /// <summary>
    /// §12.2.3: the library helper <see cref="SignedCredentialIssuerMetadata.CreateAsync"/>
    /// produces a conformant <c>signed_metadata</c> JWS — the in-repo reference path wires the
    /// app seam to it. "The signed metadata MUST be secured using a JSON Web Signature (JWS)";
    /// the JOSE header carries "<c>typ</c>: REQUIRED. MUST be <c>openidvci-issuer-metadata+jwt</c>"
    /// and "<c>alg</c>: REQUIRED ... It MUST NOT be none or an identifier for a symmetric
    /// algorithm (MAC)"; the payload carries "<c>sub</c>: REQUIRED. String matching the Credential
    /// Issuer Identifier", "<c>iat</c>: REQUIRED", and "All metadata parameters used by the
    /// Credential Issuer MUST be added as top-level claims in the JWS payload."
    /// </summary>
    [TestMethod]
    public async Task SignedMetadataHelperProducesConformantJws()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(BuildContribution(segment));

        //The reference path: the app seam composes the signed_metadata JWS THROUGH the library
        //helper, inheriting the §12.2.3 guarantees rather than re-deriving them. The deployment
        //still owns the signing key and its kid — the library is key-agnostic for signed_metadata.
        const string Kid = "issuer-signing-key-1";
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = keys.PublicKey;
        using PrivateKeyMemory issuerPrivate = keys.PrivateKey;
        string expectedIssuer = $"https://issuer.test/{segment}";

        host.Server.OAuth().SignCredentialIssuerMetadataAsync =
            async (metadata, registration, context, ct) =>
                await SignedCredentialIssuerMetadata.CreateAsync(
                    metadata,
                    expectedIssuer,
                    issuerPrivate,
                    Kid,
                    TimeProvider.GetUtcNow(),
                    AppendHeaderSerializer,
                    AppendPayloadSerializer,
                    TestSetup.Base64UrlEncoder,
                    BaseMemoryPool.Shared,
                    ct).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);
        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        string signedMetadata = doc.RootElement.GetProperty("signed_metadata").GetString()!;
        string[] segments = signedMetadata.Split('.');
        Assert.HasCount(3, segments, "signed_metadata MUST be a compact JWS (§12.2.3).");

        //JOSE header: typ = openidvci-issuer-metadata+jwt and a non-none, non-symmetric alg.
        Dictionary<string, object>? header = SecurityEventTestJson.DeserializePart(
            SecurityEventTestJson.DecodeSegment(segments[0], BaseMemoryPool.Shared));
        Assert.IsNotNull(header);
        Assert.AreEqual("openidvci-issuer-metadata+jwt", header!["typ"] as string,
            "§12.2.3 typ MUST be openidvci-issuer-metadata+jwt.");
        string alg = (header["alg"] as string)!;
        Assert.AreEqual(WellKnownJwaValues.Es256, alg,
            "§12.2.3 alg is the digital-signature algorithm of the P-256 signing key.");
        Assert.IsFalse(WellKnownJwaValues.IsNone(alg), "§12.2.3 alg MUST NOT be none.");

        //JWS payload: sub = issuer id, an iat, and the metadata params as top-level claims.
        Dictionary<string, object>? payload = SecurityEventTestJson.DeserializePart(
            SecurityEventTestJson.DecodeSegment(segments[1], BaseMemoryPool.Shared));
        Assert.IsNotNull(payload);
        Assert.AreEqual(expectedIssuer, payload!["sub"] as string,
            "§12.2.3 sub MUST match the Credential Issuer Identifier.");
        Assert.IsTrue(payload.ContainsKey("iat"), "§12.2.3 iat is REQUIRED.");
        Assert.AreEqual(expectedIssuer, payload["credential_issuer"] as string,
            "Every metadata parameter MUST be a top-level claim (§12.2.3).");
        Assert.AreEqual($"https://issuer.test/connect/{segment}/credential",
            payload["credential_endpoint"] as string,
            "credential_endpoint MUST be a top-level claim (§12.2.3).");
        Assert.IsTrue(payload.ContainsKey("credential_configurations_supported"),
            "credential_configurations_supported MUST be a top-level claim (§12.2.3).");
    }


    /// <summary>
    /// §12.2.3: "<c>alg</c>: REQUIRED ... It MUST NOT be none or an identifier for a symmetric
    /// algorithm (MAC)." The library helper rejects an attempt to sign the metadata with
    /// <c>none</c> or an <c>HS*</c> MAC, making the §12.2.3 alg MUST a library guarantee rather
    /// than an unguarded app responsibility.
    /// </summary>
    [TestMethod]
    public void SignedMetadataHelperRejectsNoneAndSymmetricAlg()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => SignedCredentialIssuerMetadata.EnsureSignatureAlgorithmAllowed(WellKnownJwaValues.None),
            "§12.2.3 forbids alg=none for signed_metadata.");
        Assert.ThrowsExactly<ArgumentException>(
            () => SignedCredentialIssuerMetadata.EnsureSignatureAlgorithmAllowed(WellKnownJwaValues.Hs256),
            "§12.2.3 forbids a symmetric (MAC) alg for signed_metadata.");
        Assert.ThrowsExactly<ArgumentException>(
            () => SignedCredentialIssuerMetadata.EnsureSignatureAlgorithmAllowed(WellKnownJwaValues.Hs512),
            "§12.2.3 forbids a symmetric (MAC) alg for signed_metadata.");

        //A digital-signature algorithm is accepted — the guard does not over-reach.
        SignedCredentialIssuerMetadata.EnsureSignatureAlgorithmAllowed(WellKnownJwaValues.Es256);
    }


    /// <summary>
    /// Fail-closed: declaring the metadata capability without wiring the contribution seam leaves
    /// the endpoint absent from the chain (the REQUIRED catalog cannot be derived), so the
    /// request 404s rather than serving a non-conformant document.
    /// </summary>
    [TestMethod]
    public async Task MetadataEndpointAbsentWhenContributionSeamUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unwired contribution seam must leave the metadata endpoint absent (fail-closed).");
    }


    /// <summary>
    /// <c>credential_endpoint</c> is REQUIRED (§12.2.4): when the Credential Endpoint is not on
    /// the chain (its capability/seams unwired), the metadata endpoint fails loud rather than
    /// serving a document missing the required field.
    /// </summary>
    [TestMethod]
    public async Task FailsLoudWhenCredentialEndpointMissingFromChain()
    {
        await using TestHostShell host = new(TimeProvider);
        //Only the metadata capability — the Credential Endpoint is deliberately absent.
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri,
            ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata));
        string segment = material.Registration.TenantId.Value;

        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(BuildContribution(segment));

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.ServerError, response.Body);
    }


    /// <summary>
    /// §12.2.4: "<c>format</c> : REQUIRED. A JSON string identifying the format of this Credential."
    /// A configuration without <c>format</c> is a server misconfiguration — the endpoint fails loud
    /// (500) rather than serving a non-conformant document.
    /// </summary>
    [TestMethod]
    public async Task FailsLoudWhenCredentialConfigurationMissingFormat()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(new CredentialIssuerMetadataContribution
            {
                CredentialConfigurationsSupported = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    //No "format" — the §12.2.4 REQUIRED inner member is missing.
                    [ConfigurationId] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["scope"] = "UniversityDegree"
                    }
                }
            });

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.ServerError, response.Body);
    }


    /// <summary>
    /// §12.2.4: "<c>proof_signing_alg_values_supported</c> : REQUIRED. A non-empty array of
    /// algorithm identifiers that the Issuer supports for this proof type." A
    /// <c>proof_types_supported</c> entry without it fails loud (500).
    /// </summary>
    [TestMethod]
    public async Task FailsLoudWhenProofTypeMissingSigningAlgValues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(new CredentialIssuerMetadataContribution
            {
                CredentialConfigurationsSupported = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [ConfigurationId] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["format"] = "dc+sd-jwt",
                        ["proof_types_supported"] = new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            //The "jwt" proof type omits the REQUIRED proof_signing_alg_values_supported.
                            ["jwt"] = new Dictionary<string, object>(StringComparer.Ordinal)
                        }
                    }
                }
            });

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.ServerError, response.Body);
    }


    /// <summary>
    /// §12.2.4: "<c>batch_size</c> : REQUIRED. Integer value specifying the maximum array size for
    /// the proofs parameter in a Credential Request. It MUST be 2 or greater." A
    /// <c>batch_credential_issuance</c> with <c>batch_size</c> = 1 fails loud (500).
    /// </summary>
    [TestMethod]
    public async Task FailsLoudWhenBatchSizeBelowTwo()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(BuildContribution(segment) with
            {
                BatchCredentialIssuance = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    //§12.2.4: batch_size MUST be 2 or greater — 1 is non-conformant.
                    ["batch_size"] = 1
                }
            });

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.ServerError, response.Body);
    }


    /// <summary>
    /// §12.2.4: a present <c>credential_response_encryption</c> object's
    /// "<c>alg_values_supported</c> : REQUIRED" / "<c>enc_values_supported</c> : REQUIRED" /
    /// "<c>encryption_required</c> : REQUIRED" inner members are enforced — omitting
    /// <c>alg_values_supported</c> fails loud (500).
    /// </summary>
    [TestMethod]
    public async Task FailsLoudWhenResponseEncryptionMissingAlgValues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(BuildContribution(segment) with
            {
                CredentialResponseEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    //No alg_values_supported — the §12.2.4 REQUIRED inner member is missing.
                    ["enc_values_supported"] = new List<object> { "A128GCM" },
                    ["encryption_required"] = false
                }
            });

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.ServerError, response.Body);
    }


    /// <summary>
    /// §12.2.4: well-formed metadata (every REQUIRED inner member present) serves 200 — the
    /// validation does not over-reach and reject conformant documents. The library helper
    /// <see cref="CredentialIssuerMetadataValidation.Validate"/> the endpoint calls returns no
    /// fault for the representative contribution.
    /// </summary>
    [TestMethod]
    public void ValidationAcceptsWellFormedMetadata()
    {
        CredentialIssuerMetadataContribution contribution = BuildContribution("tenant") with
        {
            BatchCredentialIssuance = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                //§12.2.4: batch_size MUST be 2 or greater — 2 is the conformant floor.
                ["batch_size"] = 2
            },
            CredentialResponseEncryption = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["alg_values_supported"] = new List<object> { "ECDH-ES" },
                ["enc_values_supported"] = new List<object> { "A128GCM" },
                ["encryption_required"] = false
            },
            Display = new List<object>
            {
                new Dictionary<string, object>(StringComparer.Ordinal) { ["name"] = "Example Issuer", ["locale"] = "en" }
            }
        };

        Assert.IsNull(CredentialIssuerMetadataValidation.Validate(contribution),
            "Well-formed §12.2.4 metadata must pass validation.");
    }


    /// <summary>
    /// §12.2.2: "a signed JSON Web Token (JWT) containing the Credential Issuer Metadata in its
    /// payload using the media type <c>application/jwt</c>." When the Wallet's <c>Accept</c> prefers
    /// <c>application/jwt</c> and the signer seam is wired, the WHOLE document is served as the
    /// signed JWS with Content-Type <c>application/jwt</c>, and its payload carries the metadata
    /// params plus the §12.2.3 <c>typ</c> / <c>sub</c> / <c>iat</c>.
    /// </summary>
    [TestMethod]
    public async Task AcceptApplicationJwtServesSignedDocument()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(BuildContribution(segment));

        const string Kid = "issuer-signing-key-1";
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = keys.PublicKey;
        using PrivateKeyMemory issuerPrivate = keys.PrivateKey;
        string expectedIssuer = $"https://issuer.test/{segment}";

        host.Server.OAuth().SignCredentialIssuerMetadataAsync =
            async (metadata, registration, context, ct) =>
                await SignedCredentialIssuerMetadata.CreateAsync(
                    metadata, expectedIssuer, issuerPrivate, Kid, TimeProvider.GetUtcNow(),
                    AppendHeaderSerializer, AppendPayloadSerializer, TestSetup.Base64UrlEncoder,
                    BaseMemoryPool.Shared, ct).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchMetadataAsync(
            host, segment, SingleHeader(WellKnownHttpHeaderNames.Accept, WellKnownMediaTypes.Application.Jwt))
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        //§12.2.2: the response is the JWT itself, typed application/jwt — not a JSON document.
        Assert.AreEqual(WellKnownMediaTypes.Application.Jwt, response.ContentType);
        string[] segments = response.Body.Split('.');
        Assert.HasCount(3, segments, "An application/jwt metadata response is a compact JWS (§12.2.2).");

        Dictionary<string, object>? header = SecurityEventTestJson.DeserializePart(
            SecurityEventTestJson.DecodeSegment(segments[0], BaseMemoryPool.Shared));
        Assert.IsNotNull(header);
        Assert.AreEqual("openidvci-issuer-metadata+jwt", header!["typ"] as string,
            "§12.2.3 typ MUST be openidvci-issuer-metadata+jwt.");

        Dictionary<string, object>? payload = SecurityEventTestJson.DeserializePart(
            SecurityEventTestJson.DecodeSegment(segments[1], BaseMemoryPool.Shared));
        Assert.IsNotNull(payload);
        Assert.AreEqual(expectedIssuer, payload!["sub"] as string,
            "§12.2.3 sub MUST match the Credential Issuer Identifier.");
        Assert.IsTrue(payload.ContainsKey("iat"), "§12.2.3 iat is REQUIRED.");
        Assert.AreEqual(expectedIssuer, payload["credential_issuer"] as string,
            "Every metadata parameter MUST be a top-level claim (§12.2.3).");
        Assert.IsTrue(payload.ContainsKey("credential_configurations_supported"),
            "credential_configurations_supported MUST be a top-level claim (§12.2.3).");
    }


    /// <summary>
    /// §12.2.2: "The Credential Issuer MUST support returning metadata in an unsigned form
    /// 'application/json'". With <c>Accept: application/json</c> (or no Accept) the plain JSON
    /// document is served, not the signed JWT — even when the signer seam is wired.
    /// </summary>
    [TestMethod]
    public async Task AcceptApplicationJsonServesPlainDocument()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(BuildContribution(segment));

        const string signedJwt = "eyJ0eXAiOiJvcGVuaWR2Y2ktaXNzdWVyLW1ldGFkYXRhK2p3dCJ9.eyJzdWIiOiJpc3MifQ.sig";
        host.Server.OAuth().SignCredentialIssuerMetadataAsync =
            (metadata, registration, context, ct) => ValueTask.FromResult<string?>(signedJwt);

        ServerHttpResponse response = await DispatchMetadataAsync(
            host, segment, SingleHeader(WellKnownHttpHeaderNames.Accept, WellKnownMediaTypes.Application.Json))
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.ContentType);

        //The plain document is JSON and embeds signed_metadata as a field (not the whole body).
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual($"https://issuer.test/{segment}",
            doc.RootElement.GetProperty("credential_issuer").GetString());
        Assert.AreEqual(signedJwt, doc.RootElement.GetProperty("signed_metadata").GetString());
    }


    /// <summary>
    /// §12.2.2: "send a subset the metadata containing internationalized display data for one or
    /// all of the requested languages and indicate returned languages using the HTTP
    /// Content-Language Header." A document whose issuer <c>display</c> carries <c>en</c> and
    /// <c>de</c>, requested with <c>Accept-Language: de</c>, serves only the <c>de</c> display and
    /// sets <c>Content-Language: de</c>.
    /// </summary>
    [TestMethod]
    public async Task AcceptLanguageFiltersDisplayAndSetsContentLanguage()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(BuildContribution(segment) with
            {
                Display = new List<object>
                {
                    new Dictionary<string, object>(StringComparer.Ordinal) { ["name"] = "Example Issuer", ["locale"] = "en" },
                    new Dictionary<string, object>(StringComparer.Ordinal) { ["name"] = "Beispiel-Aussteller", ["locale"] = "de" }
                }
            });

        ServerHttpResponse response = await DispatchMetadataAsync(
            host, segment, SingleHeader(WellKnownHttpHeaderNames.AcceptLanguage, "de")).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        //§12.2.2: the served language is echoed in Content-Language.
        Assert.IsTrue(response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentLanguage, out string? contentLanguage),
            "A negotiated response MUST set Content-Language (§12.2.2).");
        Assert.AreEqual("de", contentLanguage);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement display = doc.RootElement.GetProperty("display");
        Assert.AreEqual(1, display.GetArrayLength(), "Only the requested language's display is served.");
        Assert.AreEqual("de", display[0].GetProperty("locale").GetString());
        Assert.AreEqual("Beispiel-Aussteller", display[0].GetProperty("name").GetString());
    }


    /// <summary>
    /// §12.2.2: "ignore the Accept-Language Header and send all supported languages or any chosen
    /// subset." With no <c>Accept-Language</c>, all display languages are served and no
    /// <c>Content-Language</c> is set.
    /// </summary>
    [TestMethod]
    public async Task NoAcceptLanguageServesAllDisplayLanguages()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, MetadataCapabilities);
        string segment = material.Registration.TenantId.Value;

        WireChainEndpointSeams(host);
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync =
            (registration, context, ct) => ValueTask.FromResult(BuildContribution(segment) with
            {
                Display = new List<object>
                {
                    new Dictionary<string, object>(StringComparer.Ordinal) { ["name"] = "Example Issuer", ["locale"] = "en" },
                    new Dictionary<string, object>(StringComparer.Ordinal) { ["name"] = "Beispiel-Aussteller", ["locale"] = "de" }
                }
            });

        ServerHttpResponse response = await DispatchMetadataAsync(host, segment).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.IsFalse(response.Headers.ContainsKey(WellKnownHttpHeaderNames.ContentLanguage),
            "With no Accept-Language, no language is negotiated and Content-Language is not set (§12.2.2).");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement display = doc.RootElement.GetProperty("display");
        Assert.AreEqual(2, display.GetArrayLength(), "All display languages are served when none is requested.");
    }


    /// <summary>
    /// A JOSE-header serializer backed by the library's <see cref="JsonAppender"/> firewall walker
    /// — the same path that serializes the plain §12.2.4 document, so it handles the metadata
    /// claim set's string arrays and nested object trees verbatim.
    /// </summary>
    private static readonly JwtHeaderSerializer AppendHeaderSerializer = static header => AppendDictionary(header);

    /// <summary>A JWS-payload serializer backed by the same <see cref="JsonAppender"/> firewall walker.</summary>
    private static readonly JwtPayloadSerializer AppendPayloadSerializer = static payload => AppendDictionary(payload);


    private static byte[] AppendDictionary(IReadOnlyDictionary<string, object> dictionary)
    {
        System.Text.StringBuilder sb = JsonAppender.Rent();
        try
        {
            JsonAppender.AppendObject(sb, dictionary);

            return JsonAppender.ToUtf8Bytes(sb);
        }
        finally
        {
            JsonAppender.Return(sb);
        }
    }


    /// <summary>
    /// Wires the Credential and Nonce Endpoint seams so both land on the per-request chain and
    /// the metadata document can derive their URLs.
    /// </summary>
    private static void WireChainEndpointSeams(TestHostShell host)
    {
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync =
            (request, accessToken, registration, context, ct) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue(["credential"]));
        host.Server.OAuth().IssueCredentialNonceAsync =
            (_, _) => ValueTask.FromResult("c-nonce");
    }


    /// <summary>
    /// A representative §12.2.4 contribution: one <c>dc+sd-jwt</c> Credential Configuration with
    /// a <c>jwt</c> proof type, and the issuer as its own Authorization Server.
    /// </summary>
    private static CredentialIssuerMetadataContribution BuildContribution(string segment)
    {
        return new CredentialIssuerMetadataContribution
        {
            AuthorizationServers = [$"https://issuer.test/{segment}"],
            CredentialConfigurationsSupported = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [ConfigurationId] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "dc+sd-jwt",
                    ["scope"] = "UniversityDegree",
                    ["cryptographic_binding_methods_supported"] = new List<object> { "jwk" },
                    ["proof_types_supported"] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["jwt"] = new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            ["proof_signing_alg_values_supported"] = new List<object> { "ES256" }
                        }
                    }
                }
            }
        };
    }


    /// <summary>
    /// GETs the §12.2.2 well-known Credential Issuer Metadata document for the tenant.
    /// </summary>
    private async Task<ServerHttpResponse> DispatchMetadataAsync(TestHostShell host, string segment)
    {
        return await host.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.Oid4VciCredentialIssuerMetadata,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// GETs the §12.2.2 well-known Credential Issuer Metadata document for the tenant, carrying the
    /// supplied request headers (for example <c>Accept</c> / <c>Accept-Language</c> negotiation).
    /// </summary>
    private async Task<ServerHttpResponse> DispatchMetadataAsync(
        TestHostShell host, string segment, RequestHeaders headers)
    {
        return await host.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.Oid4VciCredentialIssuerMetadata,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            headers,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Builds a <see cref="RequestHeaders"/> carrying a single header.</summary>
    private static RequestHeaders SingleHeader(string name, string value) =>
        new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [name] = [value]
        });
}
