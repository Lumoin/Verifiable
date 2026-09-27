using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// The request-body encoding rule on every VCALM endpoint family that reads a JSON body: holder, exchange, interaction,
/// issuer, status, verifier and workflow. <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259
/// §8.1</see>: "JSON text exchanged between systems that are not part of a closed ecosystem MUST be encoded using
/// UTF-8" (RFC 3629). <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Options</see>: "Implementations MUST
/// throw an error if an endpoint receives data, options, or option values that it does not understand or know how to
/// process." A body whose bytes are not valid UTF-8 is not JSON text an endpoint can process, so each endpoint refuses
/// it with HTTP 400 and the malformed-value problem type, and writes nothing, instead of decoding the damaged bytes into
/// the Unicode replacement character and acting on a value the client never sent.
/// </summary>
/// <remarks>
/// Every test sends its body over the real wire as raw bytes through
/// <see cref="VcalmWireFixtures.SendRawBytesWireAsync(TestHostShell, string, string, byte[], string, string?, CancellationToken)"/>,
/// since a <see cref="string"/> body re-encodes to valid UTF-8 on the way out. Each body is otherwise valid for its
/// endpoint and carries one invalid byte inside a JSON string value, so an endpoint that repaired the byte would
/// accept the request and write what it names; each test wires a recording seam for that write and asserts it never
/// ran.
/// </remarks>
[TestClass]
internal sealed class VcalmRequestEncodingTests
{
    /// <summary>The MSTest context of the running test; its cancellation token bounds every request in this class.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fake clock the host and the signing helpers read, fixed at the canonical test epoch.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The memory pool the test-side signing and key material rent from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The client identifier every tenant of this class is registered under with <see cref="TestHostShell"/>.</summary>
    private static string ClientId { get; } = "https://encoding.client.test";

    /// <summary>The base URI registered with <see cref="TestHostShell"/> alongside <see cref="ClientId"/>.</summary>
    private static Uri ClientBaseUri { get; } = new("https://encoding.client.test");

    /// <summary>
    /// The byte every request body of this class carries inside a JSON string value. RFC 3629 §1: "The octet values C0,
    /// C1, F5 to FF never appear." in UTF-8, so a body carrying it is not valid UTF-8 wherever it stands.
    /// </summary>
    private static byte InvalidUtf8Byte { get; } = 0xFF;

    /// <summary>The media type every request body of this class is labelled with, the only one the VCALM endpoints read.</summary>
    private static string JsonMediaType { get; } = "application/json";

    /// <summary>The serializer options every credential and presentation in this class is written and read with.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>Builds the did:key document of the issuer the issuance test configures.</summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    /// <summary>
    /// The JCS canonicalizer the holder's presentations and the issuer's credentials are signed with (eddsa-jcs-2022):
    /// JCS is context-free, so no context resolution is wired.
    /// </summary>
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    /// <summary>Serializes a credential with <see cref="JsonOptions"/>.</summary>
    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    /// <summary>Deserializes a credential with <see cref="JsonOptions"/>.</summary>
    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    /// <summary>Serializes a presentation with <see cref="JsonOptions"/>.</summary>
    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    /// <summary>Deserializes a presentation with <see cref="JsonOptions"/>.</summary>
    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    /// <summary>Serializes a proof options document with <see cref="JsonOptions"/>.</summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    /// <summary>The host registrations the test made, disposed at cleanup.</summary>
    private List<VerifierKeyMaterial> RegisteredMaterials { get; } = [];

    /// <summary>
    /// Key material the holder and issuer signing configurations retain for the host's lifetime, disposed at cleanup
    /// after the host, which holds the configurations, is torn down.
    /// </summary>
    private List<IDisposable> OwnedKeys { get; } = [];

    /// <summary>The in-memory presentation store the holder's §3.5.2 storage seam writes.</summary>
    private ConcurrentDictionary<string, VcalmStoredPresentation> PresentationStore { get; } =
        new(StringComparer.Ordinal);


    /// <summary>Disposes the registrations and key material the test created, and empties the presentation store.</summary>
    [TestCleanup]
    public void DisposeRegisteredMaterials()
    {
        foreach(VerifierKeyMaterial material in RegisteredMaterials)
        {
            material.Dispose();
        }

        foreach(IDisposable key in OwnedKeys)
        {
            key.Dispose();
        }

        RegisteredMaterials.Clear();
        OwnedKeys.Clear();
        PresentationStore.Clear();
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 §8.1</see> requires JSON text to be
    /// "encoded using UTF-8" for interoperable transmission, which
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#content-serialization">VCALM §2.4</see> ("MUST be serialized as
    /// JSON") relies on. A body whose bytes are not valid UTF-8 — a lone <c>0xFF</c> byte inside the
    /// <c>options.challenge</c> string — is data this holder cannot process, refused with HTTP 400 and
    /// <c>https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR</c>, never silently repaired into the Unicode
    /// replacement character and signed as if the client had sent that character.
    /// </summary>
    [TestMethod]
    public async Task CreatePresentationRefusesABodyThatIsNotValidUtf8()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterHolderAsync(app, holder).ConfigureAwait(false);

        string presentationJson = VcalmWireFixtures.SerializeUnproofedPresentation(holder.HolderDid, SerializePresentation);
        byte[] prefixBytes = Encoding.UTF8.GetBytes(
            "{\"presentation\":" + presentationJson + ",\"options\":{\"challenge\":\"c-");
        byte[] suffixBytes = Encoding.UTF8.GetBytes("\",\"domain\":\"verifier.example\"}}");
        byte[] bytes = new byte[prefixBytes.Length + 1 + suffixBytes.Length];
        prefixBytes.CopyTo(bytes, 0);
        bytes[prefixBytes.Length] = 0xFF;
        suffixBytes.CopyTo(bytes, prefixBytes.Length + 1);

        (int statusCode, string body) = await VcalmWireFixtures.SendRawBytesWireAsync(
            app,
            "POST",
            TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmCreatePresentation, segment),
            bytes,
            "application/json",
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        using JsonDocument refused = JsonDocument.Parse(body);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            refused.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "Bytes that are not valid UTF-8 are a malformed-value 400.");
        Assert.IsTrue(PresentationStore.IsEmpty, "The refused request signs and stores nothing.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 §8.1</see>: "JSON text exchanged between
    /// systems that are not part of a closed ecosystem MUST be encoded using UTF-8" (RFC 3629).
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Options</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." A §3.6.3
    /// create-exchange body from an authorized coordinator whose <c>variables</c> carry a byte that is not valid UTF-8 is
    /// refused with HTTP 400, <c>application/json</c> and the malformed-value problem type, and no exchange is created.
    /// </summary>
    [TestMethod]
    public async Task CreateExchangeRefusesABodyThatIsNotValidUtf8()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterTenantAsync(app, WellKnownVcalmCapabilities.VcalmExchange).ConfigureAwait(false);

        //The exchange routes materialize only with the exchange-id resolver wired, and the create route only with its
        //required authorization seam as well; the create route never resolves an exchange id, so the resolver finds none.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmExchangeFlowIdAsync = (_, _, _) => ValueTask.FromResult<string?>(null);
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizeVcalmCoordinatorAsync = VcalmWireFixtures.AuthorizeTestCoordinator;
        }).ConfigureAwait(false);

        byte[] body = ComposeBodyAroundInvalidByte("{\"variables\":{\"note\":\"n-", "\"}}");
        (int statusCode, string? mediaType, string responseBody) = await PostRawAsync(
            app,
            TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmCreateExchange, segment),
            body,
            VcalmWireFixtures.CoordinatorAuthorizationHeader).ConfigureAwait(false);

        AssertRefusedAsMalformedValue(statusCode, mediaType, responseBody);
        Assert.DoesNotContain(entry => entry.State is VcalmExchangePendingState, app.FlowStore.Values,
            "The refused request creates no exchange.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 §8.1</see>: "JSON text exchanged between
    /// systems that are not part of a closed ecosystem MUST be encoded using UTF-8" (RFC 3629).
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Options</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." A §3.7.5
    /// inviteRequest body whose <c>purpose</c> carries a byte that is not valid UTF-8 is refused with HTTP 400,
    /// <c>application/json</c> and the malformed-value problem type, and no invitation is recorded.
    /// </summary>
    [TestMethod]
    public async Task InviteRequestRefusesABodyThatIsNotValidUtf8()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterTenantAsync(app, WellKnownVcalmCapabilities.VcalmCoordinator).ConfigureAwait(false);

        ConcurrentQueue<string> recordedInviteIds = new();
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmInviteRequestAsync = (inviteId, _, _, _) =>
            {
                recordedInviteIds.Enqueue(inviteId);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        string invitePath = TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmInviteRequest, segment)
            + "/8372974/invite-request/response";
        byte[] body = ComposeBodyAroundInvalidByte(
            "{\"url\":\"https://website.example/checkout/8372974\",\"purpose\":\"Checkout at ShopCo ", "\"}");
        (int statusCode, string? mediaType, string responseBody) = await PostRawAsync(
            app, invitePath, body, authorizationHeader: null).ConfigureAwait(false);

        AssertRefusedAsMalformedValue(statusCode, mediaType, responseBody);
        Assert.IsEmpty(recordedInviteIds, "The refused request records no invitation.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 §8.1</see>: "JSON text exchanged between
    /// systems that are not part of a closed ecosystem MUST be encoded using UTF-8" (RFC 3629).
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Options</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." A §3.2.1
    /// issue body whose <c>options.credentialId</c> carries a byte that is not valid UTF-8 is refused with HTTP 400,
    /// <c>application/json</c> and the malformed-value problem type, and no credential is issued or stored.
    /// </summary>
    [TestMethod]
    public async Task IssueCredentialRefusesABodyThatIsNotValidUtf8()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterTenantAsync(app, WellKnownVcalmCapabilities.VcalmIssuer).ConfigureAwait(false);
        string issuerDid = await WireIssuanceAsync(app).ConfigureAwait(false);

        ConcurrentQueue<string> storedCredentialIds = new();
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmIssuedCredentialAsync = (credentialId, _, _, _) =>
            {
                storedCredentialIds.Enqueue(credentialId);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        string credentialJson = SerializeCredential(VcalmWireFixtures.BuildCredential(issuerDid, credentialId: null));
        byte[] body = ComposeBodyAroundInvalidByte(
            "{\"credential\":" + credentialJson + ",\"options\":{\"credentialId\":\"urn:uuid:issued-", "\"}}");
        (int statusCode, string? mediaType, string responseBody) = await PostRawAsync(
            app,
            TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmCredentialsIssue, segment),
            body,
            authorizationHeader: null).ConfigureAwait(false);

        AssertRefusedAsMalformedValue(statusCode, mediaType, responseBody);
        Assert.IsEmpty(storedCredentialIds, "The refused request issues and stores no credential.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 §8.1</see>: "JSON text exchanged between
    /// systems that are not part of a closed ecosystem MUST be encoded using UTF-8" (RFC 3629).
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Options</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." A §C.3
    /// update-status body whose <c>credentialId</c> carries a byte that is not valid UTF-8 is refused with HTTP 400,
    /// <c>application/json</c> and the malformed-value problem type, and no credential status is changed.
    /// </summary>
    [TestMethod]
    public async Task UpdateStatusRefusesABodyThatIsNotValidUtf8()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterTenantAsync(app, WellKnownVcalmCapabilities.VcalmStatus).ConfigureAwait(false);

        ConcurrentQueue<string> updatedCredentialIds = new();
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.UpdateVcalmCredentialStatusAsync = (credentialId, _, _, _, _, _) =>
            {
                updatedCredentialIds.Enqueue(credentialId);

                return ValueTask.FromResult(VcalmStatusUpdateOutcome.Updated);
            };
        }).ConfigureAwait(false);

        byte[] body = ComposeBodyAroundInvalidByte(
            "{\"credentialId\":\"urn:uuid:status-",
            "\",\"credentialStatus\":{\"type\":\"BitstringStatusListEntry\",\"statusPurpose\":\"revocation\","
            + "\"statusListIndex\":\"1\",\"statusListCredential\":\"https://status.example/status-lists/1\"},\"status\":true}");
        (int statusCode, string? mediaType, string responseBody) = await PostRawAsync(
            app,
            TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmCredentialsStatus, segment),
            body,
            authorizationHeader: null).ConfigureAwait(false);

        AssertRefusedAsMalformedValue(statusCode, mediaType, responseBody);
        Assert.IsEmpty(updatedCredentialIds, "The refused request changes no credential status.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 §8.1</see>: "JSON text exchanged between
    /// systems that are not part of a closed ecosystem MUST be encoded using UTF-8" (RFC 3629).
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Options</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." A §3.3.2
    /// verify-presentation body whose <c>options.challenge</c> carries a byte that is not valid UTF-8 is refused with
    /// HTTP 400, <c>application/json</c> and the malformed-value problem type, and no challenge is consumed.
    /// </summary>
    [TestMethod]
    public async Task VerifyPresentationRefusesABodyThatIsNotValidUtf8()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterTenantAsync(app, WellKnownVcalmCapabilities.VcalmVerifier).ConfigureAwait(false);

        ConcurrentQueue<string> consumedChallenges = new();
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ConsumeVcalmChallengeAsync = (challenge, _, _) =>
            {
                consumedChallenges.Enqueue(challenge);

                return ValueTask.FromResult(true);
            };
        }).ConfigureAwait(false);

        string presentationJson = VcalmWireFixtures.SerializeUnproofedPresentation("did:example:encoding-holder", SerializePresentation);
        byte[] body = ComposeBodyAroundInvalidByte(
            "{\"presentation\":" + presentationJson + ",\"options\":{\"challenge\":\"challenge-", "\"}}");
        (int statusCode, string? mediaType, string responseBody) = await PostRawAsync(
            app,
            TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmPresentationsVerify, segment),
            body,
            authorizationHeader: null).ConfigureAwait(false);

        AssertRefusedAsMalformedValue(statusCode, mediaType, responseBody);
        Assert.IsEmpty(consumedChallenges, "The refused request consumes no challenge.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 §8.1</see>: "JSON text exchanged between
    /// systems that are not part of a closed ecosystem MUST be encoded using UTF-8" (RFC 3629).
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM Options</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." A §3.6.1
    /// create-workflow body whose <c>id</c> carries a byte that is not valid UTF-8 is refused with HTTP 400,
    /// <c>application/json</c> and the malformed-value problem type, and no workflow is stored.
    /// </summary>
    [TestMethod]
    public async Task CreateWorkflowRefusesABodyThatIsNotValidUtf8()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterTenantAsync(app, WellKnownVcalmCapabilities.VcalmAdministration).ConfigureAwait(false);

        ConcurrentQueue<string> storedWorkflowIds = new();
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmWorkflowAsync = (workflowId, _, _, _) =>
            {
                storedWorkflowIds.Enqueue(workflowId);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        byte[] body = ComposeBodyAroundInvalidByte(
            "{\"id\":\"urn:uuid:workflow-", "\",\"initialStep\":\"only\",\"steps\":{\"only\":{}}}");
        (int statusCode, string? mediaType, string responseBody) = await PostRawAsync(
            app,
            TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmCreateWorkflow, segment),
            body,
            authorizationHeader: null).ConfigureAwait(false);

        AssertRefusedAsMalformedValue(statusCode, mediaType, responseBody);
        Assert.IsEmpty(storedWorkflowIds, "The refused request stores no workflow.");
    }


    /// <summary>
    /// Registers a tenant holding the one VCALM <paramref name="capability"/> under test and wires the default JSON parse
    /// seams, the host start every VCALM endpoint class performs before its family's own seams.
    /// </summary>
    /// <param name="app">The host shell the tenant is registered with.</param>
    /// <param name="capability">The VCALM capability the tenant is granted.</param>
    /// <returns>The tenant segment.</returns>
    private async Task<string> RegisterTenantAsync(TestHostShell app, CapabilityIdentifier capability)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(
            ClientId, ClientBaseUri, ImmutableHashSet.Create(capability)).ConfigureAwait(false);
        RegisteredMaterials.Add(material);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        return material.Registration.TenantId.Value;
    }


    /// <summary>
    /// Registers a holder tenant with <paramref name="holder"/>'s presentation signing, the §3.4.3.2 channel-domain seam
    /// the §3.5.2 route needs to materialize (answering the domain the create requests bind), and the presentation store.
    /// </summary>
    /// <param name="app">The host shell the tenant is registered with.</param>
    /// <param name="holder">The holder's presentation-signing configuration and DID.</param>
    /// <returns>The tenant segment.</returns>
    private async Task<string> RegisterHolderAsync(TestHostShell app, HolderSigningContext holder)
    {
        string segment = await RegisterTenantAsync(app, WellKnownVcalmCapabilities.VcalmHolder).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmPresentationSigning = holder.Signing;
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmChannelDomainAsync = (_, _) => ValueTask.FromResult<string?>("verifier.example");
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmPresentationAsync = (presentationId, json, _, _) =>
            {
                PresentationStore[presentationId] = new VcalmStoredPresentation
                {
                    PresentationId = presentationId,
                    VerifiablePresentationJson = json
                };

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        return segment;
    }


    /// <summary>
    /// Builds the holder's eddsa-jcs-2022 presentation signing through
    /// <see cref="VcalmWireFixtures.CreateHolderPresentationSigningAsync"/>, its private key tracked for disposal at
    /// cleanup.
    /// </summary>
    /// <returns>The holder's presentation-signing configuration and DID.</returns>
    private async Task<HolderSigningContext> CreateHolderSigningContextAsync()
    {
        (VcalmPresentationSigning signing, string holderDid) = await VcalmWireFixtures.CreateHolderPresentationSigningAsync(
            JcsCanonicalizer,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            Pool,
            OwnedKeys,
            TestContext.CancellationToken).ConfigureAwait(false);

        return new HolderSigningContext(signing, holderDid);
    }


    /// <summary>
    /// Wires the §3.2.1 issuance configuration: one eddsa-jcs-2022 signing descriptor under a did:key issuer, the
    /// configured issuer the issued credentials name. The issuer's private key lives on the configuration for the host's
    /// lifetime and is tracked for disposal at cleanup.
    /// </summary>
    /// <param name="app">The host shell whose VCALM integration is altered.</param>
    /// <returns>The configured issuer DID.</returns>
    private async Task<string> WireIssuanceAsync(TestHostShell app)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            keyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            Pool,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        keyPair.PublicKey.Dispose();
        OwnedKeys.Add(keyPair.PrivateKey);

        string issuerDid = issuerDidDocument.Id!.ToString();
        VcalmProofDescriptor descriptor = new()
        {
            PrivateKey = keyPair.PrivateKey,
            VerificationMethodId = issuerDidDocument.VerificationMethod![0].Id!,
            Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
            Canonicalize = JcsCanonicalizer,
            ContextResolver = null,
            EncodeProofValue = ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential = SerializeCredential,
            DeserializeCredential = DeserializeCredential,
            SerializeProofOptions = SerializeProofOptions,
            Encoder = TestSetup.Base58Encoder,
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync
        };

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialIssuance = new VcalmCredentialIssuance
            {
                ConfiguredIssuer = issuerDid,
                SigningDescriptors = [descriptor],
                ExistingProofHandling = VcalmExistingProofHandling.Error,
                SupportsMandatoryPointers = false,
                MemoryPool = Pool
            };
        }).ConfigureAwait(false);

        return issuerDid;
    }


    /// <summary>
    /// Composes a request body from the UTF-8 encoding of <paramref name="before"/>, the one <see cref="InvalidUtf8Byte"/>
    /// and the UTF-8 encoding of <paramref name="after"/>, so the invalid byte stands inside the JSON string value
    /// <paramref name="before"/> opens and <paramref name="after"/> closes.
    /// </summary>
    /// <param name="before">The body text up to the invalid byte, ending inside an open JSON string.</param>
    /// <param name="after">The body text after the invalid byte, closing that string and the body.</param>
    /// <returns>The body bytes the wire fixture sends as they are.</returns>
    private static byte[] ComposeBodyAroundInvalidByte(string before, string after)
    {
        byte[] beforeBytes = Encoding.UTF8.GetBytes(before);
        byte[] afterBytes = Encoding.UTF8.GetBytes(after);
        byte[] body = new byte[beforeBytes.Length + 1 + afterBytes.Length];
        beforeBytes.CopyTo(body, 0);
        body[beforeBytes.Length] = InvalidUtf8Byte;
        afterBytes.CopyTo(body, beforeBytes.Length + 1);

        return body;
    }


    /// <summary>
    /// POSTs <paramref name="body"/> labelled <see cref="JsonMediaType"/> over the real wire to <paramref name="path"/>
    /// through <see cref="VcalmWireFixtures.SendRawBytesWireAsync(TestHostShell, string, string, byte[], string, string?, CancellationToken)"/>,
    /// bounded by this test's cancellation token.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The raw request body bytes.</param>
    /// <param name="authorizationHeader">The <c>Authorization</c> header value, or <see langword="null"/> to send none.</param>
    /// <returns>The response status code, the media type its <c>Content-Type</c> header names, and its body text.</returns>
    private Task<(int StatusCode, string? MediaType, string Body)> PostRawAsync(
        TestHostShell app, string path, byte[] body, string? authorizationHeader) =>
        VcalmWireFixtures.SendRawBytesWireAsync(
            app, "POST", path, body, JsonMediaType, authorizationHeader, TestContext.CancellationToken);


    /// <summary>
    /// Asserts the refusal of a body that is not valid UTF-8: HTTP 400, an <c>application/json</c> body, and a ProblemDetail
    /// whose <c>type</c> is the literal MALFORMED_VALUE_ERROR URL.
    /// </summary>
    /// <param name="statusCode">The response status code.</param>
    /// <param name="mediaType">The media type the response's <c>Content-Type</c> header names.</param>
    /// <param name="responseBody">The response body text.</param>
    private static void AssertRefusedAsMalformedValue(int statusCode, string? mediaType, string responseBody)
    {
        Assert.AreEqual(400, statusCode, responseBody);
        Assert.AreEqual("application/json", mediaType, responseBody);
        using JsonDocument refused = JsonDocument.Parse(responseBody);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            refused.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "Bytes that are not valid UTF-8 are a malformed-value 400.");
    }


    /// <summary>The holder's §3.5.2 presentation-signing configuration plus the holder DID the presentations claim.</summary>
    /// <param name="Signing">The presentation-signing configuration.</param>
    /// <param name="HolderDid">The holder DID the presentations claim.</param>
    private sealed record HolderSigningContext(VcalmPresentationSigning Signing, string HolderDid);
}
