using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// End-to-end conformance tests for the W3C VCALM 1.0 §3.6 workflows-and-exchanges engine
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) exposed by <see cref="VcalmExchangeEndpoints"/> — the §3.6.3 create-exchange
/// interface, the §1.3 conforming-holder REQUIRED §3.6.4 get-exchange-protocols and §3.6.5
/// participate-in-an-exchange (vcapi) interfaces, and the §3.6.6 get-exchange-state interface, driven
/// through the real dispatch pipeline and the real exchange-instance pushdown automaton.
/// </summary>
/// <remarks>
/// §1.3: "A conforming holder service implementation MUST provide the interface described in Section
/// 3.6.4 Get Exchange Protocols and Section 3.6.5 Participate in an Exchange." The happy-path
/// money-shot exercises the full vcapi exchange: the client POSTs the empty initiating message, the
/// engine answers with a §3.4 verifiable presentation request bound to a fresh challenge / domain, the
/// holder signs a presentation satisfying it (eddsa-jcs-2022 under a did:key the KeyDidResolver
/// resolves locally — the same project crypto the §3.5.2 / §3.3.2 tests use), POSTs it back, the
/// engine VERIFIES it through the §3.3.2 presentation-verify path and replies complete, and the §3.6.6
/// state read shows <c>complete</c> with the presentation in <c>variables.results</c>.
/// </remarks>
[TestClass]
internal sealed class VcalmExchangeEndpointTests
{
    /// <summary>The MSTest context, whose cancellation token bounds every dispatch these tests make.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The host's clock, fixed at the canonical epoch and advanced by the expiry test.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The pool the did:key resolver, the verification configuration and the holder signing rent from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The client identifier the exchange tenant is registered under.</summary>
    private const string ClientId = "https://exchange.client.test";

    /// <summary>The base URI the exchange tenant is registered under.</summary>
    private static Uri ClientBaseUri { get; } = new("https://exchange.client.test");

    /// <summary>The capabilities of a tenant that runs exchanges only.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> ExchangeCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmExchange);

    /// <summary>
    /// The capabilities of a tenant that runs the §3.6.5 round trip: the holder signs the presentation the engine
    /// requested, so the registration also carries the holder capability.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> ExchangeAndHolderCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmExchange, WellKnownVcalmCapabilities.VcalmHolder);

    /// <summary>The serializer options every JSON delegate of these tests uses.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>Builds the holder's did:key document from its public key.</summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    /// <summary>The DID resolver the engine verifies the holder's presentation with: did:key, resolved locally.</summary>
    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    /// <summary>The JCS canonicalizer the eddsa-jcs-2022 signing and verification share.</summary>
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    /// <summary>Serializes a presentation for signing, verification and the wire.</summary>
    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    /// <summary>Reads a presentation back for the holder's presentation signing.</summary>
    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    /// <summary>Serializes a credential for the engine's verification configuration.</summary>
    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    /// <summary>Reads a credential back for tampering a contained credential after it was signed.</summary>
    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    /// <summary>Serializes the proof options a Data Integrity proof hashes.</summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    /// <summary>The context the holder signs its presentation under, outside any request.</summary>
    private static ExchangeContext EmptyContext { get; } = [];

    /// <summary>The tenant registrations of the running test, disposed after it.</summary>
    private List<VerifierKeyMaterial> RegisteredMaterials { get; } = [];

    /// <summary>The holder private keys of the running test, disposed after it.</summary>
    private List<IDisposable> OwnedKeys { get; } = [];

    /// <summary>
    /// The §3.4 query the engine sends when it requests a presentation: a DID Authentication query the holder
    /// satisfies by controlling a did:key. The engine binds the challenge and domain itself.
    /// </summary>
    private const string DidAuthQueryJson =
        "[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{\"method\":\"key\"}]}]";

    /// <summary>The issuer of the unsecured credentials the holder-flow tests hold.</summary>
    private const string HolderFlowIssuer = "did:web:authority.example";

    /// <summary>An issuer that is not <see cref="HolderFlowIssuer"/>.</summary>
    private const string OtherHolderFlowIssuer = "did:web:other.example";

    /// <summary>The specification's own <c>recognizedIn</c> accepted-issuer example, word for word.</summary>
    private const string RecognizedInExampleJson =
        "{\"recognizedIn\": {\"id\": \"https://url.example/list.vc\", \"type\": \"RecognizedEntityCredential\"}}";


    /// <summary>Disposes the tenant registrations and holder keys the finished test created.</summary>
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
    }


    /// <summary>
    /// §3.6.3 create: POST .../exchanges with an empty body → HTTP 201 carrying the exchange id and the
    /// §3.6.6 <c>state:pending</c> with <c>sequence</c> 0.
    /// </summary>
    [TestMethod]
    public async Task CreateExchangeYields201PendingState()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app).ConfigureAwait(false);

        using JsonDocument created = await CreateExchangeAsync(app, segment, "{}").ConfigureAwait(false);
        JsonElement root = created.RootElement;

        Assert.IsTrue(root.TryGetProperty(VcalmParameterNames.Id, out JsonElement idElement),
            "§3.6.3 201 carries the exchange id.");
        Assert.IsFalse(string.IsNullOrEmpty(idElement.GetString()), "The exchange id is non-empty.");
        Assert.AreEqual("pending", root.GetProperty(VcalmParameterNames.State).GetString(),
            "§3.6.6: the exchange state is 'pending' on creation.");
        Assert.AreEqual(0, root.GetProperty(VcalmParameterNames.Sequence).GetInt32(),
            "§3.6.6: sequence is 0 on creation.");
    }


    /// <summary>
    /// §3.6.4 get-exchange-protocols: GET .../exchanges/{id}/protocols → HTTP 200 with a
    /// <c>protocols</c> object carrying the REQUIRED <c>vcapi</c> participation URL.
    /// </summary>
    [TestMethod]
    public async Task GetExchangeProtocolsReturnsVcapiUrl()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmExchangeProtocolsAsync(
            segment, exchangeId, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement protocols = doc.RootElement.GetProperty(VcalmParameterNames.Protocols);
        Assert.IsTrue(protocols.TryGetProperty(VcalmParameterNames.Vcapi, out JsonElement vcapi),
            "§3.6.4: the protocols object carries the vcapi URL.");
        Assert.IsTrue((vcapi.GetString() ?? string.Empty).Contains(exchangeId, StringComparison.Ordinal),
            "The vcapi URL addresses this exchange.");
    }


    /// <summary>
    /// §3.6.4 unknown exchange: GET .../exchanges/{unknown}/protocols → HTTP 404.
    /// </summary>
    [TestMethod]
    public async Task GetProtocolsOfUnknownExchangeYields404()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmExchangeProtocolsAsync(
            segment, "urn:uuid:never-created", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode, "An unknown exchange id is 404.");
    }


    /// <summary>
    /// §3.6.5 vcapi happy path (the money-shot): client POSTs {} → engine replies a
    /// verifiablePresentationRequest (more needed) → holder POSTs a verifiablePresentation satisfying it
    /// with the engine's bound challenge / domain → engine verifies it and replies the empty completion
    /// object; the §3.6.6 state then shows complete with the VP in variables.results, and the sequence
    /// increments across the two POSTs.
    /// </summary>
    [TestMethod]
    public async Task ParticipateHappyPathVerifiesPresentationAndCompletes()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterExchangeAsync(app, holder).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Step 1: client initiates with the empty message; the engine requests a presentation.
        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, initiate.StatusCode, initiate.Body);
        using JsonDocument requestDoc = JsonDocument.Parse(initiate.Body);
        JsonElement vpr = requestDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);

        //§3.6.5: the engine bound a fresh challenge / domain to the request it sent.
        string challenge = vpr.GetProperty(VcalmParameterNames.Challenge).GetString()!;
        string domain = vpr.GetProperty(VcalmParameterNames.Domain).GetString()!;
        Assert.IsFalse(string.IsNullOrEmpty(challenge), "The engine bound a challenge to the request.");
        Assert.IsFalse(string.IsNullOrEmpty(domain), "The engine bound a domain to the request.");

        //§3.6.6 mid-exchange: the state is active with the issued request's step, sequence 1.
        using JsonDocument midState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("active", midState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "After the request is issued the exchange is active.");
        Assert.AreEqual(1, midState.RootElement.GetProperty(VcalmParameterNames.Sequence).GetInt32(),
            "§3.6.6: the sequence increments to 1 after the first vcapi POST.");

        //The holder signs a presentation binding the engine's challenge / domain.
        string securedPresentationJson = await SignPresentationAsync(holder, challenge, domain).ConfigureAwait(false);
        string presentMessage = "{\"verifiablePresentation\":" + securedPresentationJson + "}";

        //Step 2: holder POSTs the presentation; the engine verifies it and completes.
        ServerHttpResponse complete = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, complete.StatusCode, complete.Body);
        using JsonDocument completeDoc = JsonDocument.Parse(complete.Body);
        Assert.IsFalse(completeDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiablePresentationRequest, out _),
            "§3.6: a complete exchange reply carries no further verifiablePresentationRequest.");
        Assert.IsFalse(completeDoc.RootElement.TryGetProperty(VcalmParameterNames.RedirectUrl, out _),
            "§3.6: the empty completion reply carries no redirectUrl.");

        //§3.6.6 final: state complete, sequence 2, with the verified VP under variables.results.
        using JsonDocument finalState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        JsonElement finalRoot = finalState.RootElement;
        Assert.AreEqual("complete", finalRoot.GetProperty(VcalmParameterNames.State).GetString(),
            "§3.6.6: the exchange is complete after the presentation verifies.");
        Assert.AreEqual(2, finalRoot.GetProperty(VcalmParameterNames.Sequence).GetInt32(),
            "§3.6.6: the sequence increments to 2 across the two vcapi POSTs.");

        JsonElement results = finalRoot.GetProperty(VcalmParameterNames.Variables).GetProperty(VcalmParameterNames.Results);
        int resultCount = results.EnumerateObject().Count();
        Assert.AreEqual(1, resultCount,
            "§3.6.6: the verified presentation is recorded under one step in variables.results.");
        foreach(JsonProperty step in results.EnumerateObject())
        {
            Assert.IsTrue(step.Value.TryGetProperty(VcalmParameterNames.VerifiablePresentation, out _),
                "§3.6.6: the step result carries the verified verifiablePresentation.");
        }
    }


    /// <summary>
    /// §3.6.5 active re-poll on an exchange the explicit step-decision seam decides: after the engine issues a
    /// presentation request, a non-presentation re-poll RE-SENDS the SAME request — the EXISTING bound challenge,
    /// never a freshly minted one — and a presentation the holder binds to the re-polled challenge still verifies and
    /// completes. A challenge minted afresh on a re-poll would desync the binding the holder is already answering, so
    /// an active exchange never consults the step seam again for a re-poll.
    /// </summary>
    [TestMethod]
    public async Task ParticipateActiveRepollResendsSameChallengeAndStillVerifies()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterExchangeAsync(app, holder).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Step 1: initiate — the engine requests a presentation and binds a challenge.
        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", [], TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument initiateDoc = JsonDocument.Parse(initiate.Body);
        JsonElement firstVpr = initiateDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);
        string firstChallenge = firstVpr.GetProperty(VcalmParameterNames.Challenge).GetString()!;
        string domain = firstVpr.GetProperty(VcalmParameterNames.Domain).GetString()!;

        //Step 2: re-poll with another empty body — the engine RE-SENDS the same active request.
        ServerHttpResponse repoll = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, repoll.StatusCode, repoll.Body);
        using JsonDocument repollDoc = JsonDocument.Parse(repoll.Body);
        JsonElement repollVpr = repollDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);
        string repollChallenge = repollVpr.GetProperty(VcalmParameterNames.Challenge).GetString()!;

        Assert.AreEqual(firstChallenge, repollChallenge,
            "§3.6.5 re-poll must re-send the EXISTING bound challenge, never mint a fresh one that desyncs the binding.");

        //The exchange is still active after the re-poll (no state change, no re-bind).
        using JsonDocument midState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("active", midState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "A re-poll leaves the exchange active with its binding intact.");

        //Step 3: the holder answers the re-polled challenge; it still verifies and completes.
        string securedPresentationJson = await SignPresentationAsync(holder, repollChallenge, domain).ConfigureAwait(false);
        string presentMessage = "{\"verifiablePresentation\":" + securedPresentationJson + "}";

        ServerHttpResponse complete = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage, [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, complete.StatusCode, complete.Body);
        using JsonDocument completeDoc = JsonDocument.Parse(complete.Body);
        Assert.IsFalse(completeDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiablePresentationRequest, out _),
            "After the re-polled presentation verifies the exchange completes with no further request.");

        using JsonDocument finalState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("complete", finalState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "§3.6.6: the exchange completes after the re-polled presentation verifies.");
    }


    /// <summary>
    /// §3.6.5 failed verification: the holder POSTs a presentation bound to a DIFFERENT challenge than
    /// the engine requested → the engine cannot verify it → HTTP 4xx + ProblemDetails carrying Data
    /// Integrity's own challenge-mismatch type, and the §3.6.6 state goes to invalid with a lastError.
    /// </summary>
    [TestMethod]
    public async Task ParticipateWithUnverifiablePresentationYields4xxAndInvalidState()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterExchangeAsync(app, holder).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", [], TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument requestDoc = JsonDocument.Parse(initiate.Body);
        JsonElement vpr = requestDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);
        string domain = vpr.GetProperty(VcalmParameterNames.Domain).GetString()!;

        //Sign the presentation with the WRONG challenge — the proof will not verify against the bound one.
        string securedPresentationJson = await SignPresentationAsync(holder, "not-the-bound-challenge", domain).ConfigureAwait(false);
        string presentMessage = "{\"verifiablePresentation\":" + securedPresentationJson + "}";

        ServerHttpResponse rejected = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, rejected.StatusCode, rejected.Body);
        using JsonDocument problem = JsonDocument.Parse(rejected.Body);
        Assert.AreEqual("https://w3id.org/security#INVALID_CHALLENGE_ERROR",
            problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "§3.6 / §3.8: an unverifiable presentation is refused with the failed check's own problem type; a "
            + "wrong-challenge proof fails Data Integrity's own challenge check, not a signature check.");

        using JsonDocument invalidState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("invalid", invalidState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "§3.6.6: a rejected presentation drives the exchange to invalid.");
        Assert.IsTrue(invalidState.RootElement.TryGetProperty(VcalmParameterNames.LastError, out _),
            "§3.6.6: an invalid exchange carries a lastError ProblemDetail.");
    }


    /// <summary>
    /// "Verifying each contained verifiable credential's proof, status, and validity period(s)" applies
    /// to a presentation an exchange verifies too, through the same
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verify-presentation">VCALM §3.3.2</see> composition
    /// its <see href="https://www.w3.org/TR/vcalm-1.0/#participate-in-an-exchange">§3.6 participate</see>
    /// step calls: a contained credential the presentation's own proof does not cover independently — an
    /// issuer-signed credential altered after it was signed, or an enveloped credential this verifier
    /// cannot dispatch — refuses the exchange with the failed check's OWN problem type (a
    /// cryptographic-security error only for the altered credential's failed signature; an
    /// unsupported-securing-mechanism error for the envelope), never the presentation-proof-only
    /// refusal a validly-signed outer envelope would otherwise pass. Driven over the real HTTPS wire
    /// through <see cref="VcalmWireFixtures"/>, so the request crosses the same transport and body
    /// handling a deployed endpoint does.
    /// </summary>
    [TestMethod]
    public async Task ParticipateWithUnverifiedContainedCredentialIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterExchangeAsync(app, holder).ConfigureAwait(false);

        //A contained credential validly issued, then altered after signing: its own proof no longer
        //matches its content, even though the outer presentation — signed AFTER the alteration — verifies.
        DataIntegritySecuredCredential signedCredential = await SignContainedCredentialAsync().ConfigureAwait(false);
        JsonObject credentialNode = JsonNode.Parse(SerializeCredential(signedCredential))!.AsObject();
        credentialNode["credentialSubject"]!["id"] = "did:example:vcalm-exchange-attacker-subject";
        DataIntegritySecuredCredential tamperedCredential =
            (DataIntegritySecuredCredential)DeserializeCredential(credentialNode.ToJsonString());

        string tamperedExchangeId = await CreateExchangeAndGetIdOverWireAsync(app, segment).ConfigureAwait(false);
        using JsonDocument tamperedInitiate = await VcalmWireFixtures.PostExchangeWireAsync(
            app, segment, tamperedExchangeId, "{}", 200, TestContext.CancellationToken).ConfigureAwait(false);
        JsonElement tamperedVpr = tamperedInitiate.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);
        string tamperedChallenge = tamperedVpr.GetProperty(VcalmParameterNames.Challenge).GetString()!;
        string tamperedDomain = tamperedVpr.GetProperty(VcalmParameterNames.Domain).GetString()!;

        string tamperedPresentationJson = await SignPresentationAsync(
            holder, tamperedChallenge, tamperedDomain, containedCredentials: [tamperedCredential]).ConfigureAwait(false);
        using JsonDocument tamperedRejection = await VcalmWireFixtures.PostExchangeWireAsync(
            app, segment, tamperedExchangeId, "{\"verifiablePresentation\":" + tamperedPresentationJson + "}", 400,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR",
            tamperedRejection.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "A contained credential altered after signing fails its own signature check.");

        using JsonDocument tamperedState = await VcalmWireFixtures.GetExchangeWireAsync(
            app, segment, tamperedExchangeId, 200, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual("invalid", tamperedState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "A presentation refused for a contained credential's failure drives the exchange to invalid.");
        Assert.IsTrue(tamperedState.RootElement.TryGetProperty(VcalmParameterNames.LastError, out _),
            "An invalid exchange carries a lastError ProblemDetail naming the failed check.");

        //A contained enveloped credential: this verifier dispatches no envelope verifier for it.
        string envelopeExchangeId = await CreateExchangeAndGetIdOverWireAsync(app, segment).ConfigureAwait(false);
        using JsonDocument envelopeInitiate = await VcalmWireFixtures.PostExchangeWireAsync(
            app, segment, envelopeExchangeId, "{}", 200, TestContext.CancellationToken).ConfigureAwait(false);
        JsonElement envelopeVpr = envelopeInitiate.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);
        string envelopeChallenge = envelopeVpr.GetProperty(VcalmParameterNames.Challenge).GetString()!;
        string envelopeDomain = envelopeVpr.GetProperty(VcalmParameterNames.Domain).GetString()!;

        string envelopePresentationJson = await SignPresentationAsync(
            holder, envelopeChallenge, envelopeDomain,
            envelopedCredentials:
            [
                new EnvelopedVerifiableCredential
                {
                    Context = Context.FromIris(Context.Credentials20),
                    Id = "data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.e30.c2ln",
                    Type = [CredentialConstants.EnvelopedVerifiableCredentialType]
                }
            ]).ConfigureAwait(false);
        using JsonDocument envelopeRejection = await VcalmWireFixtures.PostExchangeWireAsync(
            app, segment, envelopeExchangeId, "{\"verifiablePresentation\":" + envelopePresentationJson + "}", 400,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual("https://verifiable.lumoin.com/problems#UNSUPPORTED_SECURING_MECHANISM",
            envelopeRejection.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "A contained enveloped credential has no envelope verifier dispatched for it.");

        using JsonDocument envelopeState = await VcalmWireFixtures.GetExchangeWireAsync(
            app, segment, envelopeExchangeId, 200, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual("invalid", envelopeState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "A presentation refused for a contained credential's failure drives the exchange to invalid.");
    }


    /// <summary>
    /// §3.6 anti-replay binding: a verifiablePresentation POSTed as the FIRST message — before the
    /// engine has issued a presentation request, while the exchange is still pending with no bound
    /// challenge — is REFUSED, not accepted. The engine never completes on an unsolicited, unverified
    /// presentation even though the deployment's step seam would accept a presentation; the library
    /// fails closed regardless of the step logic.
    /// </summary>
    [TestMethod]
    public async Task ParticipateWithUnsolicitedPresentationInPendingStateIsRefusedAndDoesNotComplete()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterExchangeAsync(app, holder).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //A structurally valid, signed presentation presented as the very first message — the exchange
        //is pending, so no anti-replay challenge has been bound for it to be verified against.
        string securedPresentationJson = await SignPresentationAsync(holder, "unsolicited-challenge", "verifier.example").ConfigureAwait(false);
        string presentMessage = "{\"verifiablePresentation\":" + securedPresentationJson + "}";

        ServerHttpResponse refused = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        using JsonDocument problem = JsonDocument.Parse(refused.Body);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR",
            problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "§3.6: a presentation arriving with no bound anti-replay challenge is refused as a cryptographic-security error.");

        //The exchange MUST NOT have completed on the unverified presentation — it stays pending so the
        //proper request → present flow can still proceed.
        using JsonDocument state = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("pending", state.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "The engine never completes on an unsolicited, unverified presentation.");
    }


    /// <summary>
    /// §3.6.6 unknown exchange: GET .../exchanges/{unknown} → HTTP 404.
    /// </summary>
    [TestMethod]
    public async Task GetStateOfUnknownExchangeYields404()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmExchangeByIdAsync(
            segment, "GET", "urn:uuid:never-created", jsonBody: null, [], TestContext.CancellationToken,
            VcalmWireFixtures.CoordinatorAuthorizationHeaders).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode, "An unknown exchange id is 404.");
    }


    /// <summary>
    /// §3.6 unknown vcapi member: a participate POST carrying a custom property the engine does not
    /// recognize → HTTP 400 (§3.6: "Custom properties and values … are expected to trigger errors in
    /// implementations that do not recognize them").
    /// </summary>
    [TestMethod]
    public async Task ParticipateWithUnknownMemberYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{\"notARealProperty\":true}", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§3.6: an unrecognized custom vcapi property triggers an error.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>: "Each object in the array MUST contain a property called method with a value that
    /// is a DID Method name", the DID syntax rules being "method-name = 1*method-char" and "method-char =
    /// %x61-7A / DIGIT" (<see href="https://www.w3.org/TR/did-core/#did-syntax">DID Core 1.0 §3.1</see>).
    /// A participate message whose verifiable presentation request carries an <c>acceptedMethods</c>
    /// value of another shape, or a <c>method</c> that is not a DID method name, is refused over the real
    /// HTTPS wire as <see cref="AssertParticipateRefusesRequestAsync"/> states, and the exchange is left
    /// exactly as it was.
    /// </summary>
    /// <param name="acceptedMethodsJson">The <c>acceptedMethods</c> member value.</param>
    [TestMethod]
    [DataRow("[{}]")]
    [DataRow("[{\"method\":7}]")]
    [DataRow("\"key\"")]
    [DataRow("[{\"method\":\"did:key\"}]")]
    [DataRow("[{\"method\":\"KEY\"}]")]
    [DataRow("[{\"method\":\"k-y\"}]")]
    public async Task ParticipateWithMalformedAcceptedMethodYields400(string acceptedMethodsJson)
    {
        await AssertParticipateRefusesRequestAsync(
            "{\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":" + acceptedMethodsJson + "}]}").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#the-did-authentication-query-format">VCALM
    /// §3.4.3.1</see>: <c>acceptedCryptosuites</c> is "An optional array of objects" and "Each object in
    /// the array MUST contain a property called cryptosuite with a value that is a Data Integrity
    /// cryptosuite name (or Ed25519Signature2020 for legacy)". A participate message whose DID
    /// Authentication query carries an element that is not such an object is refused over the real
    /// HTTPS wire as <see cref="AssertParticipateRefusesRequestAsync"/> states.
    /// </summary>
    /// <param name="acceptedCryptosuitesJson">The <c>acceptedCryptosuites</c> member value.</param>
    [TestMethod]
    [DataRow("[{}]")]
    [DataRow("[\"ecdsa-rdfc-2019\"]")]
    public async Task ParticipateWithMalformedDidAuthenticationCryptosuiteYields400(string acceptedCryptosuitesJson)
    {
        await AssertParticipateRefusesRequestAsync(
            "{\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedCryptosuites\":" + acceptedCryptosuitesJson + "}]}").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedIssuers</c> is "An OPTIONAL array of items, or lists that contain items", and "Each
    /// item MUST be either 1) a [URL] that identifies an issuer in the issuer property of the received
    /// verifiable credential, or 2) an object that contains an id property whose value is a [URL] that
    /// identifies an issuer in the issuer property of the received verifiable credential, or 3) an
    /// object that contains a recognizedIn property that is associated with an object with a type
    /// property that is set to RecognizedEntityCredential and an id property with a [URL] value", [URL]
    /// being the <see href="https://url.spec.whatwg.org/#url-writing">URL Standard</see>, under which
    /// "A valid URL string defines what input would not trigger a validation error or failure when
    /// parsed by the URL parser", and whose URL code points outside ASCII are "code points in the range
    /// U+00A0 to U+10FFFD, inclusive, excluding surrogates and noncharacters". A participate message whose
    /// Query By Example carries an item of none of the three shapes, a URL the URL Standard refuses in any
    /// of the three forms (a C1 control code point below U+00A0 among them), or the type name
    /// <c>VerifiableRecognitionCredential</c> is refused over the real HTTPS wire as
    /// <see cref="AssertParticipateRefusesRequestAsync"/> states.
    /// </summary>
    /// <param name="acceptedIssuersJson">The <c>acceptedIssuers</c> member value.</param>
    [TestMethod]
    [DataRow("[{}]")]
    [DataRow("\"did:web:authority.example\"")]
    [DataRow("[[]]")]
    [DataRow("[\"https://test.42/\"]")]
    [DataRow("[{\"id\": \"https://test.42/\"}]")]
    [DataRow("[{\"recognizedIn\": {\"id\": \"https://test.42/\", \"type\": \"RecognizedEntityCredential\"}}]")]
    [DataRow("[{\"recognizedIn\": {\"id\": \"https://url.example/list.vc\", \"type\": \"VerifiableRecognitionCredential\"}}]")]
    [DataRow("[\"https://a.example/a\\u0085b\"]")]
    public async Task ParticipateWithMalformedAcceptedIssuerYields400(string acceptedIssuersJson)
    {
        await AssertParticipateRefusesRequestAsync(QueryByExampleRequestJson("acceptedIssuers", acceptedIssuersJson)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedCryptosuites</c> is "An OPTIONAL array specifying which cryptographic proof suites the
    /// verifier will accept. Each element SHOULD be an object with a cryptosuite property referencing a
    /// Data Integrity cryptosuite name or Ed25519Signature2020 for legacy (for backwards compatibility,
    /// string values MAY also be used and are to be interpreted as the cryptosuite name)". A participate
    /// message whose Query By Example carries a value that is not an array, or an element that names no
    /// cryptosuite, is refused over the real HTTPS wire as
    /// <see cref="AssertParticipateRefusesRequestAsync"/> states.
    /// </summary>
    /// <param name="acceptedCryptosuitesJson">The <c>acceptedCryptosuites</c> member value.</param>
    [TestMethod]
    [DataRow("[{}]")]
    [DataRow("[\"\"]")]
    [DataRow("\"eddsa-rdfc-2022\"")]
    public async Task ParticipateWithMalformedQueryByExampleCryptosuiteYields400(string acceptedCryptosuitesJson)
    {
        await AssertParticipateRefusesRequestAsync(QueryByExampleRequestJson("acceptedCryptosuites", acceptedCryptosuitesJson)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedEnvelopes</c> is "An OPTIONAL array specifying which envelope formats the verifier will
    /// accept. Each element SHOULD be an object with a mediaType property referencing the media type for
    /// the envelope (for backwards compatibility, string values MAY also be used and are to be
    /// interpreted as the media type)". A participate message whose Query By Example carries an element
    /// that names no media type is refused over the real HTTPS wire as
    /// <see cref="AssertParticipateRefusesRequestAsync"/> states.
    /// </summary>
    /// <param name="acceptedEnvelopesJson">The <c>acceptedEnvelopes</c> member value.</param>
    [TestMethod]
    [DataRow("[{}]")]
    [DataRow("[{\"mediaType\": \"\"}]")]
    public async Task ParticipateWithMalformedAcceptedEnvelopeYields400(string acceptedEnvelopesJson)
    {
        await AssertParticipateRefusesRequestAsync(QueryByExampleRequestJson("acceptedEnvelopes", acceptedEnvelopesJson)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: <c>example</c>
    /// is "An OPTIONAL object that provides an example of the credential being requested, including its
    /// @context, type, and optionally credentialSubject fields to indicate which claims are needed". A
    /// participate message whose Query By Example carries an example that is not an object, or whose
    /// <c>type</c> or <c>credentialSubject</c> is of another shape, is refused over the real HTTPS wire as
    /// <see cref="AssertParticipateRefusesRequestAsync"/> states; read as absent it would ask for any
    /// credential at all.
    /// </summary>
    /// <param name="exampleJson">The <c>example</c> member value.</param>
    [TestMethod]
    [DataRow("42")]
    [DataRow("[]")]
    [DataRow("{\"type\": 7}")]
    [DataRow("{\"credentialSubject\": \"Alumni\"}")]
    public async Task ParticipateWithMalformedExampleYields400(string exampleJson)
    {
        await AssertParticipateRefusesRequestAsync(QueryByExampleRequestJson("example", exampleJson)).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: "Multiple
    /// queries with the same group value are processed as "AND" operations, while queries with different
    /// or missing group values are processed as "OR" operations." A participate message whose query
    /// entry carries a <c>group</c> that is not a string is refused over the real HTTPS wire as
    /// <see cref="AssertParticipateRefusesRequestAsync"/> states, never read as a missing group that
    /// would turn the verifier's AND into an OR.
    /// </summary>
    /// <param name="groupJson">The <c>group</c> member value.</param>
    [TestMethod]
    [DataRow("1")]
    [DataRow("null")]
    public async Task ParticipateWithNonStringGroupYields400(string groupJson)
    {
        await AssertParticipateRefusesRequestAsync(
            "{\"query\":[{\"type\":\"QueryByExample\",\"group\":" + groupJson + ",\"credentialQuery\":{\"example\":{\"type\":\"ExampleAlumniCredential\"}}},"
            + "{\"type\":\"QueryByExample\",\"group\":" + groupJson + ",\"credentialQuery\":{\"example\":{\"type\":\"MembershipCredential\"}}}]}")
            .ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM §3.4.1</see>:
    /// <c>domain</c> is "An OPTIONAL string that a verifier provides to a holder during a presentation
    /// request". A participate message whose verifiable presentation request carries a <c>domain</c> that
    /// is not a string is refused over the real HTTPS wire as
    /// <see cref="AssertParticipateRefusesRequestAsync"/> states.
    /// </summary>
    [TestMethod]
    public async Task ParticipateWithNonStringDomainYields400()
    {
        await AssertParticipateRefusesRequestAsync(
            "{\"query\":[{\"type\":\"DIDAuthentication\"}],\"domain\":[\"reunion.example\"]}").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verifiable-presentation-request">VCALM §3.4.1</see>:
    /// <c>challenge</c> is "An OPTIONAL, unique string that is provided by a verifier to a holder during a
    /// specific presentation request". A participate message whose verifiable presentation request carries
    /// a <c>challenge</c> that is not a string is refused over the real HTTPS wire as
    /// <see cref="AssertParticipateRefusesRequestAsync"/> states.
    /// </summary>
    [TestMethod]
    public async Task ParticipateWithNonStringChallengeYields400()
    {
        await AssertParticipateRefusesRequestAsync(
            "{\"query\":[{\"type\":\"DIDAuthentication\"}],\"challenge\":42}").ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: <c>reason</c> is
    /// "An OPTIONAL string that provides a human-readable explanation for why the credential is being
    /// requested". A participate message whose Query By Example carries a <c>reason</c> that is not a
    /// string is refused over the real HTTPS wire as <see cref="AssertParticipateRefusesRequestAsync"/>
    /// states.
    /// </summary>
    [TestMethod]
    public async Task ParticipateWithNonStringReasonYields400()
    {
        await AssertParticipateRefusesRequestAsync(QueryByExampleRequestJson("reason", "{\"text\":\"alumni\"}")).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw
    /// an error if an endpoint receives data, options, or option values that it does not understand or
    /// know how to process." A member name repeated inside one object of the verifiable presentation
    /// request, whichever occurrence is malformed or narrower, is refused over the real HTTPS wire as
    /// <see cref="AssertParticipateRefusesRequestAsync"/> states, never resolved to one occurrence that
    /// leaves an acceptance constraint empty or drops a malformed one.
    /// </summary>
    /// <param name="presentationRequestJson">The verifiable presentation request JSON text.</param>
    [TestMethod]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedIssuers\":42,\"acceptedIssuers\":[]}}]}")]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedIssuers\":[\"https://a.example\"],\"acceptedIssuers\":[]}}]}")]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedCryptosuites\":[{}],\"acceptedCryptosuites\":[]}}]}")]
    [DataRow("{\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{}],\"acceptedMethods\":[]}]}")]
    [DataRow("{\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":7,\"acceptedMethods\":[{\"method\":\"key\"}]}]}")]
    [DataRow("{\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{\"method\":7,\"method\":\"key\"}]}]}")]
    [DataRow("{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedIssuers\":[\"https://a.example\"]},\"credentialQuery\":{}}]}")]
    public async Task ParticipateWithRepeatedRequestMemberYields400(string presentationRequestJson)
    {
        await AssertParticipateRefusesRequestAsync(presentationRequestJson).ConfigureAwait(false);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedCryptosuites</c> specifies "which cryptographic proof suites the verifier will accept".
    /// A holder that receives the verifier's Query By Example over the real HTTPS wire and parses it
    /// selects, of a credential secured with an accepted cryptosuite and an unsecured credential that
    /// matches the query otherwise, only the secured one.
    /// </summary>
    [TestMethod]
    public async Task HolderFlowAcceptedCryptosuitesSelectCredentialSecuredWithAcceptedSuite()
    {
        VerifiablePresentationRequest request = await ReceivePresentationRequestOverWireAsync(
            "[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedCryptosuites\":[{\"cryptosuite\":\"eddsa-jcs-2022\"}]}}]")
            .ConfigureAwait(false);
        DataIntegritySecuredCredential secured = await SignContainedCredentialAsync().ConfigureAwait(false);
        VerifiableCredential unsecured = VcalmWireFixtures.BuildCredential(HolderFlowIssuer, credentialId: null);

        VprEvaluationResult result = VprEvaluator.Evaluate(request, [unsecured, secured]);

        VprQueryMatch match = result.Groups[0].QueryMatches[0];
        Assert.HasCount(1, match.Matches, "Only a credential secured with an accepted cryptosuite is selected.");
        Assert.AreSame(secured, match.Matches[0].Credential);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedCryptosuites</c> specifies "which cryptographic proof suites the verifier will accept".
    /// A holder that receives a Query By Example accepting only <c>bbs-2023</c> over the real HTTPS wire,
    /// and holds an unsecured credential and one secured with another cryptosuite, cannot satisfy it.
    /// </summary>
    [TestMethod]
    public async Task HolderFlowAcceptedCryptosuitesRefuseCredentialOfOtherSuite()
    {
        VerifiablePresentationRequest request = await ReceivePresentationRequestOverWireAsync(
            "[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedCryptosuites\":[{\"cryptosuite\":\"bbs-2023\"}]}}]")
            .ConfigureAwait(false);
        DataIntegritySecuredCredential secured = await SignContainedCredentialAsync().ConfigureAwait(false);
        VerifiableCredential unsecured = VcalmWireFixtures.BuildCredential(HolderFlowIssuer, credentialId: null);

        Assert.IsFalse(VprEvaluator.Evaluate(request, [unsecured, secured]).IsSatisfiable,
            "No held credential is secured with a cryptosuite the verifier will accept.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedEnvelopes</c> specifies "which envelope formats the verifier will accept". A holder that
    /// receives a Query By Example accepting only the <c>application/jwt</c> envelope over the real HTTPS
    /// wire cannot satisfy it with an unsecured credential, which is secured by no envelope at all.
    /// </summary>
    [TestMethod]
    public async Task HolderFlowAcceptedEnvelopesRefuseUnsecuredCredential()
    {
        VerifiablePresentationRequest request = await ReceivePresentationRequestOverWireAsync(
            "[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"acceptedEnvelopes\":[{\"mediaType\":\"application/jwt\"}]}}]")
            .ConfigureAwait(false);
        VerifiableCredential unsecured = VcalmWireFixtures.BuildCredential(HolderFlowIssuer, credentialId: null);

        Assert.IsFalse(VprEvaluator.Evaluate(request, [unsecured]).IsSatisfiable,
            "An unsecured credential is in no envelope format the verifier will accept.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: a
    /// <c>recognizedIn</c> item points to a <c>RecognizedEntityCredential</c> and "the list contains
    /// recognized issuers that are acceptable to the verifier". A holder that receives the
    /// specification's own <c>recognizedIn</c> example as the only accepted-issuer item over the real
    /// HTTPS wire, and has not retrieved and verified that list, accepts no issuer from it.
    /// </summary>
    [TestMethod]
    public async Task HolderFlowRecognizedInWithoutRetrievedListAcceptsNoIssuer()
    {
        VerifiablePresentationRequest request = await ReceivePresentationRequestOverWireAsync(
            QueryByExampleWithIssuersQueryJson(RecognizedInExampleJson)).ConfigureAwait(false);
        VerifiableCredential credential = VcalmWireFixtures.BuildCredential(HolderFlowIssuer, credentialId: null);

        Assert.IsFalse(VprEvaluator.Evaluate(request, [credential]).IsSatisfiable,
            "A list the holder has not retrieved names no issuer.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>: "the list
    /// contains recognized issuers that are acceptable to the verifier". A holder that receives a
    /// <c>recognizedIn</c>-only Query By Example over the real HTTPS wire, and whose retrieved and
    /// verified list names another issuer, cannot satisfy it with a credential from an issuer off the
    /// list.
    /// </summary>
    [TestMethod]
    public async Task HolderFlowRecognizedInRefusesIssuerOffTheRetrievedList()
    {
        VerifiablePresentationRequest received = await ReceivePresentationRequestOverWireAsync(
            QueryByExampleWithIssuersQueryJson(RecognizedInExampleJson)).ConfigureAwait(false);
        VerifiablePresentationRequest request = WithRecognizedIssuers(received, OtherHolderFlowIssuer);
        VerifiableCredential credential = VcalmWireFixtures.BuildCredential(HolderFlowIssuer, credentialId: null);

        Assert.IsFalse(VprEvaluator.Evaluate(request, [credential]).IsSatisfiable,
            "An issuer absent from the retrieved list is not accepted.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#query-by-example">VCALM §3.4.2</see>:
    /// <c>acceptedIssuers</c> identifies "entities that the verifier recognizes and accepts as issuers",
    /// and for a <c>recognizedIn</c> item "the list contains recognized issuers that are acceptable to the
    /// verifier". A holder that receives, over the real HTTPS wire, a direct item naming another issuer
    /// beside the specification's <c>recognizedIn</c> example, and whose retrieved list names the
    /// credential's issuer, satisfies the query with that credential.
    /// </summary>
    [TestMethod]
    public async Task HolderFlowRecognizedInAcceptsListedIssuerBesideUnmatchedDirectItem()
    {
        VerifiablePresentationRequest received = await ReceivePresentationRequestOverWireAsync(
            QueryByExampleWithIssuersQueryJson("{\"id\":\"" + OtherHolderFlowIssuer + "\"}," + RecognizedInExampleJson)).ConfigureAwait(false);
        VerifiablePresentationRequest request = WithRecognizedIssuers(received, HolderFlowIssuer);
        VerifiableCredential credential = VcalmWireFixtures.BuildCredential(HolderFlowIssuer, credentialId: null);

        Assert.IsTrue(VprEvaluator.Evaluate(request, [credential]).IsSatisfiable,
            "Any accepted-issuer item that names the issuer accepts it.");
    }


    /// <summary>
    /// §2.4 content-serialization MUST: a §3.6.3 create with a non-application/json Content-Type is
    /// rejected with HTTP 400 before parsing.
    /// </summary>
    [TestMethod]
    public async Task CreateExchangeWithNonJsonContentTypeYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app).ConfigureAwait(false);

        byte[] bytes = Encoding.UTF8.GetBytes("{}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateExchange, "POST",
            bytes, "text/plain", [], TestContext.CancellationToken,
            VcalmWireFixtures.CoordinatorAuthorizationHeaders).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "A non-application/json body is rejected before parsing (§2.4 content-serialization MUST).");
    }


    /// <summary>
    /// An expired exchange: a participate POST after the exchange's <c>expires</c> instant is rejected
    /// — the dispatcher's flow-expiry gate refuses the continuing flow (§3.6.2: a challenge bound to an
    /// exchange ceases to be valid at the expires date).
    /// </summary>
    [TestMethod]
    public async Task ParticipateAfterExpiryIsRejected()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app).ConfigureAwait(false);

        //Create an exchange that expires one minute from now.
        string expires = TimeProvider.GetUtcNow().AddMinutes(1).ToString("o");
        string createBody = "{\"expires\":\"" + expires + "\"}";
        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment, createBody).ConfigureAwait(false);

        //Advance past the expiry, then attempt to participate.
        TimeProvider.Advance(TimeSpan.FromMinutes(2));

        ServerHttpResponse response = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "A participate POST after the exchange expires is rejected by the flow-expiry gate.");
    }


    /// <summary>
    /// §3.6.5 participate route: a whitespace-only exchange id in the path — decoded by
    /// <c>ExtractExchangeId</c> from a percent-escaped space — is a present value under
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>'s presence
    /// rule ("Parameters sent without a value MUST be treated as if they were omitted"; whitespace is a
    /// value, not the empty string). It is refused before any flow-state load or save, never carried
    /// into flow-id validation. Driven over the real transport
    /// (<see cref="VcalmWireFixtures.SendWireAsync"/>) so Kestrel's own decoding of the percent-escaped
    /// path segment into a space is what this test observes, and the literal refusal body is asserted,
    /// not only its status.
    /// </summary>
    [TestMethod]
    public async Task ParticipateWithBlankExchangeIdIsRefusedBeforeAnyStoreCall()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app).ConfigureAwait(false);

        int loadCount = 0;
        int saveCount = 0;
        LoadServerFlowStateDelegate originalLoad = app.Server.Integration.LoadFlowStateAsync!;
        SaveServerFlowStateDelegate originalSave = app.Server.Integration.SaveFlowStateAsync!;

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
            {
                _ = Interlocked.Increment(ref loadCount);

                return await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
            };

            candidateIntegration.SaveFlowStateAsync = async (tenantId, key, state, stepCount, ctx, ct) =>
            {
                _ = Interlocked.Increment(ref saveCount);
                await originalSave(tenantId, key, state, stepCount, ctx, ct).ConfigureAwait(false);
            };
        }).ConfigureAwait(false);

        //The raw path segment is the percent-escaped space; ExtractExchangeId Uri.UnescapeDataString's
        //it back to a whitespace-only value, exercising the same site VcalmExchangeEndpoints shares
        //with EndpointServer's blank-handle refusal.
        string collectionPath = TestHostShell.ComposeEndpointPath(
            WellKnownVcalmEndpointNames.VcalmParticipateInExchange, segment);

        (int statusCode, _, string body) = await VcalmWireFixtures.SendWireAsync(
            app, "POST", $"{collectionPath}/%20", "{}", authorizationHeader: null, TestContext.CancellationToken)
            .ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.LoadFlowStateAsync = originalLoad;
            candidateIntegration.SaveFlowStateAsync = originalSave;
        }).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "A whitespace-only exchange id is a present, unresolvable value; refused, not carried into flow-id validation.");
        Assert.Contains($"\"error\":\"{ServerErrors.InvalidRequest}\"", body, StringComparison.Ordinal, body);
        Assert.Contains("\"error_description\":\"Flow not found or expired.\"", body, StringComparison.Ordinal, body);
        Assert.AreEqual(0, loadCount, "A blank exchange id is refused before any flow-state load.");
        Assert.AreEqual(0, saveCount, "A blank exchange id is refused before any flow-state save.");
    }


    /// <summary>
    /// The same route as <see cref="ParticipateWithBlankExchangeIdIsRefusedBeforeAnyStoreCall"/>, with
    /// the correlation resolver <c>EndpointServer.HandleCoreAsync</c> reads for every flow kind —
    /// <see cref="ServerIntegration.ResolveCorrelationKeyAsync"/> on the host's primary integration,
    /// the same seam the exchange id normally resolves through
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/">VCALM 1.0</see> §3.6.5) — cleared entirely, a
    /// configuration this class's other tests never exercise. The refusal per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.1">RFC 6749 §3.1</see>'s presence
    /// rule ("Parameters sent without a value MUST be treated as if they were omitted") does not depend
    /// on whether a resolver is wired: a present, whitespace-only handle is refused before any resolver
    /// call and before any flow-state load or save either way. Driven over the real transport for the
    /// same reason as <see cref="ParticipateWithBlankExchangeIdIsRefusedBeforeAnyStoreCall"/>.
    /// </summary>
    [TestMethod]
    public async Task ParticipateWithBlankExchangeIdIsRefusedBeforeAnyStoreCallWithNoResolverWired()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app).ConfigureAwait(false);

        int loadCount = 0;
        int saveCount = 0;
        LoadServerFlowStateDelegate originalLoad = app.Server.Integration.LoadFlowStateAsync!;
        SaveServerFlowStateDelegate originalSave = app.Server.Integration.SaveFlowStateAsync!;
        ResolveCorrelationKeyDelegate? originalResolve = app.Server.Integration.ResolveCorrelationKeyAsync;

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCorrelationKeyAsync = null;

            candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
            {
                _ = Interlocked.Increment(ref loadCount);

                return await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
            };

            candidateIntegration.SaveFlowStateAsync = async (tenantId, key, state, stepCount, ctx, ct) =>
            {
                _ = Interlocked.Increment(ref saveCount);
                await originalSave(tenantId, key, state, stepCount, ctx, ct).ConfigureAwait(false);
            };
        }).ConfigureAwait(false);

        string collectionPath = TestHostShell.ComposeEndpointPath(
            WellKnownVcalmEndpointNames.VcalmParticipateInExchange, segment);

        (int statusCode, _, string body) = await VcalmWireFixtures.SendWireAsync(
            app, "POST", $"{collectionPath}/%20", "{}", authorizationHeader: null, TestContext.CancellationToken)
            .ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCorrelationKeyAsync = originalResolve;
            candidateIntegration.LoadFlowStateAsync = originalLoad;
            candidateIntegration.SaveFlowStateAsync = originalSave;
        }).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "A whitespace-only exchange id is refused the same way whether or not a resolver is wired.");
        Assert.Contains($"\"error\":\"{ServerErrors.InvalidRequest}\"", body, StringComparison.Ordinal, body);
        Assert.Contains("\"error_description\":\"Flow not found or expired.\"", body, StringComparison.Ordinal, body);
        Assert.AreEqual(0, loadCount, "A blank exchange id is refused before any flow-state load.");
        Assert.AreEqual(0, saveCount, "A blank exchange id is refused before any flow-state save.");
    }


    /// <summary>
    /// Registers a tenant with the exchange capability and wires the exchange seams: the parsers, the exchange id to
    /// flow id resolver over the host's flow store, and the step decisions.
    /// </summary>
    /// <param name="app">The host the tenant is registered on.</param>
    /// <returns>The tenant's path segment.</returns>
    private Task<string> RegisterExchangeAsync(TestHostShell app) => RegisterExchangeAsync(app, DidAuthQueryJson);


    /// <summary>
    /// Registers a tenant with the exchange capability and wires the exchange seams, the step decisions
    /// requesting a presentation for <paramref name="queryJson"/> on the initiating message.
    /// </summary>
    /// <param name="app">The host the tenant is registered on.</param>
    /// <param name="queryJson">The §3.4 query array the engine's presentation request carries.</param>
    /// <returns>The tenant's path segment.</returns>
    private async Task<string> RegisterExchangeAsync(TestHostShell app, string queryJson)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(ClientId, ClientBaseUri, ExchangeCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(material);

        await WireExchangeSeamsAsync(app, holder: null, queryJson).ConfigureAwait(false);

        return material.Registration.TenantId.Value;
    }


    /// <summary>
    /// Registers a tenant with the exchange and holder capabilities and wires the exchange seams together with the
    /// engine's presentation verification and <paramref name="holder"/>'s presentation signing, for the §3.6.5
    /// round trip.
    /// </summary>
    /// <param name="app">The host the tenant is registered on.</param>
    /// <param name="holder">The holder whose presentation the engine verifies.</param>
    /// <returns>The tenant's path segment.</returns>
    private async Task<string> RegisterExchangeAsync(TestHostShell app, HolderSigningContext holder)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(ClientId, ClientBaseUri, ExchangeAndHolderCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(material);

        await WireExchangeSeamsAsync(app, holder, DidAuthQueryJson).ConfigureAwait(false);

        return material.Registration.TenantId.Value;
    }


    /// <summary>
    /// Installs the workflow and exchange delegates used by the endpoint cases.
    /// </summary>
    /// <param name="app">The host whose integration is altered.</param>
    /// <param name="holder">The holder whose presentation the engine verifies, or <see langword="null"/> for none.</param>
    /// <param name="queryJson">The §3.4 query array the engine's presentation request carries.</param>
    private static async Task WireExchangeSeamsAsync(TestHostShell app, HolderSigningContext? holder, string queryJson)
    {
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        //§3.6.4 / §3.6.6: resolve the exchange id to its flow id by scanning the host's flow store for
        //the exchange flow state carrying the id (the production deployment keys a secondary index; the
        //test host already keys exchangeId -> flowId in SaveFlowStateAsync, but the read seam can derive
        //it from the flow store the shell exposes).
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmExchangeFlowIdAsync = (exchangeId, _, _) =>
                ValueTask.FromResult(ResolveExchangeFlowId(app, exchangeId));
        }).ConfigureAwait(false);

        //§3.6.3 / §3.6.6 REQUIRED seam: the coordinator authorization the create-exchange and
        //state-read routes need to materialize at all.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizeVcalmCoordinatorAsync = VcalmWireFixtures.AuthorizeTestCoordinator;
        }).ConfigureAwait(false);

        //§3.6.5 step logic: on the empty initiating message request a DID Authentication presentation;
        //the holder's POSTed verifiablePresentation is verified by the engine (the AcceptPresentation
        //path the engine drives once it sees a presentation), and any later message completes.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmExchangeStepAsync = (exchangeId, message, _, _) =>
            {
                if(message.VerifiablePresentation is not null)
                {
                    //A presented presentation is verified-and-accepted by the engine directly; the decision
                    //is only consulted for non-presentation messages.

                    return ValueTask.FromResult(VcalmExchangeStepDecision.AcceptPresentation("did-auth"));
                }

                return ValueTask.FromResult(
                    VcalmExchangeStepDecision.RequestPresentation("did-auth", queryJson, domain: "exchange.verifier.test"));
            };
        }).ConfigureAwait(false);

        if(holder is not null)
        {
            //The engine verifies the holder's presentation against the bound challenge / domain using
            //the §3.3.2 presentation-verify configuration (eddsa-jcs-2022 over the JCS canonicalizer and
            //the did:key resolver).
            await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.VcalmExchangeVerification = new VcalmCredentialVerification
                {
                    Resolver = KeyDidResolverSeam,
                    Canonicalize = JcsCanonicalizer,
                    ContextResolver = null,
                    KnownContext = Context.FromIris(Context.Credentials20),
                    DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
                    SerializeCredential = SerializeCredential,
                    SerializePresentation = SerializePresentation,
                    SerializeProofOptions = SerializeProofOptions,
                    Decoder = TestSetup.Base58Decoder,
                    ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
                    MemoryPool = Pool
                };
            }).ConfigureAwait(false);

            await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.VcalmPresentationSigning = holder.Signing;
            }).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Scans the host's flow store for the exchange flow state carrying <paramref name="exchangeId"/>.
    /// </summary>
    /// <param name="app">The host whose flow store is scanned.</param>
    /// <param name="exchangeId">The exchange id to look up.</param>
    /// <returns>The flow id keying that state, or <see langword="null"/> when no such exchange exists.</returns>
    private static string? ResolveExchangeFlowId(TestHostShell app, string exchangeId)
    {
        foreach(KeyValuePair<string, (FlowState State, int StepCount)> entry in app.FlowStore)
        {
            string? stateExchangeId = entry.Value.State switch
            {
                VcalmExchangePendingState pending => pending.ExchangeId,
                VcalmExchangeActiveState active => active.ExchangeId,
                VcalmExchangeCompleteState complete => complete.ExchangeId,
                VcalmExchangeInvalidState invalid => invalid.ExchangeId,
                _ => null
            };

            if(string.Equals(stateExchangeId, exchangeId, StringComparison.Ordinal))
            {
                return entry.Key;
            }
        }

        return null;
    }


    /// <summary>
    /// Builds the holder's eddsa-jcs-2022 presentation signing under a did:key the <see cref="KeyDidResolver"/>
    /// resolves locally, with the holder DID the round trip presents under.
    /// </summary>
    /// <returns>The holder's signing configuration and DID.</returns>
    private async Task<HolderSigningContext> CreateHolderSigningContextAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        DidDocument holderDidDocument = await KeyDidBuilder.BuildAsync(
            keyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        string holderDid = holderDidDocument.Id!.ToString();

        keyPair.PublicKey.Dispose();
        OwnedKeys.Add(keyPair.PrivateKey);

        VcalmPresentationSigning signing = new()
        {
            PrivateKey = keyPair.PrivateKey,
            DefaultVerificationMethodId = verificationMethodId,
            Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
            Canonicalize = JcsCanonicalizer,
            ContextResolver = null,
            EncodeProofValue = ProofValueCodecs.EncodeBase58Btc,
            SerializePresentation = SerializePresentation,
            DeserializePresentation = DeserializePresentation,
            SerializeProofOptions = SerializeProofOptions,
            Encoder = TestSetup.Base58Encoder,
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            MemoryPool = Pool
        };

        return new HolderSigningContext(signing, holderDid);
    }


    /// <summary>
    /// Signs a minimal VC Data Model 2.0 presentation bound to <paramref name="challenge"/> and
    /// <paramref name="domain"/>: the holder's answer to the engine's DID Authentication request.
    /// </summary>
    /// <param name="holder">The holder signing the presentation.</param>
    /// <param name="challenge">The challenge the engine bound to the request.</param>
    /// <param name="domain">The domain the engine bound to the request.</param>
    /// <param name="containedCredentials">The presentation's <c>verifiableCredential</c> entries, or <see langword="null"/> for none.</param>
    /// <param name="envelopedCredentials">The presentation's enveloped credential entries, or <see langword="null"/> for none.</param>
    /// <returns>The serialized signed presentation.</returns>
    private async Task<string> SignPresentationAsync(
        HolderSigningContext holder,
        string challenge,
        string domain,
        List<VerifiableCredential>? containedCredentials = null,
        List<EnvelopedVerifiableCredential>? envelopedCredentials = null)
    {
        VerifiablePresentation unproofed = new()
        {
            Context = Context.FromIris(Context.Credentials20),
            Type = ["VerifiablePresentation"],
            Holder = holder.HolderDid,
            VerifiableCredential = containedCredentials,
            EnvelopedVerifiableCredential = envelopedCredentials
        };

        DataIntegritySecuredPresentation secured = await VcalmHolderService.CreatePresentationAsync(
            unproofed,
            challenge,
            domain,
            holder.Signing.DefaultVerificationMethodId,
            TimeProvider.GetUtcNow().UtcDateTime,
            holder.Signing,
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        return holder.Signing.SerializePresentation(secured);
    }


    /// <summary>
    /// Signs a minimal VC Data Model 2.0 credential with eddsa-jcs-2022 under a FRESH did:key issuer the
    /// <see cref="KeyDidResolverSeam"/> resolves locally, for embedding as a <c>verifiableCredential</c>
    /// entry inside a presentation the engine verifies. Its <c>@context</c> is the single base context
    /// the engine's <see cref="VcalmCredentialVerification.KnownContext"/> is configured with
    /// (<see cref="WireExchangeSeamsAsync"/>), so it context-validates cleanly before any tampering.
    /// </summary>
    /// <returns>The signed, validly-issued contained credential.</returns>
    private async Task<DataIntegritySecuredCredential> SignContainedCredentialAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuerPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            Pool,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        VerifiableCredential unsignedCredential = new()
        {
            Context = Context.FromIris(Context.Credentials20),
            Id = "urn:uuid:vcalm-exchange-contained-credential",
            Type = ["VerifiableCredential"],
            Issuer = new Issuer { Id = issuerDidDocument.Id!.ToString() },
            CredentialSubject = [new CredentialSubject { Id = "did:example:vcalm-exchange-contained-subject" }]
        };

        return await unsignedCredential.SignAsync(
            issuerPrivate,
            issuerDidDocument.VerificationMethod![0].Id!,
            EddsaJcs2022CryptosuiteInfo.Instance,
            TimeProvider.GetUtcNow().UtcDateTime,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            Pool,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Creates an exchange through the §3.6.3 endpoint and asserts its HTTP 201.</summary>
    /// <param name="app">The host running the exchange tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="body">The create-exchange request body.</param>
    /// <returns>The parsed created exchange; the caller disposes it.</returns>
    private async Task<JsonDocument> CreateExchangeAsync(TestHostShell app, string segment, string body)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateExchange, "POST",
            new RequestFields(), VcalmWireFixtures.CoordinatorAuthorizationHeaders, body,
            [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>Creates an exchange through <see cref="CreateExchangeAsync"/> and returns its id.</summary>
    /// <param name="app">The host running the exchange tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="body">The create-exchange request body; an empty object by default.</param>
    /// <returns>The created exchange's id.</returns>
    private async Task<string> CreateExchangeAndGetIdAsync(TestHostShell app, string segment, string body = "{}")
    {
        using JsonDocument created = await CreateExchangeAsync(app, segment, body).ConfigureAwait(false);

        return created.RootElement.GetProperty(VcalmParameterNames.Id).GetString()!;
    }


    /// <summary>Creates an exchange through the §3.6.3 endpoint over the real wire and returns its id.</summary>
    /// <param name="app">The host running the exchange tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <returns>The created exchange's id.</returns>
    private async Task<string> CreateExchangeAndGetIdOverWireAsync(TestHostShell app, string segment)
    {
        using JsonDocument created = await VcalmWireFixtures.PostCreateExchangeWireAsync(
            app, segment, "{}", 201, TestContext.CancellationToken).ConfigureAwait(false);

        return created.RootElement.GetProperty(VcalmParameterNames.Id).GetString()!;
    }


    /// <summary>Reads an exchange's state through the §3.6.6 endpoint and asserts its HTTP 200.</summary>
    /// <param name="app">The host running the exchange tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="exchangeId">The exchange whose state is read.</param>
    /// <returns>The parsed exchange state; the caller disposes it.</returns>
    private async Task<JsonDocument> GetExchangeStateAsync(TestHostShell app, string segment, string exchangeId)
    {
        ServerHttpResponse response = await app.DispatchVcalmExchangeByIdAsync(
            segment, "GET", exchangeId, jsonBody: null, [], TestContext.CancellationToken,
            VcalmWireFixtures.CoordinatorAuthorizationHeaders).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>
    /// Posts a participate message carrying <paramref name="presentationRequestJson"/> as its
    /// <c>verifiablePresentationRequest</c> over the real HTTPS wire to a freshly created exchange and
    /// asserts the refusal the draft gives such a message: the participate interface lists "400 Invalid
    /// input" (<see href="https://www.w3.org/TR/vcalm-1.0/#participate-in-an-exchange">VCALM §3.6.6</see>:
    /// "Posting a Verifiable Presentation Request will result in either a 4xx error or one of the
    /// following"), under "Implementations MUST throw an error if an endpoint receives data, options, or
    /// option values that it does not understand or know how to process"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>); the body is a
    /// ProblemDetails of the malformed-value type, and it is "serialized as JSON" with "the Content-Type
    /// header with a media type value of application/json"
    /// (<see href="https://www.w3.org/TR/vcalm-1.0/#content-serialization">VCALM §2.4</see>). The
    /// exchange's state read before and after the refusal is identical, its sequence included: the
    /// refused message neither advances nor alters the exchange.
    /// </summary>
    /// <param name="presentationRequestJson">The verifiable presentation request JSON text the message carries.</param>
    /// <returns>A task completing when the assertions have run.</returns>
    private async Task AssertParticipateRefusesRequestAsync(string presentationRequestJson)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app).ConfigureAwait(false);
        string exchangeId = await CreateExchangeAndGetIdOverWireAsync(app, segment).ConfigureAwait(false);
        using JsonDocument before = await VcalmWireFixtures.GetExchangeWireAsync(
            app, segment, exchangeId, 200, TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string? mediaType, string body) = await VcalmWireFixtures.PostExchangeMessageWireAsync(
            app, segment, exchangeId, "{\"verifiablePresentationRequest\":" + presentationRequestJson + "}",
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual("application/json", mediaType, body);
        using JsonDocument problem = JsonDocument.Parse(body);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            problem.RootElement.GetProperty("type").GetString(), body);

        using JsonDocument after = await VcalmWireFixtures.GetExchangeWireAsync(
            app, segment, exchangeId, 200, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(before.RootElement.GetRawText(), after.RootElement.GetRawText(),
            "A message refused as malformed leaves the exchange exactly as it was.");
    }


    /// <summary>
    /// Runs the holder's side of an exchange over the real HTTPS wire: registers an exchange whose step
    /// requests a presentation for <paramref name="queryJson"/>, POSTs the empty initiating message, and
    /// parses the verifiable presentation request the engine answers with, as the holder receives it.
    /// </summary>
    /// <param name="queryJson">The §3.4 query array the verifier's request carries.</param>
    /// <returns>The request the holder parsed.</returns>
    private async Task<VerifiablePresentationRequest> ReceivePresentationRequestOverWireAsync(string queryJson)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = await RegisterExchangeAsync(app, queryJson).ConfigureAwait(false);
        string exchangeId = await CreateExchangeAndGetIdOverWireAsync(app, segment).ConfigureAwait(false);

        using JsonDocument initiated = await VcalmWireFixtures.PostExchangeWireAsync(
            app, segment, exchangeId, "{}", 200, TestContext.CancellationToken).ConfigureAwait(false);
        string presentationRequestJson = initiated.RootElement
            .GetProperty(VcalmParameterNames.VerifiablePresentationRequest).GetRawText();

        VerifiablePresentationRequest request = VcalmPresentationRequestJsonParsing.Parse(presentationRequestJson, JsonOptions);
        Assert.AreEqual(VcalmParseFailure.None, request.Failure, presentationRequestJson);

        return request;
    }


    /// <summary>
    /// The holder's own step after retrieving and verifying the Recognized Entities list every
    /// <c>recognizedIn</c> item of <paramref name="request"/> points to: the request with those items
    /// carrying <paramref name="recognizedIssuerIds"/>, the issuers the list names.
    /// </summary>
    /// <param name="request">The request the holder parsed.</param>
    /// <param name="recognizedIssuerIds">The issuer ids the retrieved list names.</param>
    /// <returns>The request with the recognized issuers supplied.</returns>
    private static VerifiablePresentationRequest WithRecognizedIssuers(
        VerifiablePresentationRequest request, params string[] recognizedIssuerIds) =>
        request with
        {
            Query =
            [
                .. request.Query.Select(query => query is QueryByExampleQuery qbe
                    ? qbe with
                    {
                        CredentialQuery = qbe.CredentialQuery with
                        {
                            AcceptedIssuers =
                            [
                                .. qbe.CredentialQuery.AcceptedIssuers.Select(accepted => accepted.RecognizedInId is null
                                    ? accepted
                                    : accepted with { RecognizedIssuerIds = [.. recognizedIssuerIds] })
                            ]
                        }
                    }
                    : query)
            ]
        };


    /// <summary>
    /// A verifiable presentation request with one Query By Example whose <c>credentialQuery</c> carries
    /// the single member <paramref name="memberName"/> with the JSON value <paramref name="valueJson"/>.
    /// </summary>
    /// <param name="memberName">The <c>credentialQuery</c> member name.</param>
    /// <param name="valueJson">The member's JSON value text.</param>
    /// <returns>The request JSON text.</returns>
    private static string QueryByExampleRequestJson(string memberName, string valueJson) =>
        "{\"query\":[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"" + memberName + "\":" + valueJson + "}}]}";


    /// <summary>
    /// A §3.4 query array with one Query By Example asking for an <c>ExampleAlumniCredential</c> from the
    /// accepted-issuer items <paramref name="acceptedIssuerItemsJson"/>.
    /// </summary>
    /// <param name="acceptedIssuerItemsJson">The accepted-issuer items, comma-separated JSON text.</param>
    /// <returns>The query array JSON text.</returns>
    private static string QueryByExampleWithIssuersQueryJson(string acceptedIssuerItemsJson) =>
        "[{\"type\":\"QueryByExample\",\"credentialQuery\":{\"example\":{\"type\":\"ExampleAlumniCredential\"},"
        + "\"acceptedIssuers\":[" + acceptedIssuerItemsJson + "]}}]";


    /// <summary>The holder's presentation signing and DID for the §3.6.5 round trip.</summary>
    /// <param name="Signing">The holder's presentation-signing configuration.</param>
    /// <param name="HolderDid">The did:key the holder presents under.</param>
    private sealed record HolderSigningContext(VcalmPresentationSigning Signing, string HolderDid);
}
