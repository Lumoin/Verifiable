using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Server;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.OAuth;

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
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://exchange.client.test";
    private static readonly Uri ClientBaseUri = new("https://exchange.client.test");

    private static readonly ImmutableHashSet<CapabilityIdentifier> ExchangeCapabilities =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmExchange);

    //The §3.6.5 round-trip needs the holder presentation signing too (the holder signs the
    //presentation the engine requested), so the registration also carries the holder capability.
    private static readonly ImmutableHashSet<CapabilityIdentifier> ExchangeAndHolderCapabilities =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmExchange, WellKnownVcalmCapabilities.VcalmHolder);

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    private static readonly ExchangeContext EmptyContext = new();

    private List<VerifierKeyMaterial> RegisteredMaterials { get; } = [];
    private List<IDisposable> OwnedKeys { get; } = [];

    //The §3.4 query the engine sends when it requests a presentation: a DID Authentication query the
    //holder satisfies by controlling a did:key. The engine binds the challenge / domain itself.
    private const string DidAuthQueryJson =
        "[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{\"method\":\"key\"}]}]";


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
        string segment = RegisterExchange(app);

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
        string segment = RegisterExchange(app);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmExchangeProtocolsAsync(
            segment, exchangeId, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = RegisterExchange(app);

        ServerHttpResponse response = await app.DispatchVcalmExchangeProtocolsAsync(
            segment, "urn:uuid:never-created", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = RegisterExchange(app, holder);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Step 1: client initiates with the empty message; the engine requests a presentation.
        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
            segment, "POST", exchangeId, presentMessage, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
    /// §3.6.5 active re-poll (V-5b single-step regression): after the engine issues a presentation
    /// request, a non-presentation re-poll RE-SENDS the SAME request — the EXISTING bound challenge,
    /// never a freshly minted one — and a presentation the holder binds to the re-polled challenge still
    /// verifies and completes. Re-minting a fresh challenge on a re-poll desynced the binding the holder
    /// was already answering (the single-step path formerly re-consulted the step seam here).
    /// </summary>
    [TestMethod]
    public async Task ParticipateActiveRepollResendsSameChallengeAndStillVerifies()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterExchange(app, holder);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Step 1: initiate — the engine requests a presentation and binds a challenge.
        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument initiateDoc = JsonDocument.Parse(initiate.Body);
        JsonElement firstVpr = initiateDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);
        string firstChallenge = firstVpr.GetProperty(VcalmParameterNames.Challenge).GetString()!;
        string domain = firstVpr.GetProperty(VcalmParameterNames.Domain).GetString()!;

        //Step 2: re-poll with another empty body — the engine RE-SENDS the same active request.
        ServerHttpResponse repoll = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, repoll.StatusCode, repoll.Body);
        using JsonDocument repollDoc = JsonDocument.Parse(repoll.Body);
        JsonElement repollVpr = repollDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);
        string repollChallenge = repollVpr.GetProperty(VcalmParameterNames.Challenge).GetString()!;

        Assert.AreEqual(firstChallenge, repollChallenge,
            "§3.6.5 re-poll must re-send the EXISTING bound challenge, never mint a fresh one (the V-5b desync).");

        //The exchange is still active after the re-poll (no state change, no re-bind).
        using JsonDocument midState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("active", midState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "A re-poll leaves the exchange active with its binding intact.");

        //Step 3: the holder answers the re-polled challenge; it still verifies and completes.
        string securedPresentationJson = await SignPresentationAsync(holder, repollChallenge, domain).ConfigureAwait(false);
        string presentMessage = "{\"verifiablePresentation\":" + securedPresentationJson + "}";

        ServerHttpResponse complete = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
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
    /// the engine requested → the engine cannot verify it → HTTP 4xx + ProblemDetails, and the §3.6.6
    /// state goes to invalid with a lastError.
    /// </summary>
    [TestMethod]
    public async Task ParticipateWithUnverifiablePresentationYields4xxAndInvalidState()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterExchange(app, holder);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        using JsonDocument requestDoc = JsonDocument.Parse(initiate.Body);
        JsonElement vpr = requestDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);
        string domain = vpr.GetProperty(VcalmParameterNames.Domain).GetString()!;

        //Sign the presentation with the WRONG challenge — the proof will not verify against the bound one.
        string securedPresentationJson = await SignPresentationAsync(holder, "not-the-bound-challenge", domain).ConfigureAwait(false);
        string presentMessage = "{\"verifiablePresentation\":" + securedPresentationJson + "}";

        ServerHttpResponse rejected = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, rejected.StatusCode, rejected.Body);
        using JsonDocument problem = JsonDocument.Parse(rejected.Body);
        Assert.AreEqual(VcalmProblemTypes.CryptographicSecurityError,
            problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "§3.6 / §3.8: an unverifiable presentation is a cryptographic-security ProblemDetail.");

        using JsonDocument invalidState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("invalid", invalidState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "§3.6.6: a rejected presentation drives the exchange to invalid.");
        Assert.IsTrue(invalidState.RootElement.TryGetProperty(VcalmParameterNames.LastError, out _),
            "§3.6.6: an invalid exchange carries a lastError ProblemDetail.");
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
        string segment = RegisterExchange(app, holder);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //A structurally valid, signed presentation presented as the very first message — the exchange
        //is pending, so no anti-replay challenge has been bound for it to be verified against.
        string securedPresentationJson = await SignPresentationAsync(holder, "unsolicited-challenge", "verifier.example").ConfigureAwait(false);
        string presentMessage = "{\"verifiablePresentation\":" + securedPresentationJson + "}";

        ServerHttpResponse refused = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        using JsonDocument problem = JsonDocument.Parse(refused.Body);
        Assert.AreEqual(VcalmProblemTypes.CryptographicSecurityError,
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
        string segment = RegisterExchange(app);

        ServerHttpResponse response = await app.DispatchVcalmExchangeByIdAsync(
            segment, "GET", "urn:uuid:never-created", jsonBody: null, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = RegisterExchange(app);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{\"notARealProperty\":true}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "§3.6: an unrecognized custom vcapi property triggers an error.");
    }


    /// <summary>
    /// §2.4 content-serialization MUST: a §3.6.3 create with a non-application/json Content-Type is
    /// rejected with HTTP 400 before parsing.
    /// </summary>
    [TestMethod]
    public async Task CreateExchangeWithNonJsonContentTypeYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterExchange(app);

        byte[] bytes = Encoding.UTF8.GetBytes("{}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateExchange, "POST",
            bytes, "text/plain", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = RegisterExchange(app);

        //Create an exchange that expires one minute from now.
        string expires = TimeProvider.GetUtcNow().AddMinutes(1).ToString("o");
        string createBody = "{\"expires\":\"" + expires + "\"}";
        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment, createBody).ConfigureAwait(false);

        //Advance past the expiry, then attempt to participate.
        TimeProvider.Advance(TimeSpan.FromMinutes(2));

        ServerHttpResponse response = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "A participate POST after the exchange expires is rejected by the flow-expiry gate.");
    }


    //Registers a tenant with the VcalmExchange capability and wires the exchange seams (the parsers,
    //the exchange-id -> flow-id resolver over the host's flow store, and the step-decision logic).
    private string RegisterExchange(TestHostShell app)
    {
        VerifierKeyMaterial material = app.RegisterClient(ClientId, ClientBaseUri, ExchangeCapabilities);
        RegisteredMaterials.Add(material);

        WireExchangeSeams(app, holder: null);

        return material.Registration.TenantId.Value;
    }


    private string RegisterExchange(TestHostShell app, HolderSigningContext holder)
    {
        VerifierKeyMaterial material = app.RegisterClient(ClientId, ClientBaseUri, ExchangeAndHolderCapabilities);
        RegisteredMaterials.Add(material);

        WireExchangeSeams(app, holder);

        return material.Registration.TenantId.Value;
    }


    private static void WireExchangeSeams(TestHostShell app, HolderSigningContext? holder)
    {
        app.Server.Vcalm().UseDefaultVcalmJsonParsing(JsonOptions);

        //§3.6.4 / §3.6.6: resolve the exchange id to its flow id by scanning the host's flow store for
        //the exchange flow state carrying the id (the production deployment keys a secondary index; the
        //test host already keys exchangeId -> flowId in SaveFlowStateAsync, but the read seam can derive
        //it from the flow store the shell exposes).
        app.Server.Vcalm().ResolveVcalmExchangeFlowIdAsync = (exchangeId, _, _) =>
            ValueTask.FromResult(ResolveExchangeFlowId(app, exchangeId));

        //§3.6.5 step logic: on the empty initiating message request a DID Authentication presentation;
        //the holder's POSTed verifiablePresentation is verified by the engine (the AcceptPresentation
        //path the engine drives once it sees a presentation), and any later message completes.
        app.Server.Vcalm().ResolveVcalmExchangeStepAsync = (exchangeId, message, _, _) =>
        {
            if(message.VerifiablePresentation is not null)
            {
                //A presented presentation is verified-and-accepted by the engine directly; the decision
                //is only consulted for non-presentation messages.
                return ValueTask.FromResult(VcalmExchangeStepDecision.AcceptPresentation("did-auth"));
            }

            return ValueTask.FromResult(
                VcalmExchangeStepDecision.RequestPresentation("did-auth", DidAuthQueryJson, domain: "exchange.verifier.test"));
        };

        if(holder is not null)
        {
            //The engine verifies the holder's presentation against the bound challenge / domain using
            //the §3.3.2 presentation-verify configuration (eddsa-jcs-2022 over the JCS canonicalizer and
            //the did:key resolver).
            app.Server.Vcalm().VcalmExchangeVerification = new VcalmCredentialVerification
            {
                Resolver = KeyDidResolverSeam,
                Canonicalize = JcsCanonicalizer,
                ContextResolver = null,
                DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
                SerializeCredential = SerializeCredential,
                SerializePresentation = SerializePresentation,
                SerializeProofOptions = SerializeProofOptions,
                Decoder = TestSetup.Base58Decoder,
                ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
                MemoryPool = Pool
            };

            app.Server.Vcalm().VcalmPresentationSigning = holder.Signing;
        }
    }


    //Scans the host's flow store for the exchange flow state carrying the given exchange id, returning
    //its flow id (the dictionary key) or null when no such exchange exists.
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


    //Builds the holder's eddsa-jcs-2022 signing configuration under a did:key holder the KeyDidResolver
    //resolves locally — the presentation-signing seam plus the holder DID for the round-trip.
    private async Task<HolderSigningContext> CreateHolderSigningContextAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        DidDocument holderDidDocument = await KeyDidBuilder.BuildAsync(
            keyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
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
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
            MemoryPool = Pool
        };

        return new HolderSigningContext(signing, holderDid);
    }


    //Signs a minimal VC-DM 2.0 presentation binding the given challenge / domain, the holder's answer
    //to the engine's DID Authentication request.
    private async Task<string> SignPresentationAsync(HolderSigningContext holder, string challenge, string domain)
    {
        VerifiablePresentation unproofed = new()
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holder.HolderDid
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


    private async Task<JsonDocument> CreateExchangeAsync(TestHostShell app, string segment, string body)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateExchange, "POST",
            new RequestFields(), body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    private async Task<string> CreateExchangeAndGetIdAsync(TestHostShell app, string segment, string body = "{}")
    {
        using JsonDocument created = await CreateExchangeAsync(app, segment, body).ConfigureAwait(false);

        return created.RootElement.GetProperty(VcalmParameterNames.Id).GetString()!;
    }


    private async Task<JsonDocument> GetExchangeStateAsync(TestHostShell app, string segment, string exchangeId)
    {
        ServerHttpResponse response = await app.DispatchVcalmExchangeByIdAsync(
            segment, "GET", exchangeId, jsonBody: null, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    //The holder's presentation-signing configuration plus the holder DID for the §3.6.5 round-trip.
    private sealed record HolderSigningContext(VcalmPresentationSigning Signing, string HolderDid);
}
