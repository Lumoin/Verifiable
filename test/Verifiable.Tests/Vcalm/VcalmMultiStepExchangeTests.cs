using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Model.Did.Methods;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.JsonPointer.Jsonata;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Server;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// End-to-end conformance tests for the W3C VCALM 1.0 §3.6 MULTI-STEP exchange engine
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) — the §3.6.1 step graph layered over the §3.6.5 vcapi participation: an exchange
/// walks the admin-authored <c>nextStep</c> chain, accumulating each step's output in §3.6.6
/// <c>variables.results</c>, minting a credential for an <c>issueRequests</c> step and offering it back
/// over vcapi, firing a §3.6.7 callback, and holding the fail-closed anti-replay property at EVERY step.
/// </summary>
/// <remarks>
/// The step decision DERIVES from the workflow config (the §3.6.1 step graph the
/// <c>ResolveVcalmWorkflowForExchangeAsync</c> seam resolves), not the explicit single-step seam. The
/// holder signs presentations with eddsa-jcs-2022 and the engine mints credentials with eddsa-jcs-2022,
/// both under did:key the KeyDidResolver resolves locally — the same project crypto the §3.5.2 / §3.3.2
/// / §3.2.1 tests use.
/// </remarks>
[TestClass]
internal sealed class VcalmMultiStepExchangeTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://multistep.client.test";
    private static readonly Uri ClientBaseUri = new("https://multistep.client.test");

    private static readonly ImmutableHashSet<CapabilityIdentifier> Capabilities =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmExchange,
            WellKnownVcalmCapabilities.VcalmHolder,
            WellKnownVcalmCapabilities.VcalmAdministration,
            WellKnownVcalmCapabilities.VcalmVerifier);

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

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    private static readonly ExchangeContext EmptyContext = new();

    private List<VerifierKeyMaterial> RegisteredMaterials { get; } = [];
    private List<IDisposable> OwnedKeys { get; } = [];

    //The workflow store the §3.6.1 create endpoint persists to and the exchange's workflow resolves
    //from — so an exchange runs on the SAME parser-produced configuration the real endpoint stored.
    private Dictionary<string, VcalmWorkflowConfiguration> WorkflowStore { get; } = new(StringComparer.Ordinal);

    //The two presentation-requesting steps of the multi-step walk: each asks for a DID Authentication
    //the holder satisfies by controlling a did:key. The engine binds a FRESH challenge per step.
    private const string DidAuthQueryJson =
        "[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{\"method\":\"key\"}]}]";

    //The §3.4 VPR object wrapping the query — the UNIFIED step contract the parser produces: the whole
    //verifiablePresentationRequest object (query REQUIRED) round-trips through §3.6.2; the extracted
    //query is what the engine sends under its bound challenge / domain.
    private const string DidAuthVprJson = "{\"query\":" + DidAuthQueryJson + "}";


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
    /// §3.6.5 / §3.6.6 / §3.6.8 multi-step walk: a two-presentation-step workflow (present at step 1 →
    /// verified → advance to step 2 → present at step 2 → verified → complete) accumulates BOTH steps'
    /// presentations in variables.results, and the sequence increments per POST. Each step binds its OWN
    /// fresh challenge.
    /// </summary>
    [TestMethod]
    public async Task TwoPresentationStepsAccumulateResultsAndComplete()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterMultiStep(app, holder, TwoPresentationStepWorkflow());

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Step 1: initiate → the engine requests a presentation at step "stepOne".
        (string challenge1, string domain1) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);

        using(JsonDocument midState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false))
        {
            Assert.AreEqual("active", midState.RootElement.GetProperty(VcalmParameterNames.State).GetString());
            Assert.AreEqual("stepOne", midState.RootElement.GetProperty(VcalmParameterNames.Step).GetString(),
                "The exchange is at the first step.");
            Assert.AreEqual(1, midState.RootElement.GetProperty(VcalmParameterNames.Sequence).GetInt32());
        }

        //Step 1 present → verified → the engine ADVANCES to step 2 and requests another presentation,
        //bound to a FRESH challenge.
        string presentMessage1 = await SignPresentationMessageAsync(holder, challenge1, domain1).ConfigureAwait(false);
        ServerHttpResponse advance = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage1, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, advance.StatusCode, advance.Body);
        string challenge2;
        string domain2;
        using(JsonDocument advanceDoc = JsonDocument.Parse(advance.Body))
        {
            Assert.IsTrue(advanceDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiablePresentationRequest, out JsonElement vpr2),
                "§3.6.5: after the first step verifies, the engine advances and requests the second presentation.");
            challenge2 = vpr2.GetProperty(VcalmParameterNames.Challenge).GetString()!;
            domain2 = vpr2.GetProperty(VcalmParameterNames.Domain).GetString()!;
        }

        Assert.AreNotEqual(challenge1, challenge2, "§3.6: each step binds its OWN fresh anti-replay challenge.");

        using(JsonDocument midState2 = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false))
        {
            Assert.AreEqual("active", midState2.RootElement.GetProperty(VcalmParameterNames.State).GetString());
            Assert.AreEqual("stepTwo", midState2.RootElement.GetProperty(VcalmParameterNames.Step).GetString(),
                "The exchange advanced to the second step.");
            Assert.AreEqual(2, midState2.RootElement.GetProperty(VcalmParameterNames.Sequence).GetInt32(),
                "§3.6.6: the sequence increments per vcapi POST.");

            //The first step's result is already recorded.
            JsonElement results = midState2.RootElement.GetProperty(VcalmParameterNames.Variables).GetProperty(VcalmParameterNames.Results);
            Assert.IsTrue(results.TryGetProperty("stepOne", out _), "The first step's presentation is recorded.");
        }

        //Step 2 present → verified → complete.
        string presentMessage2 = await SignPresentationMessageAsync(holder, challenge2, domain2).ConfigureAwait(false);
        ServerHttpResponse complete = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage2, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, complete.StatusCode, complete.Body);

        using JsonDocument finalState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        JsonElement finalRoot = finalState.RootElement;
        Assert.AreEqual("complete", finalRoot.GetProperty(VcalmParameterNames.State).GetString(),
            "§3.6.6: the exchange completes after the final step's presentation verifies.");
        Assert.AreEqual(3, finalRoot.GetProperty(VcalmParameterNames.Sequence).GetInt32(),
            "§3.6.6: the sequence increments across the three vcapi POSTs.");

        JsonElement finalResults = finalRoot.GetProperty(VcalmParameterNames.Variables).GetProperty(VcalmParameterNames.Results);
        Assert.IsTrue(finalResults.TryGetProperty("stepOne", out _), "variables.results carries BOTH steps — step 1.");
        Assert.IsTrue(finalResults.TryGetProperty("stepTwo", out _), "variables.results carries BOTH steps — step 2.");
        Assert.HasCount(2, finalResults.EnumerateObject().ToList(), "§3.6.6: both steps' outputs accumulate.");
    }


    /// <summary>
    /// §3.6 multi-step SECURITY: the fail-closed anti-replay property holds PER STEP. A presentation
    /// signed with step 1's challenge, replayed at step 2 (where the engine bound a DIFFERENT fresh
    /// challenge), is REFUSED — the engine verifies only against the current active step's bound
    /// challenge, so a prior step's challenge cannot satisfy a later step.
    /// </summary>
    [TestMethod]
    public async Task Step1ChallengeReplayedAtStep2IsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterMultiStep(app, holder, TwoPresentationStepWorkflow());

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Step 1: initiate, capture step 1's (challenge, domain), present it correctly → advance to step 2.
        (string challenge1, string domain1) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);
        string present1 = await SignPresentationMessageAsync(holder, challenge1, domain1).ConfigureAwait(false);
        ServerHttpResponse advance = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present1, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, advance.StatusCode, advance.Body);

        //At step 2, REPLAY step 1's challenge (not the fresh step-2 challenge the engine just bound).
        string replay = await SignPresentationMessageAsync(holder, challenge1, domain1).ConfigureAwait(false);
        ServerHttpResponse refused = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, replay, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        using JsonDocument problem = JsonDocument.Parse(refused.Body);
        Assert.AreEqual(VcalmProblemTypes.CryptographicSecurityError,
            problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "§3.6: a presentation echoing a PRIOR step's challenge does not verify against the current step's bound challenge.");

        using JsonDocument invalidState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("invalid", invalidState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "The per-step fail-closed property drives the exchange to invalid on a replayed challenge.");

        //The earlier step's result is preserved on the invalid state (the §3.6.6 view still surfaces it).
        JsonElement results = invalidState.RootElement.GetProperty(VcalmParameterNames.Variables).GetProperty(VcalmParameterNames.Results);
        Assert.IsTrue(results.TryGetProperty("stepOne", out _),
            "The verified first step's result survives the later step's failure.");
    }


    /// <summary>
    /// §3.6 issuance-in-exchange: a step with issueRequests mints a credential by evaluating its
    /// credentialTemplate through the template seam, signs it via the issuance seam, and offers the
    /// issued credential back over vcapi as a verifiablePresentation — which VERIFIES (the credential
    /// carries a valid eddsa-jcs-2022 proof under a resolvable did:key issuer).
    /// </summary>
    [TestMethod]
    public async Task IssueRequestsStepMintsCredentialAndOffersItBack()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        IssuerSigningContext issuer = await CreateIssuerSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterMultiStep(app, holder, PresentThenIssueWorkflow(issuer.IssuerDid), issuer);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Step 1: initiate → present a DID-auth → the engine advances to the issue step, mints the
        //credential, and offers it back in the same reply as a verifiablePresentation.
        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);
        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);

        ServerHttpResponse offered = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, offered.StatusCode, offered.Body);
        using JsonDocument offeredDoc = JsonDocument.Parse(offered.Body);
        Assert.IsTrue(offeredDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiablePresentation, out JsonElement vp),
            "§3.6.5 / §3.6.8: the issue step offers the minted credential back as a verifiablePresentation.");

        JsonElement credentials = vp.GetProperty("verifiableCredential");
        Assert.AreEqual(1, credentials.GetArrayLength(), "The offered presentation carries one issued credential.");
        JsonElement issuedCredential = credentials[0];

        //The issued credential VERIFIES: POST it straight to /credentials/verify on the same tenant.
        string issuedCredentialJson = issuedCredential.GetRawText();
        string verifyBody = "{\"verifiableCredential\":" + issuedCredentialJson + "}";
        ServerHttpResponse verify = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, "POST",
            new RequestFields(), verifyBody, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, verify.StatusCode, verify.Body);
        using JsonDocument verifyDoc = JsonDocument.Parse(verify.Body);
        Assert.IsTrue(verifyDoc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "§3.6: the credential the exchange issued verifies (a valid eddsa-jcs-2022 proof under a resolvable issuer).");

        using JsonDocument finalState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("complete", finalState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "The issue step completes the exchange.");
    }


    /// <summary>
    /// §3.6 multi-tenant issuance-in-exchange: TWO tenants run the present-then-issue workflow on ONE
    /// host, each minting its credential under its OWN issuer key (resolved per tenant). The two minted
    /// verification methods differ — no tenant's exchange mints under another tenant's identity. This is
    /// the full §3.6 PDA flow proof that complements the resolution-level
    /// <c>ExchangeIssuanceResolvesPerTenantWithIssuerFallback</c> test.
    /// </summary>
    [TestMethod]
    public async Task IssueStepMintsUnderEachTenantsOwnIssuerKey()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        IssuerSigningContext issuerA = await CreateFreshIssuerSigningContextAsync().ConfigureAwait(false);
        IssuerSigningContext issuerB = await CreateFreshIssuerSigningContextAsync().ConfigureAwait(false);

        (string segmentA, string segmentB) = RegisterTwoTenantExchange(app, holder, issuerA, issuerB);

        string mintedVmA = await RunIssueExchangeAndGetMintedVmAsync(app, segmentA, holder).ConfigureAwait(false);
        string mintedVmB = await RunIssueExchangeAndGetMintedVmAsync(app, segmentB, holder).ConfigureAwait(false);

        Assert.AreEqual(issuerA.Descriptor.VerificationMethodId, mintedVmA,
            "Tenant A's exchange mints the credential under tenant A's issuer key.");
        Assert.AreEqual(issuerB.Descriptor.VerificationMethodId, mintedVmB,
            "Tenant B's exchange mints the credential under tenant B's issuer key.");
        Assert.AreNotEqual(mintedVmA, mintedVmB,
            "The two tenants' exchanges mint under distinct per-tenant issuer keys.");
    }


    /// <summary>
    /// §3.6 offered-completion non-leak: the vcapi reply that offers a minted credential back to the
    /// client carries ONLY the artifact (<c>verifiablePresentation</c>) plus the optional
    /// <c>referenceId</c> — it MUST NOT leak internal state: the accumulated <c>variables.results</c>,
    /// the bound anti-replay <c>challenge</c>/<c>domain</c>, or internal flow identifiers. The §3.6.6
    /// view exposes the accumulated results through the SEPARATE state endpoint; the terminal reply does
    /// not. BuildOfferedPresentationReply enforces this by construction; this test locks it so a
    /// regression that widened the reply (e.g. serializing StepResults or the bound challenge) would fail
    /// with the suite still green.
    /// </summary>
    [TestMethod]
    public async Task OfferedPresentationReplyCarriesOnlyArtifactAndReferenceId()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        IssuerSigningContext issuer = await CreateIssuerSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterMultiStep(app, holder, PresentThenIssueWorkflow(issuer.IssuerDid), issuer);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);
        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);

        ServerHttpResponse offered = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, offered.StatusCode, offered.Body);
        using JsonDocument offeredDoc = JsonDocument.Parse(offered.Body);
        JsonElement root = offeredDoc.RootElement;

        //The intended artifact is present.
        Assert.IsTrue(root.TryGetProperty(VcalmParameterNames.VerifiablePresentation, out _),
            "The offered-completion reply carries the verifiablePresentation artifact.");

        //No member outside {verifiablePresentation, referenceId}: the reply leaks no internal state.
        HashSet<string> allowed = new(StringComparer.Ordinal)
        {
            VcalmParameterNames.VerifiablePresentation,
            VcalmParameterNames.ReferenceId
        };
        foreach(JsonProperty property in root.EnumerateObject())
        {
            Assert.Contains(property.Name, allowed,
                $"§3.6: the offered-completion reply leaked the member '{property.Name}'.");
        }

        //Explicit negatives on the named leak surface.
        Assert.IsFalse(root.TryGetProperty(VcalmParameterNames.Variables, out _), "no variables in the offered reply.");
        Assert.IsFalse(root.TryGetProperty(VcalmParameterNames.Results, out _), "no results in the offered reply.");
        Assert.IsFalse(root.TryGetProperty(VcalmParameterNames.Challenge, out _), "no bound challenge in the offered reply.");
        Assert.IsFalse(root.TryGetProperty(VcalmParameterNames.Domain, out _), "no bound domain in the offered reply.");
    }


    /// <summary>
    /// §3.6.7 callback: a step that names a callback fires it — the engine composes the
    /// {event{data{exchangeId}}} body and invokes the outbound-callback seam (the app's HTTP POST). The
    /// callback then arrives at the §3.6.7 endpoint, which answers 200.
    /// </summary>
    [TestMethod]
    public async Task StepCallbackFiresAndCallbackEndpointAccepts()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        List<(string Url, string Body)> deliveredCallbacks = [];

        string segment = RegisterMultiStep(app, holder, CallbackWorkflow());
        app.Server.Vcalm().DeliverVcalmCallbackAsync = (url, body, _, _) =>
        {
            deliveredCallbacks.Add((url, body));

            return ValueTask.CompletedTask;
        };

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Initiate → the single presentation-requesting step (which names a callback) is reached and
        //fires its callback after staging the presentation request.
        await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);

        Assert.HasCount(1, deliveredCallbacks, "§3.6.7: the step's callback fired through the delivery seam.");
        (string url, string body) = deliveredCallbacks[0];
        Assert.AreEqual("https://callback.test/notify", url, "The callback was delivered to the step's callback.url.");
        using(JsonDocument callbackDoc = JsonDocument.Parse(body))
        {
            JsonElement data = callbackDoc.RootElement.GetProperty(VcalmParameterNames.Event).GetProperty(VcalmParameterNames.Data);
            Assert.AreEqual(exchangeId, data.GetProperty(VcalmParameterNames.ExchangeId).GetString(),
                "§3.6.7: the callback body carries event.data.exchangeId.");
        }

        //The §3.6.7 RECEIVING endpoint accepts a well-formed callback body with 200.
        string callbackBody = "{\"event\":{\"data\":{\"exchangeId\":\"" + exchangeId + "\"}}}";
        ServerHttpResponse received = await app.DispatchVcalmCallbackAsync(
            segment, "urn:callback:abc123", callbackBody, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, received.StatusCode, "§3.6.7: a well-formed callback body is accepted (200).");
    }


    /// <summary>
    /// §3.6.7 callback endpoint rejects a malformed body: a POST that is not the
    /// {event{data{exchangeId}}} shape → HTTP 400 ("Callback data was not received.").
    /// </summary>
    [TestMethod]
    public async Task CallbackEndpointRejectsMalformedBodyWith400()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterMultiStep(app, holder, CallbackWorkflow());

        ServerHttpResponse response = await app.DispatchVcalmCallbackAsync(
            segment, "urn:callback:abc123", "{\"notAnEvent\":true}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, "§3.6.7: a body that is not {event{data{exchangeId}}} is 400.");
    }


    /// <summary>
    /// §3.6 cycle bounding: a workflow whose step graph cycles (supplied DIRECTLY to the exchange
    /// engine, bypassing §3.6.1 create-time validation) does NOT loop forever — the engine caps the
    /// per-message step walk and fails the exchange as invalid.
    /// </summary>
    [TestMethod]
    public async Task MalformedNextStepCycleIsBoundedToInvalid()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);

        //A cyclic non-interactive workflow: "a" → "b" → "a", with no presentation request to suspend the
        //walk. Supplied directly to the engine (not through the validated create endpoint).
        VcalmWorkflowConfiguration cyclic = new()
        {
            InitialStep = "a",
            Steps = ImmutableDictionary<string, VcalmWorkflowStep>.Empty
                .SetItem("a", new VcalmWorkflowStep { NextStep = "b" })
                .SetItem("b", new VcalmWorkflowStep { NextStep = "a" })
        };

        string segment = RegisterMultiStep(app, holder, cyclic);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Initiate the exchange — the walk would loop a→b→a→… forever; the engine bounds it and fails.
        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, initiate.StatusCode, initiate.Body);

        using JsonDocument state = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("invalid", state.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "§3.6: a malformed nextStep cycle is bounded to invalid, not an infinite loop.");
    }


    /// <summary>
    /// §3.6.1 → §3.6.3 → §3.6.5 END-TO-END: a workflow AUTHORED through the real <c>POST /workflows</c>
    /// endpoint (its presentation step carrying a <c>verifiablePresentationRequest</c> OBJECT, query
    /// REQUIRED) and then RUN as an exchange yields a WELL-FORMED §3.4 verifiable presentation request to
    /// the holder: <c>verifiablePresentationRequest.query</c> is an ARRAY (not the whole VPR object
    /// re-nested), the engine's bound <c>challenge</c> / <c>domain</c> are present, and there is no
    /// double-nesting. The holder then presents against that challenge / domain and the exchange verifies
    /// and completes. This crosses the parser → engine seam the directly-constructed configs never did.
    /// </summary>
    [TestMethod]
    public async Task AuthoredWorkflowRunYieldsWellFormedPresentationRequest()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);

        //Resolve the exchange's workflow from the store the §3.6.1 endpoint authors into (no direct config).
        string segment = RegisterMultiStep(app, holder, workflow: null);

        //§3.6.1: author the workflow through the REAL POST /workflows — the parser produces the unified
        //step contract (whole VPR object kept, query extracted) the engine then drives.
        const string authoredWorkflow =
            "{" +
                "\"initialStep\":\"didAuth\"," +
                "\"steps\":{" +
                    "\"didAuth\":{" +
                        "\"createChallenge\":true," +
                        "\"verifiablePresentationRequest\":{" +
                            "\"query\":[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{\"method\":\"key\"}]}]," +
                            "\"domain\":\"https://authored.step.domain.test\"" +
                        "}" +
                    "}" +
                "}" +
            "}";

        await CreateWorkflowAsync(app, segment, authoredWorkflow).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //§3.6.5: initiate the exchange — the engine requests the authored step's presentation.
        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, initiate.StatusCode, initiate.Body);

        string challenge;
        string domain;
        using(JsonDocument requestDoc = JsonDocument.Parse(initiate.Body))
        {
            JsonElement vpr = requestDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);

            //The DEFECT this test guards: query is an ARRAY, not the whole VPR object doubly nested.
            JsonElement query = vpr.GetProperty(VcalmParameterNames.Query);
            Assert.AreEqual(JsonValueKind.Array, query.ValueKind,
                "§3.4.1: the holder receives query as an ARRAY of typed query maps, not a re-nested VPR object.");
            Assert.AreEqual(1, query.GetArrayLength(), "The authored single DIDAuthentication query rides through.");
            Assert.AreEqual("DIDAuthentication", query[0].GetProperty(VcalmParameterNames.Type).GetString(),
                "The query's type is the authored DIDAuthentication, reached directly (no double-nesting).");
            Assert.IsFalse(query[0].TryGetProperty(VcalmParameterNames.Query, out _),
                "There is NO nested query member — the whole VPR object was not wrapped as the query.");

            //The engine's bound anti-replay values are present and authoritative.
            challenge = vpr.GetProperty(VcalmParameterNames.Challenge).GetString()!;
            domain = vpr.GetProperty(VcalmParameterNames.Domain).GetString()!;
            Assert.IsFalse(string.IsNullOrEmpty(challenge), "§3.4.1: the engine binds a fresh challenge.");
            Assert.AreNotEqual("https://authored.step.domain.test", domain,
                "§3.4.1: the engine owns the domain binding; the step-authored domain is not propagated.");
        }

        //The holder presents against the engine's bound challenge / domain → verifies → completes.
        string presentMessage = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);
        ServerHttpResponse complete = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, complete.StatusCode, complete.Body);

        using JsonDocument finalState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("complete", finalState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "§3.6.6: the presentation against the well-formed request verifies and completes the exchange.");
    }


    /// <summary>
    /// §3.6.5 active re-poll: "Posting an empty body will start the exchange or return what the exchange
    /// is expecting to complete the next step." On a config-driven (V-5c) exchange ALREADY active (the
    /// engine has issued a presentation request and is awaiting it), an empty re-poll RE-SENDS the
    /// current step's bound verifiablePresentationRequest with the SAME challenge / domain and NO state
    /// change — never a 500. The fail-closed property holds: the challenge is not re-minted, so the
    /// presentation the holder is composing still answers.
    /// </summary>
    [TestMethod]
    public async Task EmptyRepollOnActiveExchangeResendsBoundRequestWithoutStateChange()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = RegisterMultiStep(app, holder, TwoPresentationStepWorkflow());

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Initiate → the engine binds step one's challenge / domain and goes active.
        (string challenge1, string domain1) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);

        //Re-poll with an empty body while ACTIVE → the SAME request comes back, no 500, no state change.
        ServerHttpResponse repoll = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, repoll.StatusCode, repoll.Body);
        string challenge2;
        string domain2;
        using(JsonDocument repollDoc = JsonDocument.Parse(repoll.Body))
        {
            JsonElement vpr = repollDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);
            Assert.AreEqual(JsonValueKind.Array, vpr.GetProperty(VcalmParameterNames.Query).ValueKind,
                "§3.4.1: the re-polled request is well-formed (query is an array).");
            challenge2 = vpr.GetProperty(VcalmParameterNames.Challenge).GetString()!;
            domain2 = vpr.GetProperty(VcalmParameterNames.Domain).GetString()!;
        }

        Assert.AreEqual(challenge1, challenge2,
            "§3.6.5: a re-poll re-sends the EXISTING bound challenge — it is not re-minted.");
        Assert.AreEqual(domain1, domain2, "§3.6.5: the re-poll re-sends the same bound domain.");

        using(JsonDocument midState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false))
        {
            Assert.AreEqual("active", midState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
                "§3.6.5: a re-poll causes NO state change — the exchange stays active on the same step.");
            Assert.AreEqual("stepOne", midState.RootElement.GetProperty(VcalmParameterNames.Step).GetString(),
                "The re-poll did not advance the step.");
        }

        //The holder can still answer the (unchanged) bound challenge → verifies → advances.
        string presentMessage = await SignPresentationMessageAsync(holder, challenge1, domain1).ConfigureAwait(false);
        ServerHttpResponse advance = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, presentMessage, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, advance.StatusCode, advance.Body);
        using JsonDocument advanceDoc = JsonDocument.Parse(advance.Body);
        Assert.IsTrue(advanceDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiablePresentationRequest, out _),
            "§3.6.5: the presentation answering the re-polled request verifies and the exchange advances.");
    }


    //--- Workflow configurations -------------------------------------------------------------------

    //Two presentation steps: stepOne requests a presentation and advances to stepTwo, which also requests
    //a presentation and is the final step (no nextStep).
    private static VcalmWorkflowConfiguration TwoPresentationStepWorkflow() => new()
    {
        InitialStep = "stepOne",
        Steps = ImmutableDictionary<string, VcalmWorkflowStep>.Empty
            .SetItem("stepOne", new VcalmWorkflowStep
            {
                CreateChallenge = true,
                VerifiablePresentationRequestJson = DidAuthVprJson,
                PresentationQueryJson = DidAuthQueryJson,
                NextStep = "stepTwo"
            })
            .SetItem("stepTwo", new VcalmWorkflowStep
            {
                CreateChallenge = true,
                VerifiablePresentationRequestJson = DidAuthVprJson,
                PresentationQueryJson = DidAuthQueryJson
            })
    };


    //Present then issue: stepOne requests a presentation and advances to the issue step, which mints a
    //credential from the named template and offers it back (the final step).
    private static VcalmWorkflowConfiguration PresentThenIssueWorkflow(string issuerDid) => new()
    {
        InitialStep = "stepOne",
        Steps = ImmutableDictionary<string, VcalmWorkflowStep>.Empty
            .SetItem("stepOne", new VcalmWorkflowStep
            {
                CreateChallenge = true,
                VerifiablePresentationRequestJson = DidAuthVprJson,
                PresentationQueryJson = DidAuthQueryJson,
                NextStep = "issue"
            })
            .SetItem("issue", new VcalmWorkflowStep
            {
                IssueRequests = [new VcalmIssueRequest { CredentialTemplateId = "urn:tmpl-1" }]
            }),
        CredentialTemplates = [new VcalmCredentialTemplate
        {
            Id = "urn:tmpl-1",
            TemplateType = VcalmTemplateEvaluatorRegistry.JsonataTemplateType,

            //A constant credential body (the minimal engine evaluates literals); the issuer identity is
            //fixed by the issuance seam's ConfiguredIssuer, so the template carries the matching issuer.
            Template =
                "{\"credential\":{" +
                    "\"@context\":[\"https://www.w3.org/ns/credentials/v2\"]," +
                    "\"type\":[\"VerifiableCredential\"]," +
                    "\"issuer\":\"" + issuerDid + "\"," +
                    "\"credentialSubject\":{\"name\":\"Example Holder\"}" +
                "}}"
        }]
    };


    //A single presentation step that names a callback (fired when the step's request is staged).
    private static VcalmWorkflowConfiguration CallbackWorkflow() => new()
    {
        InitialStep = "stepOne",
        Steps = ImmutableDictionary<string, VcalmWorkflowStep>.Empty
            .SetItem("stepOne", new VcalmWorkflowStep
            {
                CreateChallenge = true,
                VerifiablePresentationRequestJson = DidAuthVprJson,
                PresentationQueryJson = DidAuthQueryJson,
                CallbackUrl = "https://callback.test/notify"
            })
    };


    //--- Wiring ------------------------------------------------------------------------------------

    private string RegisterMultiStep(
        TestHostShell app, HolderSigningContext holder, VcalmWorkflowConfiguration? workflow, IssuerSigningContext? issuer = null)
    {
        VerifierKeyMaterial material = app.RegisterClient(ClientId, ClientBaseUri, Capabilities);
        RegisteredMaterials.Add(material);

        app.Server.Vcalm().UseDefaultVcalmJsonParsing(JsonOptions);

        //§3.6.1 / §3.6.2: the real create-workflow endpoint persists the parser-produced configuration
        //here; the exchange's workflow resolves from the same store, so a workflow AUTHORED through the
        //real POST /workflows is the one the exchange engine drives (the seam the missing test crosses).
        app.Server.Vcalm().StoreVcalmWorkflowAsync = (workflowId, configuration, _, _) =>
        {
            WorkflowStore[workflowId] = configuration;

            return ValueTask.CompletedTask;
        };

        app.Server.Vcalm().LoadVcalmWorkflowAsync = (workflowId, _, _) =>
            ValueTask.FromResult(WorkflowStore.GetValueOrDefault(workflowId));

        //§3.6.4 / §3.6.6: resolve exchange id -> flow id over the host's flow store.
        app.Server.Vcalm().ResolveVcalmExchangeFlowIdAsync = (exchangeId, _, _) =>
            ValueTask.FromResult(ResolveExchangeFlowId(app, exchangeId));

        //§3.6.5 / §3.6.8: the exchange runs on a workflow — a directly-supplied config (the unit-style
        //multi-step tests) or, when none is supplied, the single configuration the §3.6.1 endpoint
        //authored into the store (the end-to-end test). The step decision DERIVES from its step graph.
        app.Server.Vcalm().ResolveVcalmWorkflowForExchangeAsync = (exchangeId, _, _) =>
            ValueTask.FromResult(workflow ?? WorkflowStore.Values.FirstOrDefault());

        //The engine verifies the holder's presentation against the bound challenge / domain.
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

        if(issuer is not null)
        {
            //§3.6 issuance-in-exchange: the engine mints credentials with the issuer's eddsa-jcs-2022
            //configuration. The verifier role (also allowed on this tenant) lets the offered credential
            //be POSTed straight to /credentials/verify.
            app.Server.Vcalm().VcalmExchangeIssuance = new VcalmCredentialIssuance
            {
                ConfiguredIssuer = issuer.IssuerDid,
                SigningDescriptors = [issuer.Descriptor],
                MemoryPool = Pool
            };

            app.Server.Vcalm().VcalmCredentialVerification = new VcalmCredentialVerification
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
        }

        return material.Registration.TenantId.Value;
    }


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


    //--- Holder / issuer signing -------------------------------------------------------------------

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


    private async Task<IssuerSigningContext> CreateIssuerSigningContextAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            keyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        keyPair.PublicKey.Dispose();
        OwnedKeys.Add(keyPair.PrivateKey);

        VcalmProofDescriptor descriptor = new()
        {
            PrivateKey = keyPair.PrivateKey,
            VerificationMethodId = verificationMethodId,
            Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
            Canonicalize = JcsCanonicalizer,
            ContextResolver = null,
            EncodeProofValue = ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential = SerializeCredential,
            DeserializeCredential = DeserializeCredential,
            SerializeProofOptions = SerializeProofOptions,
            Encoder = TestSetup.Base58Encoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync
        };

        return new IssuerSigningContext(descriptor, issuerDid);
    }


    //A FRESH, distinct issuer signing context (its own Ed25519 key + did:key) — the precondition for a
    //multi-tenant test where each tenant must mint under a different key (CreateIssuerSigningContextAsync
    //uses the fixed test vector, which would collapse two tenants onto one issuer).
    private async Task<IssuerSigningContext> CreateFreshIssuerSigningContextAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            keyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        keyPair.PublicKey.Dispose();
        OwnedKeys.Add(keyPair.PrivateKey);

        VcalmProofDescriptor descriptor = new()
        {
            PrivateKey = keyPair.PrivateKey,
            VerificationMethodId = verificationMethodId,
            Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
            Canonicalize = JcsCanonicalizer,
            ContextResolver = null,
            EncodeProofValue = ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential = SerializeCredential,
            DeserializeCredential = DeserializeCredential,
            SerializeProofOptions = SerializeProofOptions,
            Encoder = TestSetup.Base58Encoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync
        };

        return new IssuerSigningContext(descriptor, issuerDid);
    }


    //Registers two exchange tenants on one host, each with its own issuer and its own present-then-issue
    //workflow (whose template names that tenant's issuer). The exchange issuance and the workflow resolve
    //per tenant off the dispatcher-stamped context.TenantId; the exchange-flow-id resolution and the
    //identity-based present verification are shared. The holder presents client-side to both tenants.
    private (string SegmentA, string SegmentB) RegisterTwoTenantExchange(
        TestHostShell app, HolderSigningContext holder, IssuerSigningContext issuerA, IssuerSigningContext issuerB)
    {
        VerifierKeyMaterial materialA = app.RegisterClient(
            "https://multistep-a.client.test", new Uri("https://multistep-a.client.test"), Capabilities);
        RegisteredMaterials.Add(materialA);
        VerifierKeyMaterial materialB = app.RegisterClient(
            "https://multistep-b.client.test", new Uri("https://multistep-b.client.test"), Capabilities);
        RegisteredMaterials.Add(materialB);

        string segmentA = materialA.Registration.TenantId.Value;
        string segmentB = materialB.Registration.TenantId.Value;

        VcalmIntegration vcalm = app.Server.Vcalm();
        vcalm.UseDefaultVcalmJsonParsing(JsonOptions);

        Dictionary<string, VcalmCredentialIssuance> issuanceBySegment = new(StringComparer.Ordinal)
        {
            [segmentA] = new VcalmCredentialIssuance
            {
                ConfiguredIssuer = issuerA.IssuerDid, SigningDescriptors = [issuerA.Descriptor], MemoryPool = Pool
            },
            [segmentB] = new VcalmCredentialIssuance
            {
                ConfiguredIssuer = issuerB.IssuerDid, SigningDescriptors = [issuerB.Descriptor], MemoryPool = Pool
            }
        };
        Dictionary<string, VcalmWorkflowConfiguration> workflowBySegment = new(StringComparer.Ordinal)
        {
            [segmentA] = PresentThenIssueWorkflow(issuerA.IssuerDid),
            [segmentB] = PresentThenIssueWorkflow(issuerB.IssuerDid)
        };

        vcalm.ResolveVcalmExchangeIssuanceAsync = (context, _) =>
            ValueTask.FromResult(issuanceBySegment.GetValueOrDefault(Seg(context)));
        vcalm.ResolveVcalmWorkflowForExchangeAsync = (exchangeId, context, _) =>
            ValueTask.FromResult(workflowBySegment.GetValueOrDefault(Seg(context)));

        vcalm.ResolveVcalmExchangeFlowIdAsync = (exchangeId, _, _) =>
            ValueTask.FromResult(ResolveExchangeFlowId(app, exchangeId));

        vcalm.VcalmExchangeVerification = new VcalmCredentialVerification
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

        return (segmentA, segmentB);
    }


    //Runs one tenant's present-then-issue exchange end to end (create -> initiate -> present -> the
    //engine advances to the issue step and offers the minted credential back) and returns the minted
    //credential's proof verification method — the cryptographic witness of WHICH tenant's key signed it.
    private async Task<string> RunIssueExchangeAndGetMintedVmAsync(TestHostShell app, string segment, HolderSigningContext holder)
    {
        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);
        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);
        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);

        ServerHttpResponse offered = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, offered.StatusCode, offered.Body);
        using JsonDocument offeredDoc = JsonDocument.Parse(offered.Body);
        JsonElement vp = offeredDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentation);
        JsonElement issuedCredential = vp.GetProperty("verifiableCredential")[0];
        JsonElement proof = issuedCredential.GetProperty("proof");
        JsonElement firstProof = proof.ValueKind == JsonValueKind.Array ? proof[0] : proof;

        return firstProof.GetProperty("verificationMethod").GetString()!;
    }


    //The dispatcher-stamped tenant segment on the request context — the key the per-tenant exchange
    //issuance and workflow resolvers scope themselves by.
    private static string Seg(ExchangeContext context) =>
        context.TenantId is { } tenant
            ? tenant.Value
            : throw new InvalidOperationException("The dispatcher did not stamp a tenant on the request context.");


    //--- Helpers -----------------------------------------------------------------------------------

    //Initiates the exchange and returns the engine's bound (challenge, domain) for the first step's
    //request — the holder MUST sign against BOTH, as the engine verifies against both.
    private async Task<(string Challenge, string Domain)> InitiateAndExtractBindingAsync(
        TestHostShell app, string segment, string exchangeId)
    {
        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, initiate.StatusCode, initiate.Body);
        using JsonDocument requestDoc = JsonDocument.Parse(initiate.Body);
        JsonElement vpr = requestDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);

        return (vpr.GetProperty(VcalmParameterNames.Challenge).GetString()!,
            vpr.GetProperty(VcalmParameterNames.Domain).GetString()!);
    }


    private async Task<string> SignPresentationMessageAsync(HolderSigningContext holder, string challenge, string domain)
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

        string securedJson = holder.Signing.SerializePresentation(secured);

        return "{\"verifiablePresentation\":" + securedJson + "}";
    }


    private async Task<string> CreateExchangeAndGetIdAsync(TestHostShell app, string segment)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateExchange, "POST",
            new RequestFields(), "{}", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
        using JsonDocument created = JsonDocument.Parse(response.Body);

        return created.RootElement.GetProperty(VcalmParameterNames.Id).GetString()!;
    }


    private async Task<JsonDocument> GetExchangeStateAsync(TestHostShell app, string segment, string exchangeId)
    {
        ServerHttpResponse response = await app.DispatchVcalmExchangeByIdAsync(
            segment, "GET", exchangeId, jsonBody: null, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    //§3.6.1: author a workflow through the REAL POST /workflows endpoint (the parser produces the
    //unified step contract the exchange engine then drives).
    private async Task CreateWorkflowAsync(TestHostShell app, string segment, string workflowJson)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateWorkflow, "POST",
            new RequestFields(), workflowJson, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
    }


    private sealed record HolderSigningContext(VcalmPresentationSigning Signing, string HolderDid);

    private sealed record IssuerSigningContext(VcalmProofDescriptor Descriptor, string IssuerDid);
}
