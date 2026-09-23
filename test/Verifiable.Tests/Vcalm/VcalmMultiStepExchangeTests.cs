using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
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
using Verifiable.Json;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;

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
    /// <summary>The MSTest context, whose cancellation token bounds every dispatch these tests make.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The host's clock, fixed at the canonical epoch.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The pool the did:key resolver, the verification configuration and the signing configurations rent from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The client identifier the multi-step tenant is registered under.</summary>
    private const string ClientId = "https://multistep.client.test";

    /// <summary>The base URI the multi-step tenant is registered under.</summary>
    private static Uri ClientBaseUri { get; } = new("https://multistep.client.test");

    /// <summary>
    /// The capabilities of the multi-step tenant: it runs exchanges, signs the holder's presentations, authors
    /// workflows and verifies presentations.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> Capabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmExchange,
            WellKnownVcalmCapabilities.VcalmHolder,
            WellKnownVcalmCapabilities.VcalmAdministration,
            WellKnownVcalmCapabilities.VcalmVerifier);

    /// <summary>The serializer options every JSON delegate of these tests uses.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>Builds the holder's and the issuers' did:key documents from their public keys.</summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    /// <summary>The DID resolver the engine verifies presentations with: did:key, resolved locally.</summary>
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

    /// <summary>Serializes a credential for issuance, verification and the wire.</summary>
    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    /// <summary>Reads the credential a workflow template rendered, for the exchange's issuance.</summary>
    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    /// <summary>Serializes the proof options a Data Integrity proof hashes.</summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    /// <summary>The context the holder signs its presentations under, outside any request.</summary>
    private static ExchangeContext EmptyContext { get; } = [];

    /// <summary>The tenant registrations of the running test, disposed after it.</summary>
    private List<VerifierKeyMaterial> RegisteredMaterials { get; } = [];

    /// <summary>The private keys of the running test, disposed after it.</summary>
    private List<IDisposable> OwnedKeys { get; } = [];

    /// <summary>
    /// The workflow store the §3.6.1 create endpoint persists to and the exchange's workflow resolves from, so an
    /// exchange runs on the same parser-produced configuration the endpoint stored.
    /// </summary>
    private Dictionary<string, VcalmWorkflowConfiguration> WorkflowStore { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// The query of the presentation-requesting steps: each asks for a DID Authentication the holder satisfies by
    /// controlling a did:key. The engine binds a fresh challenge per step.
    /// </summary>
    private const string DidAuthQueryJson =
        "[{\"type\":\"DIDAuthentication\",\"acceptedMethods\":[{\"method\":\"key\"}]}]";

    /// <summary>
    /// The §3.4 verifiable presentation request wrapping <see cref="DidAuthQueryJson"/>, the step contract the
    /// workflow parser produces: the whole <c>verifiablePresentationRequest</c> object, whose <c>query</c> is
    /// required, round-trips through §3.6.2, and the engine sends its query under the challenge and domain it binds.
    /// </summary>
    private const string DidAuthVprJson = "{\"query\":" + DidAuthQueryJson + "}";


    /// <summary>Disposes the tenant registrations and keys the finished test created.</summary>
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
        string segment = await RegisterMultiStepAsync(app, holder, TwoPresentationStepWorkflow()).ConfigureAwait(false);

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
            segment, "POST", exchangeId, presentMessage1, [], TestContext.CancellationToken).ConfigureAwait(false);

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
            segment, "POST", exchangeId, presentMessage2, [], TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = await RegisterMultiStepAsync(app, holder, TwoPresentationStepWorkflow()).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Step 1: initiate, capture step 1's (challenge, domain), present it correctly → advance to step 2.
        (string challenge1, string domain1) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);
        string present1 = await SignPresentationMessageAsync(holder, challenge1, domain1).ConfigureAwait(false);
        ServerHttpResponse advance = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present1, [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, advance.StatusCode, advance.Body);

        //At step 2, REPLAY step 1's challenge (not the fresh step-2 challenge the engine just bound).
        string replay = await SignPresentationMessageAsync(holder, challenge1, domain1).ConfigureAwait(false);
        ServerHttpResponse refused = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, replay, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        using JsonDocument problem = JsonDocument.Parse(refused.Body);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#CRYPTOGRAPHIC_SECURITY_ERROR",
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
    /// carries a valid eddsa-jcs-2022 proof under a resolvable did:key issuer). The template renders
    /// the <see href="https://www.w3.org/TR/vcalm-1.0/#example-a-basic-workflow">VCALM 1.0 Example 13
    /// ("A Basic Workflow")</see> <c>{"credential": {...}}</c> wrapper shape: the engine signs the
    /// unwrapped inner credential, never the wrapper, so the signed and verified body carries the
    /// credential's own top-level members rather than a single <c>credential</c> member.
    /// </summary>
    [TestMethod]
    public async Task IssueRequestsStepMintsCredentialAndOffersItBack()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        IssuerSigningContext issuer = await CreateIssuerSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterMultiStepAsync(app, holder, PresentThenIssueWorkflow(issuer.IssuerDid), issuer).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Step 1: initiate → present a DID-auth → the engine advances to the issue step, mints the
        //credential, and offers it back in the same reply as a verifiablePresentation.
        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);
        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);

        ServerHttpResponse offered = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, offered.StatusCode, offered.Body);
        using JsonDocument offeredDoc = JsonDocument.Parse(offered.Body);
        Assert.IsTrue(offeredDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiablePresentation, out JsonElement vp),
            "§3.6.5 / §3.6.8: the issue step offers the minted credential back as a verifiablePresentation.");

        JsonElement credentials = vp.GetProperty("verifiableCredential");
        Assert.AreEqual(1, credentials.GetArrayLength(), "The offered presentation carries one issued credential.");
        JsonElement issuedCredential = credentials[0];

        //VCALM 1.0 Example 13's { "credential": {...} } wrapper is stripped before signing: the
        //issued credential carries its OWN top-level members, not a single "credential" member.
        Assert.IsFalse(issuedCredential.TryGetProperty("credential", out _),
            "The rendered {\"credential\": {...}} wrapper is stripped before signing (VCALM 1.0 Example 13).");
        Assert.IsTrue(issuedCredential.TryGetProperty("@context", out _),
            "The unwrapped inner credential's own @context is signed, not the wrapper's.");

        //The issued credential VERIFIES: POST it straight to /credentials/verify on the same tenant.
        string issuedCredentialJson = issuedCredential.GetRawText();
        string verifyBody = "{\"verifiableCredential\":" + issuedCredentialJson + "}";
        ServerHttpResponse verify = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, "POST",
            new RequestFields(), verifyBody, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, verify.StatusCode, verify.Body);
        using JsonDocument verifyDoc = JsonDocument.Parse(verify.Body);
        Assert.IsTrue(verifyDoc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "§3.6: the credential the exchange issued verifies (a valid eddsa-jcs-2022 proof under a resolvable issuer).");

        using JsonDocument finalState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("complete", finalState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "The issue step completes the exchange.");
    }


    /// <summary>
    /// §3.6.1 reserves <c>results</c> for the accumulated <c>variables.results</c> object (see
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see>: "a
    /// workflow will also reference the reserved <c>results</c> variable"): an issueRequest whose OWN
    /// per-request variables object redefines <c>results</c> is refused with a
    /// <c>MALFORMED_VALUE_ERROR</c> rather than composing a template-evaluation document carrying two
    /// <c>results</c> members.
    /// </summary>
    [TestMethod]
    public async Task IssueRequestVariablesRedefiningReservedResultsIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        IssuerSigningContext issuer = await CreateIssuerSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterMultiStepAsync(
            app, holder, PresentThenIssueWorkflowWithReservedVariablesCollision(issuer.IssuerDid), issuer).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);
        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);
        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);

        ServerHttpResponse refused = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        using JsonDocument problem = JsonDocument.Parse(refused.Body);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "An issueRequest redefining the reserved 'results' member is a MALFORMED_VALUE_ERROR refusal.");
    }


    /// <summary>
    /// §3.6.1's <c>credentialTemplates[].type</c> selects the evaluation mechanism; a type no evaluator
    /// is registered for is refused with <c>MALFORMED_VALUE_ERROR</c>, and the refusal states that the
    /// type is not registered WITHOUT repeating the client-supplied value back on the wire.
    /// </summary>
    [TestMethod]
    public async Task IssueRequestWithUnregisteredTemplateTypeRefusesWithoutEchoingTheType()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        IssuerSigningContext issuer = await CreateIssuerSigningContextAsync().ConfigureAwait(false);
        const string distinctiveTemplateType = "vnd.example.unregistered-mechanism-9f2c";
        string segment = await RegisterMultiStepAsync(
            app, holder, PresentThenIssueWorkflowWithUnregisteredTemplateType(issuer.IssuerDid, distinctiveTemplateType), issuer).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);
        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);
        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);

        ServerHttpResponse refused = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        using JsonDocument problem = JsonDocument.Parse(refused.Body);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "An unregistered template type is a MALFORMED_VALUE_ERROR refusal, unchanged by not echoing the type.");
        Assert.DoesNotContain(distinctiveTemplateType, refused.Body, StringComparison.Ordinal,
            "The client-supplied template type must not be echoed back into the 400 problem detail.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#issue-credential">VCALM §3.2.1</see>: "If a provided credential
    /// already contains one or more proofs, the behavior is determined by the configuration of the issuer instance",
    /// one configuration being "Error Handling: Return an error if credential values that contain existing proof values
    /// are provided, when the instance is configured to only accept credentials without existing proofs." A credential
    /// template that renders a <c>proof</c> member hands the exchange's issuance an existing proof, so under that
    /// default configuration the issue step fails with the issuing refusal, a MALFORMED_VALUE_ERROR, rather than the
    /// instance's proof being chained onto the rendered one.
    /// </summary>
    [TestMethod]
    public async Task TemplateRenderedProofIsRefusedUnderTheDefaultExistingProofHandling()
    {
        using JsonDocument refused = await RunIssueExchangeWithTemplateProofOverWireAsync(
            "proof", CompleteRenderedProof, VcalmExistingProofHandling.Error).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            refused.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString());
        Assert.Contains("already contains a proof", refused.RootElement.GetProperty("detail").GetString()!, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#issue-credential">VCALM §3.2.1</see>: "If a provided credential
    /// already contains one or more proofs, the behavior is determined by the configuration of the issuer instance",
    /// one configuration being "Error Handling: Return an error if credential values that contain existing proof values
    /// are provided, when the instance is configured to only accept credentials without existing proofs." A template that
    /// spells the <c>proof</c> member name with a JSON escape (<c>"proof"</c>) renders the same member,
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 §7</see>: "Any character may be escaped", so
    /// the credential it renders already contains a proof, and under that default configuration the issue step fails
    /// with the issuing refusal, a MALFORMED_VALUE_ERROR, rather than the instance's proof being chained onto it.
    /// </summary>
    [TestMethod]
    public async Task TemplateRenderedEscapedProofMemberIsRefusedUnderTheDefaultExistingProofHandling()
    {
        using JsonDocument refused = await RunIssueExchangeWithTemplateProofOverWireAsync(
            "pr\\u006fof", CompleteRenderedProof, VcalmExistingProofHandling.Error).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            refused.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString());
        Assert.Contains("already contains a proof", refused.RootElement.GetProperty("detail").GetString()!, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#options">VCALM §2.4</see>: "Implementations MUST throw an error if
    /// an endpoint receives data, options, or option values that it does not understand or know how to process." An
    /// exchange whose issuance chains onto existing proofs still refuses a template-rendered proof that lacks its
    /// <c>verificationMethod</c>, a member <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data
    /// Integrity §4.4</see> requires of every proof, before any signing, exactly as the issuing endpoint does.
    /// </summary>
    [TestMethod]
    public async Task TemplateRenderedIncompleteProofIsRefusedUnderProofChainHandling()
    {
        const string RenderedProof =
            "{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\",\"proofPurpose\":\"assertionMethod\","
            + "\"proofValue\":\"z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk\"}";
        using JsonDocument refused = await RunIssueExchangeWithTemplateProofOverWireAsync(
            "proof", RenderedProof, VcalmExistingProofHandling.ProofChain).ConfigureAwait(false);

        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            refused.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString());
        Assert.Contains("lacks its type, verificationMethod or proofPurpose", refused.RootElement.GetProperty("detail").GetString()!,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// A complete Data Integrity proof a credential template renders: it carries every member
    /// <see href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">Data Integrity §4.4</see> requires, so only the
    /// existing-proof configuration decides whether the issuing step accepts it.
    /// </summary>
    private const string CompleteRenderedProof =
        "{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\",\"verificationMethod\":\"did:example:issuer#key-1\","
        + "\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk\"}";


    /// <summary>
    /// Runs a present-then-issue exchange over the real wire whose credential template renders
    /// <paramref name="renderedProofJson"/> as the credential's proof under the member name
    /// <paramref name="proofMemberName"/>: creates the exchange, initiates it, presents a DID-authentication
    /// presentation, and returns the refusal the issuing step answers with.
    /// </summary>
    /// <param name="proofMemberName">The member name as the template writes it, JSON escapes included.</param>
    /// <param name="renderedProofJson">The proof member value the template renders.</param>
    /// <param name="existingProofHandling">How the exchange issuance treats that rendered proof.</param>
    /// <returns>The parsed 400 problem body; the caller disposes it.</returns>
    private async Task<JsonDocument> RunIssueExchangeWithTemplateProofOverWireAsync(
        string proofMemberName, string renderedProofJson, VcalmExistingProofHandling existingProofHandling)
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        IssuerSigningContext issuer = await CreateIssuerSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterMultiStepAsync(
            app, holder, PresentThenIssueWorkflowWithTemplateProof(issuer.IssuerDid, proofMemberName, renderedProofJson), issuer,
            existingProofHandling).ConfigureAwait(false);

        string exchangeId;
        using(JsonDocument created = await VcalmWireFixtures.PostEndpointWireAsync(
            app, segment, WellKnownVcalmEndpointNames.VcalmCreateExchange, "{}", 201, TestContext.CancellationToken).ConfigureAwait(false))
        {
            exchangeId = created.RootElement.GetProperty(VcalmParameterNames.Id).GetString()!;
        }

        string challenge;
        string domain;
        using(JsonDocument request = await VcalmWireFixtures.PostExchangeWireAsync(
            app, segment, exchangeId, "{}", 200, TestContext.CancellationToken).ConfigureAwait(false))
        {
            JsonElement vpr = request.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);
            challenge = vpr.GetProperty(VcalmParameterNames.Challenge).GetString()!;
            domain = vpr.GetProperty(VcalmParameterNames.Domain).GetString()!;
        }

        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);

        return await VcalmWireFixtures.PostExchangeWireAsync(
            app, segment, exchangeId, present, 400, TestContext.CancellationToken).ConfigureAwait(false);
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

        (string segmentA, string segmentB) = await RegisterTwoTenantExchangeAsync(app, issuerA, issuerB).ConfigureAwait(false);

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
        string segment = await RegisterMultiStepAsync(app, holder, PresentThenIssueWorkflow(issuer.IssuerDid), issuer).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);
        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);

        ServerHttpResponse offered = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, [], TestContext.CancellationToken).ConfigureAwait(false);

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

        string segment = await RegisterMultiStepAsync(app, holder, CallbackWorkflow()).ConfigureAwait(false);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.DeliverVcalmCallbackAsync = (url, body, _, _) =>
            {
                deliveredCallbacks.Add((url, body));

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Initiate → the single presentation-requesting step (which names a callback) is reached and
        //fires its callback after staging the presentation request.
        _ = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);

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
            segment, "urn:callback:abc123", callbackBody, [], TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = await RegisterMultiStepAsync(app, holder, CallbackWorkflow()).ConfigureAwait(false);

        ServerHttpResponse response = await app.DispatchVcalmCallbackAsync(
            segment, "urn:callback:abc123", "{\"notAnEvent\":true}", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, "§3.6.7: a body that is not {event{data{exchangeId}}} is 400.");
    }


    /// <summary>
    /// §3.6 cycle bounding: a workflow whose step graph cycles (supplied DIRECTLY to the exchange
    /// engine, bypassing §3.6.1 create-time validation) does NOT loop forever — the engine caps the
    /// per-message step walk and fails the exchange as invalid. The <c>ImmutableDictionary&lt;,&gt;.Empty</c>
    /// read that seeds the cyclic step map needs no lock: it is a get-only BCL singleton that nothing mutates in place.
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

        string segment = await RegisterMultiStepAsync(app, holder, cyclic).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Initiate the exchange — the walk would loop a→b→a→… forever; the engine bounds it and fails.
        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", [], TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = await RegisterMultiStepAsync(app, holder, workflow: null).ConfigureAwait(false);

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
            segment, "POST", exchangeId, "{}", [], TestContext.CancellationToken).ConfigureAwait(false);

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
            segment, "POST", exchangeId, presentMessage, [], TestContext.CancellationToken).ConfigureAwait(false);

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
        string segment = await RegisterMultiStepAsync(app, holder, TwoPresentationStepWorkflow()).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);

        //Initiate → the engine binds step one's challenge / domain and goes active.
        (string challenge1, string domain1) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);

        //Re-poll with an empty body while ACTIVE → the SAME request comes back, no 500, no state change.
        ServerHttpResponse repoll = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", [], TestContext.CancellationToken).ConfigureAwait(false);

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
            segment, "POST", exchangeId, presentMessage, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, advance.StatusCode, advance.Body);
        using JsonDocument advanceDoc = JsonDocument.Parse(advance.Body);
        Assert.IsTrue(advanceDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiablePresentationRequest, out _),
            "§3.6.5: the presentation answering the re-polled request verifies and the exchange advances.");
    }


    /// <summary>
    /// §3.6.1 <c>presentationSchema</c>: a presented presentation that conforms to the step's
    /// declared JSON Schema (type MUST be <c>JsonSchema</c>) passes and the exchange completes.
    /// See <see href="https://www.w3.org/TR/vcalm-1.0/">VCALM 1.0 §3.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PresentationConformingToStepSchemaCompletes()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterMultiStepAsync(app, holder, SchemaGatedWorkflow(ProofRequiringSchemaEnvelope)).ConfigureAwait(false);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmSchemaValidators.Register(
                VcalmSchemaValidatorRegistry.JsonSchemaType,
                SchemaValidationTestUtilities.CreateVeritasSchemaValidator());
        }).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);
        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);

        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);
        ServerHttpResponse complete = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, complete.StatusCode, complete.Body);
        using JsonDocument finalState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("complete", finalState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "A schema-conforming presentation completes the schema-gated step.");
    }


    /// <summary>
    /// §3.6.1 <c>presentationSchema</c> fail-closed: a cryptographically valid presentation that
    /// VIOLATES the step's declared schema is refused with a <c>MALFORMED_VALUE_ERROR</c> and the
    /// exchange goes invalid — the schema Failure outcome per
    /// <see href="https://www.w3.org/TR/vc-json-schema/#evaluation">VC JSON Schema §4.2</see>.
    /// </summary>
    [TestMethod]
    public async Task PresentationViolatingStepSchemaIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string segment = await RegisterMultiStepAsync(app, holder, SchemaGatedWorkflow(AbsentMemberRequiringSchemaEnvelope)).ConfigureAwait(false);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmSchemaValidators.Register(
                VcalmSchemaValidatorRegistry.JsonSchemaType,
                SchemaValidationTestUtilities.CreateVeritasSchemaValidator());
        }).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);
        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);

        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);
        ServerHttpResponse refused = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        using JsonDocument problem = JsonDocument.Parse(refused.Body);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "A schema-violating presentation is a MALFORMED_VALUE_ERROR refusal.");

        using JsonDocument invalidState = await GetExchangeStateAsync(app, segment, exchangeId).ConfigureAwait(false);
        Assert.AreEqual("invalid", invalidState.RootElement.GetProperty(VcalmParameterNames.State).GetString(),
            "The schema refusal drives the exchange to invalid.");
    }


    /// <summary>
    /// §3.6.1 fail-closed: a step declaring a <c>presentationSchema</c> whose mechanism has no
    /// registered validator refuses presented presentations — the workflow author demanded a check
    /// this instance cannot run, so the check is not skipped.
    /// </summary>
    [TestMethod]
    public async Task UnregisteredSchemaMechanismRefusesPresentation()
    {
        await using TestHostShell app = new(TimeProvider);
        HolderSigningContext holder = await CreateHolderSigningContextAsync().ConfigureAwait(false);
        string vendorEnvelope = /*lang=json,strict*/ """{ "type": "VendorMechanism" }""";
        string segment = await RegisterMultiStepAsync(app, holder, SchemaGatedWorkflow(vendorEnvelope)).ConfigureAwait(false);

        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);
        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);

        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);
        ServerHttpResponse refused = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, refused.StatusCode, refused.Body);
        using JsonDocument problem = JsonDocument.Parse(refused.Body);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "An unrunnable declared check refuses fail-closed.");
    }


    /// <summary>A workflow of a single presentation step gated by a §3.6.1 <c>presentationSchema</c> envelope.</summary>
    /// <param name="presentationSchemaJson">The step's <c>presentationSchema</c> envelope.</param>
    private static VcalmWorkflowConfiguration SchemaGatedWorkflow(string presentationSchemaJson) => new()
    {
        InitialStep = "stepOne",
        Steps = ImmutableDictionary<string, VcalmWorkflowStep>.Empty
            .SetItem("stepOne", new VcalmWorkflowStep
            {
                CreateChallenge = true,
                VerifiablePresentationRequestJson = DidAuthVprJson,
                PresentationQueryJson = DidAuthQueryJson,
                PresentationSchemaJson = presentationSchemaJson
            })
    };

    /// <summary>
    /// A <c>presentationSchema</c> envelope requiring a <c>proof</c> member, which the signed DID Authentication
    /// presentation always carries, so it passes every presentation these tests sign.
    /// </summary>
    private const string ProofRequiringSchemaEnvelope = /*lang=json,strict*/ """
        {
          "type": "JsonSchema",
          "jsonSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["proof"]
          }
        }
        """;

    /// <summary>
    /// A <c>presentationSchema</c> envelope requiring a member no presentation carries, so it refuses every
    /// presentation.
    /// </summary>
    private const string AbsentMemberRequiringSchemaEnvelope = /*lang=json,strict*/ """
        {
          "type": "JsonSchema",
          "jsonSchema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["definitelyAbsentMember"]
          }
        }
        """;


    /// <summary>
    /// A workflow of two presentation steps: <c>stepOne</c> requests a presentation and advances to
    /// <c>stepTwo</c>, which also requests a presentation and is the final step, having no <c>nextStep</c>.
    /// </summary>
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


    /// <summary>
    /// A present-then-issue workflow: <c>stepOne</c> requests a presentation and advances to the final
    /// <c>issue</c> step, which mints a credential from the named template and offers it back.
    /// </summary>
    /// <param name="issuerDid">The issuer the template's credential names, matching the issuance configuration.</param>
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
            TemplateType = VcalmTemplateEvaluatorRegistry.LiteralTemplateType,

            //A constant credential body — no variable references, so the literal template type (its
            //source IS the rendered result, no engine needed) applies. The issuer identity is fixed by
            //the issuance seam's ConfiguredIssuer, so the template carries the matching issuer.
            //
            //Wrapped in a "credential" member, matching VCALM 1.0 Example 13's ("A Basic Workflow")
            //POST /credentials/issue body shape: the rendered value is the whole request body, not
            //the bare credential, and VcalmWorkflowStepEngine unwraps the "credential" member before
            //signing regardless of which evaluator rendered it.
            Template =
                "{\"credential\":{" +
                    "\"@context\":[\"https://www.w3.org/ns/credentials/v2\"]," +
                    "\"type\":[\"VerifiableCredential\"]," +
                    "\"issuer\":\"" + issuerDid + "\"," +
                    "\"credentialSubject\":{\"name\":\"Example Holder\"}" +
                "}}"
        }]
    };


    /// <summary>
    /// The present-then-issue shape of <see cref="PresentThenIssueWorkflow"/>, except that the credential template
    /// renders a credential carrying <paramref name="renderedProofJson"/> as its <c>proof</c> member, written as
    /// <paramref name="proofMemberName"/>, so the issuing step receives an existing proof from the template itself.
    /// </summary>
    /// <param name="issuerDid">The issuer the rendered credential names, matching the issuance configuration.</param>
    /// <param name="proofMemberName">The member name as the template writes it, JSON escapes included.</param>
    /// <param name="renderedProofJson">The <c>proof</c> member value the template renders.</param>
    private static VcalmWorkflowConfiguration PresentThenIssueWorkflowWithTemplateProof(string issuerDid, string proofMemberName, string renderedProofJson) => new()
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
            TemplateType = VcalmTemplateEvaluatorRegistry.LiteralTemplateType,
            Template =
                "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"]," +
                "\"type\":[\"VerifiableCredential\"]," +
                "\"issuer\":\"" + issuerDid + "\"," +
                "\"credentialSubject\":{\"name\":\"Example Holder\"}," +
                "\"" + proofMemberName + "\":" + renderedProofJson + "}"
        }]
    };


    /// <summary>
    /// The present-then-issue shape of <see cref="PresentThenIssueWorkflow"/>, except that the issue step's
    /// <c>issueRequest</c> carries its own <c>results</c> variable, the §3.6.1 name reserved for the accumulated
    /// results the presentation step already populated, so the template-variables composition refuses rather than
    /// emitting a document with two <c>results</c> members.
    /// </summary>
    /// <param name="issuerDid">The issuer the template's credential names, matching the issuance configuration.</param>
    private static VcalmWorkflowConfiguration PresentThenIssueWorkflowWithReservedVariablesCollision(string issuerDid) => new()
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
                IssueRequests =
                [
                    new VcalmIssueRequest { CredentialTemplateId = "urn:tmpl-1", VariablesJson = "{\"results\":true}" }
                ]
            }),
        CredentialTemplates = [new VcalmCredentialTemplate
        {
            Id = "urn:tmpl-1",
            TemplateType = VcalmTemplateEvaluatorRegistry.LiteralTemplateType,
            Template =
                "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"]," +
                "\"type\":[\"VerifiableCredential\"]," +
                "\"issuer\":\"" + issuerDid + "\"," +
                "\"credentialSubject\":{\"name\":\"Example Holder\"}}"
        }]
    };


    /// <summary>
    /// The present-then-issue shape of <see cref="PresentThenIssueWorkflow"/>, except that the credential template
    /// names a type no evaluator is registered for, which the §3.6.1 template evaluation refuses.
    /// </summary>
    /// <param name="issuerDid">The issuer the template's credential names, matching the issuance configuration.</param>
    /// <param name="templateType">The unregistered template type.</param>
    private static VcalmWorkflowConfiguration PresentThenIssueWorkflowWithUnregisteredTemplateType(string issuerDid, string templateType) => new()
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
            TemplateType = templateType,
            Template =
                "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"]," +
                "\"type\":[\"VerifiableCredential\"]," +
                "\"issuer\":\"" + issuerDid + "\"," +
                "\"credentialSubject\":{\"name\":\"Example Holder\"}}"
        }]
    };


    /// <summary>
    /// A workflow of a single presentation step that names a §3.6.7 callback, fired when the step's request is
    /// staged.
    /// </summary>
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


    /// <summary>
    /// Registers an exchange service with a multi-step workflow and its state-storage delegates.
    /// </summary>
    /// <param name="app">The host shell the tenant is registered with.</param>
    /// <param name="holder">The holder whose presentations the exchange verifies.</param>
    /// <param name="workflow">The workflow the exchange runs, or <see langword="null"/> for the one authored through the endpoint.</param>
    /// <param name="issuer">The issuer an issuing step signs with, or <see langword="null"/> when no step issues.</param>
    /// <param name="existingProofHandling">How the exchange issuance treats a proof its template renders.</param>
    /// <returns>The tenant's path segment.</returns>
    private async Task<string> RegisterMultiStepAsync(
        TestHostShell app,
        HolderSigningContext holder,
        VcalmWorkflowConfiguration? workflow,
        IssuerSigningContext? issuer = null,
        VcalmExistingProofHandling existingProofHandling = VcalmExistingProofHandling.Error)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(ClientId, ClientBaseUri, Capabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(material);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        //§3.6.1 / §3.6.2: the create-workflow endpoint persists the parser-produced configuration here; the
        //exchange's workflow resolves from the same store, so a workflow authored through POST /workflows is
        //the one the exchange engine drives.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmWorkflowAsync = (workflowId, configuration, _, _) =>
            {
                WorkflowStore[workflowId] = configuration;

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.LoadVcalmWorkflowAsync = (workflowId, _, _) =>
                ValueTask.FromResult(WorkflowStore.GetValueOrDefault(workflowId));
        }).ConfigureAwait(false);

        //§3.6.4 / §3.6.6: resolve exchange id -> flow id over the host's flow store.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmExchangeFlowIdAsync = (exchangeId, _, _) =>
                ValueTask.FromResult(ResolveExchangeFlowId(app, exchangeId));
        }).ConfigureAwait(false);

        //§3.6.5 / §3.6.8: the exchange runs on a workflow — a directly-supplied config (the unit-style
        //multi-step tests) or, when none is supplied, the single configuration the §3.6.1 endpoint
        //authored into the store (the end-to-end test). The step decision DERIVES from its step graph.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmWorkflowForExchangeAsync = (exchangeId, _, _) =>
                ValueTask.FromResult(workflow ?? WorkflowStore.Values.FirstOrDefault());
        }).ConfigureAwait(false);

        //The engine verifies the holder's presentation against the bound challenge / domain.
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

        if(issuer is not null)
        {
            //§3.6 issuance-in-exchange: the engine mints credentials with the issuer's eddsa-jcs-2022
            //configuration. The verifier role (also allowed on this tenant) lets the offered credential
            //be POSTed straight to /credentials/verify.
            await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.VcalmExchangeIssuance = new VcalmCredentialIssuance
                {
                    ConfiguredIssuer = issuer.IssuerDid,
                    SigningDescriptors = [issuer.Descriptor],
                    ExistingProofHandling = existingProofHandling,
                    MemoryPool = Pool
                };
            }).ConfigureAwait(false);

            await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.VcalmCredentialVerification = new VcalmCredentialVerification
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
        }

        return material.Registration.TenantId.Value;
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
    /// resolves locally, with the holder DID the presentations name.
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
    /// Builds the exchange issuer's eddsa-jcs-2022 signing descriptor over the fixed Ed25519 test key, under the
    /// did:key that key yields.
    /// </summary>
    /// <returns>The issuer's signing descriptor and DID.</returns>
    private async Task<IssuerSigningContext> CreateIssuerSigningContextAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            keyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
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
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync
        };

        return new IssuerSigningContext(descriptor, issuerDid);
    }


    /// <summary>
    /// Builds a distinct issuer signing context with its own fresh Ed25519 key and did:key, so each tenant of a
    /// multi-tenant test mints under a different key; <see cref="CreateIssuerSigningContextAsync"/> uses the fixed
    /// test key, which would put two tenants under one issuer.
    /// </summary>
    /// <returns>The issuer's signing descriptor and DID.</returns>
    private async Task<IssuerSigningContext> CreateFreshIssuerSigningContextAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            keyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
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
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync
        };

        return new IssuerSigningContext(descriptor, issuerDid);
    }


    /// <summary>
    /// Registers the two tenant exchange services with independent workflow state.
    /// </summary>
    /// <param name="app">The host the tenants are registered on.</param>
    /// <param name="issuerA">The issuer the first tenant mints under.</param>
    /// <param name="issuerB">The issuer the second tenant mints under.</param>
    /// <returns>The two tenants' path segments.</returns>
    private async Task<(string SegmentA, string SegmentB)> RegisterTwoTenantExchangeAsync(
        TestHostShell app, IssuerSigningContext issuerA, IssuerSigningContext issuerB)
    {
        VerifierKeyMaterial materialA = await app.RegisterClientAsync(
            "https://multistep-a.client.test", new Uri("https://multistep-a.client.test"), Capabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(materialA);
        VerifierKeyMaterial materialB = await app.RegisterClientAsync(
            "https://multistep-b.client.test", new Uri("https://multistep-b.client.test"), Capabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(materialB);

        string segmentA = materialA.Registration.TenantId.Value;
        string segmentB = materialB.Registration.TenantId.Value;

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        Dictionary<string, VcalmCredentialIssuance> issuanceBySegment = new(StringComparer.Ordinal)
        {
            [segmentA] = new VcalmCredentialIssuance
            {
                ConfiguredIssuer = issuerA.IssuerDid,
                SigningDescriptors = [issuerA.Descriptor],
                MemoryPool = Pool
            },
            [segmentB] = new VcalmCredentialIssuance
            {
                ConfiguredIssuer = issuerB.IssuerDid,
                SigningDescriptors = [issuerB.Descriptor],
                MemoryPool = Pool
            }
        };
        Dictionary<string, VcalmWorkflowConfiguration> workflowBySegment = new(StringComparer.Ordinal)
        {
            [segmentA] = PresentThenIssueWorkflow(issuerA.IssuerDid),
            [segmentB] = PresentThenIssueWorkflow(issuerB.IssuerDid)
        };

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmExchangeIssuanceAsync = (context, _) =>
                ValueTask.FromResult(issuanceBySegment.GetValueOrDefault(Seg(context)));
        }).ConfigureAwait(false);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmWorkflowForExchangeAsync = (exchangeId, context, _) =>
                ValueTask.FromResult(workflowBySegment.GetValueOrDefault(Seg(context)));
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmExchangeFlowIdAsync = (exchangeId, _, _) =>
                ValueTask.FromResult(ResolveExchangeFlowId(app, exchangeId));
        }).ConfigureAwait(false);

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

        return (segmentA, segmentB);
    }


    /// <summary>
    /// Runs one tenant's present-then-issue exchange end to end: it creates and initiates the exchange and presents,
    /// and the engine advances to the issue step and offers the minted credential back.
    /// </summary>
    /// <param name="app">The host running the tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="holder">The holder presenting at the first step.</param>
    /// <returns>
    /// The minted credential's proof verification method, the cryptographic witness of which tenant's key signed it.
    /// </returns>
    private async Task<string> RunIssueExchangeAndGetMintedVmAsync(TestHostShell app, string segment, HolderSigningContext holder)
    {
        string exchangeId = await CreateExchangeAndGetIdAsync(app, segment).ConfigureAwait(false);
        (string challenge, string domain) = await InitiateAndExtractBindingAsync(app, segment, exchangeId).ConfigureAwait(false);
        string present = await SignPresentationMessageAsync(holder, challenge, domain).ConfigureAwait(false);

        ServerHttpResponse offered = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, present, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, offered.StatusCode, offered.Body);
        using JsonDocument offeredDoc = JsonDocument.Parse(offered.Body);
        JsonElement vp = offeredDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentation);
        JsonElement issuedCredential = vp.GetProperty("verifiableCredential")[0];
        JsonElement proof = issuedCredential.GetProperty("proof");
        JsonElement firstProof = proof.ValueKind == JsonValueKind.Array ? proof[0] : proof;

        return firstProof.GetProperty("verificationMethod").GetString()!;
    }


    /// <summary>
    /// The tenant segment the dispatcher stamped on the request context: the key the per-tenant exchange issuance
    /// and workflow resolvers scope themselves by.
    /// </summary>
    /// <param name="context">The request context.</param>
    private static string Seg(ExchangeContext context) =>
        context.TenantId is { } tenant
            ? tenant.Value
            : throw new InvalidOperationException("The dispatcher did not stamp a tenant on the request context.");


    /// <summary>
    /// Initiates the exchange and returns the challenge and domain the engine bound to the first step's request;
    /// the holder signs against both, as the engine verifies against both.
    /// </summary>
    /// <param name="app">The host running the tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="exchangeId">The exchange to initiate.</param>
    /// <returns>The bound challenge and domain.</returns>
    private async Task<(string Challenge, string Domain)> InitiateAndExtractBindingAsync(
        TestHostShell app, string segment, string exchangeId)
    {
        ServerHttpResponse initiate = await app.DispatchVcalmExchangeByIdAsync(
            segment, "POST", exchangeId, "{}", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, initiate.StatusCode, initiate.Body);
        using JsonDocument requestDoc = JsonDocument.Parse(initiate.Body);
        JsonElement vpr = requestDoc.RootElement.GetProperty(VcalmParameterNames.VerifiablePresentationRequest);

        return (vpr.GetProperty(VcalmParameterNames.Challenge).GetString()!,
            vpr.GetProperty(VcalmParameterNames.Domain).GetString()!);
    }


    /// <summary>
    /// Signs a minimal VC Data Model 2.0 presentation bound to <paramref name="challenge"/> and
    /// <paramref name="domain"/> and wraps it as the §3.6.5 exchange message's <c>verifiablePresentation</c>.
    /// </summary>
    /// <param name="holder">The holder signing the presentation.</param>
    /// <param name="challenge">The challenge the engine bound to the step's request.</param>
    /// <param name="domain">The domain the engine bound to the step's request.</param>
    /// <returns>The exchange message body.</returns>
    private async Task<string> SignPresentationMessageAsync(HolderSigningContext holder, string challenge, string domain)
    {
        VerifiablePresentation unproofed = new()
        {
            Context = Context.FromIris(Context.Credentials20),
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


    /// <summary>Creates an exchange through the §3.6.3 endpoint, asserts its HTTP 201 and returns its id.</summary>
    /// <param name="app">The host running the tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <returns>The created exchange's id.</returns>
    private async Task<string> CreateExchangeAndGetIdAsync(TestHostShell app, string segment)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateExchange, "POST",
            new RequestFields(), "{}", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
        using JsonDocument created = JsonDocument.Parse(response.Body);

        return created.RootElement.GetProperty(VcalmParameterNames.Id).GetString()!;
    }


    /// <summary>Reads an exchange's state through the §3.6.6 endpoint and asserts its HTTP 200.</summary>
    /// <param name="app">The host running the tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="exchangeId">The exchange whose state is read.</param>
    /// <returns>The parsed exchange state; the caller disposes it.</returns>
    private async Task<JsonDocument> GetExchangeStateAsync(TestHostShell app, string segment, string exchangeId)
    {
        ServerHttpResponse response = await app.DispatchVcalmExchangeByIdAsync(
            segment, "GET", exchangeId, jsonBody: null, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>
    /// Authors a workflow through the §3.6.1 <c>POST /workflows</c> endpoint, whose parser produces the step
    /// contract the exchange engine then drives, and asserts its HTTP 201.
    /// </summary>
    /// <param name="app">The host running the tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="workflowJson">The workflow configuration request body.</param>
    private async Task CreateWorkflowAsync(TestHostShell app, string segment, string workflowJson)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateWorkflow, "POST",
            new RequestFields(), workflowJson, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);
    }


    /// <summary>The holder's presentation signing and DID.</summary>
    /// <param name="Signing">The holder's presentation-signing configuration.</param>
    /// <param name="HolderDid">The did:key the holder presents under.</param>
    private sealed record HolderSigningContext(VcalmPresentationSigning Signing, string HolderDid);


    /// <summary>An exchange issuer's signing descriptor and DID.</summary>
    /// <param name="Descriptor">The issuer's eddsa-jcs-2022 signing descriptor.</param>
    /// <param name="IssuerDid">The did:key the issuer mints under.</param>
    private sealed record IssuerSigningContext(VcalmProofDescriptor Descriptor, string IssuerDid);
}
