using System.Buffers;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cbor;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Vcalm;
using Verifiable.Tests.DataIntegrity;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.OAuth;
using Verifiable.Server;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// End-to-end conformance tests for the W3C VCALM 1.0 verifier service
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) exposed by <see cref="VcalmVerifierEndpoints"/> — the §3.3.1
/// <c>/credentials/verify</c>, §3.3.2 <c>/presentations/verify</c>, and §3.3.3 <c>/challenges</c>
/// endpoints, driven through the real dispatch pipeline.
/// </summary>
/// <remarks>
/// The credential / presentation signing, the cryptosuite (eddsa-rdfc-2022 for the credential,
/// eddsa-jcs-2022 for the presentation), the RDFC / JCS canonicalizers, the did:key resolver, and
/// the project crypto are sourced from the same library primitives the Data Integrity flow tests
/// use — the verifier COMPOSES them, it does not re-roll cryptography.
/// </remarks>
[TestClass]
internal sealed class VcalmVerifierEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://verifier.client.test";
    private static readonly Uri ClientBaseUri = new("https://verifier.client.test");

    private static readonly ImmutableHashSet<CapabilityIdentifier> VerifierCapabilities =
        ImmutableHashSet.Create(WellKnownVcalmCapabilities.VcalmVerifier);

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    //The did:key resolver seam — derives the controller DID document locally with no network.
    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } =
        CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } =
        CanonicalizationTestUtilities.CreateTestContextResolver();

    //The presentation tests sign with eddsa-jcs-2022 (JCS is context-free and produces a non-empty
    //canonical form for a minimal presentation); the credential tests sign with eddsa-rdfc-2022. Each
    //verifier instance is registered with the canonicalizer matching the suite it serves — the
    //library does not hardcode the cryptosuite, and a multi-suite deployment wires a dispatching
    //canonicalizer.
    private static CanonicalizationDelegate JcsCanonicalizer { get; } = (json, contextResolver, _, cancellationToken) =>
        ValueTask.FromResult(new CanonicalizationResult { CanonicalForm = Jcs.Canonicalize(json) });

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    private static PresentationSerializeDelegate SerializePresentation { get; } = presentation =>
        JsonSerializerExtensions.Serialize(presentation, JsonOptions);

    private static PresentationDeserializeDelegate DeserializePresentation { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiablePresentation>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    private static readonly ExchangeContext EmptyContext = new();

    //Registered key material lives for the test's lifetime and is disposed at cleanup; the host
    //keeps the registration, so the material cannot be disposed at the end of RegisterVerifier.
    private List<VerifierKeyMaterial> RegisteredMaterials { get; } = [];

    //ecdsa-sd-2023 issuer / ephemeral key material the SD base-proof + derive helpers retain for the
    //test's lifetime — disposed at cleanup.
    private List<IDisposable> OwnedKeys { get; } = [];


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
    /// §3.3.1 happy path: a valid eddsa-rdfc-2022 credential verifies — HTTP 200 with
    /// <c>verified:true</c>. §3.3.1: "verified … is set to true if no errors were detected during the
    /// verification process."
    /// </summary>
    [TestMethod]
    public async Task ValidCredentialVerifiesTrue()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A valid eddsa-rdfc-2022 credential must verify true.");
    }


    /// <summary>
    /// §3.3.1 / §3.8.1 ERROR: a tampered credential's proof fails to verify — still HTTP 200 (the
    /// process ran), but <c>verified:false</c> with a cryptographic ERROR ProblemDetail. §3.8.1:
    /// "If an error is included, the verified property … MUST be set to false."
    /// </summary>
    [TestMethod]
    public async Task TamperedCredentialVerifiesFalseWithError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        //Tamper the subject claim after signing — the RDFC hash no longer matches the signature.
        credential.CredentialSubject![0].AdditionalData!["alumniOf"] = "Tampered University";

        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A tampered credential must verify false (the process still ran → 200).");

        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.IsGreaterThan(0, problems.GetArrayLength(), "A crypto failure surfaces a ProblemDetail.");
        Assert.AreEqual(VcalmProblemTypes.CryptographicSecurityError,
            problems[0].GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "The proof failure is a §3.8.1 cryptographic ERROR.");
    }


    /// <summary>
    /// §3.8.1 SAFETY invariant (the verifier-side analogue of the issuer's GAP A): a structurally
    /// malformed credential — a missing or wrong-typed core member, or a missing proof sub-member, the
    /// exact negatives the external W3C <c>vc-api-verifier-test-suite</c> drives — MUST NEVER verify
    /// TRUE, and MUST NEVER leak an uncaught exception (a 500). Either outcome is spec-conformant: a
    /// 400 (input so malformed the verification process could not run, §3.3.1) OR a 200 with
    /// <c>verified:false</c> and an ERROR ProblemDetail (the process ran and detected a data-model /
    /// malformed-context / cryptographic error, §3.8.1 — which §3.8 PREFERS: "avoid raising errors
    /// while performing verification, and instead gather ProblemDetails objects"). What is NOT
    /// acceptable is <c>verified:true</c> (a fail-open) or a 500 (an unsanitized server error, §3.8).
    /// The CCG suite expects 400 for every one of these; VCALM §3.8.1's 200+verified:false is the
    /// documented deviation — this test pins the property that actually matters either way.
    /// </summary>
    [TestMethod]
    [DataRow("delete:@context", "missing @context")]
    [DataRow("delete:type", "missing type")]
    [DataRow("delete:issuer", "missing issuer")]
    [DataRow("delete:credentialSubject", "missing credentialSubject")]
    [DataRow("delete:proof", "missing proof")]
    [DataRow("delete:proof.type", "missing proof.type")]
    [DataRow("delete:proof.created", "missing proof.created")]
    [DataRow("delete:proof.verificationMethod", "missing proof.verificationMethod")]
    [DataRow("delete:proof.proofValue", "missing proof.proofValue")]
    [DataRow("delete:proof.proofPurpose", "missing proof.proofPurpose")]
    [DataRow("set:@context=4", "@context not an array")]
    [DataRow("setArray:@context=4", "@context item not a string/object")]
    [DataRow("set:type=\"VerifiableCredential\"", "type not an array")]
    [DataRow("setArray:type=4", "type item not a string")]
    [DataRow("set:issuer=[]", "issuer not a string/object")]
    [DataRow("set:credentialSubject=\"did:example:1234\"", "credentialSubject not an object")]
    [DataRow("set:proof=\"not-an-object\"", "proof not an object")]
    //Wrong-typed scalar members the hand-written converters bind with GetString() — a non-string value
    //makes GetString() throw InvalidOperationException (NOT JsonException), the exact §3.8 500-leak the
    //hunt workflow flagged. These run in the PARSE seam, before (and independent of) the verification guard.
    [DataRow("set:proof.created=4", "proof.created a number")]
    [DataRow("set:proof.cryptosuite=4", "proof.cryptosuite a number")]
    [DataRow("set:proof.proofValue=[]", "proof.proofValue an array")]
    [DataRow("set:proof.proofPurpose={}", "proof.proofPurpose an object")]
    [DataRow("set:issuer.id=4", "object issuer with a numeric id")]
    [DataRow("set:validFrom=4", "validFrom a number")]
    [DataRow("set:validUntil=true", "validUntil a bool")]
    [DataRow("set:id=4", "credential id a number")]
    public async Task MalformedCredentialNeverVerifiesTrue(string mutation, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string mutatedCredentialJson = MutateSignedCredentialJson(SerializeCredential(credential), mutation);
        string body = "{\"verifiableCredential\":" + mutatedCredentialJson
            + ",\"options\":{\"returnProblemDetails\":true}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            "POST",
            new RequestFields(),
            body,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //An uncaught exception during verification would surface as a 500 — that is the §3.8
        //"unsanitized server error" failure mode. The only conformant statuses are 400 (verification
        //could not run) or 200 (verification ran; the result is in the body).
        Assert.IsTrue(response.StatusCode is 200 or 400,
            $"A malformed credential ({reason}) must be 200 or 400, never {response.StatusCode}: {response.Body}");

        if(response.StatusCode == 200)
        {
            using JsonDocument doc = JsonDocument.Parse(response.Body);
            Assert.IsFalse(doc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
                $"A malformed credential ({reason}) MUST NEVER verify true (the §3.8.1 fail-open guard).");

            JsonElement problems = doc.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
            Assert.IsGreaterThan(0, problems.GetArrayLength(),
                $"A verified:false from a malformed credential ({reason}) carries a §3.8.1 ERROR ProblemDetail.");
        }
    }


    //Applies one structural mutation (the vc-api-verifier-test-suite negative vectors) to a signed
    //credential's JSON, returning the mutated credential JSON. The proof is an array; proof.* mutations
    //target its first member.
    private static string MutateSignedCredentialJson(string signedCredentialJson, string mutation)
    {
        System.Text.Json.Nodes.JsonObject credential =
            System.Text.Json.Nodes.JsonNode.Parse(signedCredentialJson)!.AsObject();

        static System.Text.Json.Nodes.JsonObject FirstProof(System.Text.Json.Nodes.JsonObject credential)
        {
            System.Text.Json.Nodes.JsonNode proof = credential["proof"]!;

            return (proof is System.Text.Json.Nodes.JsonArray array ? array[0]! : proof).AsObject();
        }

        switch(mutation)
        {
            case "delete:@context": credential.Remove("@context"); break;
            case "delete:type": credential.Remove("type"); break;
            case "delete:issuer": credential.Remove("issuer"); break;
            case "delete:credentialSubject": credential.Remove("credentialSubject"); break;
            case "delete:proof": credential.Remove("proof"); break;
            case "delete:proof.type": FirstProof(credential).Remove("type"); break;
            case "delete:proof.created": FirstProof(credential).Remove("created"); break;
            case "delete:proof.verificationMethod": FirstProof(credential).Remove("verificationMethod"); break;
            case "delete:proof.proofValue": FirstProof(credential).Remove("proofValue"); break;
            case "delete:proof.proofPurpose": FirstProof(credential).Remove("proofPurpose"); break;
            case "set:@context=4": credential["@context"] = 4; break;
            case "setArray:@context=4": credential["@context"] = new System.Text.Json.Nodes.JsonArray(4); break;
            case "set:type=\"VerifiableCredential\"": credential["type"] = "VerifiableCredential"; break;
            case "setArray:type=4": credential["type"] = new System.Text.Json.Nodes.JsonArray(4); break;
            case "set:issuer=[]": credential["issuer"] = new System.Text.Json.Nodes.JsonArray(); break;
            case "set:credentialSubject=\"did:example:1234\"": credential["credentialSubject"] = "did:example:1234"; break;
            case "set:proof=\"not-an-object\"": credential["proof"] = "not-an-object"; break;
            case "set:proof.created=4": FirstProof(credential)["created"] = 4; break;
            case "set:proof.cryptosuite=4": FirstProof(credential)["cryptosuite"] = 4; break;
            case "set:proof.proofValue=[]": FirstProof(credential)["proofValue"] = new System.Text.Json.Nodes.JsonArray(); break;
            case "set:proof.proofPurpose={}": FirstProof(credential)["proofPurpose"] = new System.Text.Json.Nodes.JsonObject(); break;
            case "set:issuer.id=4": credential["issuer"] = new System.Text.Json.Nodes.JsonObject { ["id"] = 4 }; break;
            case "set:validFrom=4": credential["validFrom"] = 4; break;
            case "set:validUntil=true": credential["validUntil"] = true; break;
            case "set:id=4": credential["id"] = 4; break;
            default: throw new ArgumentOutOfRangeException(nameof(mutation), mutation, "Unknown mutation.");
        }

        return credential.ToJsonString();
    }


    /// <summary>
    /// §3.8.1 SAFETY invariant for §3.3.2 (the presentation-side analogue): a structurally malformed
    /// presentation — a missing / wrong-typed core member, a missing proof sub-member, a non-object
    /// holder — MUST NEVER verify TRUE and MUST NEVER leak an uncaught exception (a 500). Either a 400
    /// or a 200 with <c>verified:false</c> is conformant; <c>verified:true</c> or a 500 is not. This
    /// pins the presentation proof-verification guard the same way <see cref="MalformedCredentialNeverVerifiesTrue"/>
    /// pins the credential one.
    /// </summary>
    //Each vector either breaks the present proof / the signed content, is rejected by the parse seam, or
    //(delete:proof) makes the verifiablePresentation unsecured — all MUST verify false, never true. A
    //semantically-identical mutation (e.g. type as a bare string the model coerces back to a one-element
    //array) is NOT a malformation and is excluded. The unsecured no-proof case is pinned in detail by
    //UnsecuredVerifiablePresentationVerifiesFalseWithError; the legitimately-unproofed 'presentation'
    //member (which verifies true) is covered by UnproofedPresentationVerifies.
    [TestMethod]
    [DataRow("delete:@context", "missing @context")]
    [DataRow("set:@context=4", "@context not an array")]
    [DataRow("setArray:@context=4", "@context item not a string/object")]
    [DataRow("delete:type", "missing type")]
    [DataRow("delete:proof", "no proof and no envelope (unsecured)")]
    [DataRow("delete:proof.proofValue", "missing proof.proofValue")]
    [DataRow("set:proof.created=4", "proof.created a number")]
    [DataRow("set:proof=\"not-an-object\"", "proof not an object")]
    [DataRow("set:holder=4", "holder a number")]
    public async Task MalformedPresentationNeverVerifiesTrue(string mutation, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app, canonicalizer: JcsCanonicalizer);

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            "challenge-xyz", "verifier.example").ConfigureAwait(false);
        string mutated = MutateSignedPresentationJson(SerializePresentation(presentation), mutation);
        string body = "{\"verifiablePresentation\":" + mutated + ",\"options\":{\"returnProblemDetails\":true}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmPresentationsVerify,
            "POST",
            new RequestFields(),
            body,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(response.StatusCode is 200 or 400,
            $"A malformed presentation ({reason}) must be 200 or 400, never {response.StatusCode}: {response.Body}");

        if(response.StatusCode == 200)
        {
            using JsonDocument doc = JsonDocument.Parse(response.Body);
            Assert.IsFalse(doc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
                $"A malformed presentation ({reason}) MUST NEVER verify true.");
        }
    }


    //Applies one structural mutation to a signed presentation's JSON. Mirrors
    //MutateSignedCredentialJson; the proof may serialize as an array, so proof.* mutations target the
    //first member.
    private static string MutateSignedPresentationJson(string signedPresentationJson, string mutation)
    {
        System.Text.Json.Nodes.JsonObject presentation =
            System.Text.Json.Nodes.JsonNode.Parse(signedPresentationJson)!.AsObject();

        static System.Text.Json.Nodes.JsonObject FirstProof(System.Text.Json.Nodes.JsonObject presentation)
        {
            System.Text.Json.Nodes.JsonNode proof = presentation["proof"]!;

            return (proof is System.Text.Json.Nodes.JsonArray array ? array[0]! : proof).AsObject();
        }

        switch(mutation)
        {
            case "delete:@context": presentation.Remove("@context"); break;
            case "set:@context=4": presentation["@context"] = 4; break;
            case "setArray:@context=4": presentation["@context"] = new System.Text.Json.Nodes.JsonArray(4); break;
            case "delete:type": presentation.Remove("type"); break;
            case "set:type=\"VerifiablePresentation\"": presentation["type"] = "VerifiablePresentation"; break;
            case "delete:proof": presentation.Remove("proof"); break;
            case "delete:proof.proofValue": FirstProof(presentation).Remove("proofValue"); break;
            case "set:proof.created=4": FirstProof(presentation)["created"] = 4; break;
            case "set:proof=\"not-an-object\"": presentation["proof"] = "not-an-object"; break;
            case "set:holder=4": presentation["holder"] = 4; break;
            default: throw new ArgumentOutOfRangeException(nameof(mutation), mutation, "Unknown mutation.");
        }

        return presentation.ToJsonString();
    }


    /// <summary>
    /// §3.3.2 / §3.8.1 secured-member contract: a presentation supplied under the
    /// <c>verifiablePresentation</c> member with NEITHER a Data Integrity proof NOR a <c>data:</c>-URL
    /// envelope is not a verifiable presentation — it verifies FALSE with a §3.8.1 cryptographic ERROR,
    /// mirroring how a proof-less <c>verifiableCredential</c> is treated. §3.3.2 reserves the
    /// <c>verifiablePresentation</c> member for the SECURED form (a proof or an
    /// <c>EnvelopedVerifiablePresentation</c>) and gives the unproofed form its own <c>presentation</c>
    /// member — see <see cref="UnproofedPresentationVerifies"/> for that legitimate (verifies-true) path.
    /// </summary>
    [TestMethod]
    public async Task UnsecuredVerifiablePresentationVerifiesFalseWithError()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app, canonicalizer: JcsCanonicalizer);

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            "challenge-xyz", "verifier.example").ConfigureAwait(false);
        string mutated = MutateSignedPresentationJson(SerializePresentation(presentation), "delete:proof");
        string body = "{\"verifiablePresentation\":" + mutated + ",\"options\":{\"returnProblemDetails\":true}}";

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A verifiablePresentation with no proof and no envelope is not a secured presentation — it "
            + "verifies false (a §3.8.1 cryptographic ERROR), like a proof-less verifiableCredential.");

        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        bool hasCryptoError = false;
        foreach(JsonElement problem in problems.EnumerateArray())
        {
            if(string.Equals(problem.GetProperty(VcalmParameterNames.ProblemType).GetString(),
                VcalmProblemTypes.CryptographicSecurityError, StringComparison.Ordinal))
            {
                hasCryptoError = true;
            }
        }

        Assert.IsTrue(hasCryptoError,
            "The unsecured verifiablePresentation surfaces a §3.8.1 cryptographic ERROR ProblemDetail.");
    }


    /// <summary>
    /// §3.8.1 WARNING: an expired credential (validUntil in the past) verifies TRUE — a validity-period
    /// ProblemDetail is a WARNING, which §3.8.1 says does NOT flip <c>verified</c> ("Warnings are
    /// ProblemDetails relating to status and validity periods … no errors are included, it MUST be set
    /// to true").
    /// </summary>
    [TestMethod]
    public async Task ExpiredCredentialVerifiesTrueWithValidityWarning()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: true).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "An expired but cryptographically valid credential verifies TRUE — a validity-period "
            + "ProblemDetail is a §3.8.1 WARNING that does not flip verified.");

        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        bool hasValidityWarning = false;
        foreach(JsonElement problem in problems.EnumerateArray())
        {
            if(string.Equals(problem.GetProperty(VcalmParameterNames.ProblemType).GetString(),
                VcalmProblemTypes.ValidityPeriodWarning, StringComparison.Ordinal))
            {
                hasValidityWarning = true;
            }
        }

        Assert.IsTrue(hasValidityWarning, "The expired validUntil must surface a validity-period WARNING.");
    }


    /// <summary>
    /// §3.8.1 status WARNING process-safety: a <c>credentialStatus</c> whose status-list resolver THROWS
    /// (an unresolvable / unverifiable / undecodable status list, or a §3.2 check failure over
    /// attacker-influenced input) must NOT become an unhandled 500. §3.8.1 makes status a WARNING, so an
    /// undeterminable status yields no status result and no warning and never flips <c>verified</c> — the
    /// credential still verifies TRUE.
    /// </summary>
    [TestMethod]
    public async Task StatusResolverThrowVerifiesTrueWithoutCrash()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        //A resolver that throws while dereferencing the status list — and records that it was reached, so
        //the test proves the credentialStatus entry mapped and the resolver was actually invoked (not a
        //false-positive where the entry never mapped and the throw path was never exercised).
        bool resolverInvoked = false;
        app.Server.Vcalm().ResolveVcalmStatusListAsync = (entry, ctx, ct) =>
        {
            resolverInvoked = true;

            throw new InvalidOperationException("The status list could not be dereferenced or decoded.");
        };

        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false, withStatus: true).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(resolverInvoked,
            "The credentialStatus entry must map so the status resolver is actually invoked (else the test proves nothing).");
        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A status-list resolver throw is swallowed (§3.8.1 status is a WARNING): the credential still verifies TRUE.");

        //A throw yields NO status result and NO status warning — an undeterminable status asserts nothing.
        if(response.RootElement.TryGetProperty(VcalmParameterNames.ProblemDetails, out JsonElement problems))
        {
            foreach(JsonElement problem in problems.EnumerateArray())
            {
                Assert.AreNotEqual(VcalmProblemTypes.StatusWarning,
                    problem.GetProperty(VcalmParameterNames.ProblemType).GetString(),
                    "A thrown (undeterminable) status must not surface a STATUS_WARNING.");
            }
        }
    }


    /// <summary>
    /// §C.3 / §3.8.1 status shape branches: a <c>credentialStatus</c> that does NOT map to a resolvable
    /// W3C status reference — a non-<c>BitstringStatusListEntry</c> type, an unparseable
    /// <c>statusListIndex</c>, or a missing <c>statusListCredential</c> — is silently SKIPPED by
    /// TryMapStatusEntry BEFORE the resolver is ever reached. It can neither warn nor crash: the
    /// unparseable index in particular must not throw a 500. The credential still verifies TRUE with no
    /// STATUS_WARNING (an undeterminable status asserts nothing). The complementary positive case — a
    /// well-formed entry DOES reach the resolver — is pinned by StatusResolverThrowVerifiesTrueWithoutCrash.
    /// </summary>
    [TestMethod]
    [DataRow("NotABitstringStatusEntry", "94567", "https://status.example/list", "non-BitstringStatusListEntry type")]
    [DataRow("BitstringStatusListEntry", "not-a-number", "https://status.example/list", "unparseable statusListIndex")]
    [DataRow("BitstringStatusListEntry", "94567", "", "missing statusListCredential")]
    public async Task NonMappingStatusEntryIsSkippedWithoutResolverOrCrash(
        string type, string statusListIndex, string statusListCredential, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        //A resolver that records being reached but resolves nothing. A MAPPING entry would reach it;
        //a NON-mapping entry must be turned away by TryMapStatusEntry first, so resolverInvoked stays false.
        bool resolverInvoked = false;
        app.Server.Vcalm().ResolveVcalmStatusListAsync = (entry, ctx, ct) =>
        {
            resolverInvoked = true;

            return ValueTask.FromResult<VcalmResolvedStatusList?>(null);
        };

        CredentialStatus nonMapping = new()
        {
            Id = "https://status.example/list#x",
            Type = type,
            StatusPurpose = "revocation",
            StatusListIndex = statusListIndex,
            StatusListCredential = statusListCredential
        };
        DataIntegritySecuredCredential credential = await SignCredentialAsync(
            validUntilPast: false, customStatus: nonMapping).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(resolverInvoked,
            $"A non-mapping credentialStatus ({reason}) must be turned away by TryMapStatusEntry before the resolver.");
        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            $"A non-mapping credentialStatus ({reason}) establishes no status: verified stays TRUE, never a 500.");

        if(response.RootElement.TryGetProperty(VcalmParameterNames.ProblemDetails, out JsonElement problems))
        {
            foreach(JsonElement problem in problems.EnumerateArray())
            {
                Assert.AreNotEqual(VcalmProblemTypes.StatusWarning,
                    problem.GetProperty(VcalmParameterNames.ProblemType).GetString(),
                    $"A non-mapping credentialStatus ({reason}) must not surface a STATUS_WARNING.");
            }
        }
    }


    /// <summary>
    /// §3.3.1 <c>returnResults</c>: the verbose results object carries validFrom/validUntil/proof
    /// sub-results, each shaped <c>{ verified, input }</c>.
    /// </summary>
    [TestMethod]
    public async Task ReturnResultsEmitsPerStepResults()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: false, returnResults: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        JsonElement results = response.RootElement.GetProperty(VcalmParameterNames.Results);
        JsonElement proofResults = results.GetProperty(VcalmParameterNames.Proof);
        Assert.AreEqual(1, proofResults.GetArrayLength(), "One proof → one proof result.");
        Assert.IsTrue(proofResults[0].GetProperty(VcalmParameterNames.Verified).GetBoolean());
        Assert.StartsWith("did:key:", proofResults[0].GetProperty(VcalmParameterNames.Input).GetString()!,
            "The proof result input is the verificationMethod.");

        JsonElement validFrom = results.GetProperty(VcalmParameterNames.ValidFrom);
        Assert.IsTrue(validFrom.GetProperty(VcalmParameterNames.Verified).GetBoolean());
    }


    /// <summary>
    /// §2.4 unknown-option MUST: an <c>options</c> member the verifier does not understand is rejected
    /// with HTTP 400 and the §3.8 <c>UNKNOWN_OPTION_PROVIDED</c> problem type. §2.4: "Implementations
    /// MUST throw an error if an endpoint receives data, options, or option values that it does not
    /// understand or know how to process."
    /// </summary>
    [TestMethod]
    public async Task UnknownOptionYields400UnknownOptionProvided()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string credentialJson = SerializeCredential(credential);
        string body = "{\"verifiableCredential\":" + credentialJson
            + ",\"options\":{\"notARealOption\":true}}";

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 400).ConfigureAwait(false);

        Assert.AreEqual(VcalmProblemTypes.UnknownOptionProvided,
            response.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "An unknown option yields the UNKNOWN_OPTION_PROVIDED problem type.");
    }


    /// <summary>
    /// §2.4 strict top-level rejection: an unrecognized top-level member is malformed input → HTTP
    /// 400 (§3.3.1 "invalid input!").
    /// </summary>
    [TestMethod]
    public async Task UnknownTopLevelMemberYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string credentialJson = SerializeCredential(credential);
        string body = "{\"verifiableCredential\":" + credentialJson + ",\"bogusTopLevel\":42}";

        using JsonDocument _ = await PostCredentialAsync(app, segment, body, expectedStatus: 400).ConfigureAwait(false);
    }


    /// <summary>
    /// §2.4 content-serialization MUST: a request whose Content-Type is not <c>application/json</c> is
    /// rejected with HTTP 400 before parsing.
    /// </summary>
    [TestMethod]
    public async Task NonJsonContentTypeYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        byte[] bytes = Encoding.UTF8.GetBytes("{\"verifiableCredential\":{}}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            "POST",
            bytes,
            "text/plain",
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "A non-application/json body is rejected before parsing (§2.4 content-serialization MUST).");
    }


    /// <summary>
    /// §2.4 / B.4 payload size: a request body over the configured cap is rejected with HTTP 413.
    /// </summary>
    [TestMethod]
    public async Task OversizeBodyYields413()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app, maxRequestBytes: 1024);

        //A body comfortably over the 1 KiB cap configured for this verifier instance.
        byte[] bytes = Encoding.UTF8.GetBytes("{\"verifiableCredential\":{\"x\":\"" + new string('a', 4096) + "\"}}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            "POST",
            bytes,
            WellKnownMediaTypes.Application.Json,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(413, response.StatusCode,
            "A body over the configured §2.4 payload-size cap is rejected with 413.");
    }


    /// <summary>
    /// §2.4 / B.4 payload size on §3.3.3: the /challenges endpoint accepts an empty body, but a PRESENT
    /// body over the configured cap is rejected with HTTP 413 — the same DoS gate every other
    /// body-bearing VCALM endpoint enforces (the challenge endpoint previously skipped it).
    /// </summary>
    [TestMethod]
    public async Task ChallengeOversizeBodyYields413()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app, maxRequestBytes: 1024);

        byte[] bytes = Encoding.UTF8.GetBytes("{\"x\":\"" + new string('a', 4096) + "\"}");
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCreateChallenge,
            "POST",
            bytes,
            WellKnownMediaTypes.Application.Json,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(413, response.StatusCode,
            "A present /challenges body over the §2.4 payload cap is rejected with 413, like its siblings.");
    }


    /// <summary>
    /// §3.3.2 happy path: a holder-signed presentation whose proof's challenge and domain match the
    /// verify options verifies true.
    /// </summary>
    [TestMethod]
    public async Task ValidPresentationWithChallengeAndDomainVerifiesTrue()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app, canonicalizer: JcsCanonicalizer);

        const string Challenge = "challenge-abc-123";
        const string Domain = "verifier.example";

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(Challenge, Domain).ConfigureAwait(false);
        string body = BuildPresentationRequestBody(presentation, Challenge, Domain);

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A presentation whose proof binds the expected challenge + domain verifies true.");
    }


    /// <summary>
    /// §3.3.2 challenge binding: a presentation whose proof carries a different challenge than the
    /// verify options is rejected (verified:false) — the §3.8.1 cryptographic ERROR.
    /// </summary>
    [TestMethod]
    public async Task PresentationWithWrongChallengeVerifiesFalse()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app, canonicalizer: JcsCanonicalizer);

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            "challenge-the-holder-signed", "verifier.example").ConfigureAwait(false);
        //The verify call expects a DIFFERENT challenge than the one the proof carries.
        string body = BuildPresentationRequestBody(presentation, "challenge-the-verifier-expects", "verifier.example");

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A challenge mismatch must verify false.");
    }


    /// <summary>
    /// §3.3.2 domain binding: a presentation whose proof carries a different domain than the verify
    /// options is rejected (verified:false).
    /// </summary>
    [TestMethod]
    public async Task PresentationWithWrongDomainVerifiesFalse()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app, canonicalizer: JcsCanonicalizer);

        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(
            "challenge-xyz", "holder-signed-domain.example").ConfigureAwait(false);
        string body = BuildPresentationRequestBody(presentation, "challenge-xyz", "verifier-expects-domain.example");

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A domain mismatch must verify false.");
    }


    /// <summary>
    /// §3.3.2 holder-to-key binding (soundness): a presentation whose <c>holder</c> claims one DID but
    /// whose proof is signed by a key controlled by a DIFFERENT DID is rejected (verified:false) — a
    /// valid signature alone does NOT authenticate a forged holder. The challenge and domain MATCH, so
    /// the only thing that can fail the proof is the holder-to-verificationMethod binding: the proof's
    /// verificationMethod is not found in the claimed holder's authentication relationship.
    /// </summary>
    [TestMethod]
    public async Task SwappedHolderDidVerifiesFalse()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app, canonicalizer: JcsCanonicalizer);

        const string Challenge = "challenge-forged-holder";
        const string Domain = "verifier.example";

        //Signed by the attacker's key, but the holder member claims the victim's DID — both bindings
        //(challenge, domain) are correct, so a pass here could ONLY come from accepting the forged holder.
        DataIntegritySecuredPresentation forged = await SignPresentationWithForgedHolderAsync(Challenge, Domain).ConfigureAwait(false);
        string body = BuildPresentationRequestBody(forged, Challenge, Domain);

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A presentation whose holder DID does not control the signing key MUST verify false — the "
            + "holder-to-verificationMethod binding, not a valid signature alone, authenticates the holder.");
    }


    /// <summary>
    /// §3.3.2 unproofed alternative: a <c>presentation</c> (unproofed JSON-LD) request verifies its
    /// contained credentials only; with no contained credentials, it verifies true (nothing to
    /// contradict the verification process).
    /// </summary>
    [TestMethod]
    public async Task UnproofedPresentationVerifies()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        VerifiablePresentation presentation = new()
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = "did:example:holder-unproofed"
        };

        string presentationJson = SerializePresentation(presentation);
        string body = "{\"presentation\":" + presentationJson + "}";

        using JsonDocument response = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "An unproofed presentation with no contained credentials runs the process and verifies true.");
    }


    /// <summary>
    /// §3.3.3 challenge minting + §3.3.2 consumption: <c>POST /challenges</c> mints a challenge, and a
    /// later §3.3.2 call whose presentation binds that challenge passes the issuance gate; an
    /// unissued challenge is rejected.
    /// </summary>
    [TestMethod]
    public async Task ChallengeMintedThenConsumedOnVerify()
    {
        await using TestHostShell app = new(TimeProvider);

        HashSet<string> issuedChallenges = [];
        string segment = RegisterVerifier(
            app,
            canonicalizer: JcsCanonicalizer,
            persistChallenge: (challenge, _, _) =>
            {
                issuedChallenges.Add(challenge);

                return ValueTask.CompletedTask;
            },
            consumeChallenge: (challenge, _, _) =>
                ValueTask.FromResult(issuedChallenges.Contains(challenge)));

        //§3.3.3: an empty body POST mints and returns a challenge string.
        ServerHttpResponse challengeResponse = await app.DispatchWithBodyAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCreateChallenge,
            "POST",
            ReadOnlyMemory<byte>.Empty,
            contentType: string.Empty,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, challengeResponse.StatusCode, challengeResponse.Body);
        using JsonDocument challengeDoc = JsonDocument.Parse(challengeResponse.Body);
        string mintedChallenge = challengeDoc.RootElement.GetProperty(VcalmParameterNames.Challenge).GetString()!;
        Assert.IsFalse(string.IsNullOrEmpty(mintedChallenge), "The challenge endpoint returns a challenge value.");
        Assert.Contains(mintedChallenge, issuedChallenges, "The minted challenge was persisted as issued.");

        //A verify call binding the minted challenge passes the issuance gate.
        const string Domain = "verifier.example";
        DataIntegritySecuredPresentation presentation = await SignPresentationAsync(mintedChallenge, Domain).ConfigureAwait(false);
        string body = BuildPresentationRequestBody(presentation, mintedChallenge, Domain);

        using JsonDocument issuedResponse = await PostPresentationAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);
        Assert.IsTrue(issuedResponse.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A presentation binding a minted, issued challenge passes the issuance gate and verifies.");

        //A verify call binding an unissued challenge fails the issuance gate.
        DataIntegritySecuredPresentation unissued = await SignPresentationAsync("never-minted-challenge", Domain).ConfigureAwait(false);
        string unissuedBody = BuildPresentationRequestBody(unissued, "never-minted-challenge", Domain);

        using JsonDocument unissuedResponse = await PostPresentationAsync(app, segment, unissuedBody, expectedStatus: 200).ConfigureAwait(false);
        Assert.IsFalse(unissuedResponse.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A presentation binding a challenge this instance never issued fails the §3.3.3 issuance gate.");
    }


    /// <summary>
    /// §3.3.1 malformed input: a body that is not a JSON object yields HTTP 400.
    /// </summary>
    [TestMethod]
    public async Task MalformedCredentialBodyYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        string segment = RegisterVerifier(app);

        using JsonDocument _ = await PostCredentialAsync(app, segment, "{ not valid json", expectedStatus: 400).ConfigureAwait(false);
    }


    /// <summary>
    /// §3.3.1 + §3.4 ecdsa-sd-2023 derived (the money-shot): an issuer base-proofs a credential
    /// (W3C VC-DI-ECDSA §3.4.1 createBaseProof), a holder derives a selectively-disclosed subset
    /// (§3.4.5 createDerivedProof), and the derived credential — the form a holder presents — is POSTed
    /// to the V-1 <c>/credentials/verify</c> endpoint. With the ecdsa-sd-2023 derived-proof seams
    /// wired, the verifier routes the CBOR <c>0xd9 5d 01</c>-tagged proof to the SD derived-proof
    /// verifier and returns HTTP 200 with <c>verified:true</c> and no error — the disclosed claims are
    /// authentic under the issuer's base signature.
    /// </summary>
    [TestMethod]
    public async Task DerivedEcdsaSd2023CredentialVerifiesTrue()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = RegisterVerifier(app, sd: sd);

        DataIntegritySecuredCredential derived = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(derived, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A selectively-disclosed ecdsa-sd-2023 derived credential must verify TRUE at the V-1 "
            + "/credentials/verify endpoint.");

        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.AreEqual(0, problems.GetArrayLength(),
            "A valid derived credential surfaces no §3.8.1 ProblemDetail.");
    }


    /// <summary>
    /// §3.3.1 / §3.8.1 ERROR + §3.4 no-false-positive: a TAMPERED ecdsa-sd-2023 derived credential
    /// (a disclosed claim altered after derivation, so its statement signature no longer matches) still
    /// returns HTTP 200 (the process ran) but <c>verified:false</c> with a cryptographic ERROR. The SD
    /// derived-proof verifier never wrongly returns true for a forged disclosure.
    /// </summary>
    [TestMethod]
    public async Task TamperedDerivedEcdsaSd2023CredentialVerifiesFalseWithError()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = RegisterVerifier(app, sd: sd);

        DataIntegritySecuredCredential derived = await CreateDerivedCredentialAsync(sd).ConfigureAwait(false);

        //Tamper a disclosed claim after derivation — the relabeled N-Quad no longer matches the
        //statement signature the holder carried over from the issuer's base proof.
        derived.CredentialSubject![0].AdditionalData!["degree"] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["name"] = "Tampered Master of Forgery"
        };

        string body = BuildCredentialRequestBody(derived, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsFalse(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A tampered derived credential must verify FALSE (the no-false-positive property).");

        JsonElement problems = response.RootElement.GetProperty(VcalmParameterNames.ProblemDetails);
        Assert.IsGreaterThan(0, problems.GetArrayLength(), "A crypto failure surfaces a ProblemDetail.");
        Assert.AreEqual(VcalmProblemTypes.CryptographicSecurityError,
            problems[0].GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "A derived-proof failure is a §3.8.1 cryptographic ERROR.");
    }


    /// <summary>
    /// §3.3.1 regression: with the ecdsa-sd-2023 derived-proof seams wired, an ordinary non-SD
    /// eddsa-rdfc-2022 credential still verifies through the generic Data Integrity path exactly as
    /// before — HTTP 200, <c>verified:true</c>. The cryptosuite branch routes ONLY ecdsa-sd-2023
    /// derived proofs to the SD verifier; every other cryptosuite is unchanged.
    /// </summary>
    [TestMethod]
    public async Task NonSdCredentialUnaffectedBySdSeams()
    {
        await using TestHostShell app = new(TimeProvider);
        SdIssuerContext sd = await CreateSdIssuerContextAsync().ConfigureAwait(false);
        string segment = RegisterVerifier(app, sd: sd);

        DataIntegritySecuredCredential credential = await SignCredentialAsync(validUntilPast: false).ConfigureAwait(false);
        string body = BuildCredentialRequestBody(credential, returnProblemDetails: true);

        using JsonDocument response = await PostCredentialAsync(app, segment, body, expectedStatus: 200).ConfigureAwait(false);

        Assert.IsTrue(response.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A non-SD eddsa-rdfc-2022 credential verifies TRUE through the generic path even when the "
            + "ecdsa-sd-2023 derived-proof seams are wired (regression guard).");
    }


    //Registers a tenant with the VcalmVerifier capability and wires the parse seams, the Data
    //Integrity verification record (RDFC + JCS canonicalizers via the supplied resolver), and any
    //challenge persistence seams.
    private string RegisterVerifier(
        TestHostShell app,
        long maxRequestBytes = 10L * 1024 * 1024,
        CanonicalizationDelegate? canonicalizer = null,
        ContextResolverDelegate? contextResolver = null,
        PersistVcalmChallengeDelegate? persistChallenge = null,
        ConsumeVcalmChallengeDelegate? consumeChallenge = null,
        SdIssuerContext? sd = null)
    {
        VerifierKeyMaterial material = app.RegisterClient(ClientId, ClientBaseUri, VerifierCapabilities);
        RegisteredMaterials.Add(material);

        app.Server.Vcalm().UseDefaultVcalmJsonParsing(JsonOptions);
        app.Server.Vcalm().VcalmCredentialVerification = new VcalmCredentialVerification
        {
            Resolver = KeyDidResolverSeam,
            //The canonicalizer matches the suite the verifier instance serves: RDFC-1.0 +
            //offline context resolver for eddsa-rdfc-2022 credentials, JCS for eddsa-jcs-2022
            //presentations. The library does not hardcode the choice; a multi-suite deployment
            //wires a canonicalizer that dispatches on the proof's cryptosuite.
            Canonicalize = canonicalizer ?? RdfcCanonicalizer,
            ContextResolver = contextResolver ?? ContextResolver,
            DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential = SerializeCredential,
            SerializePresentation = SerializePresentation,
            SerializeProofOptions = SerializeProofOptions,
            Decoder = TestSetup.Base58Decoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
            MemoryPool = Pool,
            //§3.4 ecdsa-sd-2023 derived-proof seams: the CBOR derived-proof parser, the P-256
            //verification function, and the base64url codec the SD verifier composes. When wired, a
            //derived (0xd9 5d 01) proof routes to the derived-proof verifier; when null, an SD derived
            //credential falls through to the generic path (verified:false). RDFC is the SD canonicalizer.
            ParseDerivedProof = sd is null ? null : EcdsaSd2023CborSerializer.ParseDerivedProof,
            VerifyDerivedSignature = sd is null ? null : BouncyCastleCryptographicFunctions.VerifyP256Async,
            SdProofEncoder = sd is null ? null : TestSetup.Base64UrlEncoder,
            SdProofDecoder = sd is null ? null : TestSetup.Base64UrlDecoder
        };

        if(persistChallenge is not null)
        {
            app.Server.Vcalm().PersistVcalmChallengeAsync = persistChallenge;
        }

        if(consumeChallenge is not null)
        {
            app.Server.Vcalm().ConsumeVcalmChallengeAsync = consumeChallenge;
        }

        //The §2.4 / B.4 payload-size cap is a server-level instance configuration.
        app.Server.Vcalm().VcalmMaxRequestBytes = maxRequestBytes;

        return material.Registration.TenantId.Value;
    }


    //Signs a VC-DM 2.0 credential with eddsa-rdfc-2022 under a did:key issuer the KeyDidResolver
    //resolves locally. validUntilPast sets validUntil before the verification instant to exercise the
    //§3.8.1 validity-period WARNING; withStatus adds a §C.3 BitstringStatusListEntry credentialStatus so
    //the verifier's status-resolution path runs.
    private async Task<DataIntegritySecuredCredential> SignCredentialAsync(
        bool validUntilPast, bool withStatus = false, CredentialStatus? customStatus = null)
    {
        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory issuerPublic = keyPair.PublicKey;
        using PrivateKeyMemory issuerPrivate = keyPair.PrivateKey;

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuerPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        VerifiableCredential credential = new()
        {
            Context = new Context
            {
                Contexts =
                [
                    Context.Credentials20,
                    CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl
                ]
            },
            Id = "urn:uuid:vcalm-test-credential",
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = validUntilPast ? "2024-01-01T00:00:00Z" : "2030-01-01T00:00:00Z",
            CredentialSubject =
            [
                new CredentialSubject
                {
                    Id = "did:example:alumni-subject",
                    AdditionalData = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["alumniOf"] = "The School of Examples"
                    }
                }
            ]
        };

        if(customStatus is not null)
        {
            //A caller-supplied credentialStatus — used to drive the non-mapping shape branches
            //(wrong type / unparseable index / missing list reference).
            credential.CredentialStatus = [customStatus];
        }
        else if(withStatus)
        {
            //A §C.3 BitstringStatusListEntry — Type MUST equal the entry type the verifier maps on, else
            //the entry never resolves and the status-resolution path is silently skipped.
            credential.CredentialStatus =
            [
                new CredentialStatus
                {
                    Id = "https://status.example/list#94567",
                    Type = "BitstringStatusListEntry",
                    StatusPurpose = "revocation",
                    StatusListIndex = "94567",
                    StatusListCredential = "https://status.example/list"
                }
            ];
        }

        DateTime proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        return await credential.SignAsync(
            issuerPrivate,
            verificationMethodId,
            EddsaRdfc2022CryptosuiteInfo.Instance,
            proofCreated,
            RdfcCanonicalizer,
            ContextResolver,
            ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            Pool,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Signs a holder presentation with eddsa-jcs-2022 binding the given challenge and domain, under a
    //did:key holder the KeyDidResolver resolves locally. JCS is context-free and yields a non-empty
    //canonical form for a minimal presentation.
    private async Task<DataIntegritySecuredPresentation> SignPresentationAsync(string challenge, string domain)
    {
        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublic = keyPair.PublicKey;
        using PrivateKeyMemory holderPrivate = keyPair.PrivateKey;

        DidDocument holderDidDocument = await KeyDidBuilder.BuildAsync(
            holderPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        string holderDid = holderDidDocument.Id!.ToString();
        DateTime proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        return await new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = holderDid
        }.SignAsync(
            holderPrivate,
            verificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            challenge,
            domain,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.EncodeBase58Btc,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            Pool,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Signs a holder presentation whose proof's verificationMethod belongs to one did:key (the
    //attacker's signing key) but whose holder member claims a DIFFERENT did:key (the victim). The
    //signature is cryptographically valid for the attacker key, but the claimed holder DID does NOT
    //control that key — the verify-time holder-to-verificationMethod binding must reject it
    //(GetLocalAuthenticationMethodById finds no such method in the victim's document).
    private async Task<DataIntegritySecuredPresentation> SignPresentationWithForgedHolderAsync(
        string challenge, string domain)
    {
        //Victim A: only its DID is borrowed into the holder member; its key never signs. FRESH keys are
        //required here — the cached CreateEd25519KeyMaterial would hand the attacker the SAME key, making
        //the two DIDs identical and the "forgery" a legitimate holder==signer presentation.
        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> victimKeys =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory victimPublic = victimKeys.PublicKey;
        using PrivateKeyMemory victimPrivate = victimKeys.PrivateKey;
        DidDocument victimDocument = await KeyDidBuilder.BuildAsync(
            victimPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string victimDid = victimDocument.Id!.ToString();

        //Attacker B: its (distinct) key signs and its verificationMethod id rides the proof.
        Verifiable.Cryptography.PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> attackerKeys =
            TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        using PublicKeyMemory attackerPublic = attackerKeys.PublicKey;
        using PrivateKeyMemory attackerPrivate = attackerKeys.PrivateKey;
        DidDocument attackerDocument = await KeyDidBuilder.BuildAsync(
            attackerPublic,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string attackerVerificationMethodId = attackerDocument.VerificationMethod![0].Id!;

        //Guard the test's premise: a vacuous "forgery" (identical DIDs) would verify true for the right
        //reason and silently pass nothing. The two identities MUST differ for the binding to be exercised.
        Assert.AreNotEqual(victimDid, attackerDocument.Id!.ToString(),
            "The forged-holder test requires two DISTINCT did:key identities.");

        DateTime proofCreated = TimeProvider.GetUtcNow().UtcDateTime;

        return await new VerifiablePresentation
        {
            Context = new Context { Contexts = [Context.Credentials20] },
            Type = ["VerifiablePresentation"],
            Holder = victimDid
        }.SignAsync(
            attackerPrivate,
            attackerVerificationMethodId,
            EddsaJcs2022CryptosuiteInfo.Instance,
            proofCreated,
            challenge,
            domain,
            JcsCanonicalizer,
            contextResolver: null,
            ProofValueCodecs.EncodeBase58Btc,
            SerializePresentation,
            DeserializePresentation,
            SerializeProofOptions,
            TestSetup.Base58Encoder,
            MicrosoftEntropyFunctions.ComputeDigestAsync,
            Pool,
            EmptyContext,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
    }


    //Creates a fresh P-256 issuer + ephemeral key pair for ecdsa-sd-2023 base proofs under a did:key
    //issuer the KeyDidResolver resolves locally — the verifier resolves this DID document to extract
    //the P-256 public key the derived-proof verifier reconstructs the base signature with. The key
    //material is tracked for disposal at cleanup.
    private async Task<SdIssuerContext> CreateSdIssuerContextAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuer =
            BouncyCastleKeyMaterialCreator.CreateP256Keys(Pool);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ephemeral =
            BouncyCastleKeyMaterialCreator.CreateP256Keys(Pool);

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuer.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        //The issuer public key is retained on the context only to round-trip key material lifetime; the
        //verifier extracts its own copy from the resolved DID document, not from the context.
        OwnedKeys.Add(issuer.PublicKey);
        OwnedKeys.Add(issuer.PrivateKey);
        OwnedKeys.Add(ephemeral.PublicKey);
        OwnedKeys.Add(ephemeral.PrivateKey);

        return new SdIssuerContext(issuer.PrivateKey, ephemeral, verificationMethodId, issuerDid);
    }


    //Issuer base-signs the standard test credential with ecdsa-sd-2023, then derives a
    //selectively-disclosed subset (the disclosed claim plus the issuer's mandatory pointers) — the
    //realistic verifier input: what a holder presents after selective disclosure.
    private async Task<DataIntegritySecuredCredential> CreateDerivedCredentialAsync(SdIssuerContext sd)
    {
        VerifiableCredential credential = JsonSerializerExtensions.Deserialize<VerifiableCredential>(
            CredentialSecuringMaterial.UnsignedCredentialJson, JsonOptions)!;

        //The credential's issuer is the resolvable did:key issuer so the verifier resolves it to the
        //P-256 verification method and extracts the issuer public key the SD verifier reconstructs the
        //base signature with.
        credential.Issuer = new Issuer { Id = sd.IssuerDid };

        List<CredentialPath> mandatoryPaths =
        [
            CredentialPath.FromJsonPointer("/issuer"),
            CredentialPath.FromJsonPointer("/type")
        ];

        DataIntegritySecuredCredential baseCredential = await credential.CreateBaseProofAsync(
            sd.IssuerPrivateKey,
            sd.EphemeralKeyPair,
            sd.VerificationMethodId,
            TimeProvider.GetUtcNow().UtcDateTime,
            mandatoryPaths,
            () => RandomNumberGenerator.GetBytes(32),
            JsonLdSelection.PartitionStatements,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            SerializeProofOptions,
            EcdsaSd2023CborSerializer.SerializeBaseProof,
            TestSetup.Base64UrlEncoder,
            Pool,
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);

        IReadOnlySet<CredentialPath> selectivePointers = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer("/credentialSubject/degree/name")
        };

        return await baseCredential.DeriveProofAsync(
            selectivePointers,
            userExclusions: null,
            JsonLdSelection.PartitionStatements,
            JsonLdSelection.SelectFragments,
            RdfcCanonicalizer,
            ContextResolver,
            SerializeCredential,
            DeserializeCredential,
            EcdsaSd2023CborSerializer.ParseBaseProof,
            EcdsaSd2023CborSerializer.SerializeDerivedProof,
            TestSetup.Base64UrlEncoder,
            TestSetup.Base64UrlDecoder,
            Pool,
            EmptyContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string BuildCredentialRequestBody(
        DataIntegritySecuredCredential credential, bool returnProblemDetails, bool returnResults = false)
    {
        string credentialJson = SerializeCredential(credential);
        StringBuilder options = new("{");
        bool first = true;
        if(returnProblemDetails)
        {
            options.Append("\"returnProblemDetails\":true");
            first = false;
        }

        if(returnResults)
        {
            if(!first) { options.Append(','); }

            options.Append("\"returnResults\":true");
        }

        options.Append('}');

        return "{\"verifiableCredential\":" + credentialJson + ",\"options\":" + options + "}";
    }


    private static string BuildPresentationRequestBody(
        DataIntegritySecuredPresentation presentation, string challenge, string domain)
    {
        string presentationJson = SerializePresentation(presentation);

        return "{\"verifiablePresentation\":" + presentationJson
            + ",\"options\":{\"challenge\":\"" + challenge + "\",\"domain\":\"" + domain + "\"}}";
    }


    private async Task<JsonDocument> PostCredentialAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmCredentialsVerify,
            "POST",
            new RequestFields(),
            body,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    private async Task<JsonDocument> PostPresentationAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownVcalmEndpointNames.VcalmPresentationsVerify,
            "POST",
            new RequestFields(),
            body,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    //The ecdsa-sd-2023 issuer key material for the §3.4 derived-proof money-shot. The issuer public
    //key is NOT carried here: the verifier extracts it from the resolved issuer DID document, which is
    //the realistic verify path. VerificationMethodId is the did:key VM the KeyDidResolver resolves.
    private sealed record SdIssuerContext(
        PrivateKeyMemory IssuerPrivateKey,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> EphemeralKeyPair,
        string VerificationMethodId,
        string IssuerDid);
}
