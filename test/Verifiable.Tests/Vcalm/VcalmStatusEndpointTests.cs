using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Resolvers;
using Verifiable.Core.StatusLists;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;
using CoreStatusList = Verifiable.Core.StatusLists.StatusList;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// End-to-end conformance tests for the W3C VCALM 1.0 status service
/// (<see href="https://www.w3.org/TR/vcalm-1.0/">A Verifiable Credential API for Lifecycle
/// Management</see>) exposed by <see cref="VcalmStatusEndpoints"/> — the §C.3
/// <c>POST /credentials/status</c> binding MUST ("A conforming status service implementation MUST
/// provide the interface described in Section C.3 Update Status."), and the MAY §C.1
/// <c>POST /status-lists</c> and §C.2 <c>GET /status-lists/{id}</c> interfaces, driven through the
/// real dispatch pipeline. The issue→set-status→verify round-trip drives a credential carrying a
/// <c>credentialStatus</c> through the V-2 issue endpoint, the §C.3 update, and the §3.3.1 verify
/// endpoint, asserting the §3.8.1 status WARNING.
/// </summary>
/// <remarks>
/// The signing key (eddsa-rdfc-2022), the RDFC canonicalizer, the did:key resolver, the Core
/// <see cref="StatusList"/> / <see cref="BitstringStatusListCodec"/> bit core, and the project crypto
/// are the same library primitives the V-1 / V-2 flow tests use — the status service COMPOSES them,
/// it does not re-roll cryptography or the bitstring codec.
/// </remarks>
[TestClass]
internal sealed class VcalmStatusEndpointTests
{
    /// <summary>The MSTest context, whose cancellation token bounds every dispatch these tests make.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The host's clock, fixed at the canonical epoch.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The pool the did:key resolver, the signing and the status lists rent from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The client identifier the status tenant is registered under.</summary>
    private const string ClientId = "https://status.client.test";

    /// <summary>The base URI the status tenant is registered under.</summary>
    private static Uri ClientBaseUri { get; } = new("https://status.client.test");

    /// <summary>
    /// The §C.3 update + status checking exercise all three roles on the same tenant: issuer (mint the
    /// credential and the status list), status (set the bit), verifier (read the warning).
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> AllRoleCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmIssuer,
            WellKnownVcalmCapabilities.VcalmVerifier,
            WellKnownVcalmCapabilities.VcalmStatus);

    /// <summary>The serializer options every JSON delegate of these tests uses.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>Builds the issuer's did:key document from its public key.</summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    /// <summary>The DID resolver the verifier resolves the issuer with: did:key, resolved locally.</summary>
    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    /// <summary>The RDFC-1.0 canonicalizer the eddsa-rdfc-2022 signing and verification share.</summary>
    private static CanonicalizationDelegate RdfcCanonicalizer { get; } =
        CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    /// <summary>The closed test context resolver the canonicalizer loads JSON-LD contexts through.</summary>
    private static ContextResolverDelegate ContextResolver { get; } =
        CanonicalizationTestUtilities.CreateTestContextResolver();

    /// <summary>Serializes a credential for issuance, verification and the wire.</summary>
    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    /// <summary>Reads a credential back from its JSON.</summary>
    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    /// <summary>Serializes the proof options a Data Integrity proof hashes.</summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    /// <summary>The standard status-list-credential url every credentialStatus in these tests references.</summary>
    private const string StatusListId = "https://status.example/status-lists/1";

    /// <summary>The standard <c>statusPurpose</c> value every credentialStatus in these tests declares.</summary>
    private const string RevocationPurpose = "revocation";

    /// <summary>The tenant registrations and signing keys of the running test, disposed after it.</summary>
    private List<StatusKeyMaterial> RegisteredMaterials { get; } = [];

    /// <summary>The in-memory status-list store the §C.1 / §C.2 seams read and write (id → secured VC JSON).</summary>
    private ConcurrentDictionary<string, string> StatusListStore { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// The live decoded status lists the §C.3 update seam mutates and the resolver seam reads. Keyed by
    /// statusListCredential url. The §C.3 seam sets / clears the bit here; the resolver hands the
    /// verifier a fresh copy it owns and disposes.
    /// </summary>
    private ConcurrentDictionary<string, CoreStatusList> LiveStatusLists { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// The credentialId → statusListCredential url map the §C.3 404 key is checked against (the status
    /// service holds a record for a credential only after it has been issued against a known list).
    /// </summary>
    private ConcurrentDictionary<string, string> KnownCredentials { get; } = new(StringComparer.Ordinal);


    /// <summary>Disposes the finished test's registrations, keys and live status lists and clears the stores.</summary>
    [TestCleanup]
    public void DisposeRegisteredMaterials()
    {
        foreach(StatusKeyMaterial material in RegisteredMaterials)
        {
            material.Dispose();
        }

        foreach(CoreStatusList list in LiveStatusLists.Values)
        {
            list.Dispose();
        }

        RegisteredMaterials.Clear();
        StatusListStore.Clear();
        LiveStatusLists.Clear();
        KnownCredentials.Clear();
    }


    /// <summary>
    /// §C.1 create: a valid create-status-list request returns HTTP 201 with a Data-Integrity-secured
    /// status-list credential under <c>verifiableCredential</c> and the list <c>id</c>, and that
    /// status-list credential verifies TRUE at the V-1 verifier endpoint.
    /// </summary>
    [TestMethod]
    public async Task CreateStatusListReturns201AndVerifies()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);

        //The status-list credential itself carries the base-only context VcalmStatusListService
        //mints it with, not the "ExampleAlumniCredential" base-plus-examples context the shared
        //verification wiring otherwise checks credentialStatus-bearing test credentials against.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialVerification = candidateIntegration.VcalmCredentialVerification! with
            {
                KnownContext = Context.FromIris(Context.Credentials20)
            };
        }).ConfigureAwait(false);

        using JsonDocument response = await PostCreateStatusListAsync(
            app, ctx.Segment, $"{{\"statusPurpose\":\"{RevocationPurpose}\",\"id\":\"{StatusListId}\"}}",
            expectedStatus: 201).ConfigureAwait(false);

        Assert.AreEqual(StatusListId, response.RootElement.GetProperty(VcalmParameterNames.Id).GetString(),
            "The §C.1 response echoes the created status-list id.");

        string securedStatusListJson = response.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        //The §C.1 status-list credential verifies TRUE at the V-1 verifier endpoint — it is itself a
        //verifiable credential secured with the same mechanism (§C.1).
        string verifyBody = "{\"verifiableCredential\":" + securedStatusListJson + "}";
        ServerHttpResponse verifyResponse = await app.DispatchAtEndpointAsync(
            ctx.Segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, "POST",
            new RequestFields(), verifyBody, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, verifyResponse.StatusCode, verifyResponse.Body);
        using JsonDocument verifyDoc = JsonDocument.Parse(verifyResponse.Body);
        Assert.IsTrue(verifyDoc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A §C.1 status-list credential must verify TRUE at the verifier service.");
    }


    /// <summary>
    /// §C.2 get: a created status list is retrievable by id with HTTP 200, and an unknown id is 404
    /// ("Status list not found").
    /// </summary>
    [TestMethod]
    public async Task GetStatusListReturns200And404()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);

        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        //200: the stored status-list credential.
        ServerHttpResponse getResponse = await app.DispatchVcalmStatusListByIdAsync(
            ctx.Segment, StatusListId, [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, getResponse.StatusCode, getResponse.Body);
        using JsonDocument getDoc = JsonDocument.Parse(getResponse.Body);
        Assert.IsTrue(getDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiableCredential, out _),
            "The §C.2 retrieval returns the status list under verifiableCredential.");

        //404: an id the store never held.
        ServerHttpResponse notFound = await app.DispatchVcalmStatusListByIdAsync(
            ctx.Segment, "https://status.example/status-lists/never", [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(404, notFound.StatusCode, "An unknown status-list id is 404.");
    }


    /// <summary>
    /// §C.3 set status: setting a known credential's <c>revocation</c> bit returns HTTP 200, and the
    /// live status list reflects the set bit.
    /// </summary>
    [TestMethod]
    public async Task UpdateStatusSetsBitAndReturns200()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 94;
        const string CredentialId = "urn:uuid:status-target";
        KnownCredentials[CredentialId] = StatusListId;

        ServerHttpResponse response = await PostUpdateStatusAsync(
            app, ctx.Segment, BuildUpdateStatusBody(CredentialId, Index, status: true)).ConfigureAwait(false);
        Assert.AreEqual(200, response.StatusCode, response.Body);

        Assert.AreEqual<byte>(1, LiveStatusLists[StatusListId].Get(Index),
            "The §C.3 update set the revocation bit at the credential's index.");
    }


    /// <summary>
    /// §C.3 404: an update targeting a credential the status service holds no record for is 404
    /// ("Credential not found").
    /// </summary>
    [TestMethod]
    public async Task UpdateStatusUnknownCredentialYields404()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        //No KnownCredentials entry for this id → the update seam reports NotFound.
        ServerHttpResponse response = await PostUpdateStatusAsync(
            app, ctx.Segment, BuildUpdateStatusBody("urn:uuid:never-issued", 1, status: true)).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode, "An unknown credential is a §C.3 404.");
    }


    /// <summary>
    /// §C.1 / §C.3 re-secure: <see cref="VcalmStatusListService.UpdateAsync"/> sets a status bit on the
    /// decoded list, rebuilds the status-list credential, and re-signs it — the re-secured credential
    /// carries the set bit (and only that bit) and verifies TRUE at the V-1 verifier. This is the
    /// issuer's revoke / republish primitive: the §C.3 update seam mutates the live list, this turns
    /// the mutated list back into a signed, publishable status-list credential.
    /// </summary>
    [TestMethod]
    public async Task UpdateAsyncReSecuresStatusListWithSetBit()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);

        //The status-list credential itself carries the base-only context VcalmStatusListService
        //mints it with, not the "ExampleAlumniCredential" base-plus-examples context the shared
        //verification wiring otherwise checks credentialStatus-bearing test credentials against.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialVerification = candidateIntegration.VcalmCredentialVerification! with
            {
                KnownContext = Context.FromIris(Context.Credentials20)
            };
        }).ConfigureAwait(false);

        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 94;
        VcalmCredentialIssuance issuance = app.Server.Vcalm().VcalmStatusListIssuance!;

        //Decode the freshly-created (all-zero) published list, then re-secure it with the
        //revocation bit set at the target index.
        using CoreStatusList list = DecodeStatusList(StatusListStore[StatusListId]);
        Assert.AreEqual<byte>(0, list.Get(Index), "The freshly created list starts all-zero.");

        DataIntegritySecuredCredential updated = await VcalmStatusListService.UpdateAsync(
            StatusListId,
            RevocationPurpose,
            list,
            new Dictionary<int, byte> { [Index] = 1 },
            issuance,
            TimeProvider.GetUtcNow().UtcDateTime,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        string updatedJson = issuance.SigningDescriptors[0].SerializeCredential(updated);

        //The re-secured credential carries the set bit, and only that bit.
        using CoreStatusList reDecoded = DecodeStatusList(updatedJson);
        Assert.AreEqual<byte>(1, reDecoded.Get(Index),
            "UpdateAsync set the revocation bit in the re-secured list.");
        Assert.AreEqual<byte>(0, reDecoded.Get(0), "Entries other than the updated one stay clear.");

        //The re-secured credential verifies TRUE — the re-signature is valid, not merely the bit set.
        string verifyBody = "{\"verifiableCredential\":" + updatedJson + "}";
        ServerHttpResponse verifyResponse = await app.DispatchAtEndpointAsync(
            ctx.Segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, "POST",
            new RequestFields(), verifyBody, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, verifyResponse.StatusCode, verifyResponse.Body);
        using JsonDocument verifyDoc = JsonDocument.Parse(verifyResponse.Body);
        Assert.IsTrue(verifyDoc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "The re-secured §C.1 status-list credential must verify TRUE.");
    }


    /// <summary>
    /// §2.4 unknown-option MUST: a §C.3 <c>credentialStatus</c> member the status service does not
    /// understand is rejected with HTTP 400 and the §3.8 <c>UNKNOWN_OPTION_PROVIDED</c> type.
    /// </summary>
    [TestMethod]
    public async Task UpdateStatusUnknownOptionYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);

        string body = "{\"credentialId\":\"urn:uuid:x\",\"credentialStatus\":{\"type\":\"BitstringStatusListEntry\","
            + $"\"statusPurpose\":\"{RevocationPurpose}\",\"statusListIndex\":\"1\","
            + $"\"statusListCredential\":\"{StatusListId}\",\"notARealMember\":true}},\"status\":true}}";

        ServerHttpResponse response = await PostUpdateStatusAsync(app, ctx.Segment, body, expectedStatus: 400)
            .ConfigureAwait(false);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual("https://www.w3.org/TR/vcalm#UNKNOWN_OPTION_PROVIDED",
            doc.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            "An unknown credentialStatus member yields the UNKNOWN_OPTION_PROVIDED type.");
    }


    /// <summary>
    /// §2.4 content-serialization MUST: a §C.3 request whose Content-Type is not
    /// <c>application/json</c> is rejected with HTTP 400 before parsing.
    /// </summary>
    [TestMethod]
    public async Task UpdateStatusNonJsonYields400()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);

        byte[] bytes = Encoding.UTF8.GetBytes(BuildUpdateStatusBody("urn:uuid:x", 1, status: true));
        ServerHttpResponse response = await app.DispatchWithBodyAsync(
            ctx.Segment, WellKnownVcalmEndpointNames.VcalmCredentialsStatus, "POST",
            bytes, "text/plain", [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode,
            "A non-application/json §C.3 body is rejected before parsing (§2.4 content-serialization MUST).");
    }


    /// <summary>
    /// §C.3 malformed update: a §C.3 POST body that is not valid JSON, or omits the REQUIRED
    /// <c>credentialId</c> or <c>credentialStatus</c> members, is rejected with HTTP 400 and the §3.8
    /// <c>MALFORMED_VALUE_ERROR</c> type — distinct from the unknown-option (UNKNOWN_OPTION_PROVIDED) and
    /// the unknown-credential (404) branches.
    /// </summary>
    [TestMethod]
    [DataRow("{ not valid json", "malformed JSON")]
    [DataRow("{\"credentialStatus\":{\"type\":\"BitstringStatusListEntry\",\"statusPurpose\":\"revocation\",\"statusListIndex\":\"1\",\"statusListCredential\":\"https://status.example/status-lists/1\"},\"status\":true}", "missing credentialId")]
    [DataRow("{\"credentialId\":\"urn:uuid:x\",\"status\":true}", "missing credentialStatus")]
    public async Task UpdateStatusMalformedBodyYields400MalformedValueError(string body, string reason)
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);

        ServerHttpResponse response = await PostUpdateStatusAsync(app, ctx.Segment, body, expectedStatus: 400)
            .ConfigureAwait(false);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual("https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            doc.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            $"A §C.3 malformed update ({reason}) yields the MALFORMED_VALUE_ERROR type.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "Warnings are
    /// ProblemDetails relating to status and validity periods". A credential carrying a NON-MAPPING
    /// credentialStatus entry FIRST (an unparseable <c>statusListIndex</c>, skipped by TryMapStatusEntry)
    /// FOLLOWED by a well-formed revocation entry whose bit is set still surfaces the STATUS_WARNING — the
    /// per-entry loop CONTINUES past the non-mapping entry rather than breaking, so the first entry cannot mask
    /// the real revocation.
    /// </summary>
    [TestMethod]
    public async Task NonMappingStatusEntryDoesNotMaskValidRevokedEntry()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListWireAsync(app, ctx.Segment).ConfigureAwait(false);

        const int ValidIndex = 23;
        const string CredentialId = "urn:uuid:two-entry-status";
        KnownCredentials[CredentialId] = StatusListId;

        string issueBody = BuildIssueRequestBodyWithTwoStatusEntries(ctx.IssuerDid, CredentialId, ValidIndex);
        using JsonDocument issued = await VcalmWireFixtures.PostIssueWireAsync(
            app, ctx.Segment, issueBody, 201, TestContext.CancellationToken).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        //Set the WELL-FORMED entry revoked; the non-mapping entry is FIRST in the credentialStatus array.
        await UpdateStatusWireAsync(app, ctx.Segment, BuildUpdateStatusBody(CredentialId, ValidIndex, status: true)).ConfigureAwait(false);

        using JsonDocument after = await VerifyWireAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);
        Assert.IsTrue(after.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "§3.8.1: status is a WARNING — the credential still verifies true.");
        Assert.IsTrue(HasStatusWarning(after),
            "A non-mapping FIRST entry must not mask a later well-formed REVOKED entry: the STATUS_WARNING still surfaces.");
    }


    /// <summary>
    /// §C.3 / §3.8.1 GetStatus §3.2 mismatch swallowed at the verify ENDPOINT: a credential whose
    /// credentialStatus declares a <c>suspension</c> purpose while the resolved status list serves only
    /// <c>revocation</c> makes GetStatus throw a §3.2 purpose-mismatch — which the verify endpoint
    /// swallows to no-result / no-warning, never a 500. The credential still verifies TRUE. This drives
    /// the GetStatus-throw branch through the endpoint (the Core throw itself is unit-pinned by
    /// BitstringStatusListValidationTests; the endpoint-level swallow shares the resolver-throw catch).
    /// </summary>
    [TestMethod]
    public async Task GetStatusPurposeMismatchSwallowedAtVerifyEndpointStaysVerified()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 31;
        const string CredentialId = "urn:uuid:purpose-mismatch-status";
        KnownCredentials[CredentialId] = StatusListId;

        //The entry declares 'suspension'; the resolver's list (CreateStatusListAsync) serves 'revocation'.
        string issueBody = BuildIssueRequestBodyWithStatus(ctx.IssuerDid, CredentialId, Index, statusPurpose: "suspension");
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        using JsonDocument verified = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);
        Assert.IsTrue(verified.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A GetStatus §3.2 purpose mismatch is swallowed at the verify endpoint (no result, no 500): verified stays TRUE.");
        Assert.IsFalse(HasStatusWarning(verified),
            "An undeterminable (purpose-mismatched) status asserts nothing — no STATUS_WARNING.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "Warnings are
    /// ProblemDetails relating to status and validity periods", and "if no errors are included, it MUST be set to
    /// true". The round-trip issues a credential carrying a <c>credentialStatus</c> through the issue endpoint, sets it
    /// revoked through §C.3, then verifies it: HTTP 200, <c>verified:true</c>, with a STATUS WARNING in
    /// <c>problemDetails</c>. A non-revoked credential verifies with NO status warning.
    /// </summary>
    [TestMethod]
    public async Task IssueThenRevokeThenVerifyEmitsStatusWarningButStaysVerified()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListWireAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 17;
        const string CredentialId = "urn:uuid:roundtrip-status";
        KnownCredentials[CredentialId] = StatusListId;

        //Issue a credential carrying a credentialStatus pointing at the status list (V-2 issue).
        string issueBody = BuildIssueRequestBodyWithStatus(ctx.IssuerDid, CredentialId, Index);
        using JsonDocument issued = await VcalmWireFixtures.PostIssueWireAsync(
            app, ctx.Segment, issueBody, 201, TestContext.CancellationToken).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        //Before revocation: the credential verifies TRUE with NO status warning.
        using(JsonDocument before = await VerifyWireAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false))
        {
            Assert.IsTrue(before.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
                "A non-revoked credential verifies true.");
            Assert.IsFalse(HasStatusWarning(before),
                "A non-revoked credential carries no status warning.");
        }

        //Set the credential revoked via §C.3.
        await UpdateStatusWireAsync(app, ctx.Segment, BuildUpdateStatusBody(CredentialId, Index, status: true)).ConfigureAwait(false);

        //After revocation: the credential STILL verifies true (status is a §3.8.1 WARNING, not an
        //error), but a status warning is now present in problemDetails.
        using JsonDocument after = await VerifyWireAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);
        Assert.IsTrue(after.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "§3.8.1: status is a WARNING, not an error — a revoked credential still verifies true.");
        Assert.IsTrue(HasStatusWarning(after),
            "A revoked credential surfaces a §3.8.1 STATUS_WARNING problem detail.");
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring Status List 1.0
    /// §3.5</see> STATUS_RETRIEVAL_ERROR, "Retrieval of the status list failed.", written as a literal so these
    /// tests do not take the expected value from <see cref="VcalmProblemTypes"/>, the catalog they exercise.
    /// </summary>
    private const string StatusRetrievalErrorType = "https://www.w3.org/ns/credentials/status-list#STATUS_RETRIEVAL_ERROR";

    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring Status List 1.0
    /// §3.5</see> STATUS_VERIFICATION_ERROR, "Validation of the status entry failed.", written as a literal so these
    /// tests do not take the expected value from <see cref="VcalmProblemTypes"/>, the catalog they exercise.
    /// </summary>
    private const string StatusVerificationErrorType = "https://www.w3.org/ns/credentials/status-list#STATUS_VERIFICATION_ERROR";

    /// <summary>
    /// <see href="https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors">Bitstring Status List 1.0
    /// §3.5</see> STATUS_LIST_LENGTH_ERROR, "The status list length does not satisfy the minimum length required for
    /// herd privacy.", written as a literal so these tests do not take the expected value from
    /// <see cref="VcalmProblemTypes"/>, the catalog they exercise.
    /// </summary>
    private const string StatusListLengthErrorType = "https://www.w3.org/ns/credentials/status-list#STATUS_LIST_LENGTH_ERROR";

    /// <summary>
    /// The RANGE_ERROR that <see href="https://www.w3.org/TR/vc-bitstring-status-list/#validate-algorithm">Bitstring
    /// Status List 1.0 §3.2</see> raises when "the credentialIndex multiplied by the size is a value outside of the
    /// range of the bitstring". That specification does not list the code among its own §3.5 errors, so the type URL
    /// is the one <see href="https://www.w3.org/TR/vc-data-model-2.0/#problem-details">VC Data Model 2.0 §7.2</see>
    /// defines: "A provided value is outside of the expected range of an associated value". It is written as a literal
    /// so these tests do not take the expected value from <see cref="VcalmProblemTypes.RangeError"/>.
    /// </summary>
    private const string RangeErrorType = "https://www.w3.org/TR/vc-data-model#RANGE_ERROR";


    /// <summary>
    /// Bitstring Status List 1.0 §3.5 <c>STATUS_RETRIEVAL_ERROR</c>: the application's
    /// <c>ResolveVcalmStatusListDelegate</c> cannot retrieve the referenced status list — it returns
    /// <see langword="null"/> because the status service holds no record for the referenced
    /// <c>statusListCredential</c>. §3.8.1 makes status a WARNING: the credential still verifies
    /// TRUE, and the entry contributes no <c>results.credentialStatus</c> item.
    /// </summary>
    [TestMethod]
    public async Task UnresolvableStatusListYieldsStatusRetrievalErrorWarning()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);

        const int Index = 61;
        const string CredentialId = "urn:uuid:status-retrieval-error";
        const string UnknownStatusList = "https://status.example/status-lists/never-created";

        string issueBody = BuildIssueRequestBodyWithStatus(
            ctx.IssuerDid, CredentialId, Index, statusListCredential: UnknownStatusList);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        using JsonDocument verified = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);

        Assert.IsTrue(verified.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "§3.8.1: an unresolvable status list is a WARNING, not an ERROR — verified stays true.");
        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(verified, StatusRetrievalErrorType),
            "An unresolvable status list surfaces the Bitstring Status List 1.0 §3.5 STATUS_RETRIEVAL_ERROR.");

        JsonElement statusResults = verified.RootElement
            .GetProperty(VcalmParameterNames.Results)
            .GetProperty(VcalmParameterNames.CredentialStatus);
        Assert.AreEqual(0, statusResults.GetArrayLength(),
            "An unresolvable status entry establishes no status result.");
    }


    /// <summary>
    /// Bitstring Status List 1.0 §3.5 <c>STATUS_VERIFICATION_ERROR</c>: the resolver reports a
    /// precise cause by throwing <c>BitstringStatusListException</c> of kind
    /// <c>StatusVerification</c> — §3.8.1 makes it a WARNING naming that specification error type,
    /// not the exception's own message.
    /// </summary>
    [TestMethod]
    public async Task ResolverThrowingStatusVerificationExceptionYieldsStatusVerificationErrorWarning()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 62;
        const string CredentialId = "urn:uuid:status-verification-exception";

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, exchangeContext, cancellationToken) =>
                throw new BitstringStatusListException(
                    BitstringStatusListErrorType.StatusVerification,
                    "The status list credential's proof did not verify.");
        }).ConfigureAwait(false);

        string issueBody = BuildIssueRequestBodyWithStatus(ctx.IssuerDid, CredentialId, Index);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        using JsonDocument verified = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);

        Assert.IsTrue(verified.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "§3.8.1: a status-verification failure is a WARNING — verified stays true.");
        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(verified, StatusVerificationErrorType),
            "A BitstringStatusListException of kind StatusVerification surfaces STATUS_VERIFICATION_ERROR.");
    }


    /// <summary>
    /// Bitstring Status List 1.0 §3.5 <c>STATUS_LIST_LENGTH_ERROR</c>: the real
    /// <c>BitstringStatusListValidation.GetStatus</c> raises the §3.2 herd-privacy minimum-length
    /// check when the resolved status list holds fewer than
    /// <c>BitstringStatusListCodec.MinimumEntries</c> entries.
    /// </summary>
    [TestMethod]
    public async Task StatusListBelowMinimumLengthYieldsStatusListLengthErrorWarning()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 0;
        const string CredentialId = "urn:uuid:status-list-length-error";

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, exchangeContext, cancellationToken) =>
            {
                CoreStatusList tooShort = CoreStatusList.Create(8, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);

                return ValueTask.FromResult<VcalmResolvedStatusList?>(new VcalmResolvedStatusList
                {
                    StatusList = tooShort,
                    Purposes = [RevocationPurpose]
                });
            };
        }).ConfigureAwait(false);

        string issueBody = BuildIssueRequestBodyWithStatus(ctx.IssuerDid, CredentialId, Index);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        using JsonDocument verified = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);

        Assert.IsTrue(verified.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "§3.8.1: an under-minimum status list is a WARNING — verified stays true.");
        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(verified, StatusListLengthErrorType),
            "A status list under the §3.2 herd-privacy minimum surfaces STATUS_LIST_LENGTH_ERROR.");
    }


    /// <summary>
    /// §3.2 Validate Algorithm <c>RANGE_ERROR</c>: the real <c>BitstringStatusListValidation.GetStatus</c>
    /// raises the range check when the entry's <c>statusListIndex</c> lies outside the resolved
    /// (herd-privacy-sized) bitstring.
    /// </summary>
    [TestMethod]
    public async Task StatusListIndexBeyondCapacityYieldsRangeErrorWarning()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        int outOfRangeIndex = BitstringStatusListCodec.MinimumEntries + 100;
        const string CredentialId = "urn:uuid:range-error";

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, exchangeContext, cancellationToken) =>
            {
                CoreStatusList list = CoreStatusList.Create(
                    BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);

                return ValueTask.FromResult<VcalmResolvedStatusList?>(new VcalmResolvedStatusList
                {
                    StatusList = list,
                    Purposes = [RevocationPurpose]
                });
            };
        }).ConfigureAwait(false);

        string issueBody = BuildIssueRequestBodyWithStatus(ctx.IssuerDid, CredentialId, outOfRangeIndex);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        using JsonDocument verified = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);

        Assert.IsTrue(verified.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "§3.8.1: an out-of-range index is a WARNING — verified stays true.");
        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(verified, RangeErrorType),
            "A statusListIndex outside the bitstring surfaces the VC Data Model 2.0 RANGE_ERROR.");
    }


    /// <summary>
    /// §3.8 sanitize-server-errors: an arbitrary resolver exception is reported as
    /// <c>STATUS_RETRIEVAL_ERROR</c> with this library's own fixed sentence — the exception's message
    /// MUST NOT reach the response ("Implementers are strongly advised to sanitize all server errors
    /// in production environments, as not doing so can lead to information disclosure.").
    /// </summary>
    [TestMethod]
    public async Task ResolverThrowingArbitraryExceptionYieldsStatusRetrievalErrorWithoutLeakingMessage()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 63;
        const string CredentialId = "urn:uuid:arbitrary-exception";
        const string Marker = "MARKER-9f3c2e77-DO-NOT-LEAK";

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, exchangeContext, cancellationToken) =>
                throw new InvalidOperationException(Marker);
        }).ConfigureAwait(false);

        string issueBody = BuildIssueRequestBodyWithStatus(ctx.IssuerDid, CredentialId, Index);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        string verifyBody = "{\"verifiableCredential\":" + securedCredentialJson
            + ",\"options\":{\"returnProblemDetails\":true}}";
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            ctx.Segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, "POST",
            new RequestFields(), verifyBody, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.IsFalse(response.Body.Contains(Marker, StringComparison.Ordinal),
            "§3.8: server errors are sanitized — the resolver's exception message must not leak.");

        using JsonDocument verified = JsonDocument.Parse(response.Body);
        Assert.IsTrue(verified.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean());
        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(verified, StatusRetrievalErrorType),
            "An arbitrary resolver exception surfaces the generic STATUS_RETRIEVAL_ERROR.");
    }


    /// <summary>
    /// Bitstring Status List 1.0 §3.5 <c>STATUS_VERIFICATION_ERROR</c> for a malformed W3C-shaped
    /// entry: a credentialStatus entry whose <c>type</c> IS <c>BitstringStatusListEntry</c> but whose
    /// <c>statusListIndex</c> is missing cannot be resolved — a different case from a foreign
    /// <c>type</c> (which this verifier implements no algorithm for and reports nothing).
    /// </summary>
    [TestMethod]
    public async Task BitstringStatusListEntryMissingIndexYieldsStatusVerificationErrorWarning()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const string CredentialId = "urn:uuid:missing-index";

        string issueBody = BuildIssueRequestBodyWithMalformedStatusEntry(ctx.IssuerDid, CredentialId);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        using JsonDocument verified = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);

        Assert.IsTrue(verified.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "§3.8.1: a malformed status entry is a WARNING — verified stays true.");
        Assert.IsTrue(VcalmWireFixtures.HasProblemOfType(verified, StatusVerificationErrorType),
            "A BitstringStatusListEntry with a missing statusListIndex surfaces STATUS_VERIFICATION_ERROR.");
    }


    /// <summary>
    /// An entry of a foreign, non-<c>BitstringStatusListEntry</c> <c>type</c> is turned away by
    /// <c>TryMapStatusEntry</c> before the resolver is reached — this verifier implements no
    /// algorithm for it and the specification names no error for it, so it stays silent. The
    /// dedicated coverage for this branch (the "non-BitstringStatusListEntry type" case, plus the
    /// two other non-mapping shapes) is <c>VcalmVerifierEndpointTests.NonMappingStatusEntryIsSkippedWithoutResolverOrCrash</c>.
    /// </summary>
    [TestMethod]
    public async Task ForeignStatusEntryTypeIsSkippedWithoutWarning()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 66;
        const string CredentialId = "urn:uuid:foreign-status-type";

        bool resolverInvoked = false;
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, exchangeContext, cancellationToken) =>
            {
                resolverInvoked = true;

                return ValueTask.FromResult<VcalmResolvedStatusList?>(null);
            };
        }).ConfigureAwait(false);

        VerifiableCredential credential = new()
        {
            Context = Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
            Id = CredentialId,
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = ctx.IssuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = "2030-01-01T00:00:00Z",
            CredentialStatus =
            [
                new CredentialStatus
                {
                    Id = $"{StatusListId}#{Index.ToString(CultureInfo.InvariantCulture)}",
                    Type = "NotABitstringStatusEntry",
                    StatusPurpose = RevocationPurpose,
                    StatusListIndex = Index.ToString(CultureInfo.InvariantCulture),
                    StatusListCredential = StatusListId
                }
            ],
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
        string issueBody = "{\"credential\":" + SerializeCredential(credential) + "}";
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        using JsonDocument verified = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);

        Assert.IsFalse(resolverInvoked,
            "A foreign credentialStatus type must be turned away by TryMapStatusEntry before the resolver.");
        Assert.IsTrue(verified.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean());
        Assert.IsFalse(HasStatusWarning(verified));
        Assert.IsFalse(VcalmWireFixtures.HasProblemOfType(verified, StatusVerificationErrorType),
            "A foreign type establishes no status: this verifier implements no algorithm for it and reports nothing.");
    }


    /// <summary>
    /// VCALM 1.0's §3.3.1 <c>results.credentialStatus[]</c> item MUST be exactly
    /// <c>{ value, verified, input }</c> — a message-purpose entry does not widen the wire item; the
    /// purpose and the message ride the in-process result only.
    /// </summary>
    [TestMethod]
    public async Task MessagePurposeStatusResultWireItemHasExactlyValueVerifiedInputMembers()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 64;
        const string CredentialId = "urn:uuid:message-purpose-wire-shape";

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, exchangeContext, cancellationToken) =>
            {
                CoreStatusList list = CoreStatusList.Create(
                    BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);

                return ValueTask.FromResult<VcalmResolvedStatusList?>(new VcalmResolvedStatusList
                {
                    StatusList = list,
                    Purposes = ["message"]
                });
            };
        }).ConfigureAwait(false);

        string issueBody = BuildIssueRequestBodyWithStatus(ctx.IssuerDid, CredentialId, Index, statusPurpose: "message");
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        using JsonDocument verified = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);

        JsonElement statusResults = verified.RootElement
            .GetProperty(VcalmParameterNames.Results)
            .GetProperty(VcalmParameterNames.CredentialStatus);
        Assert.AreEqual(1, statusResults.GetArrayLength());

        JsonElement item = statusResults[0];
        int memberCount = 0;
        foreach(JsonProperty _ in item.EnumerateObject())
        {
            ++memberCount;
        }

        Assert.AreEqual(3, memberCount, "The wire item carries exactly value, verified, input (VCALM's MUST).");
        Assert.IsTrue(item.TryGetProperty(VcalmParameterNames.Value, out _));
        Assert.IsTrue(item.TryGetProperty(VcalmParameterNames.Verified, out _));
        Assert.IsTrue(item.TryGetProperty(VcalmParameterNames.Input, out _));
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#verification-errors-vs-warnings">VCALM §3.8.1</see>: "Warnings are
    /// ProblemDetails relating to status and validity periods" — a status warning describes the credential's status,
    /// and only a dependency fetch that ends on its OWN budget while the caller still waits takes that shape. A caller
    /// that abandons its request while the status list is being fetched ends the verification itself, and the resolver
    /// honouring that cancellation must not turn it into a status warning: the server produces no response for the
    /// abandoned request at all.
    /// </summary>
    [TestMethod]
    public async Task ResolverObservingCancellationPropagatesRatherThanBecomingWarning()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListWireAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 65;
        const string CredentialId = "urn:uuid:status-cancellation";

        string issueBody = BuildIssueRequestBodyWithStatus(ctx.IssuerDid, CredentialId, Index);
        using JsonDocument issued = await VcalmWireFixtures.PostIssueWireAsync(
            app, ctx.Segment, issueBody, 201, TestContext.CancellationToken).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        TaskCompletionSource hasEnteredFetch = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource hasObservedCancellation = new(TaskCreationOptions.RunContinuationsAsynchronously);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = async (entry, exchangeContext, cancellationToken) =>
            {
                await VcalmWireFixtures.HangUntilCancelledAsync(hasEnteredFetch, hasObservedCancellation, cancellationToken).ConfigureAwait(false);

                return null;
            };
        }).ConfigureAwait(false);

        string verifyBody = "{\"verifiableCredential\":" + securedCredentialJson
            + ",\"options\":{\"returnProblemDetails\":true}}";

        await VcalmWireFixtures.AssertAbandonedRequestProducesNoResponseAsync(
            app, ctx.Segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, verifyBody, hasEnteredFetch.Task,
            hasObservedCancellation.Task, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Creates this class's status list through the §C.1 <c>POST /status-lists</c> endpoint over the real wire.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The status service tenant segment.</param>
    private async Task CreateStatusListWireAsync(TestHostShell app, string segment)
    {
        using JsonDocument _ = await VcalmWireFixtures.PostEndpointWireAsync(
            app, segment, WellKnownVcalmEndpointNames.VcalmCreateStatusList,
            $"{{\"statusPurpose\":\"{RevocationPurpose}\",\"id\":\"{StatusListId}\"}}", 201, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Sets or clears a credential's status through the §C.3 <c>POST /credentials/status</c> endpoint over the real
    /// wire, whose success answer carries no body.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The status service tenant segment.</param>
    /// <param name="body">The update-status request body JSON text.</param>
    private async Task UpdateStatusWireAsync(TestHostShell app, string segment, string body)
    {
        _ = await VcalmWireFixtures.PostWireAsync(
            app, TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmCredentialsStatus, segment),
            body, 200, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Verifies <paramref name="securedCredentialJson"/> through the §3.3.1 <c>POST /credentials/verify</c> endpoint
    /// over the real wire, asking for the problem details and the per-step results.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The verifier tenant segment.</param>
    /// <param name="securedCredentialJson">The secured credential JSON text to verify.</param>
    /// <returns>The parsed verification response; the caller disposes it.</returns>
    private Task<JsonDocument> VerifyWireAsync(TestHostShell app, string segment, string securedCredentialJson) =>
        VcalmWireFixtures.PostCredentialWireAsync(
            app, segment,
            "{\"verifiableCredential\":" + securedCredentialJson + ",\"options\":{\"returnProblemDetails\":true,\"returnResults\":true}}",
            200, TestContext.CancellationToken);


    /// <summary>
    /// Whether <paramref name="response"/> carries the library's STATUS_WARNING, the §3.8.1 status warning for a
    /// credential whose status is set, compared as the literal type URL.
    /// </summary>
    /// <param name="response">The parsed verification response.</param>
    private static bool HasStatusWarning(JsonDocument response) =>
        VcalmWireFixtures.HasProblemOfType(response, "https://verifiable.lumoin.com/problems#STATUS_WARNING");


    /// <summary>
    /// Registers the status service and installs its list-storage delegates.
    /// </summary>
    private async Task<StatusContext> RegisterStatusServiceAsync(TestHostShell app)
    {
        StatusKeyMaterial material = CreateKeyMaterial();
        RegisteredMaterials.Add(material);

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            material.SigningPublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            BaseMemoryPool.Shared,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        VerifierKeyMaterial hostMaterial = await app.RegisterClientAsync(ClientId, ClientBaseUri, AllRoleCapabilities).ConfigureAwait(false);
        RegisteredMaterials.Add(StatusKeyMaterial.Wrapping(hostMaterial));

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        VcalmCredentialIssuance issuance = new()
        {
            ConfiguredIssuer = issuerDid,
            SigningDescriptors = [BuildDescriptor(material.SigningPrivateKey, verificationMethodId)],
            ExistingProofHandling = VcalmExistingProofHandling.Error,
            SupportsMandatoryPointers = false,
            MemoryPool = Pool
        };

        //§3.2.1 issuance and §C.1 status-list issuance share the same signing config (§C.1: "the
        //status list credential typically uses the same securing mechanism … as the verifiable
        //credentials it will be linked to.").
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialIssuance = issuance;
        }).ConfigureAwait(false);
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmStatusListIssuance = issuance;
        }).ConfigureAwait(false);

        await WireVerificationSeamAsync(app).ConfigureAwait(false);

        //§C.1 / §C.2 status-list store.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmStatusListAsync = (id, json, _, _) =>
            {
                StatusListStore[id] = json;

                //Seed the live decoded list the §C.3 update mutates and the resolver reads, by decoding
                //the freshly-created (all-zero) encodedList.
                LiveStatusLists[id] = DecodeStatusList(json);

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.LoadVcalmStatusListAsync = (id, _, _) =>
                ValueTask.FromResult(StatusListStore.GetValueOrDefault(id));
        }).ConfigureAwait(false);

        //§C.3 update seam: load the live list named by the entry, set / clear the bit, report 200 /
        //404. NotFound when the status service holds no record for the credential or the list.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.UpdateVcalmCredentialStatusAsync = (credentialId, entry, status, _, _, _) =>
            {
                if(!KnownCredentials.ContainsKey(credentialId)
                    || !LiveStatusLists.TryGetValue(entry.StatusListCredential, out CoreStatusList? list))
                {

                    return ValueTask.FromResult(VcalmStatusUpdateOutcome.NotFound);
                }

                list.Set(entry.StatusListIndex, (byte)(status ? 1 : 0));

                return ValueTask.FromResult(VcalmStatusUpdateOutcome.Updated);
            };
        }).ConfigureAwait(false);

        //The verifier's status resolver: hand back a fresh copy of the live list the verifier owns
        //and disposes, plus the declared purpose. Returns null when the list is unknown.
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveVcalmStatusListAsync = (entry, _, _) =>
            {
                if(!LiveStatusLists.TryGetValue(entry.StatusListCredential, out CoreStatusList? live))
                {

                    return ValueTask.FromResult<VcalmResolvedStatusList?>(null);
                }

                CoreStatusList copy = CoreStatusList.FromRaw(live.AsSpan(), StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);

                return ValueTask.FromResult<VcalmResolvedStatusList?>(new VcalmResolvedStatusList
                {
                    StatusList = copy,
                    Purposes = [RevocationPurpose]
                });
            };
        }).ConfigureAwait(false);

        return new StatusContext(hostMaterial.Registration.TenantId.Value, issuerDid, verificationMethodId, material);
    }


    /// <summary>
    /// Installs the verification delegate that resolves credential status for the status-service cases.
    /// </summary>
    private static async Task WireVerificationSeamAsync(TestHostShell app)
    {
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialVerification = new VcalmCredentialVerification
            {
                Resolver = KeyDidResolverSeam,
                Canonicalize = RdfcCanonicalizer,
                ContextResolver = ContextResolver,
                KnownContext = Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
                DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
                SerializeCredential = SerializeCredential,
                SerializePresentation = presentation => JsonSerializerExtensions.Serialize(presentation, JsonOptions),
                SerializeProofOptions = SerializeProofOptions,
                Decoder = TestSetup.Base58Decoder,
                ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
                MemoryPool = Pool
            };
        }).ConfigureAwait(false);
    }


    /// <summary>Decodes the encodedList of a freshly-secured status-list credential JSON into a live StatusList.</summary>
    private static CoreStatusList DecodeStatusList(string securedStatusListJson)
    {
        using JsonDocument doc = JsonDocument.Parse(securedStatusListJson);
        JsonElement subject = doc.RootElement.GetProperty("credentialSubject");

        //credentialSubject is an array (the model serializes it so); read the first element's
        //encodedList.
        JsonElement subjectElement = subject.ValueKind == JsonValueKind.Array ? subject[0] : subject;
        string encodedList = subjectElement.GetProperty(VcalmParameterNames.EncodedList).GetString()!;

        return BitstringStatusListCodec.DecodeList(encodedList, StatusListBitSize.OneBit, Pool);
    }


    /// <summary>
    /// Creates the revocation status list <see cref="StatusListId"/> through the §C.1 endpoint and asserts its
    /// HTTP 201.
    /// </summary>
    /// <param name="app">The host running the status tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    private async Task CreateStatusListAsync(TestHostShell app, string segment)
    {
        using JsonDocument _ = await PostCreateStatusListAsync(
            app, segment, $"{{\"statusPurpose\":\"{RevocationPurpose}\",\"id\":\"{StatusListId}\"}}",
            expectedStatus: 201).ConfigureAwait(false);
    }


    /// <summary>Posts a §C.1 create-status-list request and asserts its HTTP status.</summary>
    /// <param name="app">The host running the status tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="body">The create-status-list request body.</param>
    /// <param name="expectedStatus">The HTTP status the endpoint must answer with.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    private async Task<JsonDocument> PostCreateStatusListAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateStatusList, "POST",
            new RequestFields(), body, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>Posts a §C.3 update-status request, asserting its HTTP status when one is expected.</summary>
    /// <param name="app">The host running the status tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="body">The update-status request body.</param>
    /// <param name="expectedStatus">The HTTP status the endpoint must answer with, or 0 to assert none.</param>
    /// <returns>The endpoint's response.</returns>
    private async Task<ServerHttpResponse> PostUpdateStatusAsync(
        TestHostShell app, string segment, string body, int expectedStatus = 0)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCredentialsStatus, "POST",
            new RequestFields(), body, [], TestContext.CancellationToken).ConfigureAwait(false);

        if(expectedStatus != 0)
        {
            Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);
        }

        return response;
    }


    /// <summary>Posts a §3.2.1 issue request and asserts its HTTP 201.</summary>
    /// <param name="app">The host running the issuer tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="body">The issue request body.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    private async Task<JsonDocument> PostIssueAsync(TestHostShell app, string segment, string body)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCredentialsIssue, "POST",
            new RequestFields(), body, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>
    /// Posts a §3.3.1 verify request for <paramref name="securedCredentialJson"/> asking for the problem details and
    /// the results, and asserts its HTTP 200.
    /// </summary>
    /// <param name="app">The host running the verifier tenant.</param>
    /// <param name="segment">The tenant's path segment.</param>
    /// <param name="securedCredentialJson">The secured credential to verify.</param>
    /// <returns>The parsed verification response; the caller disposes it.</returns>
    private async Task<JsonDocument> VerifyAsync(TestHostShell app, string segment, string securedCredentialJson)
    {
        string verifyBody = "{\"verifiableCredential\":" + securedCredentialJson
            + ",\"options\":{\"returnProblemDetails\":true,\"returnResults\":true}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, "POST",
            new RequestFields(), verifyBody, [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>
    /// Builds a §C.3 update-status body setting or clearing the revocation bit at <paramref name="index"/> of
    /// <see cref="StatusListId"/> for <paramref name="credentialId"/>.
    /// </summary>
    /// <param name="credentialId">The credential whose status changes.</param>
    /// <param name="index">The credential's index in the status list.</param>
    /// <param name="status">Whether the bit is set.</param>
    private static string BuildUpdateStatusBody(string credentialId, int index, bool status) =>
        $"{{\"credentialId\":\"{credentialId}\",\"credentialStatus\":{{\"type\":\"BitstringStatusListEntry\","
        + $"\"statusPurpose\":\"{RevocationPurpose}\",\"statusListIndex\":\"{index.ToString(CultureInfo.InvariantCulture)}\","
        + $"\"statusListCredential\":\"{StatusListId}\"}},\"status\":{(status ? "true" : "false")}}}";


    /// <summary>
    /// Builds a §3.2.1 issue body for an alumni credential carrying one <c>BitstringStatusListEntry</c> at
    /// <paramref name="index"/>.
    /// </summary>
    /// <param name="issuerDid">The credential's issuer.</param>
    /// <param name="credentialId">The credential's <c>id</c>.</param>
    /// <param name="index">The entry's <c>statusListIndex</c>.</param>
    /// <param name="statusPurpose">The entry's <c>statusPurpose</c>; revocation by default.</param>
    /// <param name="statusListCredential">The entry's status list; <see cref="StatusListId"/> by default.</param>
    private static string BuildIssueRequestBodyWithStatus(
        string issuerDid, string credentialId, int index, string statusPurpose = RevocationPurpose,
        string? statusListCredential = null)
    {
        string targetStatusList = statusListCredential ?? StatusListId;
        VerifiableCredential credential = new()
        {
            Context = Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
            Id = credentialId,
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = "2030-01-01T00:00:00Z",
            CredentialStatus =
            [
                new CredentialStatus
                {
                    Id = $"{targetStatusList}#{index.ToString(CultureInfo.InvariantCulture)}",
                    Type = BitstringStatusListConstants.EntryType,
                    StatusPurpose = statusPurpose,
                    StatusListIndex = index.ToString(CultureInfo.InvariantCulture),
                    StatusListCredential = targetStatusList
                }
            ],
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

        string credentialJson = SerializeCredential(credential);

        return "{\"credential\":" + credentialJson + "}";
    }


    /// <summary>
    /// A §C.3 issue body carrying a credentialStatus entry whose type IS BitstringStatusListEntry (the
    /// specification's shape) but whose statusListIndex is missing — distinct from a foreign type,
    /// which TryMapStatusEntry turns away silently.
    /// </summary>
    private static string BuildIssueRequestBodyWithMalformedStatusEntry(string issuerDid, string credentialId)
    {
        VerifiableCredential credential = new()
        {
            Context = Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
            Id = credentialId,
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = "2030-01-01T00:00:00Z",
            CredentialStatus =
            [
                new CredentialStatus
                {
                    Id = $"{StatusListId}#missing-index",
                    Type = BitstringStatusListConstants.EntryType,
                    StatusPurpose = RevocationPurpose,
                    StatusListIndex = null,
                    StatusListCredential = StatusListId
                }
            ],
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

        return "{\"credential\":" + SerializeCredential(credential) + "}";
    }


    /// <summary>
    /// A §C.3 issue body carrying TWO credentialStatus entries: a NON-MAPPING entry FIRST (an unparseable
    /// statusListIndex, which TryMapStatusEntry turns away) followed by a well-formed revocation entry.
    /// Used to prove a non-mapping entry does not mask (does not break the per-entry loop over) a later
    /// well-formed entry.
    /// </summary>
    private static string BuildIssueRequestBodyWithTwoStatusEntries(
        string issuerDid, string credentialId, int validIndex)
    {
        VerifiableCredential credential = new()
        {
            Context = Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
            Id = credentialId,
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = "2030-01-01T00:00:00Z",
            CredentialStatus =
            [
                new CredentialStatus
                {
                    Id = $"{StatusListId}#bogus",
                    Type = BitstringStatusListConstants.EntryType,
                    StatusPurpose = RevocationPurpose,
                    StatusListIndex = "not-a-number",
                    StatusListCredential = StatusListId
                },
                new CredentialStatus
                {
                    Id = $"{StatusListId}#{validIndex.ToString(CultureInfo.InvariantCulture)}",
                    Type = BitstringStatusListConstants.EntryType,
                    StatusPurpose = RevocationPurpose,
                    StatusListIndex = validIndex.ToString(CultureInfo.InvariantCulture),
                    StatusListCredential = StatusListId
                }
            ],
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

        return "{\"credential\":" + SerializeCredential(credential) + "}";
    }


    /// <summary>Builds the issuer's eddsa-rdfc-2022 signing descriptor over <paramref name="privateKey"/>.</summary>
    /// <param name="privateKey">The issuer's Ed25519 private key.</param>
    /// <param name="verificationMethodId">The verification method the proofs name.</param>
    private static VcalmProofDescriptor BuildDescriptor(PrivateKeyMemory privateKey, string verificationMethodId) =>
        new()
        {
            PrivateKey = privateKey,
            VerificationMethodId = verificationMethodId,
            Cryptosuite = EddsaRdfc2022CryptosuiteInfo.Instance,
            Canonicalize = RdfcCanonicalizer,
            ContextResolver = ContextResolver,
            EncodeProofValue = ProofValueCodecs.EncodeBase58Btc,
            SerializeCredential = SerializeCredential,
            DeserializeCredential = DeserializeCredential,
            SerializeProofOptions = SerializeProofOptions,
            Encoder = TestSetup.Base58Encoder,
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync
        };


    /// <summary>Creates a status signing key over the fixed Ed25519 test key, owned by no host registration.</summary>
    private static StatusKeyMaterial CreateKeyMaterial()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        return new StatusKeyMaterial(keyPair.PublicKey, keyPair.PrivateKey, hostMaterial: null);
    }


    /// <summary>A registered status tenant and the issuer identity it signs under.</summary>
    /// <param name="Segment">The tenant's path segment.</param>
    /// <param name="IssuerDid">The issuer DID the tenant's credentials and status lists name.</param>
    /// <param name="VerificationMethodId">The verification method the tenant's proofs name.</param>
    /// <param name="Material">The tenant's signing key.</param>
    private sealed record StatusContext(string Segment, string IssuerDid, string VerificationMethodId, StatusKeyMaterial Material);


    /// <summary>
    /// Owns the status service's Ed25519 signing key for the test's lifetime; disposed at cleanup. The
    /// host-material wrapper lets the cleanup loop dispose the RegisterClient material uniformly.
    /// </summary>
    private sealed class StatusKeyMaterial: IDisposable
    {
        /// <summary>The host registration owning the keys, or <see langword="null"/> when this instance owns them.</summary>
        private VerifierKeyMaterial? HostMaterial { get; }

        /// <summary>Whether <see cref="Dispose"/> already ran, so a second call is a no-op.</summary>
        private bool isDisposed;

        /// <summary>Takes the signing key pair, owned by <paramref name="hostMaterial"/> when one is given.</summary>
        /// <param name="signingPublicKey">The Ed25519 public key.</param>
        /// <param name="signingPrivateKey">The Ed25519 private key.</param>
        /// <param name="hostMaterial">The host registration owning the keys, or <see langword="null"/>.</param>
        public StatusKeyMaterial(PublicKeyMemory signingPublicKey, PrivateKeyMemory signingPrivateKey, VerifierKeyMaterial? hostMaterial)
        {
            SigningPublicKey = signingPublicKey;
            SigningPrivateKey = signingPrivateKey;
            this.HostMaterial = hostMaterial;
        }

        /// <summary>The Ed25519 public key the status service's proofs verify under.</summary>
        public PublicKeyMemory SigningPublicKey { get; }

        /// <summary>The Ed25519 private key the status service signs with.</summary>
        public PrivateKeyMemory SigningPrivateKey { get; }

        /// <summary>Wraps a host registration's signing keys, disposing the registration at cleanup.</summary>
        /// <param name="hostMaterial">The registration whose keys the status service signs with.</param>
        public static StatusKeyMaterial Wrapping(VerifierKeyMaterial hostMaterial) =>
            new(hostMaterial.SigningPublicKey, hostMaterial.SigningPrivateKey, hostMaterial);

        /// <summary>Disposes the host registration when one owns the keys, otherwise the keys themselves.</summary>
        public void Dispose()
        {
            if(isDisposed)
            {
                return;
            }

            isDisposed = true;
            if(HostMaterial is not null)
            {
                HostMaterial.Dispose();
            }
            else
            {
                SigningPublicKey.Dispose();
                SigningPrivateKey.Dispose();
            }
        }
    }
}
