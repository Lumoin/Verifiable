using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Resolvers;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.Vcalm;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.OAuth;
using Verifiable.Server;
using CoreStatusList = Verifiable.Core.StatusList.StatusList;

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
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://status.client.test";
    private static readonly Uri ClientBaseUri = new("https://status.client.test");

    //The §C.3 update + status checking exercise all three roles on the same tenant: issuer (mint the
    //credential and the status list), status (set the bit), verifier (read the warning).
    private static readonly ImmutableHashSet<CapabilityIdentifier> AllRoleCapabilities =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmIssuer,
            WellKnownVcalmCapabilities.VcalmVerifier,
            WellKnownVcalmCapabilities.VcalmStatus);

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } =
        CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } =
        CanonicalizationTestUtilities.CreateTestContextResolver();

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    private const string StatusListId = "https://status.example/status-lists/1";

    //The standard status-list-credential url every credentialStatus in these tests references.
    private const string RevocationPurpose = "revocation";

    private List<StatusKeyMaterial> RegisteredMaterials { get; } = [];

    //The in-memory status-list store the §C.1 / §C.2 seams read and write (id → secured VC JSON).
    private ConcurrentDictionary<string, string> StatusListStore { get; } = new(StringComparer.Ordinal);

    //The live decoded status lists the §C.3 update seam mutates and the resolver seam reads. Keyed by
    //statusListCredential url. The §C.3 seam sets / clears the bit here; the resolver hands the
    //verifier a fresh copy it owns and disposes.
    private ConcurrentDictionary<string, CoreStatusList> LiveStatusLists { get; } = new(StringComparer.Ordinal);

    //The credentialId → statusListCredential url map the §C.3 404 key is checked against (the status
    //service holds a record for a credential only after it has been issued against a known list).
    private ConcurrentDictionary<string, string> KnownCredentials { get; } = new(StringComparer.Ordinal);


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
            new RequestFields(), verifyBody, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
            ctx.Segment, StatusListId, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, getResponse.StatusCode, getResponse.Body);
        using JsonDocument getDoc = JsonDocument.Parse(getResponse.Body);
        Assert.IsTrue(getDoc.RootElement.TryGetProperty(VcalmParameterNames.VerifiableCredential, out _),
            "The §C.2 retrieval returns the status list under verifiableCredential.");

        //404: an id the store never held.
        ServerHttpResponse notFound = await app.DispatchVcalmStatusListByIdAsync(
            ctx.Segment, "https://status.example/status-lists/never", new ExchangeContext(),
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
        Assert.AreEqual(VcalmProblemTypes.UnknownOptionProvided,
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
            bytes, "text/plain", new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
        Assert.AreEqual(VcalmProblemTypes.MalformedValueError,
            doc.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(),
            $"A §C.3 malformed update ({reason}) yields the MALFORMED_VALUE_ERROR type.");
    }


    /// <summary>
    /// §C.3 / §3.8.1 non-mapping does not mask a revocation: a credential carrying a NON-MAPPING
    /// credentialStatus entry FIRST (an unparseable <c>statusListIndex</c>, skipped by TryMapStatusEntry)
    /// FOLLOWED by a well-formed revocation entry whose bit is set still surfaces the STATUS_WARNING — the
    /// per-entry loop CONTINUES past the non-mapping entry rather than breaking. A regression to
    /// break/return on the first non-mapping entry would silently mask the real revocation.
    /// </summary>
    [TestMethod]
    public async Task NonMappingStatusEntryDoesNotMaskValidRevokedEntry()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const int ValidIndex = 23;
        const string CredentialId = "urn:uuid:two-entry-status";
        KnownCredentials[CredentialId] = StatusListId;

        string issueBody = BuildIssueRequestBodyWithTwoStatusEntries(ctx.IssuerDid, CredentialId, ValidIndex);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        //Set the WELL-FORMED entry revoked; the non-mapping entry is FIRST in the credentialStatus array.
        ServerHttpResponse setRevoked = await PostUpdateStatusAsync(
            app, ctx.Segment, BuildUpdateStatusBody(CredentialId, ValidIndex, status: true)).ConfigureAwait(false);
        Assert.AreEqual(200, setRevoked.StatusCode, setRevoked.Body);

        using JsonDocument after = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);
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
    /// The money-shot round-trip: issue a credential carrying a <c>credentialStatus</c> (V-2 issue
    /// endpoint), set it revoked via §C.3, then verify it (V-1 verify endpoint) returns HTTP 200,
    /// <c>verified:true</c>, with a STATUS WARNING in <c>problemDetails</c> — §3.8.1: "Warnings are
    /// ProblemDetails relating to status and validity periods", and "if no errors are included, [the
    /// verified property] MUST be set to true". A non-revoked credential verifies with NO status
    /// warning.
    /// </summary>
    [TestMethod]
    public async Task IssueThenRevokeThenVerifyEmitsStatusWarningButStaysVerified()
    {
        await using TestHostShell app = new(TimeProvider);
        StatusContext ctx = await RegisterStatusServiceAsync(app).ConfigureAwait(false);
        await CreateStatusListAsync(app, ctx.Segment).ConfigureAwait(false);

        const int Index = 17;
        const string CredentialId = "urn:uuid:roundtrip-status";
        KnownCredentials[CredentialId] = StatusListId;

        //Issue a credential carrying a credentialStatus pointing at the status list (V-2 issue).
        string issueBody = BuildIssueRequestBodyWithStatus(ctx.IssuerDid, CredentialId, Index);
        using JsonDocument issued = await PostIssueAsync(app, ctx.Segment, issueBody).ConfigureAwait(false);
        string securedCredentialJson = issued.RootElement
            .GetProperty(VcalmParameterNames.VerifiableCredential).GetRawText();

        //Before revocation: the credential verifies TRUE with NO status warning.
        using(JsonDocument before = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false))
        {
            Assert.IsTrue(before.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
                "A non-revoked credential verifies true.");
            Assert.IsFalse(HasStatusWarning(before),
                "A non-revoked credential carries no status warning.");
        }

        //Set the credential revoked via §C.3.
        ServerHttpResponse setRevoked = await PostUpdateStatusAsync(
            app, ctx.Segment, BuildUpdateStatusBody(CredentialId, Index, status: true)).ConfigureAwait(false);
        Assert.AreEqual(200, setRevoked.StatusCode, setRevoked.Body);

        //After revocation: the credential STILL verifies true (status is a §3.8.1 WARNING, not an
        //error), but a status warning is now present in problemDetails.
        using JsonDocument after = await VerifyAsync(app, ctx.Segment, securedCredentialJson).ConfigureAwait(false);
        Assert.IsTrue(after.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "§3.8.1: status is a WARNING, not an error — a revoked credential still verifies true.");
        Assert.IsTrue(HasStatusWarning(after),
            "A revoked credential surfaces a §3.8.1 STATUS_WARNING problem detail.");
    }


    private static bool HasStatusWarning(JsonDocument response)
    {
        if(!response.RootElement.TryGetProperty(VcalmParameterNames.ProblemDetails, out JsonElement problems))
        {
            return false;
        }

        foreach(JsonElement problem in problems.EnumerateArray())
        {
            if(problem.TryGetProperty(VcalmParameterNames.ProblemType, out JsonElement type)
                && string.Equals(type.GetString(), VcalmProblemTypes.StatusWarning, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    //Registers a tenant allowing the issuer / verifier / status roles, wires the default JSON
    //parsing, the Data Integrity signing (shared by §3.2.1 issuance and §C.1 status-list issuance),
    //the verification seams (including the status resolver), and the §C.1 / §C.2 / §C.3 storage seams.
    private async Task<StatusContext> RegisterStatusServiceAsync(TestHostShell app)
    {
        StatusKeyMaterial material = CreateKeyMaterial();
        RegisteredMaterials.Add(material);

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            material.SigningPublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        VerifierKeyMaterial hostMaterial = app.RegisterClient(ClientId, ClientBaseUri, AllRoleCapabilities);
        RegisteredMaterials.Add(StatusKeyMaterial.Wrapping(hostMaterial));

        app.Server.Vcalm().UseDefaultVcalmJsonParsing(JsonOptions);

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
        app.Server.Vcalm().VcalmCredentialIssuance = issuance;
        app.Server.Vcalm().VcalmStatusListIssuance = issuance;

        WireVerificationSeam(app);

        //§C.1 / §C.2 status-list store.
        app.Server.Vcalm().StoreVcalmStatusListAsync = (id, json, _, _) =>
        {
            StatusListStore[id] = json;

            //Seed the live decoded list the §C.3 update mutates and the resolver reads, by decoding
            //the freshly-created (all-zero) encodedList.
            LiveStatusLists[id] = DecodeStatusList(json);

            return ValueTask.CompletedTask;
        };

        app.Server.Vcalm().LoadVcalmStatusListAsync = (id, _, _) =>
            ValueTask.FromResult(StatusListStore.GetValueOrDefault(id));

        //§C.3 update seam: load the live list named by the entry, set / clear the bit, report 200 /
        //404. NotFound when the status service holds no record for the credential or the list.
        app.Server.Vcalm().UpdateVcalmCredentialStatusAsync = (credentialId, entry, status, _, _, _) =>
        {
            if(!KnownCredentials.ContainsKey(credentialId)
                || !LiveStatusLists.TryGetValue(entry.StatusListCredential, out CoreStatusList? list))
            {
                return ValueTask.FromResult(VcalmStatusUpdateOutcome.NotFound);
            }

            list.Set(entry.StatusListIndex, (byte)(status ? 1 : 0));

            return ValueTask.FromResult(VcalmStatusUpdateOutcome.Updated);
        };

        //The verifier's status resolver: hand back a fresh copy of the live list the verifier owns
        //and disposes, plus the declared purpose. Returns null when the list is unknown.
        app.Server.Vcalm().ResolveVcalmStatusListAsync = (entry, _, _) =>
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

        return new StatusContext(hostMaterial.Registration.TenantId.Value, issuerDid, verificationMethodId, material);
    }


    private static void WireVerificationSeam(TestHostShell app)
    {
        app.Server.Vcalm().VcalmCredentialVerification = new VcalmCredentialVerification
        {
            Resolver = KeyDidResolverSeam,
            Canonicalize = RdfcCanonicalizer,
            ContextResolver = ContextResolver,
            DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential = SerializeCredential,
            SerializePresentation = presentation => JsonSerializerExtensions.Serialize(presentation, JsonOptions),
            SerializeProofOptions = SerializeProofOptions,
            Decoder = TestSetup.Base58Decoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
            MemoryPool = Pool
        };
    }


    //Decodes the encodedList of a freshly-secured status-list credential JSON into a live StatusList.
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


    private async Task CreateStatusListAsync(TestHostShell app, string segment)
    {
        using JsonDocument _ = await PostCreateStatusListAsync(
            app, segment, $"{{\"statusPurpose\":\"{RevocationPurpose}\",\"id\":\"{StatusListId}\"}}",
            expectedStatus: 201).ConfigureAwait(false);
    }


    private async Task<JsonDocument> PostCreateStatusListAsync(
        TestHostShell app, string segment, string body, int expectedStatus)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCreateStatusList, "POST",
            new RequestFields(), body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    private async Task<ServerHttpResponse> PostUpdateStatusAsync(
        TestHostShell app, string segment, string body, int expectedStatus = 0)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCredentialsStatus, "POST",
            new RequestFields(), body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        if(expectedStatus != 0)
        {
            Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);
        }

        return response;
    }


    private async Task<JsonDocument> PostIssueAsync(TestHostShell app, string segment, string body)
    {
        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCredentialsIssue, "POST",
            new RequestFields(), body, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    private async Task<JsonDocument> VerifyAsync(TestHostShell app, string segment, string securedCredentialJson)
    {
        string verifyBody = "{\"verifiableCredential\":" + securedCredentialJson
            + ",\"options\":{\"returnProblemDetails\":true}}";

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, "POST",
            new RequestFields(), verifyBody, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    private static string BuildUpdateStatusBody(string credentialId, int index, bool status) =>
        $"{{\"credentialId\":\"{credentialId}\",\"credentialStatus\":{{\"type\":\"BitstringStatusListEntry\","
        + $"\"statusPurpose\":\"{RevocationPurpose}\",\"statusListIndex\":\"{index.ToString(CultureInfo.InvariantCulture)}\","
        + $"\"statusListCredential\":\"{StatusListId}\"}},\"status\":{(status ? "true" : "false")}}}";


    private static string BuildIssueRequestBodyWithStatus(
        string issuerDid, string credentialId, int index, string statusPurpose = RevocationPurpose)
    {
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
            Id = credentialId,
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = "2030-01-01T00:00:00Z",
            CredentialStatus =
            [
                new CredentialStatus
                {
                    Id = $"{StatusListId}#{index.ToString(CultureInfo.InvariantCulture)}",
                    Type = BitstringStatusListConstants.EntryType,
                    StatusPurpose = statusPurpose,
                    StatusListIndex = index.ToString(CultureInfo.InvariantCulture),
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

        string credentialJson = SerializeCredential(credential);

        return "{\"credential\":" + credentialJson + "}";
    }


    //A §C.3 issue body carrying TWO credentialStatus entries: a NON-MAPPING entry FIRST (an unparseable
    //statusListIndex, which TryMapStatusEntry turns away) followed by a well-formed revocation entry.
    //Used to prove a non-mapping entry does not mask (does not break the per-entry loop over) a later
    //well-formed entry.
    private static string BuildIssueRequestBodyWithTwoStatusEntries(
        string issuerDid, string credentialId, int validIndex)
    {
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
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync
        };


    private static StatusKeyMaterial CreateKeyMaterial()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        return new StatusKeyMaterial(keyPair.PublicKey, keyPair.PrivateKey, hostMaterial: null);
    }


    private sealed record StatusContext(string Segment, string IssuerDid, string VerificationMethodId, StatusKeyMaterial Material);


    //Owns the status service's Ed25519 signing key for the test's lifetime; disposed at cleanup. The
    //host-material wrapper lets the cleanup loop dispose the RegisterClient material uniformly.
    private sealed class StatusKeyMaterial: IDisposable
    {
        private readonly VerifierKeyMaterial? hostMaterial;
        private bool isDisposed;

        public StatusKeyMaterial(PublicKeyMemory signingPublicKey, PrivateKeyMemory signingPrivateKey, VerifierKeyMaterial? hostMaterial)
        {
            SigningPublicKey = signingPublicKey;
            SigningPrivateKey = signingPrivateKey;
            this.hostMaterial = hostMaterial;
        }

        public PublicKeyMemory SigningPublicKey { get; }

        public PrivateKeyMemory SigningPrivateKey { get; }

        public static StatusKeyMaterial Wrapping(VerifierKeyMaterial hostMaterial) =>
            new(hostMaterial.SigningPublicKey, hostMaterial.SigningPrivateKey, hostMaterial);

        public void Dispose()
        {
            if(isDisposed)
            {
                return;
            }

            isDisposed = true;
            if(hostMaterial is not null)
            {
                hostMaterial.Dispose();
            }
            else
            {
                SigningPublicKey.Dispose();
                SigningPrivateKey.Dispose();
            }
        }
    }
}
