using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Peer;
using Verifiable.Core.Did.Methods.Web;
using Verifiable.Core.Did.Methods.WebVh;
using Verifiable.Core.Model.Did;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// End-to-end tests for <see cref="WebVhDidResolver.Build"/> — the full did:webvh resolver that fetches the
/// <c>did.jsonl</c> through the guarded <see cref="OutboundFetch"/> chokepoint, replays and verifies every
/// entry, and returns the resolved <see cref="DidDocument"/>. Logs are minted by <see cref="WebVhTestLog"/>
/// (executing the spec's Create/Update steps) and served by a faked transport, so genesis, updates, key
/// pre-rotation, the id binding and tamper-rejection are exercised deterministically without a live network.
/// </summary>
[TestClass]
internal sealed class WebVhDidResolverResolvingTests
{
    private const string Domain = "example.com";
    private const string GenesisTime = "2025-01-01T00:00:00Z";
    private const string SecondTime = "2025-02-01T00:00:00Z";
    private const string ThirdTime = "2025-03-01T00:00:00Z";

    private static readonly EncodeDelegate Base58Encoder = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase));
    private static readonly DecodeDelegate Base58Decoder = DefaultCoderSelector.SelectDecoder(typeof(PublicKeyMultibase));


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task ResolvesMintedGenesisLog()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A minted did:webvh genesis log MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(DidResolutionKind.Document, result.Kind);
        Assert.AreEqual(log.Did, result.Document!.Id?.ToString());
        Assert.AreEqual(log.VersionIds[^1], result.DocumentMetadata.VersionId);
        Assert.IsFalse(result.DocumentMetadata.Deactivated);
    }


    /// <summary>
    /// WVH-RES-9: an update entry's <c>versionTime</c> MUST be strictly later than its predecessor's, so two
    /// entries sharing the same <c>versionTime</c> MUST be rejected as invalidDid (did:webvh v1.0, Read: the
    /// versionTime ordering). The two entries are otherwise valid (same update key, no pre-rotation), so the equal
    /// timestamp is the only violation.
    /// </summary>
    [TestMethod]
    public async Task ResolveRejectsEntryWithVersionTimeEqualToPredecessor()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webvh entry whose versionTime equals its predecessor's MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error, "An equal versionTime MUST be rejected as invalidDid.");
    }


    /// <summary>
    /// WVH-RES-14: the resolved DID MUST match the top-level id of at least one verified version. A VALID log
    /// (its SCID self-certifies and its chain verifies) served under a DID with the SAME scid but a DIFFERENT host
    /// carries that host in no entry's id, so resolution MUST fail — this blocks serving one DID's log as another's.
    /// </summary>
    [TestMethod]
    public async Task ResolveRejectsLogWhoseIdMatchesNoRequestedVersion()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //Same SCID, different host: the served log is valid for its own id (example.com) but the requested DID
        //(evil.example.com) appears in no version's top-level id.
        string substitutedDid = $"did:webvh:{log.Scid}:evil.example.com";

        DidResolutionResult result = await ResolveAsync(substitutedDid, log.Lines).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webvh whose log id matches no requested version MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error, "A substituted-host DID whose log never carries it MUST be rejected as invalidDid.");
    }


    /// <summary>
    /// WVH-PAR-METHOD-3: the <c>method</c> parameter MUST NOT change to an unsupported version after the first
    /// entry. This resolver processes a single method version, so a later entry declaring a different (here lower)
    /// method value MUST be rejected at the parameter fold as invalidDid (did:webvh v1.0, Parameters: the method
    /// parameter).
    /// </summary>
    [TestMethod]
    public async Task ResolveRejectsSubsequentEntryDeclaringDifferentMethod()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime, MethodOverride: "did:webvh:0.5")
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webvh entry declaring a different method version MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error, "A method change after the first entry MUST be rejected as invalidDid.");
    }


    /// <summary>
    /// DNS-rebinding defense for the did.jsonl fetch: a did:webvh whose log host is a public NAME that resolves
    /// to a loopback address MUST be blocked at connection-time by the pinning transport — the URL gate cannot
    /// catch a rebinding host name (it does no DNS). The host is never dialed and the DID does not resolve.
    /// </summary>
    [TestMethod]
    public async Task DidLogHostRebindingToLoopbackIsBlockedAtConnectionTime()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        HostResolverDelegate rebindToLoopback = (host, cancellationToken) =>
            ValueTask.FromResult<IReadOnlyList<IPAddress>>([IPAddress.Loopback]);

        bool pinned = false;
        bool dialed = false;
        OutboundTransportDelegate pinningTransport = async (request, context, cancellationToken) =>
        {
            pinned = true;
            try
            {
                _ = await SsrfHardenedTransport.ResolveAndPinAsync(request.Target.Host, context.OutboundFetchPolicy, rebindToLoopback, cancellationToken).ConfigureAwait(false);
            }
            catch(SsrfBlockedException)
            {
                //Blocked before the dial: surface a non-fetch so the resolver fail-closes to NotFound rather
                //than serving content from a loopback-rebound address.
                return new OutboundResponse { StatusCode = 404 };
            }

            dialed = true;

            return new OutboundResponse { StatusCode = 200, Body = new TaggedMemory<byte>(Encoding.UTF8.GetBytes(string.Join('\n', log.Lines)), BufferTags.Json) };
        };

        var context = new ExchangeContext();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        DidMethodResolverDelegate resolver = WebVhDidResolver.Build(
            pinningTransport,
            WebVhLogEntryJson.Parser,
            WebVhLogEntryJson.WitnessFileParser,
            WebVhLogEntryJson.DocumentIdentityReader,
            DeserializeState,
            WebVhLogEntryJson.Canonicalizer,
            Base58Encoder,
            Base58Decoder,
            BaseMemoryPool.Shared,
            new FakeTimeProvider(TestClock.CanonicalEpoch));

        DidResolutionResult result = await resolver(log.Did, DidResolutionOptions.Empty, context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pinned, "The connection-time pin MUST run for the did.jsonl host.");
        Assert.IsFalse(dialed, "A did.jsonl host that rebinds to loopback MUST be blocked before the dial.");
        Assert.IsFalse(result.IsSuccessful, "A did:webvh whose log host rebinds to loopback MUST NOT resolve.");
    }


    [TestMethod]
    public async Task ResolvesMultiEntryLogToLatestVersion()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A two-entry did:webvh log MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.VersionIds[^1], result.DocumentMetadata.VersionId);
        Assert.StartsWith("2-", result.DocumentMetadata.VersionId!);
    }


    [TestMethod]
    public async Task ResolvesPreRotationRotation()
    {
        using WebVhController genesisKey = WebVhController.Create();
        using WebVhController nextKey = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(genesisKey, [genesisKey.Multikey], [nextKey.KeyHash], Deactivated: false, GenesisTime),
            new WebVhEntryPlan(nextKey, [nextKey.Multikey], [nextKey.KeyHash], Deactivated: false, SecondTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A pre-rotation rotation MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.VersionIds[^1], result.DocumentMetadata.VersionId);
    }


    [TestMethod]
    public async Task TamperedProofFailsResolution()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        JsonObject entry = JsonNode.Parse(log.Lines[0])!.AsObject();
        JsonObject proof = (JsonObject)((JsonArray)entry["proof"]!)[0]!;
        string proofValue = (string)proof["proofValue"]!;
        proof["proofValue"] = proofValue[..^1] + (proofValue[^1] == 'A' ? 'B' : 'A');

        DidResolutionResult result = await ResolveAsync(log.Did, [entry.ToJsonString()]).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A tampered did:webvh log MUST NOT resolve.");

        //invalidDid by problem-type, and the precise verification message is surfaced as problemDetails.Detail
        //(the Detail does not change the type-based error identity).
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
        Assert.IsNotNull(result.ResolutionMetadata.Error?.Detail);
    }


    [TestMethod]
    public async Task ReportsNotFoundForMissingLog()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [WebVhDidResolver.Resolve(log.Did)] = (404, null)
        });

        DidResolutionResult result = await ResolveAsync(log.Did, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task DispatchesDidWebVhThroughComposition()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [WebVhDidResolver.Resolve(log.Did)] = (200, string.Join('\n', log.Lines))
        });

        DidMethodResolverDelegate webVh = WebVhDidResolver.Build(
            transport.Delegate, WebVhLogEntryJson.Parser, WebVhLogEntryJson.WitnessFileParser, WebVhLogEntryJson.DocumentIdentityReader, DeserializeState, WebVhLogEntryJson.Canonicalizer,
            Base58Encoder, Base58Decoder, BaseMemoryPool.Shared, new FakeTimeProvider(TestClock.CanonicalEpoch));

        DidResolver composed = DidResolverComposition.Build(
            BaseMemoryPool.Shared,
            static (request, context, cancellationToken) => ValueTask.FromResult(new OutboundResponse { StatusCode = 404, Body = TaggedMemory<byte>.Empty }),
            static jsonUtf8 => null,
            static jsonUtf8 => null,
            additionalMethods: [(WellKnownDidMethodPrefixes.WebVhDidMethodPrefix, webVh)]);

        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        DidResolutionResult result = await composed.ResolveAsync(log.Did, context, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"did:webvh MUST dispatch through the composition. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.Did, result.Document!.Id?.ToString());
    }


    [TestMethod]
    public async Task ResolvesByVersionId()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await MintTwoEntryAsync(controller).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines, new DidResolutionOptions { VersionId = log.VersionIds[0] }).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"versionId resolution MUST succeed. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.VersionIds[0], result.DocumentMetadata.VersionId);
    }


    [TestMethod]
    public async Task ResolvesByVersionNumber()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await MintTwoEntryAsync(controller).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines, new DidResolutionOptions { VersionNumber = 1 }).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"versionNumber resolution MUST succeed. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.VersionIds[0], result.DocumentMetadata.VersionId);
    }


    [TestMethod]
    public async Task ResolvesByVersionTimeToActiveEntry()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await MintTwoEntryAsync(controller).ConfigureAwait(false);

        //A time between the two entries selects the first (it was active at that time).
        DidResolutionResult betweenEntries = await ResolveAsync(log.Did, log.Lines, new DidResolutionOptions { VersionTime = Time("2025-01-15T00:00:00Z") }).ConfigureAwait(false);
        Assert.IsTrue(betweenEntries.IsSuccessful);
        Assert.AreEqual(log.VersionIds[0], betweenEntries.DocumentMetadata.VersionId);

        //A time after the last entry selects the latest version.
        DidResolutionResult afterLast = await ResolveAsync(log.Did, log.Lines, new DidResolutionOptions { VersionTime = Time("2025-03-01T00:00:00Z") }).ConfigureAwait(false);
        Assert.IsTrue(afterLast.IsSuccessful);
        Assert.AreEqual(log.VersionIds[1], afterLast.DocumentMetadata.VersionId);
    }


    [TestMethod]
    public async Task UnknownVersionIdIsNotFound()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await MintTwoEntryAsync(controller).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines, new DidResolutionOptions { VersionId = "9-QmNoSuchVersionXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" }).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task VersionTimeBeforeGenesisIsNotFound()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await MintTwoEntryAsync(controller).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines, new DidResolutionOptions { VersionTime = Time("2024-01-01T00:00:00Z") }).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A versionTime before the DID existed MUST be NotFound.");
        Assert.AreEqual(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task VersionQueryResolvesEarlierVersionDespiteLaterInvalidEntry()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await MintTwoEntryAsync(controller).ConfigureAwait(false);

        //Tamper the second entry's proof so the latest version no longer verifies.
        JsonObject second = JsonNode.Parse(log.Lines[1])!.AsObject();
        JsonObject proof = (JsonObject)((JsonArray)second["proof"]!)[0]!;
        string proofValue = (string)proof["proofValue"]!;
        proof["proofValue"] = proofValue[..^1] + (proofValue[^1] == 'A' ? 'B' : 'A');
        ImmutableArray<string> tampered = [log.Lines[0], second.ToJsonString()];

        //The queried earlier version still resolves (Read: return the requested version even if later entries are invalid).
        DidResolutionResult earlier = await ResolveAsync(log.Did, tampered, new DidResolutionOptions { VersionId = log.VersionIds[0] }).ConfigureAwait(false);
        Assert.IsTrue(earlier.IsSuccessful, $"A valid earlier version MUST resolve despite a later invalid entry. Error: {earlier.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.VersionIds[0], earlier.DocumentMetadata.VersionId);

        //Resolving the latest (no query) fails because the last entry is invalid. A tampered entry renders the
        //did:webvh DID invalid, so the error MUST be invalidDid (matching the other tamper-rejection tests).
        DidResolutionResult latest = await ResolveAsync(log.Did, tampered).ConfigureAwait(false);
        Assert.IsFalse(latest.IsSuccessful);
        Assert.AreEqual(DidResolutionErrors.InvalidDid, latest.ResolutionMetadata.Error);
    }


    /// <summary>
    /// A FORGED later deactivation MUST NOT mark a prior version deactivated. When the later (deactivation)
    /// entry fails cryptographic verification, a prior-version query still resolves that earlier DIDDoc but
    /// reports deactivated:FALSE — deactivation is honored only from a VERIFIED entry, so an attacker who
    /// appends or tampers an unsigned deactivation cannot forge a deactivated result (did:webvh v1.0, Read:
    /// entries from the first invalid one to the end are not honored). Contrast
    /// <see cref="PriorVersionOfDeactivatedDidCarriesDeactivatedMetadata"/>, where the valid deactivation
    /// entry DOES carry deactivated:true to the prior version.
    /// </summary>
    [TestMethod]
    public async Task ForgedLaterDeactivationDoesNotMarkPriorVersionDeactivated()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: true, SecondTime)
        ]).ConfigureAwait(false);

        //Tamper the second (deactivation) entry's proof so it no longer verifies — the forged-deactivation attack.
        JsonObject second = JsonNode.Parse(log.Lines[1])!.AsObject();
        JsonObject proof = (JsonObject)((JsonArray)second["proof"]!)[0]!;
        string proofValue = (string)proof["proofValue"]!;
        proof["proofValue"] = proofValue[..^1] + (proofValue[^1] == 'A' ? 'B' : 'A');
        ImmutableArray<string> tampered = [log.Lines[0], second.ToJsonString()];

        DidResolutionResult result = await ResolveAsync(log.Did, tampered, new DidResolutionOptions { VersionId = log.VersionIds[0] }).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"The valid genesis version MUST resolve despite a forged later deactivation. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.VersionIds[0], result.DocumentMetadata.VersionId);
        Assert.IsFalse(result.DocumentMetadata.Deactivated, "A FORGED (unverified) later deactivation MUST NOT mark the prior version deactivated.");
    }


    [TestMethod]
    public async Task ResolvesWitnessedGenesisWhenThresholdMet()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController witness = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, WebVhWitnessSpec.Rule(1, witness))
        ]).ConfigureAwait(false);

        string witnessFile = await WebVhTestLog.MintWitnessFileAsync(
        [
            new WebVhWitnessApproval(log.VersionIds[0], [witness], GenesisTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveWithWitnessAsync(log.Did, log.Lines, witnessFile).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A witnessed genesis MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.VersionIds[0], result.DocumentMetadata.VersionId);
    }


    [TestMethod]
    public async Task WitnessBelowThresholdFails()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController witness1 = WebVhController.Create();
        using WebVhController witness2 = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, WebVhWitnessSpec.Rule(2, witness1, witness2))
        ]).ConfigureAwait(false);

        //Only one of the two required witnesses approves.
        string witnessFile = await WebVhTestLog.MintWitnessFileAsync(
        [
            new WebVhWitnessApproval(log.VersionIds[0], [witness1], GenesisTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveWithWitnessAsync(log.Did, log.Lines, witnessFile).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A log below the witness threshold MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task LaterWitnessProofSatisfiesPriorEntry()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController witness = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, WebVhWitnessSpec.Rule(1, witness)),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime)
        ]).ConfigureAwait(false);

        //Only the second version is approved; a later proof carries approval of all prior entries, so the
        //genesis (also witnessed by the same rule) is satisfied too.
        string witnessFile = await WebVhTestLog.MintWitnessFileAsync(
        [
            new WebVhWitnessApproval(log.VersionIds[1], [witness], SecondTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveWithWitnessAsync(log.Did, log.Lines, witnessFile).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A later witness proof MUST satisfy prior entries. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.VersionIds[1], result.DocumentMetadata.VersionId);
    }


    [TestMethod]
    public async Task TamperedWitnessProofIgnoredButThresholdMet()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController witness1 = WebVhController.Create();
        using WebVhController witness2 = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, WebVhWitnessSpec.Rule(1, witness1, witness2))
        ]).ConfigureAwait(false);

        string witnessFile = await WebVhTestLog.MintWitnessFileAsync(
        [
            new WebVhWitnessApproval(log.VersionIds[0], [witness1, witness2], GenesisTime)
        ]).ConfigureAwait(false);

        //One witness proof is corrupted; the other valid proof still meets the threshold of one.
        string tampered = TamperWitnessProof(witnessFile, witness2.VerificationMethod);

        DidResolutionResult result = await ResolveWithWitnessAsync(log.Did, log.Lines, tampered).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"An invalid witness proof MUST be ignored when the threshold is still met. Error: {result.ResolutionMetadata.Error?.Type}.");
    }


    [TestMethod]
    public async Task ForeignWitnessProofDoesNotCount()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController witness = WebVhController.Create();
        using WebVhController foreign = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, WebVhWitnessSpec.Rule(1, witness))
        ]).ConfigureAwait(false);

        //A valid proof from a witness not listed in the rule MUST NOT count toward the threshold.
        string witnessFile = await WebVhTestLog.MintWitnessFileAsync(
        [
            new WebVhWitnessApproval(log.VersionIds[0], [foreign], GenesisTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveWithWitnessAsync(log.Did, log.Lines, witnessFile).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A proof from a witness outside the rule MUST NOT satisfy the threshold.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task MissingWitnessFileWhenWitnessesActiveFails()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController witness = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, WebVhWitnessSpec.Rule(1, witness))
        ]).ConfigureAwait(false);

        //No did-witness.json is served: an active witness rule cannot be confirmed, so resolution fails closed.
        DidResolutionResult result = await ResolveWithWitnessAsync(log.Did, log.Lines, witnessJson: null).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "Active witnesses with no did-witness.json MUST fail resolution.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task MidLogWitnessActivationDefersToNextEntry()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController witness = WebVhController.Create();

        //Genesis has no witnesses; the second entry first activates them. Per the fold timing, that activation
        //takes effect for the NEXT entry, so neither the genesis nor the activating entry requires witnessing —
        //the two-entry log resolves with no did-witness.json at all.
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime, WebVhWitnessSpec.Rule(1, witness))
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveWithWitnessAsync(log.Did, log.Lines, witnessJson: null).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A mid-log witness activation defers to the next entry. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.VersionIds[1], result.DocumentMetadata.VersionId);
    }


    [TestMethod]
    public async Task WitnessDisableTakesEffectAfterEntry()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController witness = WebVhController.Create();

        //Genesis activates witnesses; the second entry disables them with {}. The disable takes effect for the
        //THIRD entry, so the genesis and the disabling entry are still witnessed, but the third is not.
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, WebVhWitnessSpec.Rule(1, witness)),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime, WebVhWitnessSpec.Disable),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, ThirdTime)
        ]).ConfigureAwait(false);

        //Approving only the second version covers the genesis and the disabling entry; the third needs none.
        string witnessFile = await WebVhTestLog.MintWitnessFileAsync(
        [
            new WebVhWitnessApproval(log.VersionIds[1], [witness], SecondTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveWithWitnessAsync(log.Did, log.Lines, witnessFile).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"Witnessing disabled mid-log MUST stop requiring proofs for later entries. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.VersionIds[2], result.DocumentMetadata.VersionId);
    }


    [TestMethod]
    public void NonObjectWitnessParameterIsRejected()
    {
        //A witness value that is not a JSON object (here an array) does not conform to the witness data model
        //and MUST be rejected at parse, not coerced to "no witnesses" (did:webvh v1.0, Parameters).
        const string line = "{\"versionId\":\"1-abc\",\"versionTime\":\"2025-01-01T00:00:00Z\",\"parameters\":{\"method\":\"did:webvh:1.0\",\"scid\":\"Qm\",\"updateKeys\":[\"z6Mk\"],\"witness\":[]},\"state\":{\"id\":\"did:webvh:Qm:example.com\"}}";

        Assert.ThrowsExactly<JsonException>(() => WebVhLogEntryJson.Parser(Encoding.UTF8.GetBytes(line)));
    }


    /// <summary>
    /// A negative ttl does not conform to the ttl data model (an unsigned cache hint) and MUST be rejected at
    /// parse, not coerced to the default (did:webvh v1.0, Parameters: a non-conforming value invalidates the
    /// entry).
    /// </summary>
    [TestMethod]
    public void NegativeTtlIsRejected()
    {
        const string line = "{\"versionId\":\"1-abc\",\"versionTime\":\"2025-01-01T00:00:00Z\",\"parameters\":{\"method\":\"did:webvh:1.0\",\"scid\":\"Qm\",\"updateKeys\":[\"z6Mk\"],\"ttl\":-5},\"state\":{\"id\":\"did:webvh:Qm:example.com\"}}";

        Assert.ThrowsExactly<JsonException>(() => WebVhLogEntryJson.Parser(Encoding.UTF8.GetBytes(line)));
    }


    /// <summary>A type-mismatched ttl (a non-integer) MUST be rejected, not silently dropped to the default.</summary>
    [TestMethod]
    public void NonIntegerTtlIsRejected()
    {
        const string line = "{\"versionId\":\"1-abc\",\"versionTime\":\"2025-01-01T00:00:00Z\",\"parameters\":{\"method\":\"did:webvh:1.0\",\"scid\":\"Qm\",\"updateKeys\":[\"z6Mk\"],\"ttl\":\"3600\"},\"state\":{\"id\":\"did:webvh:Qm:example.com\"}}";

        Assert.ThrowsExactly<JsonException>(() => WebVhLogEntryJson.Parser(Encoding.UTF8.GetBytes(line)));
    }


    /// <summary>
    /// A type-mismatched updateKeys (not a JSON array) MUST be rejected at parse, not coerced to the default
    /// (did:webvh v1.0, Parameters: a non-conforming value invalidates the entry).
    /// </summary>
    [TestMethod]
    public void NonArrayUpdateKeysIsRejected()
    {
        const string line = "{\"versionId\":\"1-abc\",\"versionTime\":\"2025-01-01T00:00:00Z\",\"parameters\":{\"method\":\"did:webvh:1.0\",\"scid\":\"Qm\",\"updateKeys\":\"z6Mk\"},\"state\":{\"id\":\"did:webvh:Qm:example.com\"}}";

        Assert.ThrowsExactly<JsonException>(() => WebVhLogEntryJson.Parser(Encoding.UTF8.GetBytes(line)));
    }


    /// <summary>A type-mismatched portable (not a JSON boolean) MUST be rejected, not coerced to the default.</summary>
    [TestMethod]
    public void NonBooleanPortableIsRejected()
    {
        const string line = "{\"versionId\":\"1-abc\",\"versionTime\":\"2025-01-01T00:00:00Z\",\"parameters\":{\"method\":\"did:webvh:1.0\",\"scid\":\"Qm\",\"updateKeys\":[\"z6Mk\"],\"portable\":\"true\"},\"state\":{\"id\":\"did:webvh:Qm:example.com\"}}";

        Assert.ThrowsExactly<JsonException>(() => WebVhLogEntryJson.Parser(Encoding.UTF8.GetBytes(line)));
    }


    /// <summary>
    /// The parameters object MUST only include properties defined by this did:webvh version; an unknown property
    /// invalidates the entry (did:webvh v1.0, Parameters: L1035).
    /// </summary>
    [TestMethod]
    public void UnknownParameterPropertyIsRejected()
    {
        const string line = "{\"versionId\":\"1-abc\",\"versionTime\":\"2025-01-01T00:00:00Z\",\"parameters\":{\"method\":\"did:webvh:1.0\",\"scid\":\"Qm\",\"updateKeys\":[\"z6Mk\"],\"undefinedParam\":true},\"state\":{\"id\":\"did:webvh:Qm:example.com\"}}";

        Assert.ThrowsExactly<JsonException>(() => WebVhLogEntryJson.Parser(Encoding.UTF8.GetBytes(line)));
    }


    /// <summary>The deprecated JSON null form of the witness parameter is accepted as the empty (disabled) default.</summary>
    [TestMethod]
    public void NullWitnessParameterIsAcceptedAsDisabled()
    {
        const string line = "{\"versionId\":\"1-abc\",\"versionTime\":\"2025-01-01T00:00:00Z\",\"parameters\":{\"method\":\"did:webvh:1.0\",\"scid\":\"Qm\",\"updateKeys\":[\"z6Mk\"],\"witness\":null},\"state\":{\"id\":\"did:webvh:Qm:example.com\"}}";

        WebVhRawEntry entry = WebVhLogEntryJson.Parser(Encoding.UTF8.GetBytes(line));

        Assert.IsNotNull(entry.DeclaredParameters.Witness, "A JSON null witness is the empty (disabled) declaration, not absent.");
        Assert.IsNull(entry.DeclaredParameters.Witness!.Rule);
    }


    /// <summary>
    /// The deprecated JSON null form of a parameter normalizes to that parameter's documented default, uniformly
    /// across every null-accepting parameter (did:webvh v1.0, Parameters: L1048). nextKeyHashes and updateKeys
    /// default to the empty array, ttl defaults to 3600.
    /// </summary>
    [TestMethod]
    public void NullParametersNormalizeToTheirDocumentedDefaults()
    {
        const string line = "{\"versionId\":\"1-abc\",\"versionTime\":\"2025-01-01T00:00:00Z\",\"parameters\":{\"method\":\"did:webvh:1.0\",\"scid\":\"Qm\",\"updateKeys\":null,\"nextKeyHashes\":null,\"ttl\":null,\"watchers\":null},\"state\":{\"id\":\"did:webvh:Qm:example.com\"}}";

        WebVhRawEntry entry = WebVhLogEntryJson.Parser(Encoding.UTF8.GetBytes(line));

        Assert.IsNotNull(entry.DeclaredParameters.UpdateKeys, "A JSON null updateKeys MUST normalize to the empty-array default, not 'retain'.");
        Assert.IsEmpty(entry.DeclaredParameters.UpdateKeys!.Value);

        Assert.IsNotNull(entry.DeclaredParameters.NextKeyHashes, "A JSON null nextKeyHashes MUST normalize to the empty-array default, not 'retain'.");
        Assert.IsEmpty(entry.DeclaredParameters.NextKeyHashes!.Value);

        Assert.IsNotNull(entry.DeclaredParameters.Ttl, "A JSON null ttl MUST normalize to the documented default, not 'retain'.");
        Assert.AreEqual(WebVhParameters.DefaultTtlSeconds, entry.DeclaredParameters.Ttl!.Value);

        Assert.IsNotNull(entry.DeclaredParameters.Watchers, "A JSON null watchers MUST normalize to the empty-array default.");
        Assert.IsEmpty(entry.DeclaredParameters.Watchers!.Value);
    }


    /// <summary>
    /// Rewriting a genesis nextKeyHashes commitment's multihash code AFTER minting corrupts the entry, so the
    /// genesis fails the entryHash integrity check (which runs ahead of the per-parameter multihash-algorithm
    /// guard) and the chain fail-closes the mutation. The per-parameter nextKeyHashes multihash guard is itself
    /// defensive depth on the same Cryptographic-Agility MUST that the entryHash test exercises by algorithm
    /// directly (did:webvh v1.0, Cryptographic Agility).
    /// </summary>
    [TestMethod]
    public async Task TamperedGenesisNextKeyHashFailsEntryHashIntegrity()
    {
        using WebVhController genesisKey = WebVhController.Create();
        using WebVhController nextKey = WebVhController.Create();

        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, genesisKey, GenesisTime, nextKeyHashes: [nextKey.KeyHash]).ConfigureAwait(false);

        //Re-encode the genesis nextKeyHashes commitment with a SHA3-256 (0x16) multihash code AFTER the entry is
        //minted, so the genesis entryHash (computed over the original commitment) no longer matches the tampered
        //entry. The entryHash integrity check runs ahead of the per-parameter multihash-algorithm guard, so this
        //tamper is caught by the chain's entryHash verification — the integrity gate that fail-closes any post-mint
        //mutation of a genesis entry, which is the load-bearing rejection here.
        JsonObject genesis = JsonNode.Parse(log.Lines[0])!.AsObject();
        JsonObject parameters = (JsonObject)genesis["parameters"]!;
        JsonArray nextKeyHashes = (JsonArray)parameters["nextKeyHashes"]!;
        nextKeyHashes[0] = RewriteMultihashAlgorithm((string)nextKeyHashes[0]!, replacementMultihashCode: 0x16);

        DidResolutionResult result = await ResolveAsync(log.Did, [genesis.ToJsonString()]).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A nextKeyHashes commitment with a non-sha2-256 multihash prefix MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);

        //The tampered genesis MUST be rejected by the entryHash integrity check (the entryHash no longer verifies
        //against the mutated entry content), proving the chain fail-closes the post-mint mutation rather than
        //silently admitting a non-sha2-256 commitment.
        Assert.Contains("does not verify", result.ResolutionMetadata.Error!.Detail!,
            "The tampered genesis MUST be rejected by entryHash integrity verification.");
    }


    /// <summary>
    /// A resolver MUST NOT return the DIDDoc of a deactivated DID and MUST include deactivated:true in the
    /// resolution metadata (did:webvh v1.0, Deactivate: L1019). Resolving the latest version of a two-entry log
    /// whose second entry sets deactivated:true succeeds with a null document and deactivated metadata.
    /// </summary>
    [TestMethod]
    public async Task DeactivatedLatestReturnsNoDocument()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: true, SecondTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A deactivated did:webvh DID MUST resolve (successfully) with deactivated metadata. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.IsNull(result.Document, "A resolver MUST NOT return the DIDDoc for a deactivated DID.");
        Assert.IsTrue(result.DocumentMetadata.Deactivated, "A deactivated DID MUST carry deactivated:true in the resolution metadata.");
        Assert.AreEqual(log.VersionIds[^1], result.DocumentMetadata.VersionId, "The resolved version MUST be the deactivation entry.");
    }


    /// <summary>
    /// Resolving a PRIOR version of a deactivated DID via versionId returns that earlier DIDDoc but MUST still
    /// carry deactivated:true in the resolution metadata (did:webvh v1.0, Deactivate: L1023).
    /// </summary>
    [TestMethod]
    public async Task PriorVersionOfDeactivatedDidCarriesDeactivatedMetadata()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: true, SecondTime)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines, new DidResolutionOptions { VersionId = log.VersionIds[0] }).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A prior version of a deactivated DID MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.IsNotNull(result.Document, "A prior version of a deactivated DID returns that version's DIDDoc.");
        Assert.AreEqual(log.Did, result.Document!.Id?.ToString());
        Assert.AreEqual(log.VersionIds[0], result.DocumentMetadata.VersionId, "The resolved version MUST be the queried earlier version.");
        Assert.IsTrue(result.DocumentMetadata.Deactivated, "A prior version of a deactivated DID MUST still carry deactivated:true.");
    }


    /// <summary>
    /// A did:webvh resolution always determines the deactivation status, so the resolution metadata carries
    /// deactivated explicitly — present as false for a live DID, not omitted (did:webvh v1.0, Read: the metadata
    /// example shows "deactivated": false).
    /// </summary>
    [TestMethod]
    public async Task ActiveDidMetadataCarriesDeactivatedFalse()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A live did:webvh DID MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");

        string metadataJson = JsonSerializerExtensions.Serialize(result.DocumentMetadata, TestSetup.DefaultSerializationOptions);
        using JsonDocument document = JsonDocument.Parse(metadataJson);

        Assert.IsTrue(document.RootElement.TryGetProperty("deactivated", out JsonElement deactivated),
            "A did:webvh resolution MUST carry an explicit deactivated property, not omit it.");
        Assert.IsFalse(deactivated.GetBoolean(), "A live DID MUST carry deactivated:false.");
    }


    /// <summary>
    /// When a watcher configuration is active but the list is empty, the resolution metadata MUST carry watchers
    /// as an explicit empty array, not omit it (did:webvh v1.0, Read). The watchers parameter defaults to [] and
    /// is part of the resolved configuration.
    /// </summary>
    [TestMethod]
    public async Task ActiveEmptyWatcherListIsExplicitEmptyArray()
    {
        using WebVhController controller = WebVhController.Create();

        //An entry declaring watchers as an explicit empty array: the metadata MUST surface watchers as [].
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, Watchers: ImmutableArray<string>.Empty)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A did:webvh DID with empty watchers MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");

        string metadataJson = JsonSerializerExtensions.Serialize(result.DocumentMetadata, TestSetup.DefaultSerializationOptions);
        using JsonDocument document = JsonDocument.Parse(metadataJson);

        Assert.IsTrue(document.RootElement.TryGetProperty("watchers", out JsonElement watchers),
            "An active empty watcher list MUST be emitted as an explicit [].");
        Assert.AreEqual(JsonValueKind.Array, watchers.ValueKind);
        Assert.AreEqual(0, watchers.GetArrayLength(), "The active watcher list MUST be an explicit empty array.");
    }


    /// <summary>
    /// did:webvh v1.0 fixes SHA-256, and the entryHash is a self-describing multihash. A genesis versionId whose
    /// entryHash carries a non-sha2-256 multihash prefix MUST be rejected by algorithm as invalidDid, not only
    /// by a recomputed-value mismatch (did:webvh v1.0, Cryptographic Agility).
    /// </summary>
    [TestMethod]
    public async Task NonSha256EntryHashMultihashIsRejected()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //Re-encode the genesis versionId's entryHash as a multihash with the SHA3-256 code (0x16) instead of
        //sha2-256 (0x12), preserving the 32-byte digest and the version number. The value would still be a
        //32-byte multihash, so only the algorithm prefix distinguishes it.
        JsonObject genesis = JsonNode.Parse(log.Lines[0])!.AsObject();
        string versionId = (string)genesis["versionId"]!;
        string reEncoded = RewriteEntryHashAlgorithm(versionId, replacementMultihashCode: 0x16);
        genesis["versionId"] = reEncoded;

        DidResolutionResult result = await ResolveAsync(log.Did, [genesis.ToJsonString()]).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "An entryHash with a non-sha2-256 multihash prefix MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);

        //The rejection MUST be by the multihash ALGORITHM prefix, not only by a recomputed-value mismatch — the
        //algorithm-specific detail pins the IsSha256Multihash guard (reverting it would surface a value-mismatch
        //message and fail this assertion).
        Assert.Contains("not a SHA-256 multihash", result.ResolutionMetadata.Error!.Detail!,
            "The entryHash MUST be rejected by multihash algorithm.");
    }


    /// <summary>
    /// A did:webvh proof whose validity window has closed (an <c>expires</c> in the past) MUST NOT verify, so the
    /// entry it secures fails resolution (VC Data Integrity, proof options 'expires').
    /// </summary>
    [TestMethod]
    public async Task ExpiredProofIsRejected()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //Inject an 'expires' in the past into the proof. The signature still covers the proof options it was
        //minted over (without 'expires'), so the rejection is specifically the expiry gate, not a signature
        //failure — but the resolver MUST still reject the entry whose proof has expired.
        JsonObject genesis = JsonNode.Parse(log.Lines[0])!.AsObject();
        JsonObject proof = (JsonObject)((JsonArray)genesis["proof"]!)[0]!;
        proof["expires"] = "2020-01-01T00:00:00Z";

        DidResolutionResult result = await ResolveAsync(log.Did, [genesis.ToJsonString()]).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webvh entry whose proof has expired MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// The fetched did.jsonl size is bounded: an oversized DID Log MUST be rejected before it is parsed
    /// (did:webvh v1.0, Read: guard retrieval against resource exhaustion).
    /// </summary>
    [TestMethod]
    public async Task OversizedDidLogIsRejected()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //A DID Log padded beyond the resolver's size bound (8 MiB) with trailing whitespace: the parser is never
        //reached, so the size guard alone rejects it.
        string oversized = string.Join('\n', log.Lines) + "\n" + new string(' ', 9 * 1024 * 1024);

        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [WebVhDidResolver.Resolve(log.Did)] = (200, oversized)
        });

        DidResolutionResult result = await ResolveAsync(log.Did, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "An oversized did:webvh DID Log MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// A malformed SCID (not the ABNF's 46 base58btc characters) MUST be rejected fail-fast as invalidDid at the
    /// identifier boundary, before the DID Log is fetched (did:webvh v1.0: "scid = 46(base58-alphabet)").
    /// </summary>
    [TestMethod]
    public async Task MalformedScidIsRejectedEarly()
    {
        //A 10-character SCID is not the required 46-character shape.
        const string malformedDid = "did:webvh:QmTooShort:example.com";

        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal));

        DidResolutionResult result = await ResolveAsync(malformedDid, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A did:webvh DID with a malformed SCID MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// A genesis entry whose versionId is not of the shape "1-&lt;entryHash&gt;" MUST be rejected fail-fast as
    /// invalidDid (did:webvh v1.0, Creating the DID: the genesis version number is 1).
    /// </summary>
    [TestMethod]
    public async Task GenesisVersionIdNotVersionOneIsRejected()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //Renumber the genesis versionId to "2-<entryHash>": the genesis MUST be version 1.
        JsonObject genesis = JsonNode.Parse(log.Lines[0])!.AsObject();
        string versionId = (string)genesis["versionId"]!;
        genesis["versionId"] = "2-" + versionId[(versionId.IndexOf('-', StringComparison.Ordinal) + 1)..];

        DidResolutionResult result = await ResolveAsync(log.Did, [genesis.ToJsonString()]).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A genesis versionId not numbered 1 MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    /// <summary>
    /// On a primary not-found, the resolver MAY retrieve the DID Log from a supplied alternative source (a
    /// Watcher URL) and resolves from it (did:webvh v1.0, Read: L886). The log served from the watcher is
    /// verified exactly as the primary would be.
    /// </summary>
    [TestMethod]
    public async Task WatcherUrlFallbackResolvesOnPrimaryNotFound()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        const string watcherUrl = "https://watcher.example/cache/did.jsonl";

        //The primary location is a 404; the watcher serves the valid log.
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [WebVhDidResolver.Resolve(log.Did)] = (404, null),
            [watcherUrl] = (200, string.Join('\n', log.Lines))
        });

        DidResolutionResult result = await ResolveAsync(log.Did, transport, new DidResolutionOptions { WatcherUrls = [watcherUrl] }).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A watcher fallback MUST resolve on a primary 404. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.Did, result.Document!.Id?.ToString());
    }


    /// <summary>A primary not-found with no supplied watcher source stays notFound (the watcher fallback is opt-in).</summary>
    [TestMethod]
    public async Task PrimaryNotFoundWithoutWatchersStaysNotFound()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [WebVhDidResolver.Resolve(log.Did)] = (404, null)
        });

        DidResolutionResult result = await ResolveAsync(log.Did, transport).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A primary 404 with no watcher source MUST stay NotFound.");
        Assert.AreEqual(DidResolutionErrors.NotFound, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolvesMovedDidWhenPortable()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, Portable: true),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime, MoveToDomain: "moved.example")
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A portable did:webvh DID MUST resolve after a move. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.AreEqual(log.Did, result.Document!.Id?.ToString());
        Assert.IsTrue(log.Did.Contains("moved.example", StringComparison.Ordinal), "The resolved DID MUST reflect the new location.");
    }


    /// <summary>
    /// A move MUST keep the SAME SCID: the SCID is the established identity binding the DID across the move
    /// (did:webvh v1.0, DID Portability). A move whose new id carries a different SCID MUST NOT resolve.
    /// </summary>
    [TestMethod]
    public async Task MoveChangingScidFails()
    {
        using WebVhController controller = WebVhController.Create();

        //A different, well-formed SCID placed in the moved id. The established SCID is fixed by the genesis, so a
        //moved id bearing any other SCID is not the same DID.
        const string differentScid = "QmDifferentScidXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, Portable: true),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime, MoveToDomain: "moved.example", MoveChangeScid: differentScid)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A move changing the SCID MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task MoveWithoutPortabilityFails()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime, MoveToDomain: "moved.example")
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A move on a non-portable DID MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task MoveWithoutAlsoKnownAsFails()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, Portable: true),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime, MoveToDomain: "moved.example", SuppressAlsoKnownAs: true)
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A move missing the prior DID in alsoKnownAs MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task MoveWithTypeMalformedAlsoKnownAsFails()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, Portable: true),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime, MoveToDomain: "moved.example", MalformAlsoKnownAs: true)
        ]).ConfigureAwait(false);

        //The moved entry carries a non-string alsoKnownAs member: a malformed state MUST fail closed with the
        //invalidDid error, not surface as an unhandled exception or InternalError.
        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccessful, "A move with a type-malformed alsoKnownAs MUST NOT resolve.");
        Assert.AreEqual(DidResolutionErrors.InvalidDid, result.ResolutionMetadata.Error);
    }


    [TestMethod]
    public async Task ResolvedMetadataCarriesWatchers()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime, Watchers: ["https://watcher.example/watch"])
        ]).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A did:webvh DID with watchers MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");

        //The resolver surfaces the active watchers in the open-world metadata bucket (read typed via GetWatchers).
        IReadOnlyList<string> watchers = result.DocumentMetadata.GetWatchers();
        Assert.HasCount(1, watchers);
        Assert.AreEqual("https://watcher.example/watch", watchers[0]);
    }


    [TestMethod]
    public async Task ResolvedMetadataCarriesRicherFields()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A did:webvh DID MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");

        DidDocumentMetadata metadata = result.DocumentMetadata;
        Assert.AreEqual(log.Scid, metadata.GetScid());
        Assert.IsFalse(metadata.GetPortable()!.Value);
        Assert.AreEqual("3600", metadata.GetTtl());
        Assert.AreEqual(GenesisTime, metadata.GetVersionTime());
        Assert.AreEqual(log.VersionIds[0], metadata.VersionId);

        //created = first entry's versionTime, updated = resolved entry's versionTime (the same for a genesis-only log).
        Assert.IsNotNull(metadata.Created);
        Assert.IsNotNull(metadata.Updated);
        Assert.AreEqual(metadata.Created, metadata.Updated);
    }


    [TestMethod]
    public async Task ResolvedDocumentCarriesImplicitServices()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A did:webvh DID MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");
        Assert.IsNotNull(result.Document!.Service);

        //example.com is a bare-domain DID, so the implicit service base drops the .well-known segment.
        Service files = result.Document.Service!.Single(s => s.Id!.ToString().EndsWith(WellKnownWebVhValues.FilesServiceFragment, StringComparison.Ordinal));
        Assert.AreEqual(WellKnownServiceTypes.RelativeRef, files.Type);
        Assert.AreEqual("https://example.com/", files.ServiceEndpoint);

        Service whois = result.Document.Service!.Single(s => s.Id!.ToString().EndsWith(WellKnownWebVhValues.WhoisServiceFragment, StringComparison.Ordinal));
        Assert.AreEqual(WellKnownServiceTypes.LinkedVerifiablePresentation, whois.Type);
        Assert.AreEqual("https://example.com/whois.vp", whois.ServiceEndpoint);

        //The LinkedVerifiablePresentation service carries the linked-vp @context (the #files service does not).
        Assert.IsNotNull(whois.AdditionalData);
        Assert.AreEqual(WellKnownServiceTypes.LinkedVerifiablePresentationContext, (string)whois.AdditionalData!["@context"]);
        Assert.IsNull(files.AdditionalData);
    }


    [TestMethod]
    public async Task ImplicitServiceEndpointForPathDid()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync("example.com:dids:issuer", controller, GenesisTime).ConfigureAwait(false);

        DidResolutionResult result = await ResolveAsync(log.Did, log.Lines).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccessful, $"A path-bearing did:webvh DID MUST resolve. Error: {result.ResolutionMetadata.Error?.Type}.");

        //A path-bearing DID has no .well-known segment; the implicit service base is the full path location.
        Service files = result.Document!.Service!.Single(s => s.Id!.ToString().EndsWith(WellKnownWebVhValues.FilesServiceFragment, StringComparison.Ordinal));
        Assert.AreEqual("https://example.com/dids/issuer/", files.ServiceEndpoint);
    }


    //Resolves over a transport serving the did.jsonl and, when witnessJson is non-null, the did-witness.json.
    private Task<DidResolutionResult> ResolveWithWitnessAsync(string did, ImmutableArray<string> lines, string? witnessJson, DidResolutionOptions? options = null)
    {
        string logUrl = WebVhDidResolver.Resolve(did);
        var routes = new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [logUrl] = (200, string.Join('\n', lines))
        };

        if(witnessJson is not null)
        {
            routes[WitnessUrl(logUrl)] = (200, witnessJson);
        }

        return ResolveAsync(did, new RoutingTransport(routes), options);
    }


    private static string WitnessUrl(string logUrl) =>
        string.Concat(logUrl.AsSpan(0, logUrl.Length - "did.jsonl".Length), "did-witness.json");


    private static string TamperWitnessProof(string witnessJson, string verificationMethod)
    {
        JsonArray records = JsonNode.Parse(witnessJson)!.AsArray();
        foreach(JsonNode? recordNode in records)
        {
            foreach(JsonNode? proofNode in recordNode!["proof"]!.AsArray())
            {
                if(string.Equals((string?)proofNode!["verificationMethod"], verificationMethod, StringComparison.Ordinal))
                {
                    string proofValue = (string)proofNode["proofValue"]!;
                    proofNode["proofValue"] = proofValue[..^1] + (proofValue[^1] == 'A' ? 'B' : 'A');
                }
            }
        }

        return records.ToJsonString();
    }


    private static Task<WebVhMintedLog> MintTwoEntryAsync(WebVhController controller)
    {
        return WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            new WebVhEntryPlan(controller, [controller.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime)
        ]);
    }


    private static DateTimeOffset Time(string iso8601) =>
        DateTimeOffset.Parse(iso8601, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);


    //Rewrites a versionId's entryHash multihash to declare a different algorithm code while keeping the 32-byte
    //digest, so the resulting value is still a 32-byte multihash but with a non-sha2-256 algorithm prefix. The
    //version-number prefix ("1-") is preserved.
    private static string RewriteEntryHashAlgorithm(string versionId, byte replacementMultihashCode)
    {
        int dashIndex = versionId.IndexOf('-', StringComparison.Ordinal);
        string prefix = versionId[..(dashIndex + 1)];
        string entryHash = versionId[(dashIndex + 1)..];

        return prefix + RewriteMultihashAlgorithm(entryHash, replacementMultihashCode);
    }


    //Rewrites a base58btc-encoded multihash so it declares a different algorithm code while keeping the 32-byte
    //digest, producing a value that is still a 32-byte multihash but with a non-sha2-256 algorithm prefix.
    private static string RewriteMultihashAlgorithm(string base58Multihash, byte replacementMultihashCode)
    {
        using IMemoryOwner<byte> decoded = Base58Decoder(base58Multihash, BaseMemoryPool.Shared);
        byte[] bytes = decoded.Memory.Span.ToArray();

        //bytes[0] is the multihash algorithm code (0x12 for sha2-256); bytes[1] is the digest length (0x20).
        bytes[0] = replacementMultihashCode;

        return Base58Encoder(bytes);
    }


    private Task<DidResolutionResult> ResolveAsync(string did, System.Collections.Immutable.ImmutableArray<string> lines, DidResolutionOptions? options = null)
    {
        var transport = new RoutingTransport(new Dictionary<string, (int, string?)>(StringComparer.Ordinal)
        {
            [WebVhDidResolver.Resolve(did)] = (200, string.Join('\n', lines))
        });

        return ResolveAsync(did, transport, options);
    }


    private async Task<DidResolutionResult> ResolveAsync(string did, RoutingTransport transport, DidResolutionOptions? options = null)
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        DidMethodResolverDelegate resolver = WebVhDidResolver.Build(
            transport.Delegate,
            WebVhLogEntryJson.Parser,
            WebVhLogEntryJson.WitnessFileParser,
            WebVhLogEntryJson.DocumentIdentityReader,
            DeserializeState,
            WebVhLogEntryJson.Canonicalizer,
            Base58Encoder,
            Base58Decoder,
            BaseMemoryPool.Shared,
            new FakeTimeProvider(TestClock.CanonicalEpoch));

        return await resolver(did, options ?? DidResolutionOptions.Empty, context, TestContext.CancellationToken).ConfigureAwait(false);
    }


    //The JSON layer supplies state deserialization; Verifiable.Core never parses the did.jsonl itself.
    private static DidDocument? DeserializeState(ReadOnlySpan<byte> rawEntryLine)
    {
        try
        {
            if(JsonNode.Parse(rawEntryLine) is not JsonObject entry || entry["state"] is not JsonObject state)
            {
                return null;
            }

            return JsonSerializerExtensions.Deserialize<DidDocument>(state.ToJsonString(), TestSetup.DefaultSerializationOptions);
        }
        catch(JsonException)
        {
            return null;
        }
    }


    //A single-hop transport returning a canned (status, body) per absolute URL; an unknown URL is a 404.
    private sealed class RoutingTransport
    {
        private readonly Dictionary<string, (int Status, string? Body)> routes;

        public RoutingTransport(Dictionary<string, (int Status, string? Body)> routes)
        {
            this.routes = routes;
        }

        public OutboundTransportDelegate Delegate => (request, context, cancellationToken) =>
        {
            if(!routes.TryGetValue(request.Target.AbsoluteUri, out (int Status, string? Body) route))
            {
                route = (404, null);
            }

            TaggedMemory<byte> body = route.Body is null
                ? TaggedMemory<byte>.Empty
                : new TaggedMemory<byte>(Encoding.UTF8.GetBytes(route.Body), BufferTags.Json);

            return ValueTask.FromResult(new OutboundResponse { StatusCode = route.Status, Body = body });
        };
    }
}
