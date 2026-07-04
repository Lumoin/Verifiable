using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Verifiable.Core.Did.Methods.WebVh;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebVhChainVerification"/> — the did:webvh entryHash chain check that links each log
/// entry to its predecessor (Entry Hash Generation and Verification). Anchored on the specification's
/// entryHash worked example: a genesis entry whose body is the specification's preliminary log entry and
/// whose predecessor is the SCID reproduces the published entryHash.
/// </summary>
[TestClass]
internal sealed class WebVhChainVerificationTests
{
    //The body of the specification's Entry Hash Generation worked example, with the placeholder versionId
    //(the SCID) and no proof. A published genesis entry sets versionId to "1-<entryHash>" and adds a proof;
    //the chain check sets versionId back to the predecessor (the SCID) and removes the proof to reproduce
    //this exact body before hashing.
    private const string SpecPreliminaryBody =
        """
        {"versionId": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE", "versionTime": "2025-04-01T17:39:50Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6Mkkc51mg2vpQzKWAbWQZupeGYhowaBjYkmvcKMTqteqHB4", "weight": 1}, {"id": "did:key:z6MkuDdJdKLCgwZuQuEi9xG6LVgJJ9Tebr74CXPYPSumqgJs", "weight": 1}, {"id": "did:key:z6MkoSWmQyp4fTk4ZQy4KUsss9dFX51XfEUzKKKj1J1JUsrF", "weight": 1}]}, "updateKeys": ["z6MkgzBDcBFV3sk4ypPE5YXMZHmS213A3HpYY2LmcVKV15jr"], "nextKeyHashes": ["QmZreDcjvWEpyRFznQeExWNCsvMLk5i59AcRJJuQC8UodJ"], "method": "did:webvh:0.5", "scid": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE:domain.example"}}
        """;

    private const string GenesisEntryHash = "QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ";
    private const string GenesisVersionId = "1-" + GenesisEntryHash;

    private static readonly EncodeDelegate Base58Encoder = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase));
    private static readonly DecodeDelegate Base58Decoder = DefaultCoderSelector.SelectDecoder(typeof(PublicKeyMultibase));
    private static readonly VerifyChainIntegrityDelegate<WebVhRawEntry, WebVhProof> Verify =
        WebVhChainVerification.Create(WebVhLogEntryJson.Canonicalizer.EntryHashInput, MicrosoftEntropyFunctions.ComputeDigestAsync, Base58Encoder, Base58Decoder, BaseMemoryPool.Shared);


    public TestContext TestContext { get; set; } = null!;


    /// <summary>The specification's genesis entryHash verifies when the predecessor is the declared SCID.</summary>
    [TestMethod]
    public async Task GenesisEntryHashVerifiesAgainstSpecificationVector()
    {
        LogEntry<WebVhRawEntry, WebVhProof> genesis = BuildEntry(PublishGenesis(GenesisVersionId), index: 0);

        string? error = await Verify(genesis, previousEntryDigest: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(error, $"The specification genesis entryHash MUST verify. Error: {error}.");
    }


    /// <summary>Tampering the entry body breaks the entryHash — the published hash no longer reproduces.</summary>
    [TestMethod]
    public async Task TamperedBodyFailsEntryHash()
    {
        JsonObject tampered = JsonNode.Parse(PublishGenesis(GenesisVersionId))!.AsObject();
        tampered["versionTime"] = "2030-01-01T00:00:00Z";
        LogEntry<WebVhRawEntry, WebVhProof> genesis = BuildEntry(tampered.ToJsonString(), index: 0);

        string? error = await Verify(genesis, previousEntryDigest: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(error, "A tampered entry body MUST fail the entryHash check.");
    }


    /// <summary>The version number MUST equal the entry index plus one.</summary>
    [TestMethod]
    public async Task WrongVersionNumberFails()
    {
        //A genesis body published with version number 2 instead of 1.
        LogEntry<WebVhRawEntry, WebVhProof> genesis = BuildEntry(PublishGenesis("2-" + GenesisEntryHash), index: 0);

        string? error = await Verify(genesis, previousEntryDigest: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(error, "A version number that does not match the entry index MUST fail.");
    }


    /// <summary>A versionId that is not a '&lt;number&gt;-&lt;entryHash&gt;' value is rejected.</summary>
    [TestMethod]
    public async Task MalformedVersionIdFails()
    {
        LogEntry<WebVhRawEntry, WebVhProof> genesis = BuildEntry(PublishGenesis("not-a-version-id-without-number"), index: 0);

        string? error = await Verify(genesis, previousEntryDigest: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(error, "A malformed versionId MUST fail.");
    }


    /// <summary>
    /// A second entry verifies against the previous entry's versionId threaded forward as the predecessor,
    /// and fails when the threaded predecessor does not match the one its entryHash was computed over.
    /// </summary>
    [TestMethod]
    public async Task SecondEntryChainsToThreadedPredecessor()
    {
        const string secondBody =
            """
            {"versionId":"2-placeholder","versionTime":"2025-04-02T10:00:00Z","parameters":{},"state":{"@context":["https://www.w3.org/ns/did/v1"],"id":"did:webvh:QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE:domain.example","service":[]},"proof":[{"type":"DataIntegrityProof","proofValue":"zDummy"}]}
            """;

        //Mint the second entry's versionId over the genesis versionId as predecessor.
        var canonicalInput = WebVhLogEntryJson.Canonicalizer.EntryHashInput(Encoding.UTF8.GetBytes(secondBody), GenesisVersionId);
        string secondEntryHash = WebVhTestLog.MultihashBase58(canonicalInput.Span);
        string secondVersionId = "2-" + secondEntryHash;

        JsonObject published = JsonNode.Parse(secondBody)!.AsObject();
        published["versionId"] = secondVersionId;
        LogEntry<WebVhRawEntry, WebVhProof> second = BuildEntry(published.ToJsonString(), index: 1);

        ReadOnlyMemory<byte> correctPredecessor = Encoding.UTF8.GetBytes(GenesisVersionId);
        string? ok = await Verify(second, correctPredecessor, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsNull(ok, $"The second entry MUST verify against the correct threaded predecessor. Error: {ok}.");

        ReadOnlyMemory<byte> wrongPredecessor = Encoding.UTF8.GetBytes("1-QmWrongPredecessorVersionIdValueXXXXXXXXXXXXXXX");
        string? tampered = await Verify(second, wrongPredecessor, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsNotNull(tampered, "A mismatched threaded predecessor MUST break the chain.");
    }


    //Publishes the specification preliminary body as a genesis entry: sets the final versionId and adds a
    //minimal proof, without disturbing the scid that appears inside parameters and state.
    private static string PublishGenesis(string versionId)
    {
        JsonObject entry = JsonNode.Parse(SpecPreliminaryBody)!.AsObject();
        entry["versionId"] = versionId;
        entry["proof"] = new JsonArray(new JsonObject
        {
            ["type"] = "DataIntegrityProof",
            ["cryptosuite"] = "eddsa-jcs-2022",
            ["proofValue"] = "zDummySignatureValue"
        });

        return entry.ToJsonString();
    }


    private static LogEntry<WebVhRawEntry, WebVhProof> BuildEntry(string rawLine, ulong index)
    {
        ReadOnlyMemory<byte> rawBytes = Encoding.UTF8.GetBytes(rawLine);
        WebVhRawEntry parsed = WebVhLogEntryJson.Parser(rawBytes);

        return new LogEntry<WebVhRawEntry, WebVhProof>
        {
            Index = index,
            PreviousDigest = null,
            Digest = Encoding.UTF8.GetBytes(parsed.VersionId),
            CanonicalBytes = rawBytes,
            Operation = parsed,
            Proofs = parsed.Proofs
        };
    }
}
