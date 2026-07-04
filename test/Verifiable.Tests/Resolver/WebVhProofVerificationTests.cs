using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Verifiable.Core.Did.Methods.WebVh;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebVhProofVerification"/> — the did:webvh authorization core: SCID self-certification,
/// the eddsa-jcs-2022 controller proof against the active <c>updateKeys</c>, key pre-rotation, and the
/// <c>versionTime</c> checks. Each log is minted by <see cref="WebVhTestLog"/> executing the specification's
/// Create and Update steps, so a faithfully minted entry verifies and any tampering fails closed.
/// </summary>
[TestClass]
internal sealed class WebVhProofVerificationTests
{
    private const string Domain = "example.com";
    private const string GenesisTime = "2025-01-01T00:00:00Z";
    private const string SecondTime = "2025-02-01T00:00:00Z";

    private static readonly WebVhValidationContext Context = new()
    {
        Canonicalizer = WebVhLogEntryJson.Canonicalizer,
        ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
        Base58Encoder = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase)),
        Base58Decoder = DefaultCoderSelector.SelectDecoder(typeof(PublicKeyMultibase)),
        MemoryPool = BaseMemoryPool.Shared,
        TimeProvider = TimeProvider.System
    };


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task GenesisVerifies()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        string? error = await ValidateAsync(log.Lines[0], index: 0, new EmptyLogState<WebVhState>()).ConfigureAwait(false);

        Assert.IsNull(error, $"A faithfully minted genesis entry MUST verify. Error: {error}.");
    }


    [TestMethod]
    public async Task TamperedProofValueFails()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        string tampered = MutateProof(log.Lines[0], proof => proof["proofValue"] = FlipLastCharacter((string)proof["proofValue"]!));

        string? error = await ValidateAsync(tampered, index: 0, new EmptyLogState<WebVhState>()).ConfigureAwait(false);

        Assert.IsNotNull(error, "A tampered proofValue MUST fail.");
    }


    [TestMethod]
    public async Task TamperedDocumentFails()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //Change the signed document without re-signing: the proof no longer covers these bytes.
        string tampered = Mutate(log.Lines[0], entry => entry["versionTime"] = "2025-01-01T12:00:00Z");

        string? error = await ValidateAsync(tampered, index: 0, new EmptyLogState<WebVhState>()).ConfigureAwait(false);

        Assert.IsNotNull(error, "A document tampered after signing MUST fail.");
    }


    [TestMethod]
    public async Task VerificationMethodNotInUpdateKeysFails()
    {
        using WebVhController controller = WebVhController.Create();
        using WebVhController stranger = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //Point the proof at a key that is not in the active updateKeys.
        string tampered = MutateProof(log.Lines[0], proof => proof["verificationMethod"] = stranger.VerificationMethod);

        string? error = await ValidateAsync(tampered, index: 0, new EmptyLogState<WebVhState>()).ConfigureAwait(false);

        Assert.IsNotNull(error, "A proof signed by a key outside updateKeys MUST fail.");
    }


    [TestMethod]
    public async Task WrongCryptosuiteFails()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        string tampered = MutateProof(log.Lines[0], proof => proof["cryptosuite"] = "ecdsa-sd-2023");

        string? error = await ValidateAsync(tampered, index: 0, new EmptyLogState<WebVhState>()).ConfigureAwait(false);

        Assert.IsNotNull(error, "did:webvh v1.0 MUST reject a cryptosuite other than eddsa-jcs-2022.");
    }


    [TestMethod]
    public async Task TamperedScidFails()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        //Replace the scid with a different (well-formed) multihash that no longer certifies the entry.
        string tampered = Mutate(log.Lines[0], entry =>
            ((JsonObject)entry["parameters"]!)["scid"] = "QmTamperedScidValueXXXXXXXXXXXXXXXXXXXXXXXXXXXX");

        string? error = await ValidateAsync(tampered, index: 0, new EmptyLogState<WebVhState>()).ConfigureAwait(false);

        Assert.IsNotNull(error, "A scid that does not self-certify the first entry MUST fail.");
    }


    [TestMethod]
    public async Task FutureVersionTimeFails()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, "2099-01-01T00:00:00Z").ConfigureAwait(false);

        string? error = await ValidateAsync(log.Lines[0], index: 0, new EmptyLogState<WebVhState>()).ConfigureAwait(false);

        Assert.IsNotNull(error, "An entry whose versionTime is in the future MUST fail.");
    }


    [TestMethod]
    public async Task DeactivatedStateRejectsFurtherEntries()
    {
        using WebVhController controller = WebVhController.Create();
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, GenesisTime).ConfigureAwait(false);

        WebVhState deactivated = PriorState(log.Lines[0]);
        string? error = await ValidateAsync(log.Lines[0], index: 1, new DeactivatedLogState<WebVhState>(deactivated)).ConfigureAwait(false);

        Assert.IsNotNull(error, "A deactivated did:webvh DID MUST reject further log entries.");
    }


    [TestMethod]
    public async Task PreRotationRotationVerifies()
    {
        using WebVhController genesisKey = WebVhController.Create();
        using WebVhController nextKey = WebVhController.Create();

        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(genesisKey, [genesisKey.Multikey], [nextKey.KeyHash], Deactivated: false, GenesisTime),
            new WebVhEntryPlan(nextKey, [nextKey.Multikey], [nextKey.KeyHash], Deactivated: false, SecondTime)
        ]).ConfigureAwait(false);

        string? error = await ValidateAsync(log.Lines[1], index: 1, new ActiveLogState<WebVhState>(PriorState(log.Lines[0]))).ConfigureAwait(false);

        Assert.IsNull(error, $"A rotation to a pre-rotation-committed key MUST verify. Error: {error}.");
    }


    [TestMethod]
    public async Task PreRotationUncommittedKeyFails()
    {
        using WebVhController genesisKey = WebVhController.Create();
        using WebVhController committedKey = WebVhController.Create();
        using WebVhController attackerKey = WebVhController.Create();

        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(genesisKey, [genesisKey.Multikey], [committedKey.KeyHash], Deactivated: false, GenesisTime),
            new WebVhEntryPlan(attackerKey, [attackerKey.Multikey], [attackerKey.KeyHash], Deactivated: false, SecondTime)
        ]).ConfigureAwait(false);

        string? error = await ValidateAsync(log.Lines[1], index: 1, new ActiveLogState<WebVhState>(PriorState(log.Lines[0]))).ConfigureAwait(false);

        Assert.IsNotNull(error, "A rotation to a key not committed in the previous nextKeyHashes MUST fail.");
    }


    [TestMethod]
    public async Task PreRotationMissingNextKeyHashesFails()
    {
        using WebVhController genesisKey = WebVhController.Create();
        using WebVhController nextKey = WebVhController.Create();

        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(genesisKey, [genesisKey.Multikey], [nextKey.KeyHash], Deactivated: false, GenesisTime),
            new WebVhEntryPlan(nextKey, [nextKey.Multikey], NextKeyHashes: null, Deactivated: false, SecondTime)
        ]).ConfigureAwait(false);

        string? error = await ValidateAsync(log.Lines[1], index: 1, new ActiveLogState<WebVhState>(PriorState(log.Lines[0]))).ConfigureAwait(false);

        Assert.IsNotNull(error, "Under active pre-rotation an entry omitting nextKeyHashes MUST fail.");
    }


    [TestMethod]
    public async Task PreRotationEmptyUpdateKeysFails()
    {
        using WebVhController genesisKey = WebVhController.Create();
        using WebVhController committedKey = WebVhController.Create();

        //Under active pre-rotation the entry declares an empty updateKeys array. The spec requires updateKeys
        //to be present and non-empty while pre-rotation is active (deactivation to [] needs a separate entry
        //after pre-rotation is turned off), so the pre-rotation gate itself MUST reject this.
        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(genesisKey, [genesisKey.Multikey], [committedKey.KeyHash], Deactivated: false, GenesisTime),
            new WebVhEntryPlan(genesisKey, ImmutableArray<string>.Empty, [committedKey.KeyHash], Deactivated: false, SecondTime)
        ]).ConfigureAwait(false);

        string? error = await ValidateAsync(log.Lines[1], index: 1, new ActiveLogState<WebVhState>(PriorState(log.Lines[0]))).ConfigureAwait(false);

        Assert.IsNotNull(error, "An empty updateKeys array while pre-rotation is active MUST fail at the pre-rotation gate.");
    }


    [TestMethod]
    public async Task DateOnlyVersionTimeRejected()
    {
        using WebVhController controller = WebVhController.Create();

        //A date-only string is not a valid UTC ISO8601 versionTime; the previous lenient parse coerced it to
        //midnight UTC and accepted it, diverging from a conformant resolver.
        WebVhMintedLog log = await WebVhTestLog.MintGenesisAsync(Domain, controller, "2025-01-01").ConfigureAwait(false);

        string? error = await ValidateAsync(log.Lines[0], index: 0, new EmptyLogState<WebVhState>()).ConfigureAwait(false);

        Assert.IsNotNull(error, "A versionTime that is not a UTC ISO8601 date/time with a 'Z' designator MUST fail.");
    }


    [TestMethod]
    public async Task NonMonotonicVersionTimeFails()
    {
        using WebVhController genesisKey = WebVhController.Create();

        WebVhMintedLog log = await WebVhTestLog.MintAsync(Domain,
        [
            new WebVhEntryPlan(genesisKey, [genesisKey.Multikey], NextKeyHashes: null, Deactivated: false, GenesisTime),
            //The second entry's versionTime is earlier than the genesis entry's.
            new WebVhEntryPlan(genesisKey, [genesisKey.Multikey], NextKeyHashes: null, Deactivated: false, "2024-01-01T00:00:00Z")
        ]).ConfigureAwait(false);

        string? error = await ValidateAsync(log.Lines[1], index: 1, new ActiveLogState<WebVhState>(PriorState(log.Lines[0]))).ConfigureAwait(false);

        Assert.IsNotNull(error, "A versionTime not greater than the previous entry's MUST fail.");
    }


    private async Task<string?> ValidateAsync(string line, ulong index, LogState<WebVhState> currentState)
    {
        LogEntry<WebVhRawEntry, WebVhProof> entry = BuildEntry(line, index);

        return await WebVhProofVerification.ValidateProofAsync(entry, currentState, Context, TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static WebVhState PriorState(string genesisLine)
    {
        WebVhRawEntry genesis = WebVhLogEntryJson.Parser(Encoding.UTF8.GetBytes(genesisLine));
        (WebVhParameters? parameters, _) = WebVhParameters.FoldGenesis(genesis.DeclaredParameters);

        return new WebVhState(parameters!, genesis.VersionId, genesis.VersionTime);
    }


    private static LogEntry<WebVhRawEntry, WebVhProof> BuildEntry(string line, ulong index)
    {
        ReadOnlyMemory<byte> bytes = Encoding.UTF8.GetBytes(line);
        WebVhRawEntry parsed = WebVhLogEntryJson.Parser(bytes);

        return new LogEntry<WebVhRawEntry, WebVhProof>
        {
            Index = index,
            PreviousDigest = null,
            Digest = Encoding.UTF8.GetBytes(parsed.VersionId),
            CanonicalBytes = bytes,
            Operation = parsed,
            Proofs = parsed.Proofs
        };
    }


    private static string Mutate(string line, Action<JsonObject> mutate)
    {
        JsonObject entry = JsonNode.Parse(line)!.AsObject();
        mutate(entry);

        return entry.ToJsonString();
    }


    private static string MutateProof(string line, Action<JsonObject> mutateProof)
    {
        return Mutate(line, entry => mutateProof((JsonObject)((JsonArray)entry["proof"]!)[0]!));
    }


    private static string FlipLastCharacter(string value)
    {
        char last = value[^1];
        char replacement = last == 'A' ? 'B' : 'A';

        return value[..^1] + replacement;
    }
}
