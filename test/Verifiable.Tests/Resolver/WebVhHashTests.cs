using System.Security.Cryptography;
using Verifiable.Core.Did.Methods.WebVh;
using Verifiable.Core.Model.Did;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebVhHash.ComputeBase58Async"/> — the did:webvh <c>base58btc(multihash(input, SHA-256))</c>
/// primitive that underpins the SCID, the entryHash and the pre-rotation key hashes. Anchored on the
/// entryHash worked example in the did:webvh specification (Entry Hash Generation section).
/// </summary>
[TestClass]
internal sealed class WebVhHashTests
{
    //The preliminary log entry from the specification's Entry Hash Generation example; its versionId is the
    //SCID (this is the first entry), and the example is processed as base58btc(multihash(JCS(entry), SHA-256)).
    private const string PreliminaryLogEntry =
        """
        {"versionId": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE", "versionTime": "2025-04-01T17:39:50Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6Mkkc51mg2vpQzKWAbWQZupeGYhowaBjYkmvcKMTqteqHB4", "weight": 1}, {"id": "did:key:z6MkuDdJdKLCgwZuQuEi9xG6LVgJJ9Tebr74CXPYPSumqgJs", "weight": 1}, {"id": "did:key:z6MkoSWmQyp4fTk4ZQy4KUsss9dFX51XfEUzKKKj1J1JUsrF", "weight": 1}]}, "updateKeys": ["z6MkgzBDcBFV3sk4ypPE5YXMZHmS213A3HpYY2LmcVKV15jr"], "nextKeyHashes": ["QmZreDcjvWEpyRFznQeExWNCsvMLk5i59AcRJJuQC8UodJ"], "method": "did:webvh:0.5", "scid": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE:domain.example"}}
        """;

    private const string ExpectedEntryHash = "QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ";


    /// <summary>The specification's entryHash example reproduces exactly: base58btc(multihash(JCS(entry), SHA-256)).</summary>
    [TestMethod]
    public async Task ComputesSpecificationEntryHashVector()
    {
        EncodeDelegate base58Encoder = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase));

        string hash = await WebVhHash.ComputeBase58Async(Jcs.CanonicalizeToUtf8Bytes(PreliminaryLogEntry), MicrosoftEntropyFunctions.ComputeDigestAsync, base58Encoder, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(ExpectedEntryHash, hash);
    }


    /// <summary>A SHA-256 multihash always renders to a base58btc string of the canonical Qm... shape.</summary>
    [TestMethod]
    public async Task ProducesCanonicalSha256MultihashShape()
    {
        EncodeDelegate base58Encoder = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase));

        string hash = await WebVhHash.ComputeBase58Async("did:webvh test input"u8.ToArray(), MicrosoftEntropyFunctions.ComputeDigestAsync, base58Encoder, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.StartsWith("Qm", hash, "A base58btc SHA-256 multihash begins with the 0x12 0x20 prefix, which encodes to 'Qm'.");
        Assert.AreEqual(46, hash.Length, "A base58btc-encoded 34-byte SHA-256 multihash is 46 characters.");
    }


    /// <summary>The hash is a deterministic function of its input.</summary>
    [TestMethod]
    public async Task IsDeterministic()
    {
        EncodeDelegate base58Encoder = DefaultCoderSelector.SelectEncoder(typeof(PublicKeyMultibase));

        string first = await WebVhHash.ComputeBase58Async("same input"u8.ToArray(), MicrosoftEntropyFunctions.ComputeDigestAsync, base58Encoder, BaseMemoryPool.Shared, CancellationToken.None);
        string second = await WebVhHash.ComputeBase58Async("same input"u8.ToArray(), MicrosoftEntropyFunctions.ComputeDigestAsync, base58Encoder, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(first, second);
    }
}
