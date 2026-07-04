using System;
using Verifiable.BouncyCastle;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebPlusHashedKey"/> — the did:webplus <c>hashedKey</c> pre-rotation commitment (WP-UR-4).
/// Anchored on the specification's second worked example, whose root <c>updateRules</c> is
/// <c>{"hashedKey":"uHiCMmFu…"}</c> and whose next document's proof <c>kid</c> is the MBPubKey that commitment
/// must match (LedgerDomain Draft v0.4, L1251). BLAKE3 is supplied from BouncyCastle as an independent oracle.
/// </summary>
[TestClass]
internal sealed class WebPlusHashedKeyTests
{
    private const int Blake3DigestLength = 32;

    //The proof kid (MBPubKey) of the versionId-1 document, and the hashedKey commitment in the root updateRules.
    private const string MbPubKey = "u7QG2O2Vm22e1g4v6VRxjY9Qgm9XqJAKf_b3cH6Oc4R0bhw";
    private const string ExpectedHashedKey = "uHiCMmFumKCTx6yxWPtoRM_VZj4DvdcHs2KEBK941pr8SXQ";


    /// <summary>The MBHash of the worked example's MBPubKey reproduces the root updateRules <c>hashedKey</c>.</summary>
    [TestMethod]
    public async Task ComputesSpecificationHashedKeyVector()
    {
        string hashedKey = await WebPlusHashedKey.ComputeAsync(
            MbPubKey, MultihashHeaders.Blake3.ToArray(), Blake3DigestLength, BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync, CryptoTags.Blake3Digest, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(ExpectedHashedKey, hashedKey);
    }


    /// <summary>The matcher accepts the MBPubKey that commits to the hashedKey and rejects an unrelated key.</summary>
    [TestMethod]
    public async Task MatcherAcceptsCommittedKeyAndRejectsOthers()
    {
        HashedKeyMatcher matcher = WebPlusHashedKey.CreateMatcher(
            MultihashHeaders.Blake3.ToArray(), Blake3DigestLength, BouncyCastleEntropyFunctions.ComputeBlake3DigestAsync, CryptoTags.Blake3Digest, TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        Assert.IsTrue(await matcher(MbPubKey, ExpectedHashedKey, CancellationToken.None), "The committed MBPubKey MUST satisfy its hashedKey commitment.");
        Assert.IsFalse(await matcher("u7QF0zsY-DxwlvuzDsosc0ZgD5drHhvNHXVkxwDDCMZHSIQ", ExpectedHashedKey, CancellationToken.None), "An unrelated key MUST NOT satisfy the commitment.");
    }
}
