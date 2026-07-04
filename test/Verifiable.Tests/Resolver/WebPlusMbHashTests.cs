using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebPlusMbHash"/> — the did:webplus MBHash primitive
/// <c>multibase(base64url, multihash(code ‖ length ‖ digest))</c>. The placeholder cases are anchored on the
/// did:webplus specification's MBHash Placeholder Values table (Draft v0.4), which pins the exact base64url
/// encoding of the all-zeros multihash per hash function and therefore validates the multihash header bytes.
/// </summary>
[TestClass]
internal sealed class WebPlusMbHashTests
{
    private const int Bits256DigestLength = 32;

    private static EncodeDelegate Base64UrlEncoder => TestSetup.Base64UrlEncoder;


    /// <summary>The BLAKE3 (256-bit) placeholder reproduces the specification's value, fixing the <c>0x1e 0x20</c> header.</summary>
    [TestMethod]
    public void Blake3PlaceholderMatchesSpecification()
    {
        Assert.AreEqual(
            "uHiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            WebPlusMbHash.Placeholder(MultihashHeaders.Blake3, Bits256DigestLength, Base64UrlEncoder, BaseMemoryPool.Shared));
    }


    /// <summary>The SHA-256 placeholder reproduces the specification's value, fixing the <c>0x12 0x20</c> header.</summary>
    [TestMethod]
    public void Sha256PlaceholderMatchesSpecification()
    {
        Assert.AreEqual(
            "uEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            WebPlusMbHash.Placeholder(MultihashHeaders.Sha2Bits256, Bits256DigestLength, Base64UrlEncoder, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A computed SHA-256 MBHash is a deterministic function of its input and carries the base64url multibase
    /// prefix <c>u</c> followed by the <c>0x12 0x20</c> SHA-256 header (which renders as <c>Ei…</c>).
    /// </summary>
    [TestMethod]
    public async Task ComputesDeterministicSha256MbHash()
    {
        string first = await WebPlusMbHash.ComputeAsync(
            "did:webplus test input"u8.ToArray(), MultihashHeaders.Sha2Bits256.ToArray(), Bits256DigestLength, MicrosoftEntropyFunctions.ComputeDigestAsync, CryptoTags.Sha256Digest, Base64UrlEncoder, BaseMemoryPool.Shared, CancellationToken.None);
        string second = await WebPlusMbHash.ComputeAsync(
            "did:webplus test input"u8.ToArray(), MultihashHeaders.Sha2Bits256.ToArray(), Bits256DigestLength, MicrosoftEntropyFunctions.ComputeDigestAsync, CryptoTags.Sha256Digest, Base64UrlEncoder, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(first, second);
        Assert.StartsWith("uEi", first, "A base64url SHA-256 MBHash begins with the 'u' prefix and the 0x12 0x20 header ('Ei').");
        Assert.AreEqual(47, first.Length, "A base64url-encoded 34-byte multihash with the 'u' prefix is 47 characters.");
    }


    /// <summary>The placeholder differs from the hash of real content (the placeholder is the all-zeros digest).</summary>
    [TestMethod]
    public async Task PlaceholderDiffersFromComputedHash()
    {
        string placeholder = WebPlusMbHash.Placeholder(MultihashHeaders.Sha2Bits256, Bits256DigestLength, Base64UrlEncoder, BaseMemoryPool.Shared);
        string computed = await WebPlusMbHash.ComputeAsync(
            "content"u8.ToArray(), MultihashHeaders.Sha2Bits256.ToArray(), Bits256DigestLength, MicrosoftEntropyFunctions.ComputeDigestAsync, CryptoTags.Sha256Digest, Base64UrlEncoder, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreNotEqual(placeholder, computed);
    }
}
