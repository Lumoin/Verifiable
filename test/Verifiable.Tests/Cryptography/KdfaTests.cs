using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Known-answer tests for <see cref="Kdfa"/> (the TPM 2.0 KDFa, Part 1 §11.4.10.2).
/// </summary>
/// <remarks>
/// <para>
/// KDFa is the SP800-108 counter-mode HMAC KDF with the fixed input
/// <c>[i]_32 || label || 0x00 || context || [bits]_32</c>, where <c>context = contextU || contextV</c>.
/// The oracle here is .NET's <see cref="SP800108HmacCounterKdf"/>, a trusted independent implementation of
/// that exact construction — so these tests validate not only the counter loop and truncation but the byte
/// layout itself (label terminator, field order, big-endian counter and length). The complementary
/// end-to-end check is the Phase-1 hardware bound-session HMAC, whose verification only succeeds if KDFa is
/// byte-exact against the real TPM.
/// </para>
/// <para>
/// <see cref="SP800108HmacCounterKdf"/> is used deliberately as an independent KAT oracle, not as the
/// system under test — the system under test is <see cref="Kdfa.DeriveAsync"/>, which routes through the
/// project's registered HMAC primitive.
/// </para>
/// </remarks>
[TestClass]
internal sealed class KdfaTests
{
    public TestContext TestContext { get; set; } = null!;

    private static byte[] Key { get; } = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    private static byte[] ContextU { get; } = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];

    private static byte[] ContextV { get; } = [0xB0, 0xB1, 0xB2, 0xB3];

    [TestMethod]
    [DataRow("SHA1", "ATH", 20)]    //Single block.
    [DataRow("SHA1", "ATH", 50)]    //Three blocks (20+20+10), truncated.
    [DataRow("SHA256", "ATH", 32)]  //Single block.
    [DataRow("SHA256", "ATH", 48)]  //Two blocks, truncated.
    [DataRow("SHA256", "ATH", 64)]  //Two full blocks.
    [DataRow("SHA256", "CFB", 44)]  //Two blocks, non-digest-multiple length.
    [DataRow("SHA384", "ATH", 48)]  //Single block.
    [DataRow("SHA384", "ATH", 96)]  //Two full blocks.
    [DataRow("SHA512", "ATH", 64)]  //Single block.
    [DataRow("SHA512", "ATH", 100)] //Two blocks, truncated.
    public async Task KdfaMatchesSp800108Oracle(string algName, string label, int outputBytes)
    {
        await AssertOracleMatchAsync(algName, label, ContextU, ContextV, outputBytes).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task KdfaEmptyContextMatchesOracle()
    {
        //A session key for an unbound/unsalted session derives over an empty context on one side; KDFa must
        //handle a zero-length context field identically to the oracle.
        await AssertOracleMatchAsync("SHA256", "XOR", ContextU, [], 32).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task DistinctLabelsProduceDistinctOutput()
    {
        using IMemoryOwner<byte> ath = await Kdfa.DeriveAsync(
            HashAlgorithmName.SHA256, Key, "ATH", ContextU, ContextV, 256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> cfb = await Kdfa.DeriveAsync(
            HashAlgorithmName.SHA256, Key, "CFB", ContextU, ContextV, 256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(ath.Memory.Span[..32].SequenceEqual(cfb.Memory.Span[..32]), "Different labels must yield different keying material.");
    }

    [TestMethod]
    public async Task EmptyLabelIsRejected()
    {
        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await Kdfa.DeriveAsync(HashAlgorithmName.SHA256, Key, string.Empty, ContextU, ContextV, 256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task NonPositiveOutputIsRejected()
    {
        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(async () =>
            await Kdfa.DeriveAsync(HashAlgorithmName.SHA256, Key, "ATH", ContextU, ContextV, 0, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task NonOctetOutputIsRejected()
    {
        //KDFa performs no sub-octet masking and every TPM use is octet-aligned, so a non-multiple-of-8 bit
        //length is rejected rather than silently masked.
        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(async () =>
            await Kdfa.DeriveAsync(HashAlgorithmName.SHA256, Key, "ATH", ContextU, ContextV, 100, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    private async Task AssertOracleMatchAsync(string algName, string label, byte[] contextU, byte[] contextV, int outputBytes)
    {
        HashAlgorithmName algorithm = Hash(algName);
        byte[] expected = SP800108HmacCounterKdf.DeriveBytes(
            Key, algorithm, Encoding.ASCII.GetBytes(label), Concat(contextU, contextV), outputBytes);

        using IMemoryOwner<byte> actual = await Kdfa.DeriveAsync(
            algorithm, Key, label, contextU, contextV, outputBytes * 8, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(actual.Memory.Span[..outputBytes].SequenceEqual(expected),
            $"KDFa({algName}, '{label}', {outputBytes} bytes) must match the SP800-108 oracle.");
    }

    private static HashAlgorithmName Hash(string algName) => algName switch
    {
        "SHA1" => HashAlgorithmName.SHA1,
        "SHA256" => HashAlgorithmName.SHA256,
        "SHA384" => HashAlgorithmName.SHA384,
        "SHA512" => HashAlgorithmName.SHA512,
        _ => throw new ArgumentException($"Unmapped hash algorithm '{algName}'.", nameof(algName))
    };

    private static byte[] Concat(byte[] first, byte[] second)
    {
        byte[] result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);

        return result;
    }
}
