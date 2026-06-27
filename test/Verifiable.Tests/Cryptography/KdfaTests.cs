using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Known-answer tests for <see cref="Kdfa"/> (the TPM 2.0 KDFa, Part 1 §11.4.10.2).
/// </summary>
/// <remarks>
/// <para>
/// KDFa is the SP800-108 counter-mode HMAC KDF with the fixed input
/// <c>[i]_32 || label || 0x00 || contextU || contextV || [bits]_32</c>, counter starting at 1. The expected
/// values below were produced offline by an independent implementation of that construction and are pinned here
/// as known-answer vectors, matching the convention used by <c>HmacFunctionsTests</c> (hardcoded vectors
/// compared against the library's own crypto). The system under test, <see cref="Kdfa.DeriveAsync"/>, routes
/// through the project's registered HMAC primitive; the test itself performs no cryptography. The vectors pin the
/// counter loop and truncation as well as the byte layout: the label terminator, field order, and the big-endian
/// counter and length.
/// </para>
/// <para>
/// The complementary end-to-end check is the hardware/software-TPM bound-session HMAC, whose verification only
/// succeeds if KDFa is byte-exact against the TPM.
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
    //Independent (offline) known answers over Key = 0x10..0x1F, contextU = 0xA0..0xA7, contextV = 0xB0..0xB3.
    [DataRow("SHA1", "ATH", 20, "75a02df7aa2336f3b201e95daa2fa5d06cf00c5d")]    //Single block.
    [DataRow("SHA1", "ATH", 50, "dbdfc047b23a411d13203d50bea88ccbf7cb1da53384cf94de26567c1ebffe3e76779176240679dea1e52139cb15e855ff1c")] //Three blocks, truncated.
    [DataRow("SHA256", "ATH", 32, "8a0d642226f6315499f0a0355272347b95c17d31bc03355ec8f63a807018b31c")] //Single block.
    [DataRow("SHA256", "ATH", 48, "0bc530050b65ab3ffc00c42239c8900c4f1295be858952c4df1079d271b9bda938b45c376f2c8aca16bb75580e3b76c6")] //Two blocks, truncated.
    [DataRow("SHA256", "ATH", 64, "2e2272ba79ee7510f0113371c5c3d5c6d0906ceb91afcb16d36d3dc12383e9245bb25caa9462fb59823a3a555f24f2e4875766c38273ea94dabfabe303889639")] //Two full blocks.
    [DataRow("SHA256", "CFB", 44, "66aff1b8d8bce50e7ce513c17a1f158dc2a06d8629906472d5ba48aee2b6df2337253b8264c798af1ab504eb")] //Non-digest-multiple length.
    [DataRow("SHA384", "ATH", 48, "cacbe82f3fc4dbbe58538b9f52f81f572978f71ad3e870d177517141d8d705d37a33471ca2a56426596ec14c004b4dc5")] //Single block.
    [DataRow("SHA384", "ATH", 96, "4abaa6fd3ce96d32ba9f4713d188b237ad45a580994f423452e9496ce2424f74f9736f46c8a30a3e2f6e249ab93759c5ef35bb7a353d5886a7bba3242988e1953c936e0f7952d8e37b837bdb124d8f10ff6067e4d4090be7e231472ca02a7b47")] //Two full blocks.
    [DataRow("SHA512", "ATH", 64, "c2472d0b36cf06d3c4cc81b59f32d7f8e6636975de4e96f807a287ada57b5b9942aa4939ce4c4a3fe6f09bf08113c48f89aedada7cc928db8c46a5ab641afbee")] //Single block.
    [DataRow("SHA512", "ATH", 100, "4658ba7460608899402c7c92b1621843550e3565f73d79c66d66ff4de801592bbe675edb471668112c9b37bcc9da9abd2de9804841bb7a6a77069ffdf427ec1b77132b8b1ba8829f558ebf785159e09a94a789d6b2708bd3a8a5bff23a1c73b7c149c9de")] //Two blocks, truncated.
    public async Task KdfaMatchesKnownAnswer(string algName, string label, int outputBytes, string expectedHex)
    {
        using IMemoryOwner<byte> actual = await Kdfa.DeriveAsync(
            WellKnownHashAlgorithms.ToHashAlgorithmName(algName), Key, label, ContextU, ContextV, outputBytes * 8, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedHex, Convert.ToHexStringLower(actual.Memory.Span[..outputBytes]),
            $"KDFa({algName}, '{label}', {outputBytes} bytes) must match the known-answer vector.");
    }

    [TestMethod]
    public async Task KdfaEmptyContextMatchesKnownAnswer()
    {
        //A session key for an unbound/unsalted session derives over an empty context on one side; KDFa must
        //handle a zero-length context field (no length prefix) identically to the vector.
        const string ExpectedHex = "298190f8135a5580667c4eb1db3d5b629a64f149c561a3a5c2cb366df697f737";

        using IMemoryOwner<byte> actual = await Kdfa.DeriveAsync(
            HashAlgorithmName.SHA256, Key, "XOR", ContextU, ReadOnlyMemory<byte>.Empty, 256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ExpectedHex, Convert.ToHexStringLower(actual.Memory.Span[..32]));
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
}
