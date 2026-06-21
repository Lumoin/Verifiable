using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Known-answer tests for <see cref="Kdfe"/> (the TPM 2.0 KDFe, Part 1 §9.4.10.3).
/// </summary>
/// <remarks>
/// <para>
/// KDFe is the digest-based one-pass KDF with the inner hash
/// <c>H([i]_32 || Z || label || 0x00 || partyUInfo || partyVInfo)</c>, counter starting at 1, fields
/// concatenated as raw octets with no length prefix and no trailing length field. The expected values below were
/// produced offline by an independent implementation of that construction and are pinned here as known-answer
/// vectors, matching the convention used by <c>HmacFunctionsTests</c> (hardcoded vectors compared against the
/// library's own crypto). The system under test, <see cref="Kdfe.DeriveAsync"/>, routes through the project's
/// registered digest primitive; the test itself performs no cryptography. The vectors pin the byte layout: the
/// raw (length-prefix-free) field order, the single <c>0x00</c> label terminator (the KDFe landmine - the
/// reference TPM does not add a NUL but its labels are NUL-terminated), the big-endian counter, and the absence
/// of the trailing <c>bits</c> field that KDFa has.
/// </para>
/// <para>
/// The complementary end-to-end check is a salted-session HMAC against a real (hardware or software) TPM, whose
/// verification only succeeds if KDFe is byte-exact against the TPM.
/// </para>
/// </remarks>
[TestClass]
internal sealed class KdfeTests
{
    public TestContext TestContext { get; set; } = null!;

    private static byte[] Z { get; } = BuildPattern(32, 0xC0);

    private static byte[] PartyU { get; } = BuildPattern(32, 0xA0);

    private static byte[] PartyV { get; } = BuildPattern(32, 0x10);

    [TestMethod]
    //Independent (offline) known answers over Z = 0xC0..0xDF, partyU = 0xA0..0xBF, partyV = 0x10..0x2F.
    [DataRow("SHA1", "SECRET", 20, "16a97cb36488d835ec3355d2e5f8aee49cbe0224")]
    [DataRow("SHA256", "SECRET", 32, "608832aa64c43bfe7dde952f4745961184ffbe314fcb1fb1db86087d3a1c9a83")]
    [DataRow("SHA256", "SECRET", 48, "608832aa64c43bfe7dde952f4745961184ffbe314fcb1fb1db86087d3a1c9a831fbbffc5f304e66283201f93d669a3f6")]
    [DataRow("SHA256", "SECRET", 64, "608832aa64c43bfe7dde952f4745961184ffbe314fcb1fb1db86087d3a1c9a831fbbffc5f304e66283201f93d669a3f6255bf43d0a698401bebaec27d017cbe6")]
    [DataRow("SHA256", "DUPLICATE", 32, "b1bbbfb7be946709586ffb321748451af4d5245bd43a9c5f7fa5dd5ed1ff0d1d")]
    [DataRow("SHA384", "SECRET", 48, "1af38b47348cf33d42782291a2569d7da957e5a3640a01b3a250e04215c35c58b7353bc879898d5174af8daca07ddeae")]
    [DataRow("SHA512", "SECRET", 64, "0b45599ce0be0ad164e2dc659d1a8ee463b9de880e7bb246b642edd67dfb53ffb4918fe59743e0709f53fdbc19ca31129251537b2f46339a0fe096f2bcc9243e")]
    public async Task KdfeMatchesKnownAnswer(string algName, string label, int outputBytes, string expectedHex)
    {
        using IMemoryOwner<byte> actual = await Kdfe.DeriveAsync(
            WellKnownHashAlgorithms.ToHashAlgorithmName(algName), Z, label, PartyU, PartyV, outputBytes * 8, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedHex, Convert.ToHexStringLower(actual.Memory.Span[..outputBytes]),
            $"KDFe({algName}, '{label}', {outputBytes} bytes) must match the known-answer vector.");
    }

    [TestMethod]
    public async Task KdfeEmptyPartyInfoMatchesKnownAnswer()
    {
        //Empty party-info fields contribute nothing (no length prefix), so the input reduces to counter||Z||label||0x00.
        const string ExpectedHex = "e5889645e653ec6b1704dec4abd8073ba58f1f14a7d48584f4b870bcba9f7f90";

        using IMemoryOwner<byte> actual = await Kdfe.DeriveAsync(
            HashAlgorithmName.SHA256, Z, "SECRET", ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, 256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ExpectedHex, Convert.ToHexStringLower(actual.Memory.Span[..32]));
    }

    [TestMethod]
    public async Task DistinctLabelsProduceDistinctOutput()
    {
        using IMemoryOwner<byte> secret = await Kdfe.DeriveAsync(
            HashAlgorithmName.SHA256, Z, "SECRET", PartyU, PartyV, 256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> duplicate = await Kdfe.DeriveAsync(
            HashAlgorithmName.SHA256, Z, "DUPLICATE", PartyU, PartyV, 256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(secret.Memory.Span[..32].SequenceEqual(duplicate.Memory.Span[..32]), "Different labels must yield different keying material.");
    }

    [TestMethod]
    public async Task SwappedPartyInfoProducesDifferentOutput()
    {
        //PartyUInfo (ephemeral) and PartyVInfo (static TPM key) ordering is load-bearing; swapping must change output.
        using IMemoryOwner<byte> forward = await Kdfe.DeriveAsync(
            HashAlgorithmName.SHA256, Z, "SECRET", PartyU, PartyV, 256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> swapped = await Kdfe.DeriveAsync(
            HashAlgorithmName.SHA256, Z, "SECRET", PartyV, PartyU, 256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(forward.Memory.Span[..32].SequenceEqual(swapped.Memory.Span[..32]), "Swapping partyU and partyV must change the output.");
    }

    [TestMethod]
    public async Task EmptyLabelIsRejected()
    {
        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await Kdfe.DeriveAsync(HashAlgorithmName.SHA256, Z, string.Empty, PartyU, PartyV, 256, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task NonPositiveOutputIsRejected()
    {
        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(async () =>
            await Kdfe.DeriveAsync(HashAlgorithmName.SHA256, Z, "SECRET", PartyU, PartyV, 0, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task NonOctetOutputIsRejected()
    {
        await Assert.ThrowsExactlyAsync<ArgumentOutOfRangeException>(async () =>
            await Kdfe.DeriveAsync(HashAlgorithmName.SHA256, Z, "SECRET", PartyU, PartyV, 100, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    private static byte[] BuildPattern(int length, int seed)
    {
        byte[] result = new byte[length];
        for(int i = 0; i < length; i++)
        {
            result[i] = (byte)(seed + i);
        }

        return result;
    }
}
