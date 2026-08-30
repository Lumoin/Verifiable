using System;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves <see cref="VerifySignatureInput"/> frames <c>TPM2_VerifySignature()</c> byte-exactly per its command
/// table — the one handle, then <c>digest</c> as a <c>TPM2B_DIGEST</c> and <c>signature</c> as a
/// <c>TPMT_SIGNATURE</c> whose <c>sigAlg</c> selects the union member — for each member this host frames, and
/// that the two member guards refuse a mis-sized member before anything reaches the wire
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3: Commands, clause 20.2.2, Table 116; Part 2: Structures, clause 11.3.6, Table 219).
/// </summary>
[TestClass]
internal sealed class VerifySignatureInputFramingTests
{
    /// <summary>A transient handle for the verifying key; its octets are the whole handle area.</summary>
    private static uint KeyHandle => 0x80000001u;

    /// <summary>The handle area Table 116 frames: <c>keyHandle</c> big-endian.</summary>
    private static ReadOnlySpan<byte> KeyHandleOctets => [0x80, 0x00, 0x00, 0x01];

    /// <summary>A four-octet digest fixture — any length the <c>TPM2B_DIGEST</c> admits frames the same way.</summary>
    private static ReadOnlySpan<byte> DigestOctets => [0xD0, 0xD1, 0xD2, 0xD3];

    /// <summary>A 32-octet HMAC-SHA-256-width member fixture, arbitrary octets.</summary>
    private static ReadOnlySpan<byte> Sha256WidthMember =>
    [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    ];

    /// <summary>
    /// The HMAC member is a <c>TPMT_HA</c>: after <c>sigAlg</c> (<c>TPM_ALG_HMAC</c>, 0x0005) and <c>hashAlg</c>
    /// (<c>TPM_ALG_SHA256</c>, 0x000B) the digest follows UNSIZED — its width is the hash's, with no TPM2B
    /// length prefix (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 3: Commands, clause 20.2.2, Table 116; Part 2: Structures, clause 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public void VerifySignatureInputFramesTheHmacMemberByteExactlyPerTable116()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using VerifySignatureInput input = VerifySignatureInput.Create(
            TpmiDhObject.FromValue(KeyHandle), DigestOctets, Sha256WidthMember, TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_VerifySignature, input.CommandCode);
        Assert.AreEqual(0x00000177u, (uint)input.CommandCode, "TPM_CC_VerifySignature must equal Table 12's raw value 0x00000177.");

        using IMemoryOwner<byte> expectedOwner = pool.Rent(2 + DigestOctets.Length + 2 + 2 + Sha256WidthMember.Length);
        Span<byte> expected = expectedOwner.Memory.Span[..(2 + DigestOctets.Length + 2 + 2 + Sha256WidthMember.Length)];
        var expectedWriter = new TpmWriter(expected);
        expectedWriter.WriteTpm2b(DigestOctets);
        expectedWriter.WriteUInt16(0x0005);
        expectedWriter.WriteUInt16(0x000B);
        expectedWriter.WriteBytes(Sha256WidthMember);

        AssertFraming(input, KeyHandleOctets, expected, pool);
    }

    /// <summary>
    /// The ECDSA member is a <c>TPMS_SIGNATURE_ECDSA</c>: after <c>sigAlg</c> (<c>TPM_ALG_ECDSA</c>, 0x0018) and
    /// <c>hashAlg</c>, the IEEE P1363 <c>r ‖ s</c> the caller supplied splits into two equal-width
    /// <c>TPM2B_ECC_PARAMETER</c>s, each with its own size prefix
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.2.2, Table 116; Part 2: Structures, clause 11.3.2, Table 214).
    /// </summary>
    [TestMethod]
    public void VerifySignatureInputFramesTheEcdsaPairByteExactlyPerTable116()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using VerifySignatureInput input = VerifySignatureInput.ForEcdsa(
            TpmiDhObject.FromValue(KeyHandle), DigestOctets, [0xA1, 0xA2, 0xB1, 0xB2], TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        AssertFraming(
            input, KeyHandleOctets,
            [0x00, 0x04, 0xD0, 0xD1, 0xD2, 0xD3, 0x00, 0x18, 0x00, 0x0B, 0x00, 0x02, 0xA1, 0xA2, 0x00, 0x02, 0xB1, 0xB2], pool);
    }

    /// <summary>
    /// An RSA member is a <c>TPMS_SIGNATURE_RSA</c>: after <c>sigAlg</c> (<c>TPM_ALG_RSASSA</c>, 0x0014) and
    /// <c>hashAlg</c>, the whole signature rides as one <c>TPM2B_PUBLIC_KEY_RSA</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.2.2, Table 116; Part 2: Structures, clause 11.3.1, Table 212).
    /// </summary>
    [TestMethod]
    public void VerifySignatureInputFramesTheRsaMemberByteExactlyPerTable116()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using VerifySignatureInput input = VerifySignatureInput.ForRsaSsa(
            TpmiDhObject.FromValue(KeyHandle), DigestOctets, [0xC1, 0xC2, 0xC3], TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        AssertFraming(
            input, KeyHandleOctets,
            [0x00, 0x04, 0xD0, 0xD1, 0xD2, 0xD3, 0x00, 0x14, 0x00, 0x0B, 0x00, 0x03, 0xC1, 0xC2, 0xC3], pool);
    }

    /// <summary>
    /// An IEEE P1363 pair of odd length has no equal-width halves, so the framer refuses it before anything
    /// reaches the wire (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
    /// Library Specification</see>, Part 2: Structures, clause 11.3.2, Table 214).
    /// </summary>
    [TestMethod]
    public void VerifySignatureInputRefusesAnOddLengthEcdsaPair()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using VerifySignatureInput input = VerifySignatureInput.ForEcdsa(
            TpmiDhObject.FromValue(KeyHandle), DigestOctets, [0xA1, 0xA2, 0xB1], TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        using IMemoryOwner<byte> scratch = pool.Rent(input.GetSerializedSize());

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => Frame(input, scratch.Memory.Span));
    }

    /// <summary>
    /// The HMAC member's digest is unsized, so a digest of any width but the hash's would desynchronize every
    /// parameter after it on the wire; the framer refuses it before anything reaches the wire, the posture its
    /// ECDSA arm takes for an odd-length pair (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
    /// 2.0 Library Specification</see>, Part 2: Structures, clause 10.2.2, Table 89).
    /// </summary>
    [TestMethod]
    public void VerifySignatureInputRefusesAnHmacMemberWhoseWidthIsNotTheHashes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using VerifySignatureInput input = VerifySignatureInput.Create(
            TpmiDhObject.FromValue(KeyHandle), DigestOctets, Sha256WidthMember[..31], TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        using IMemoryOwner<byte> scratch = pool.Rent(input.GetSerializedSize());

        _ = Assert.ThrowsExactly<InvalidOperationException>(() => Frame(input, scratch.Memory.Span));
    }

    /// <summary>Frames <paramref name="input"/>'s parameters into <paramref name="destination"/> — a static local so the <c>ref struct</c> writer never crosses a lambda.</summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="destination">The scratch the parameters are written into.</param>
    private static void Frame(VerifySignatureInput input, Span<byte> destination)
    {
        var writer = new TpmWriter(destination);
        input.WriteParameters(ref writer);
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle and parameter areas into pooled buffers sized exactly to the
    /// hand-computed expectations and asserts each reproduces those octets, and that
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for precisely the two areas combined.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    /// <param name="pool">The memory pool the framing buffers are rented from.</param>
    private static void AssertFraming(VerifySignatureInput input, ReadOnlySpan<byte> expectedHandles, ReadOnlySpan<byte> expectedParameters, BaseMemoryPool pool)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(),
            "GetSerializedSize must account for exactly the handle area plus the parameter area.");

        using IMemoryOwner<byte> handlesOwner = pool.Rent(expectedHandles.Length);
        Span<byte> handles = handlesOwner.Memory.Span[..expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the handle area.");
        Assert.IsTrue(expectedHandles.SequenceEqual(handles), "The handle area must frame byte-exactly per Table 116.");

        using IMemoryOwner<byte> parametersOwner = pool.Rent(expectedParameters.Length);
        Span<byte> parameters = parametersOwner.Memory.Span[..expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.IsTrue(expectedParameters.SequenceEqual(parameters), "The parameter area must frame byte-exactly per Table 116.");
    }
}
