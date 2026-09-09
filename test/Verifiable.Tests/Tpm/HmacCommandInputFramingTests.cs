using System;
using System.Buffers;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of the HMAC key family's command inputs against their published tables —
/// <c>TPM2_HMAC_Start()</c> (TPM 2.0 Library Part 3, Table 80) and <c>TPM2_HMAC()</c> (Table 71) — plus the
/// response codecs' parse of Tables 81 and 72, and the commands' <c>TPMA_CC</c> rows.
/// </summary>
[TestClass]
internal sealed class HmacCommandInputFramingTests
{
    /// <summary>
    /// Table 80: <c>@handle</c> (the HMAC key) then parameters <c>auth</c> (TPM2B_AUTH) and <c>hashAlg</c>
    /// (TPMI_ALG_HASH+); the raw command code is 0x0000015B (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.2.2, Table 80</see>.
    /// </summary>
    [TestMethod]
    public void HmacStartInputCreateFramesTheHandleAndParametersByteExactlyPerTable80()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var handle = TpmiDhObject.FromValue(0x80000001u);
        byte[] sequenceAuth = [0xA1, 0xA2, 0xA3];

        using HmacStartInput input = HmacStartInput.Create(handle, sequenceAuth, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA384), pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_HMAC_Start, input.CommandCode);
        Assert.AreEqual(0x0000015Bu, (uint)input.CommandCode, "TPM_CC_HMAC_Start must equal Table 12's raw value 0x0000015B.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "auth is the first TPM2B parameter, so it must be marked encryptable.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x01];
        byte[] expectedParameters =
        [
            0x00, 0x03, 0xA1, 0xA2, 0xA3, //auth: TPM2B_AUTH, size 3.
            0x00, 0x0C //hashAlg: TPM_ALG_SHA384.
        ];

        AssertFraming(pool, input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// Table 80: a UTF-8 password frames as <c>auth</c>'s TPM2B_AUTH body exactly, so a password-derived
    /// sequence auth still frames byte-exactly against the same table.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.2.2, Table 80</see>.
    /// </summary>
    [TestMethod]
    public void HmacStartInputCreateFromPasswordFramesByteExactlyPerTable80()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var handle = TpmiDhObject.FromValue(0x80000002u);
        const string SequencePassword = "hm";

        using HmacStartInput input = HmacStartInput.CreateFromPassword(handle, SequencePassword, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);

        byte[] expectedParameters =
        [
            0x00, 0x02, (byte)'h', (byte)'m', //auth: TPM2B_AUTH, the UTF-8 password.
            0x00, 0x0B //hashAlg: TPM_ALG_SHA256.
        ];

        AssertFraming(pool, input, [0x80, 0x00, 0x00, 0x02], expectedParameters);
    }

    /// <summary>
    /// Table 71: <c>@handle</c> (the HMAC key) then parameters <c>buffer</c> (TPM2B_MAX_BUFFER) and
    /// <c>hashAlg</c> (TPMI_ALG_HASH+); the raw command code is 0x00000155 (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.5.2, Table 71</see>.
    /// </summary>
    [TestMethod]
    public void HmacInputCreateFramesTheHandleAndParametersByteExactlyPerTable71()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var handle = TpmiDhObject.FromValue(0x80000003u);
        byte[] buffer = [0xD1, 0xD2, 0xD3, 0xD4, 0xD5];

        using HmacInput input = HmacInput.Create(handle, buffer, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_HMAC, input.CommandCode);
        Assert.AreEqual(0x00000155u, (uint)input.CommandCode, "TPM_CC_HMAC must equal Table 12's raw value 0x00000155.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "buffer is the first TPM2B parameter, so it must be marked encryptable.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x03];
        byte[] expectedParameters =
        [
            0x00, 0x05, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, //buffer: TPM2B_MAX_BUFFER, size 5.
            0x00, 0x0B //hashAlg: TPM_ALG_SHA256.
        ];

        AssertFraming(pool, input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// Table 71: an empty <c>buffer</c> ("HMAC data") frames as the empty TPM2B.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.5.2, Table 71</see>.
    /// </summary>
    [TestMethod]
    public void HmacInputCreateWithAnEmptyBufferFramesByteExactlyPerTable71()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var handle = TpmiDhObject.FromValue(0x80000004u);

        using HmacInput input = HmacInput.Create(handle, [], TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA1), pool);

        byte[] expectedParameters =
        [
            0x00, 0x00, //buffer: empty TPM2B_MAX_BUFFER.
            0x00, 0x04 //hashAlg: TPM_ALG_SHA1.
        ];

        AssertFraming(pool, input, [0x80, 0x00, 0x00, 0x04], expectedParameters);
    }

    /// <summary>
    /// Part 2, Table 96: <c>TPM2B_MAX_BUFFER</c> is bounded by <c>MAX_2B_BUFFER_SIZE</c> — <c>HmacInput</c>
    /// refuses a larger buffer at construction, before any rent, mirroring <c>HashInput</c> and
    /// <c>SequenceCompleteInput</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.3.8, Table 96</see>.
    /// </summary>
    [TestMethod]
    public void HmacInputOverMaxSizeThrowsArgumentException()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int OversizedLength = Tpm2bMaxBuffer.MaxSize + 1;
        using IMemoryOwner<byte> oversizedOwner = pool.Rent(OversizedLength);

        _ = Assert.ThrowsExactly<ArgumentException>(() => HmacInput.Create(
            TpmiDhObject.FromValue(0x80000000u), oversizedOwner.Memory.Span[..OversizedLength], TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), pool));
    }

    /// <summary>
    /// Table 81: the response handle area alone carries <c>sequenceHandle</c>; there are no response
    /// parameters, so the codec's parse consumes nothing from the reader.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.2.2, Table 81</see>.
    /// </summary>
    [TestMethod]
    public void HmacStartResponseParsesTheSequenceHandleAloneFromTable81()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var sequenceHandle = TpmiDhObject.FromValue(0x80000005u);
        var reader = new TpmReader([]);

        HmacStartResponse response = HmacStartResponse.Parse(ref reader, sequenceHandle, pool);

        Assert.AreEqual(sequenceHandle, response.SequenceHandle);
        Assert.AreEqual(0, reader.Remaining, "Table 81 has no response parameters, so the parse must consume nothing.");
    }

    /// <summary>
    /// Table 72: the sole response parameter is <c>outHMAC</c> (TPM2B_DIGEST).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.5.2, Table 72</see>.
    /// </summary>
    [TestMethod]
    public void HmacResponseParsesTheOutHmacDigestFromTable72()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] frame = [0x00, 0x02, 0xEE, 0xFF]; //outHMAC: TPM2B_DIGEST, size 2.
        var reader = new TpmReader(frame);

        using HmacResponse response = HmacResponse.Parse(ref reader, pool);

        Assert.IsTrue(response.OutHmac.AsReadOnlySpan().SequenceEqual(new byte[] { 0xEE, 0xFF }), "outHMAC must parse as Table 72's TPM2B_DIGEST octets.");
        Assert.AreEqual(0, reader.Remaining, "The parse must consume the whole frame.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> rows (Part 2, clause 8.9): both commands take one handle requiring USER auth;
    /// <c>TPM2_HMAC_Start</c> returns one (<c>rHandle</c>) and is not <c>{F}</c>; <c>TPM2_HMAC</c> returns none.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, Tables 71, 80</see>.
    /// </summary>
    [TestMethod]
    public void HmacFamilyCommandAttributesCarryTheirHandleCountAndResponseHandleBit()
    {
        TpmaCc start = TpmCcConstants.TPM_CC_HMAC_Start.GetCommandAttributes();
        Assert.AreEqual((byte)1, start.C_HANDLES);
        Assert.IsTrue(start.R_HANDLE, "TPM2_HMAC_Start returns sequenceHandle in the response handle area.");
        Assert.IsFalse(start.FLUSHED);
        Assert.IsFalse(start.NV);
        Assert.IsFalse(start.EXTENSIVE);

        TpmaCc hmac = TpmCcConstants.TPM_CC_HMAC.GetCommandAttributes();
        Assert.AreEqual((byte)1, hmac.C_HANDLES);
        Assert.IsFalse(hmac.R_HANDLE);
        Assert.IsFalse(hmac.FLUSHED);
        Assert.IsFalse(hmac.NV);
        Assert.IsFalse(hmac.EXTENSIVE);
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle and parameter areas into freshly-rented buffers and asserts each
    /// reproduces the hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for precisely the two areas combined.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(BaseMemoryPool pool, ITpmCommandInput input, byte[] expectedHandles, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(),
            "GetSerializedSize must account for exactly the handle area plus the parameter area.");

        using IMemoryOwner<byte> handlesOwner = pool.Rent(expectedHandles.Length);
        Span<byte> handles = handlesOwner.Memory.Span[..expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the handle area.");
        Assert.IsTrue(handles.SequenceEqual(expectedHandles), "The handle area must reproduce the hand-computed octets exactly.");

        using IMemoryOwner<byte> parametersOwner = pool.Rent(expectedParameters.Length);
        Span<byte> parameters = parametersOwner.Memory.Span[..expectedParameters.Length];
        var paramWriter = new TpmWriter(parameters);
        input.WriteParameters(ref paramWriter);
        Assert.AreEqual(parameters.Length, paramWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.IsTrue(parameters.SequenceEqual(expectedParameters), "The parameter area must reproduce the hand-computed octets exactly.");
    }
}
