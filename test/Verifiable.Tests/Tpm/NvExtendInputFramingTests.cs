using System;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_NV_Extend()</c>'s input against TPM 2.0 Library Part 3, clause 31.9 (Table
/// 257), plus the response codec's parse of Table 258 and the command's <c>TPMA_CC</c> row.
/// </summary>
[TestClass]
internal sealed class NvExtendInputFramingTests
{
    /// <summary>The authHandle/nvIndex value used for the Index-authorization arm across these tests.</summary>
    private static uint IndexHandle => 0x01000045u;

    /// <summary>Five deterministic octets used as the <c>data</c> parameter for the byte-exact framing case.</summary>
    private static ReadOnlySpan<byte> FiveDeterministicOctets => [0xD0, 0xD1, 0xD2, 0xD3, 0xD4];

    /// <summary>The handle area of the Index-authorization arm: <c>@authHandle</c> and <c>nvIndex</c> both name <see cref="IndexHandle"/>.</summary>
    private static ReadOnlySpan<byte> IndexArmHandles => [0x01, 0x00, 0x00, 0x45, 0x01, 0x00, 0x00, 0x45];

    /// <summary>
    /// Table 257: <c>@authHandle</c> and <c>nvIndex</c> (both TPMI_RH_NV*) then <c>data</c> (TPM2B_MAX_NV_BUFFER);
    /// the raw command code is 0x00000136 (Part 2, Table 12, and <see cref="TpmCcConstants.TPM_CC_NV_Extend"/>).
    /// The NV family keeps parameter encryption on <c>data</c> closed on both the host and the simulator, so
    /// <see cref="ITpmCommandInput.FirstCommandParameterIsEncryptable"/> stays at its default
    /// <see langword="false"/> even though <c>data</c> is a sized TPM2B.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9, Table 257</see>.
    /// </summary>
    [TestMethod]
    public void NvExtendInputFramesBothHandlesAndTheDataByteExactlyPerTable257()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(FiveDeterministicOctets, pool);
        var input = new NvExtendInput(IndexHandle, IndexHandle, buffer);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_Extend, input.CommandCode);
        Assert.AreEqual(0x00000136u, (uint)input.CommandCode, "TPM_CC_NV_Extend must equal Table 12's raw value 0x00000136.");
        ITpmCommandInput asInput = input;
        Assert.IsFalse(asInput.FirstCommandParameterIsEncryptable, "The NV family keeps data parameter encryption closed on both sides, so data is not marked encryptable even though it is a TPM2B.");

        //Parameter area: data as TPM2B_MAX_NV_BUFFER — a UINT16 size of 5 then the five octets.
        AssertFraming(input, IndexArmHandles, [0x00, 0x05, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4], pool);
    }

    /// <summary>
    /// Clause 31.9.1's Note: <c>data.buffer</c> need not be the size of the Index, so an empty buffer frames as
    /// a bare size of zero and is a valid extend.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9, Table 257</see>.
    /// </summary>
    [TestMethod]
    public void NvExtendInputWithEmptyDataFramesTheBareSizePrefix()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create([], pool);
        var input = new NvExtendInput(IndexHandle, IndexHandle, buffer);

        AssertFraming(input, IndexArmHandles, [0x00, 0x00], pool);
    }

    /// <summary>
    /// The owner arm: <c>@authHandle</c> carries <c>TPM_RH_OWNER</c> (0x40000001) rather than the Index itself,
    /// while <c>nvIndex</c> still names the Index being extended.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9, Table 257</see>.
    /// </summary>
    [TestMethod]
    public void NvExtendInputFramesTheOwnerArmAuthHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create([0xA5], pool);
        var input = new NvExtendInput((uint)TpmRh.TPM_RH_OWNER, IndexHandle, buffer);

        //Handle area: @authHandle TPM_RH_OWNER, then nvIndex.
        AssertFraming(input, [0x40, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x45], [0x00, 0x01, 0xA5], pool);
    }

    /// <summary>
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> must account for exactly the two 4-byte handles plus the
    /// TPM2B_MAX_NV_BUFFER's 2-byte size prefix and payload.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9, Table 257</see>.
    /// </summary>
    [TestMethod]
    public void NvExtendInputGetSerializedSizeAccountsForHandlesAndTheSizedBuffer()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(FiveDeterministicOctets, pool);
        var input = new NvExtendInput(IndexHandle, IndexHandle, buffer);

        Assert.AreEqual(8 + 2 + FiveDeterministicOctets.Length, input.GetSerializedSize());
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_NV_Extend</c> takes two handles, is
    /// <c>{NV}</c>, is not flushed, and returns no response handle; its COMMAND_INDEX is the low 16 bits of
    /// 0x00000136.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 31.9, Table 257</see>.
    /// </summary>
    [TestMethod]
    public void NvExtendCommandAttributesCarryTwoHandlesAndTheNvBit()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_NV_Extend.GetCommandAttributes();

        Assert.AreEqual((byte)2, attributes.C_HANDLES);
        Assert.IsTrue(attributes.NV, "TPM2_NV_Extend is {NV}.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.IsFalse(attributes.R_HANDLE, "TPM2_NV_Extend returns no response handle.");
        Assert.AreEqual((ushort)0x0136, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response is the 10-byte header alone (Table 258): the codec declares zero output handles, no parser,
    /// and <see cref="NvExtendResponse.Instance"/> as the value a header-only success response resolves to.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9, Table 258</see>.
    /// </summary>
    [TestMethod]
    public void NvExtendCodecResolvesAHeaderOnlySuccessResponseToItsOwnSingleton()
    {
        TpmResponseCodec codec = TpmResponseCodec.NvExtend;

        Assert.AreEqual(0, codec.OutHandleCount, "A header-only response declares no output handles.");
        Assert.IsFalse(codec.HasResponseParameters, "A header-only response has no parser.");
        Assert.AreSame(NvExtendResponse.Instance, codec.EmptyResponse, "The codec must resolve to TPM2_NV_Extend's own parameterless singleton.");
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
    private static void AssertFraming(NvExtendInput input, ReadOnlySpan<byte> expectedHandles, ReadOnlySpan<byte> expectedParameters, BaseMemoryPool pool)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(),
            "GetSerializedSize must account for exactly the handle area plus the parameter area.");

        using IMemoryOwner<byte> handlesOwner = pool.Rent(expectedHandles.Length);
        Span<byte> handles = handlesOwner.Memory.Span[..expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the handle area.");
        Assert.IsTrue(expectedHandles.SequenceEqual(handles), "The handle area must frame byte-exactly per Table 257.");

        using IMemoryOwner<byte> parametersOwner = pool.Rent(expectedParameters.Length);
        Span<byte> parameters = parametersOwner.Memory.Span[..expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.IsTrue(expectedParameters.SequenceEqual(parameters), "The parameter area must frame byte-exactly per Table 257.");
    }
}
