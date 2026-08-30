using System;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_NV_SetBits()</c>'s input against TPM 2.0 Library Part 3, Section 31.10 (Table
/// 259), plus the response codec's parse of Table 260 and the command's <c>TPMA_CC</c> row.
/// </summary>
[TestClass]
internal sealed class NvSetBitsInputFramingTests
{
    /// <summary>The authHandle/nvIndex value used for the Index-authorization arm across these tests.</summary>
    private static uint IndexHandle => 0x01000060u;

    /// <summary>
    /// The <c>bits</c> value used for the byte-exact framing case: its eight octets are all distinct and
    /// ascending, so a big-endian framing is distinguishable from a little-endian one.
    /// </summary>
    private static ulong AscendingOctetBits => 0x0102_0304_0506_0708UL;

    /// <summary>The handle area of the Index-authorization arm: <c>@authHandle</c> and <c>nvIndex</c> both name <see cref="IndexHandle"/>.</summary>
    private static ReadOnlySpan<byte> IndexArmHandles => [0x01, 0x00, 0x00, 0x60, 0x01, 0x00, 0x00, 0x60];

    /// <summary>
    /// Table 259: <c>@authHandle</c> (TPMI_RH_NV_AUTH) and <c>nvIndex</c> (TPMI_RH_NV_INDEX) then <c>bits</c>
    /// (UINT64), "the data to OR with the current contents", framed big-endian as eight bare octets with no size
    /// prefix; the raw command code is 0x00000135 (Part 2, Table 12, and
    /// <see cref="TpmCcConstants.TPM_CC_NV_SetBits"/>). Part 1, clause 18.1 answers the encryption question for
    /// this command: "only the first parameter in the parameter area of a request or response can be encrypted.
    /// That parameter must have an explicit size field." <c>bits</c> is a plain UINT64 with no size field, so it
    /// is ineligible and <see cref="ITpmCommandInput.FirstCommandParameterIsEncryptable"/> stays
    /// <see langword="false"/>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, Section 31.10, Table 259; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void NvSetBitsInputFramesBothHandlesAndTheBitsByteExactlyPerTable259()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var input = new NvSetBitsInput(IndexHandle, IndexHandle, AscendingOctetBits);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_SetBits, input.CommandCode);
        Assert.AreEqual(0x00000135u, (uint)input.CommandCode, "TPM_CC_NV_SetBits must equal Table 12's raw value 0x00000135.");
        ITpmCommandInput asInput = input;
        Assert.IsFalse(asInput.FirstCommandParameterIsEncryptable, "bits is a UINT64 with no explicit size field, so Part 1 clause 18.1 makes it ineligible for parameter encryption.");

        //Parameter area: bits as a bare big-endian UINT64 — the eight octets of 0x0102030405060708 in order.
        AssertFraming(input, IndexArmHandles, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], pool);
    }

    /// <summary>
    /// The owner arm: <c>@authHandle</c> carries <c>TPM_RH_OWNER</c> (0x40000001) rather than the Index itself,
    /// while <c>nvIndex</c> still names the Bit Field Index whose bits are SET.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, Section 31.10, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void NvSetBitsInputFramesTheOwnerArmAuthHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var input = new NvSetBitsInput((uint)TpmRh.TPM_RH_OWNER, IndexHandle, AscendingOctetBits);

        //Handle area: @authHandle TPM_RH_OWNER, then nvIndex.
        AssertFraming(input, [0x40, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x60], [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], pool);
    }

    /// <summary>
    /// Clause 31.10.1: "Any number of bits from 0 to 64 may be SET", so a <c>bits</c> of zero is a legal command
    /// and frames as eight zero octets rather than as an omitted or shortened parameter.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, Section 31.10, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void NvSetBitsInputWithZeroBitsFramesEightZeroOctets()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var input = new NvSetBitsInput(IndexHandle, IndexHandle, 0UL);

        AssertFraming(input, IndexArmHandles, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], pool);
    }

    /// <summary>
    /// Clause 31.10.1's upper end of "from 0 to 64" bits: every bit SET frames as eight 0xFF octets, the widest
    /// value the UINT64 parameter carries.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, Section 31.10, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void NvSetBitsInputWithAllBitsSetFramesEightFullOctets()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        var input = new NvSetBitsInput(IndexHandle, IndexHandle, ulong.MaxValue);

        AssertFraming(input, IndexArmHandles, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], pool);
    }

    /// <summary>
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> must account for exactly the two 4-byte handles plus the
    /// eight octets of the UINT64 <c>bits</c>, a fixed sixteen octets for every value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, Section 31.10, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void NvSetBitsInputGetSerializedSizeAccountsForHandlesAndTheSixtyFourBitValue()
    {
        var input = new NvSetBitsInput(IndexHandle, IndexHandle, AscendingOctetBits);

        Assert.AreEqual(4 + 4 + 8, input.GetSerializedSize());
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_NV_SetBits</c> takes two handles, is
    /// <c>{NV}</c>, is not flushed, and returns no response handle; its COMMAND_INDEX is the low 16 bits of
    /// 0x00000135.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, Section 31.10, Table 259</see>.
    /// </summary>
    [TestMethod]
    public void NvSetBitsCommandAttributesCarryTwoHandlesAndTheNvBit()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_NV_SetBits.GetCommandAttributes();

        Assert.AreEqual((byte)2, attributes.C_HANDLES);
        Assert.IsTrue(attributes.NV, "TPM2_NV_SetBits is {NV}.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.IsFalse(attributes.R_HANDLE, "TPM2_NV_SetBits returns no response handle.");
        Assert.AreEqual((ushort)0x0135, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response is the 10-byte header alone (Table 260): the codec declares zero output handles, no parser,
    /// and <see cref="NvSetBitsResponse.Instance"/> as the value a header-only success response resolves to.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, Section 31.10, Table 260</see>.
    /// </summary>
    [TestMethod]
    public void NvSetBitsCodecResolvesAHeaderOnlySuccessResponseToItsOwnSingleton()
    {
        TpmResponseCodec codec = TpmResponseCodec.NvSetBits;

        Assert.AreEqual(0, codec.OutHandleCount, "A header-only response declares no output handles.");
        Assert.IsFalse(codec.HasResponseParameters, "A header-only response has no parser.");
        Assert.AreSame(NvSetBitsResponse.Instance, codec.EmptyResponse, "The codec must resolve to TPM2_NV_SetBits's own parameterless singleton.");
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
    private static void AssertFraming(NvSetBitsInput input, ReadOnlySpan<byte> expectedHandles, ReadOnlySpan<byte> expectedParameters, BaseMemoryPool pool)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(),
            "GetSerializedSize must account for exactly the handle area plus the parameter area.");

        using IMemoryOwner<byte> handlesOwner = pool.Rent(expectedHandles.Length);
        Span<byte> handles = handlesOwner.Memory.Span[..expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the handle area.");
        Assert.IsTrue(expectedHandles.SequenceEqual(handles), "The handle area must frame byte-exactly per Table 259.");

        using IMemoryOwner<byte> parametersOwner = pool.Rent(expectedParameters.Length);
        Span<byte> parameters = parametersOwner.Memory.Span[..expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.IsTrue(expectedParameters.SequenceEqual(parameters), "The parameter area must frame byte-exactly per Table 259.");
    }
}
