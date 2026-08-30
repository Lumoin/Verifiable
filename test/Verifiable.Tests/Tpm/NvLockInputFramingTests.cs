using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of the two NV lock commands' inputs against their published tables -
/// <c>TPM2_NV_WriteLock()</c> (TPM 2.0 Library Part 3, clause 31.11, Table 261) and <c>TPM2_NV_ReadLock()</c>
/// (clause 31.14, Table 267) - plus their raw <c>TPM_CC</c> pins, their <c>TPMA_CC</c> rows and their response
/// codecs' header-only parse (Tables 262 and 268). Both commands carry two handles and no parameters at all, so
/// the parameter area is empty on the wire.
/// </summary>
[TestClass]
internal sealed class NvLockInputFramingTests
{
    /// <summary>The <c>@authHandle</c>/<c>nvIndex</c> value used for <c>TPM2_NV_WriteLock()</c>'s Index-authorization arm.</summary>
    private static uint WriteLockIndexHandle => 0x01000070u;

    /// <summary>The <c>@authHandle</c>/<c>nvIndex</c> value used for <c>TPM2_NV_ReadLock()</c>'s Index-authorization arm.</summary>
    private static uint ReadLockIndexHandle => 0x01000080u;

    /// <summary>
    /// Table 261: <c>@authHandle</c> (TPMI_RH_NV_AUTH, "handle indicating the source of the authorization value
    /// for the NV Index", Auth Index 1, Auth Role USER) then <c>nvIndex</c> (TPMI_RH_NV_INDEX, "the NV Index of
    /// the area to lock", Auth Index None); the table lists no parameters, so <c>WriteParameters</c> writes
    /// nothing. Part 1, clause 18.1 makes only a sized TPM2B first parameter decrypt-eligible, so a command with
    /// no parameters at all marks none encryptable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.11, Table 261; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void NvWriteLockInputFramesBothHandlesAndAnEmptyParameterAreaByteExactlyPerTable261()
    {
        var input = new NvWriteLockInput(WriteLockIndexHandle, WriteLockIndexHandle);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_WriteLock, input.CommandCode);
        ITpmCommandInput asInput = input;
        Assert.IsFalse(asInput.FirstCommandParameterIsEncryptable, "TPM2_NV_WriteLock has no parameters, so none is encryptable.");

        //Handle area: @authHandle then nvIndex, both naming the Index itself.
        AssertFraming(input, [0x01, 0x00, 0x00, 0x70, 0x01, 0x00, 0x00, 0x70], []);
    }

    /// <summary>
    /// Table 267: <c>@authHandle</c> (TPMI_RH_NV_AUTH, "handle indicating the source of the authorization value
    /// for the NV Index", Auth Index 1, Auth Role USER) then <c>nvIndex</c> (TPMI_RH_NV_INDEX, "the NV Index to
    /// be locked", Auth Index None); the table lists no parameters, so <c>WriteParameters</c> writes nothing.
    /// Part 1, clause 18.1 makes only a sized TPM2B first parameter decrypt-eligible, so a command with no
    /// parameters at all marks none encryptable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.14, Table 267; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void NvReadLockInputFramesBothHandlesAndAnEmptyParameterAreaByteExactlyPerTable267()
    {
        var input = new NvReadLockInput(ReadLockIndexHandle, ReadLockIndexHandle);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_ReadLock, input.CommandCode);
        ITpmCommandInput asInput = input;
        Assert.IsFalse(asInput.FirstCommandParameterIsEncryptable, "TPM2_NV_ReadLock has no parameters, so none is encryptable.");

        //Handle area: @authHandle then nvIndex, both naming the Index itself.
        AssertFraming(input, [0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x80], []);
    }

    /// <summary>
    /// Table 261's <c>commandCode</c> row is <c>TPM_CC_NV_WriteLock {NV}</c>, whose assigned value in Part 2's
    /// listing of command codes is 0x00000138.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 31.11, Table 261</see>.
    /// </summary>
    [TestMethod]
    public void NvWriteLockCommandCodeEqualsTheRawValueListedInTable12()
    {
        var input = new NvWriteLockInput(WriteLockIndexHandle, WriteLockIndexHandle);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_WriteLock, input.CommandCode);
        Assert.AreEqual(0x00000138u, (uint)input.CommandCode, "TPM_CC_NV_WriteLock must equal Table 12's raw value 0x00000138.");
    }

    /// <summary>
    /// Table 267's <c>commandCode</c> row is <c>TPM_CC_NV_ReadLock {NV}</c>, whose assigned value in Part 2's
    /// listing of command codes is 0x0000014F.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 31.14, Table 267</see>.
    /// </summary>
    [TestMethod]
    public void NvReadLockCommandCodeEqualsTheRawValueListedInTable12()
    {
        var input = new NvReadLockInput(ReadLockIndexHandle, ReadLockIndexHandle);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_ReadLock, input.CommandCode);
        Assert.AreEqual(0x0000014Fu, (uint)input.CommandCode, "TPM_CC_NV_ReadLock must equal Table 12's raw value 0x0000014F.");
    }

    /// <summary>
    /// The owner arm: <c>@authHandle</c> is "the source of the authorization value for the NV Index" (Table 261),
    /// which for an Index carrying <c>TPMA_NV_OWNERWRITE</c> is <c>TPM_RH_OWNER</c> (0x40000001) rather than the
    /// Index itself, while <c>nvIndex</c> still names the Index being locked.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.11, Table 261</see>.
    /// </summary>
    [TestMethod]
    public void NvWriteLockInputFramesTheOwnerArmAuthHandle()
    {
        var input = new NvWriteLockInput((uint)TpmRh.TPM_RH_OWNER, WriteLockIndexHandle);

        //Handle area: @authHandle TPM_RH_OWNER, then nvIndex.
        AssertFraming(input, [0x40, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x70], []);
    }

    /// <summary>
    /// The owner arm: <c>@authHandle</c> is "the source of the authorization value for the NV Index" (Table 267),
    /// which for an Index carrying <c>TPMA_NV_OWNERREAD</c> is <c>TPM_RH_OWNER</c> (0x40000001) rather than the
    /// Index itself, while <c>nvIndex</c> still names the Index being locked.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.14, Table 267</see>.
    /// </summary>
    [TestMethod]
    public void NvReadLockInputFramesTheOwnerArmAuthHandle()
    {
        var input = new NvReadLockInput((uint)TpmRh.TPM_RH_OWNER, ReadLockIndexHandle);

        //Handle area: @authHandle TPM_RH_OWNER, then nvIndex.
        AssertFraming(input, [0x40, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x80], []);
    }

    /// <summary>
    /// Table 261 lists two handles and no parameters, so
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for exactly the two 4-octet handles.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.11, Table 261</see>.
    /// </summary>
    [TestMethod]
    public void NvWriteLockInputGetSerializedSizeAccountsForTheTwoHandlesAlone()
    {
        var input = new NvWriteLockInput(WriteLockIndexHandle, WriteLockIndexHandle);

        Assert.AreEqual(8, input.GetSerializedSize());
    }

    /// <summary>
    /// Table 267 lists two handles and no parameters, so
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for exactly the two 4-octet handles.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.14, Table 267</see>.
    /// </summary>
    [TestMethod]
    public void NvReadLockInputGetSerializedSizeAccountsForTheTwoHandlesAlone()
    {
        var input = new NvReadLockInput(ReadLockIndexHandle, ReadLockIndexHandle);

        Assert.AreEqual(8, input.GetSerializedSize());
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_NV_WriteLock</c> takes the two handles of
    /// Table 261, is <c>{NV}</c>, is not flushed, and returns no response handle; its COMMAND_INDEX is the low 16
    /// bits of 0x00000138.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 31.11, Table 261</see>.
    /// </summary>
    [TestMethod]
    public void NvWriteLockCommandAttributesCarryTwoHandlesAndTheNvBit()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_NV_WriteLock.GetCommandAttributes();

        Assert.AreEqual((byte)2, attributes.C_HANDLES);
        Assert.IsTrue(attributes.NV, "TPM2_NV_WriteLock is {NV}.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.IsFalse(attributes.R_HANDLE, "TPM2_NV_WriteLock returns no response handle.");
        Assert.AreEqual((ushort)0x0138, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_NV_ReadLock</c> takes the two handles of
    /// Table 267, is <c>{NV}</c>, is not flushed, and returns no response handle; its COMMAND_INDEX is the low 16
    /// bits of 0x0000014F.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 31.14, Table 267</see>.
    /// </summary>
    [TestMethod]
    public void NvReadLockCommandAttributesCarryTwoHandlesAndTheNvBit()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_NV_ReadLock.GetCommandAttributes();

        Assert.AreEqual((byte)2, attributes.C_HANDLES);
        Assert.IsTrue(attributes.NV, "TPM2_NV_ReadLock is {NV}.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.IsFalse(attributes.R_HANDLE, "TPM2_NV_ReadLock returns no response handle.");
        Assert.AreEqual((ushort)0x014F, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response is the 10-byte header alone (Table 262 lists <c>tag</c>, <c>responseSize</c> and
    /// <c>responseCode</c> only): the codec declares zero output handles, no parser, and
    /// <see cref="NvWriteLockResponse.Instance"/> as the value a header-only success response resolves to.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.11, Table 262</see>.
    /// </summary>
    [TestMethod]
    public void NvWriteLockCodecResolvesAHeaderOnlySuccessResponseToItsOwnSingleton()
    {
        TpmResponseCodec codec = TpmResponseCodec.NvWriteLock;

        Assert.AreEqual(0, codec.OutHandleCount, "A header-only response declares no output handles.");
        Assert.IsFalse(codec.HasResponseParameters, "A header-only response has no parser.");
        Assert.AreSame(NvWriteLockResponse.Instance, codec.EmptyResponse, "The codec must resolve to TPM2_NV_WriteLock's own parameterless singleton.");
    }

    /// <summary>
    /// The response is the 10-byte header alone (Table 268 lists <c>tag</c>, <c>responseSize</c> and
    /// <c>responseCode</c> only): the codec declares zero output handles, no parser, and
    /// <see cref="NvReadLockResponse.Instance"/> as the value a header-only success response resolves to.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.14, Table 268</see>.
    /// </summary>
    [TestMethod]
    public void NvReadLockCodecResolvesAHeaderOnlySuccessResponseToItsOwnSingleton()
    {
        TpmResponseCodec codec = TpmResponseCodec.NvReadLock;

        Assert.AreEqual(0, codec.OutHandleCount, "A header-only response declares no output handles.");
        Assert.IsFalse(codec.HasResponseParameters, "A header-only response has no parser.");
        Assert.AreSame(NvReadLockResponse.Instance, codec.EmptyResponse, "The codec must resolve to TPM2_NV_ReadLock's own parameterless singleton.");
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle and parameter areas into freshly-sized buffers and asserts each
    /// reproduces the hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for precisely the two areas combined. An empty <paramref name="expectedParameters"/> pins that
    /// <c>WriteParameters</c> writes nothing at all.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(ITpmCommandInput input, byte[] expectedHandles, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(),
            "GetSerializedSize must account for exactly the handle area plus the parameter area.");

        byte[] handles = new byte[expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the handle area.");
        Assert.AreSequenceEqual(expectedHandles, handles);

        byte[] parameters = new byte[expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.AreSequenceEqual(expectedParameters, parameters);
    }
}
