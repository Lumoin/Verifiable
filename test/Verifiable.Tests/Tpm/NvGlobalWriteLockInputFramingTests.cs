using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_NV_GlobalWriteLock()</c>'s input against its published table (TPM 2.0 Library
/// Part 3, clause 31.12, Table 263), plus its raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row and its response
/// codec's header-only parse (Table 264). The command carries a single handle - <c>@authHandle</c>, a
/// <c>TPMI_RH_PROVISION</c> naming either the owner or the platform hierarchy - and no parameters at all, so the
/// parameter area is empty on the wire and the response is the header alone.
/// </summary>
[TestClass]
internal sealed class NvGlobalWriteLockInputFramingTests
{
    /// <summary>
    /// Table 263: a single handle <c>@authHandle</c> (<c>TPMI_RH_PROVISION</c>, "TPM_RH_OWNER or
    /// TPM_RH_PLATFORM+{PP}", Auth Index 1, Auth Role USER), and no parameters at all, so
    /// <c>WriteParameters</c> writes nothing. The owner selector is <c>TPM_RH_OWNER</c>, 0x40000001.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12, Table 263; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public void NvGlobalWriteLockInputFramesTheOwnerHandleAndAnEmptyParameterAreaByteExactlyPerTable263()
    {
        var input = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, input.CommandCode);

        //Handle area: @authHandle TPM_RH_OWNER alone; no parameter area follows it.
        AssertFraming(input, [0x40, 0x00, 0x00, 0x01], []);
    }

    /// <summary>
    /// The other selector Table 67 admits for <c>TPMI_RH_PROVISION</c>: <c>TPM_RH_PLATFORM</c>, 0x4000000C -
    /// "This command requires either platformAuth/platformPolicy or ownerAuth/ownerPolicy" (clause 31.12.1), so
    /// the platform handle frames into the same single-handle area with the same empty parameter area.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12, Table 263; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public void NvGlobalWriteLockInputFramesThePlatformHandleAndAnEmptyParameterAreaByteExactlyPerTable263()
    {
        var input = new NvGlobalWriteLockInput(TpmRh.TPM_RH_PLATFORM);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, input.CommandCode);

        //Handle area: @authHandle TPM_RH_PLATFORM alone; no parameter area follows it.
        AssertFraming(input, [0x40, 0x00, 0x00, 0x0C], []);
    }

    /// <summary>
    /// Table 263's <c>commandCode</c> row is <c>TPM_CC_NV_GlobalWriteLock {NV}</c>, whose assigned value in Part
    /// 2's listing of command codes is 0x00000132.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 31.12, Table 263</see>.
    /// </summary>
    [TestMethod]
    public void NvGlobalWriteLockCommandCodeEqualsTheRawValueListedInTable12()
    {
        var input = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, input.CommandCode);
        Assert.AreEqual(0x00000132u, (uint)input.CommandCode, "TPM_CC_NV_GlobalWriteLock must equal Table 12's raw value 0x00000132.");
    }

    /// <summary>
    /// Table 263 lists one handle and no parameters, so
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for exactly the one 4-octet handle.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12, Table 263</see>.
    /// </summary>
    [TestMethod]
    public void NvGlobalWriteLockInputGetSerializedSizeAccountsForTheSingleHandleAlone()
    {
        var input = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);

        Assert.AreEqual(4, input.GetSerializedSize());
    }

    /// <summary>
    /// "If session-based encryption is allowed, only the first parameter in the parameter area of a request or
    /// response can be encrypted. That parameter must have an explicit size field." (Part 1, clause 18.1) - Part 3's Table
    /// 263 lists no parameters at all, so nothing with a size field exists to be encryptable; and the single
    /// handle names a hierarchy rather than a hash or HMAC sequence object, so it is no sequence handle either.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 31.12, Table 263</see>.
    /// </summary>
    [TestMethod]
    public void NvGlobalWriteLockInputMarksNoParameterEncryptableAndItsHandleNoSequence()
    {
        ITpmCommandInput input = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);

        Assert.IsFalse(input.FirstCommandParameterIsEncryptable, "TPM2_NV_GlobalWriteLock has no parameters, so none is encryptable.");
        Assert.IsFalse(input.HandleIsSequence(0), "@authHandle names a hierarchy, never a sequence object.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_NV_GlobalWriteLock</c> takes the one handle
    /// of Table 263, is <c>{NV}</c>, is not flushed, and returns no response handle; its COMMAND_INDEX is the low
    /// 16 bits of 0x00000132.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 31.12, Table 263</see>.
    /// </summary>
    [TestMethod]
    public void NvGlobalWriteLockCommandAttributesCarryOneHandleAndTheNvBit()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_NV_GlobalWriteLock.GetCommandAttributes();

        Assert.AreEqual((byte)1, attributes.C_HANDLES);
        Assert.IsTrue(attributes.NV, "TPM2_NV_GlobalWriteLock is {NV}.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.IsFalse(attributes.R_HANDLE, "TPM2_NV_GlobalWriteLock returns no response handle.");
        Assert.AreEqual((ushort)0x0132, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response is the 10-byte header alone (Table 264 lists <c>tag</c>, <c>responseSize</c> and
    /// <c>responseCode</c> only): the codec declares zero output handles, no parser, and
    /// <see cref="NvGlobalWriteLockResponse.Instance"/> as the value a header-only success response resolves to.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.12, Table 264</see>.
    /// </summary>
    [TestMethod]
    public void NvGlobalWriteLockCodecResolvesAHeaderOnlySuccessResponseToItsOwnSingleton()
    {
        TpmResponseCodec codec = TpmResponseCodec.NvGlobalWriteLock;

        Assert.AreEqual(0, codec.OutHandleCount, "A header-only response declares no output handles.");
        Assert.IsFalse(codec.HasResponseParameters, "A header-only response has no parser.");
        Assert.AreSame(NvGlobalWriteLockResponse.Instance, codec.EmptyResponse, "The codec must resolve to TPM2_NV_GlobalWriteLock's own parameterless singleton.");
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
    private static void AssertFraming(NvGlobalWriteLockInput input, byte[] expectedHandles, byte[] expectedParameters)
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
