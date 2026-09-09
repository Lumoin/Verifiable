using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_NV_UndefineSpaceSpecial()</c>'s input against its published table (TPM 2.0
/// Library Part 3, clause 31.5, Table 249), plus its raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row and its
/// response codec's header-only parse (Table 250). The command carries two handles - <c>@nvIndex</c>, the Index
/// being deleted, and <c>@platform</c>, a <c>TPMI_RH_PLATFORM</c> that admits <c>TPM_RH_PLATFORM</c> alone - and
/// no parameters at all, so the parameter area is empty on the wire and the response is the header alone.
/// </summary>
[TestClass]
internal sealed class NvUndefineSpaceSpecialInputFramingTests
{
    /// <summary>An example NV Index handle: its most-significant octet is <c>TPM_HT_NV_INDEX</c> (0x01).</summary>
    private const uint ExampleIndexHandle = 0x0100_006B;

    /// <summary>
    /// Table 249: two handles in order - <c>@nvIndex</c> (<c>TPMI_RH_NV_DEFINED_INDEX</c>, "Index to be
    /// deleted", Auth Index 1, Auth Role ADMIN) then <c>@platform</c> ("TPM_RH_PLATFORM+{PP}", Auth Index 2,
    /// Auth Role USER) - and no parameters at all, so <c>WriteParameters</c> writes nothing. The platform
    /// selector is <c>TPM_RH_PLATFORM</c>, 0x4000000C.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5, Table 249; Part 2, clause 9.18, Table 64</see>.
    /// </summary>
    [TestMethod]
    public void NvUndefineSpaceSpecialInputFramesBothHandlesAndAnEmptyParameterAreaByteExactlyPerTable249()
    {
        var input = new NvUndefineSpaceSpecialInput(ExampleIndexHandle);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, input.CommandCode);

        //Handle area: @nvIndex then @platform; no parameter area follows them.
        AssertFraming(input, [0x01, 0x00, 0x00, 0x6B, 0x40, 0x00, 0x00, 0x0C], []);
    }

    /// <summary>
    /// <c>TPMI_RH_PLATFORM</c> admits the one value "TPM_RH_PLATFORM Platform hierarchy", so naming it
    /// explicitly frames the identical octets the default does - the second handle is a constant of the command
    /// shape rather than a caller choice.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 9.18, Table 64; Part 3, clause 31.5, Table 249</see>.
    /// </summary>
    [TestMethod]
    public void NvUndefineSpaceSpecialInputFramesTheExplicitPlatformHandleIdenticallyToTheDefault()
    {
        var input = new NvUndefineSpaceSpecialInput(ExampleIndexHandle, TpmRh.TPM_RH_PLATFORM);

        //Handle area: @nvIndex then the explicitly named @platform, the same two handles as the default form.
        AssertFraming(input, [0x01, 0x00, 0x00, 0x6B, 0x40, 0x00, 0x00, 0x0C], []);
    }

    /// <summary>
    /// Table 249's <c>commandCode</c> row is <c>TPM_CC_NV_UndefineSpaceSpecial {NV}</c>, whose assigned value in
    /// Part 2's listing of command codes is 0x0000011F.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 31.5, Table 249</see>.
    /// </summary>
    [TestMethod]
    public void NvUndefineSpaceSpecialCommandCodeEqualsTheRawValueListedInTable12()
    {
        var input = new NvUndefineSpaceSpecialInput(ExampleIndexHandle);

        Assert.AreEqual(TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial, input.CommandCode);
        Assert.AreEqual(0x0000011Fu, (uint)input.CommandCode, "TPM_CC_NV_UndefineSpaceSpecial must equal Table 12's raw value 0x0000011F.");
    }

    /// <summary>
    /// Table 249 lists two handles and no parameters, so
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for exactly the two 4-octet handles.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5, Table 249</see>.
    /// </summary>
    [TestMethod]
    public void NvUndefineSpaceSpecialInputGetSerializedSizeAccountsForTheTwoHandlesAlone()
    {
        var input = new NvUndefineSpaceSpecialInput(ExampleIndexHandle);

        Assert.AreEqual(8, input.GetSerializedSize());
    }

    /// <summary>
    /// "If session-based encryption is allowed, only the first parameter in the parameter area of a request or
    /// response can be encrypted. That parameter must have an explicit size field." (Part 1, clause 18.1) -
    /// Part 3's Table 249 lists no parameters at all, so nothing with a size field exists to be encryptable; and neither
    /// handle names a hash or HMAC sequence object, so neither is a sequence handle.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 31.5, Table 249</see>.
    /// </summary>
    [TestMethod]
    public void NvUndefineSpaceSpecialInputMarksNoParameterEncryptableAndNeitherHandleASequence()
    {
        ITpmCommandInput input = new NvUndefineSpaceSpecialInput(ExampleIndexHandle);

        Assert.IsFalse(input.FirstCommandParameterIsEncryptable, "TPM2_NV_UndefineSpaceSpecial has no parameters, so none is encryptable.");
        Assert.IsFalse(input.HandleIsSequence(0), "@nvIndex names an NV Index, never a sequence object.");
        Assert.IsFalse(input.HandleIsSequence(1), "@platform names a hierarchy, never a sequence object.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_NV_UndefineSpaceSpecial</c> takes the two
    /// handles of Table 249, is <c>{NV}</c>, is not flushed, and returns no response handle; its COMMAND_INDEX is
    /// the low 16 bits of 0x0000011F.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 31.5, Table 249</see>.
    /// </summary>
    [TestMethod]
    public void NvUndefineSpaceSpecialCommandAttributesCarryTwoHandlesAndTheNvBit()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_NV_UndefineSpaceSpecial.GetCommandAttributes();

        Assert.AreEqual((byte)2, attributes.C_HANDLES);
        Assert.IsTrue(attributes.NV, "TPM2_NV_UndefineSpaceSpecial is {NV}.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.IsFalse(attributes.R_HANDLE, "TPM2_NV_UndefineSpaceSpecial returns no response handle.");
        Assert.AreEqual((ushort)0x011F, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response is the 10-byte header alone (Table 250 lists <c>tag</c>, <c>responseSize</c> and
    /// <c>responseCode</c> only): the codec declares zero output handles, no parser, and
    /// <see cref="NvUndefineSpaceSpecialResponse.Instance"/> as the value a header-only success response resolves
    /// to.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.5, Table 250</see>.
    /// </summary>
    [TestMethod]
    public void NvUndefineSpaceSpecialCodecResolvesAHeaderOnlySuccessResponseToItsOwnSingleton()
    {
        TpmResponseCodec codec = TpmResponseCodec.NvUndefineSpaceSpecial;

        Assert.AreEqual(0, codec.OutHandleCount, "A header-only response declares no output handles.");
        Assert.IsFalse(codec.HasResponseParameters, "A header-only response has no parser.");
        Assert.AreSame(NvUndefineSpaceSpecialResponse.Instance, codec.EmptyResponse, "The codec must resolve to TPM2_NV_UndefineSpaceSpecial's own parameterless singleton.");
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
    private static void AssertFraming(NvUndefineSpaceSpecialInput input, byte[] expectedHandles, byte[] expectedParameters)
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
