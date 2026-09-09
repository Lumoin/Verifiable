using System.Buffers;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_StirRandom()</c>'s input against its published table (TPM 2.0 Library Part 3,
/// clause 16.2, Table 77), plus its raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row and its response codec's
/// header-only parse (Table 78). The command carries no handles at all and exactly one parameter -
/// <c>inData</c>, a <c>TPM2B_SENSITIVE_DATA</c> whose <c>UINT16</c> size prefix is what makes it eligible for
/// session-based parameter encryption - so the handle area is empty on the wire and the parameter area is the
/// sized buffer alone.
/// </summary>
[TestClass]
internal sealed class StirRandomInputFramingTests
{
    /// <summary>
    /// Table 77 lists no handles and one parameter, <c>inData</c> as a <c>TPM2B_SENSITIVE_DATA</c> -
    /// "additional input, as defined in SP 800-90A." - which Part 2's Table 170 defines as a <c>UINT16</c>
    /// <c>size</c> followed by <c>buffer[size]</c>, so four octets of additional input frame as
    /// <c>00 04 DE AD BE EF</c> behind an empty handle area.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2, Table 77; Part 2, clause 11.1.14, Table 170</see>.
    /// </summary>
    [TestMethod]
    public void StirRandomInputFramesTheAdditionalInputAsASizedBufferBehindAnEmptyHandleAreaPerTable77()
    {
        using Tpm2bSensitiveData inData = Tpm2bSensitiveData.Create([0xDE, 0xAD, 0xBE, 0xEF], BaseMemoryPool.Shared);
        var input = new StirRandomInput(inData);

        Assert.AreEqual(TpmCcConstants.TPM_CC_StirRandom, input.CommandCode);

        //Handle area: empty, Table 77 lists none. Parameter area: the UINT16 size 0x0004 then the four octets.
        AssertFraming(input, [], [0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
    }

    /// <summary>
    /// Part 2's Table 170 wraps <c>buffer[size]</c> behind a <c>UINT16</c> <c>size</c> field that is written
    /// whether or not any octets follow it, so an empty <c>inData</c> is still a well-formed
    /// <c>TPM2B_SENSITIVE_DATA</c> on the wire and frames as the two zero octets alone - the shape a caller
    /// sends to reseed the RNG with no additional information of its own.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2, Table 77; Part 2, clause 11.1.14, Table 170</see>.
    /// </summary>
    [TestMethod]
    public void StirRandomInputFramesAnEmptyAdditionalInputAsTheSizePrefixAlone()
    {
        var input = new StirRandomInput(Tpm2bSensitiveData.Empty);

        Assert.AreEqual(TpmCcConstants.TPM_CC_StirRandom, input.CommandCode);

        //Handle area: empty. Parameter area: the UINT16 size 0x0000 and nothing behind it.
        AssertFraming(input, [], [0x00, 0x00]);
    }

    /// <summary>
    /// Table 77's parameter area is the one <c>TPM2B_SENSITIVE_DATA</c> and its handle area is empty, so the
    /// serialized size is exactly Table 170's <c>UINT16</c> <c>size</c> field plus the declared octets, at every
    /// width up to the "The inData parameter may not be larger than 128 octets." bound of clause 16.2.1.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2, Table 77; Part 2, clause 11.1.14, Table 170</see>.
    /// </summary>
    /// <param name="length">The width of the additional input under test.</param>
    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(32)]
    [DataRow(128)]
    public void StirRandomInputGetSerializedSizeAccountsForTheSizePrefixPlusTheAdditionalInput(int length)
    {
        using Tpm2bSensitiveData inData = Tpm2bSensitiveData.Create(new byte[length], BaseMemoryPool.Shared);
        var input = new StirRandomInput(inData);

        Assert.AreEqual(sizeof(ushort) + length, input.GetSerializedSize(),
            "TPM2_StirRandom frames no handles, so its serialized size is Table 170's UINT16 size field plus the declared octets.");
    }

    /// <summary>
    /// Table 77's <c>commandCode</c> row is <c>TPM_CC_StirRandom {NV}</c>, whose assigned value in Part 2's
    /// listing of command codes is 0x00000146.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 16.2, Table 77</see>.
    /// </summary>
    [TestMethod]
    public void StirRandomCommandCodeEqualsTheRawValueListedInTable12()
    {
        var input = new StirRandomInput(Tpm2bSensitiveData.Empty);

        Assert.AreEqual(TpmCcConstants.TPM_CC_StirRandom, input.CommandCode);
        Assert.AreEqual(0x00000146u, (uint)input.CommandCode, "TPM_CC_StirRandom must equal Table 12's raw value 0x00000146.");
    }

    /// <summary>
    /// "If session-based encryption is allowed, only the first parameter in the parameter area of a request or
    /// response can be encrypted. That parameter must have an explicit size field." (Part 1, clause 18.1) -
    /// Part 3's Table 77's sole parameter <c>inData</c> is a <c>TPM2B_SENSITIVE_DATA</c>, which carries exactly such a
    /// size field, so it IS encryptable; Table 77's tag row admits <c>TPM_ST_SESSIONS</c> precisely "if an audit
    /// or decrypt session is present". The command lists no handles at all, so no position in its handle area
    /// names a sequence object.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 16.2, Table 77</see>.
    /// </summary>
    [TestMethod]
    public void StirRandomInputMarksItsAdditionalInputEncryptableAndDeclaresNoSequenceHandle()
    {
        ITpmCommandInput input = new StirRandomInput(Tpm2bSensitiveData.Empty);

        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "TPM2_StirRandom's inData is a sized buffer and the command's first parameter, so it is encryptable.");
        Assert.IsFalse(input.HandleIsSequence(0), "TPM2_StirRandom lists no handles, so no handle position names a sequence object.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_StirRandom</c> takes none of Table 77's
    /// handles, is <c>{NV}</c> - the decoration Table 77's <c>commandCode</c> row carries, because a reseed may
    /// touch non-volatile state - is not flushed, and returns no response handle; its COMMAND_INDEX is the low
    /// 16 bits of 0x00000146.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 16.2, Table 77</see>.
    /// </summary>
    [TestMethod]
    public void StirRandomCommandAttributesCarryNoHandlesAndTheNvBit()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_StirRandom.GetCommandAttributes();

        Assert.AreEqual((byte)0, attributes.C_HANDLES, "Table 77 lists no handles for TPM2_StirRandom.");
        Assert.IsTrue(attributes.NV, "Table 77's commandCode row is TPM_CC_StirRandom {NV}.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.IsFalse(attributes.R_HANDLE, "TPM2_StirRandom returns no response handle.");
        Assert.AreEqual((ushort)0x0146, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response is the 10-byte header alone (Table 78 lists <c>tag</c>, <c>responseSize</c> and
    /// <c>responseCode</c> only): the codec declares zero output handles, no parser, and
    /// <see cref="StirRandomResponse.Instance"/> as the value a header-only success response resolves to.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 16.2, Table 78</see>.
    /// </summary>
    [TestMethod]
    public void StirRandomCodecResolvesAHeaderOnlySuccessResponseToItsOwnSingleton()
    {
        TpmResponseCodec codec = TpmResponseCodec.StirRandom;

        Assert.AreEqual(0, codec.OutHandleCount, "A header-only response declares no output handles.");
        Assert.IsFalse(codec.HasResponseParameters, "A header-only response has no parser.");
        Assert.AreSame(StirRandomResponse.Instance, codec.EmptyResponse, "The codec must resolve to TPM2_StirRandom's own parameterless singleton.");
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle and parameter areas into freshly-sized buffers and asserts each
    /// reproduces the hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for precisely the two areas combined. An empty <paramref name="expectedHandles"/> pins that
    /// <c>WriteHandles</c> writes nothing at all.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(StirRandomInput input, byte[] expectedHandles, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(),
            "GetSerializedSize must account for exactly the handle area plus the parameter area.");

        byte[] handles = new byte[expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the handle area.");
        Assert.AreSequenceEqual(expectedHandles, handles, "The handle area must reproduce the hand-computed octets exactly.");

        byte[] parameters = new byte[expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.AreSequenceEqual(expectedParameters, parameters, "The parameter area must reproduce the hand-computed octets exactly.");
    }
}
