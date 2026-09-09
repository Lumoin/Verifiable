using System;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_ClockRateAdjust()</c>'s input against its published table (TPM 2.0 Library
/// Part 3, clause 29.3, Table 236), plus its raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row and its response
/// codec's header-only parse (Table 237). The command carries one handle — <c>@auth</c>, a
/// <c>TPMI_RH_PROVISION</c> naming either the owner or the platform hierarchy — and one parameter,
/// <c>rateAdjust</c>, "Adjustment to current Clock update rate", a single signed octet whose seven admitted
/// values are Table 19's.
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3, Table 236; Part 2, clause 6.7, Table 19</see>.
/// </summary>
[TestClass]
internal sealed class ClockRateAdjustInputFramingTests
{
    /// <summary>
    /// Table 236: a single handle <c>@auth</c> (<c>TPMI_RH_PROVISION</c>, "TPM_RH_OWNER or
    /// TPM_RH_PLATFORM+{PP}", Auth Index 1, Auth Role USER) followed by the one-octet <c>rateAdjust</c>
    /// parameter. Every Table 19 value frames as its own two's complement octet after the owner selector's
    /// four octets <c>40 00 00 01</c> — the negative half of the range included, so
    /// <c>TPM_CLOCK_COARSE_SLOWER</c> is <c>FD</c>, <c>TPM_CLOCK_NO_CHANGE</c> is <c>00</c> and
    /// <c>TPM_CLOCK_COARSE_FASTER</c> is <c>03</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3, Table 236; Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    /// <param name="rateAdjust">The requested Table 19 step.</param>
    /// <param name="expectedParameterOctet">The single octet the parameter area must carry.</param>
    [TestMethod]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER, (byte)0xFD, DisplayName = "TPM_CLOCK_COARSE_SLOWER frames as FD")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_SLOWER, (byte)0xFE, DisplayName = "TPM_CLOCK_MEDIUM_SLOWER frames as FE")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_FINE_SLOWER, (byte)0xFF, DisplayName = "TPM_CLOCK_FINE_SLOWER frames as FF")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE, (byte)0x00, DisplayName = "TPM_CLOCK_NO_CHANGE frames as 00")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER, (byte)0x01, DisplayName = "TPM_CLOCK_FINE_FASTER frames as 01")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_FASTER, (byte)0x02, DisplayName = "TPM_CLOCK_MEDIUM_FASTER frames as 02")]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER, (byte)0x03, DisplayName = "TPM_CLOCK_COARSE_FASTER frames as 03")]
    public void ClockRateAdjustInputFramesTheOwnerHandleAndTheSignedRateOctetByteExactlyPerTable236(
        TpmClockAdjustConstants rateAdjust, byte expectedParameterOctet)
    {
        var input = new ClockRateAdjustInput(TpmRh.TPM_RH_OWNER, rateAdjust);

        Assert.AreEqual(TpmCcConstants.TPM_CC_ClockRateAdjust, input.CommandCode);

        //Handle area: @auth TPM_RH_OWNER; parameter area: the single rateAdjust octet.
        AssertFraming(input, new byte[] { 0x40, 0x00, 0x00, 0x01 }, new byte[] { expectedParameterOctet });
    }

    /// <summary>
    /// "A TPM_CLOCK_ADJUST value in Table 19 is used to change the rate at which the TPM internal oscillator is
    /// divided" — Table 19 defines exactly seven members and marks any other value <c>#TPM_RC_VALUE</c>, so
    /// <see cref="ClockRateAdjustInput.WriteParameters"/> refuses a step outside them client-side, on the local
    /// stack, before a single octet is framed: <see cref="ArgumentOutOfRangeException"/>, never a round trip to
    /// the TPM only to be refused by its own Table 19 membership check.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    /// <param name="undefinedRateAdjust">A signed octet naming no Table 19 member.</param>
    [TestMethod]
    [DataRow((sbyte)4, DisplayName = "4 is one past the fastest step Table 19 lists")]
    [DataRow((sbyte)(-4), DisplayName = "-4 is one past the slowest step Table 19 lists")]
    [DataRow((sbyte)127, DisplayName = "the most positive INT8 is outside Table 19")]
    public void ClockRateAdjustInputWriteParametersThrowsForAStepOutsideTable19(sbyte undefinedRateAdjust)
    {
        var input = new ClockRateAdjustInput(TpmRh.TPM_RH_OWNER, (TpmClockAdjustConstants)undefinedRateAdjust);
        byte[] parameters = new byte[1];

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WriteParametersInto(input, parameters),
            $"'{undefinedRateAdjust}' names no Table 19 member, so the client-side guard must refuse it before framing.");
    }

    /// <summary>Frames <paramref name="input"/>'s parameter area into <paramref name="buffer"/>, the single-statement call <see cref="Assert.ThrowsExactly{T}(Action, string)"/> requires.</summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="buffer">The destination buffer, exactly one octet wide.</param>
    private static void WriteParametersInto(ClockRateAdjustInput input, byte[] buffer)
    {
        var writer = new TpmWriter(buffer);
        input.WriteParameters(ref writer);
    }

    /// <summary>
    /// The seven Table 19 values are the exact complement of the refusal above: every one of them frames
    /// without throwing, so the client-side guard refuses precisely the undefined octets and nothing defined.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    /// <param name="rateAdjust">A defined Table 19 step.</param>
    [TestMethod]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER)]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_SLOWER)]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_FINE_SLOWER)]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE)]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER)]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_FASTER)]
    [DataRow(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER)]
    public void ClockRateAdjustInputWriteParametersFramesEveryDefinedTable19Value(TpmClockAdjustConstants rateAdjust)
    {
        var input = new ClockRateAdjustInput(TpmRh.TPM_RH_OWNER, rateAdjust);
        byte[] parameters = new byte[1];
        var writer = new TpmWriter(parameters);

        input.WriteParameters(ref writer);

        Assert.AreEqual(1, writer.Written, $"'{rateAdjust}' is a Table 19 member, so it must frame its one octet without throwing.");
    }

    /// <summary>
    /// The other selector Table 67 admits for <c>TPMI_RH_PROVISION</c>: <c>TPM_RH_PLATFORM</c>, 0x4000000C,
    /// frames into the same single-handle area ahead of the same one-octet parameter area.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3, Table 236; Part 2, clause 9.21, Table 67</see>.
    /// </summary>
    [TestMethod]
    public void ClockRateAdjustInputFramesThePlatformHandleAheadOfTheSameParameterArea()
    {
        var input = new ClockRateAdjustInput(TpmRh.TPM_RH_PLATFORM, TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER);

        Assert.AreEqual(TpmCcConstants.TPM_CC_ClockRateAdjust, input.CommandCode);

        AssertFraming(input, new byte[] { 0x40, 0x00, 0x00, 0x0C }, new byte[] { 0x03 });
    }

    /// <summary>
    /// Table 236's <c>commandCode</c> row is <c>TPM_CC_ClockRateAdjust</c> — carrying no <c>{NV}</c>
    /// decoration, unlike <c>TPM2_ClockSet()</c>'s — whose assigned value in Part 2's listing of command codes
    /// is 0x00000130.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 29.3, Table 236</see>.
    /// </summary>
    [TestMethod]
    public void ClockRateAdjustCommandCodeEqualsTheRawValueListedInTable12()
    {
        var input = new ClockRateAdjustInput(TpmRh.TPM_RH_OWNER, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE);

        Assert.AreEqual(TpmCcConstants.TPM_CC_ClockRateAdjust, input.CommandCode);
        Assert.AreEqual(0x00000130u, (uint)input.CommandCode, "TPM_CC_ClockRateAdjust must equal Table 12's raw value 0x00000130.");
    }

    /// <summary>
    /// Table 236 lists one handle and one <c>INT8</c> parameter, so
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for exactly four octets of handle plus one
    /// octet of parameter.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3, Table 236</see>.
    /// </summary>
    [TestMethod]
    public void ClockRateAdjustInputGetSerializedSizeAccountsForOneHandleAndOneSignedOctet()
    {
        var input = new ClockRateAdjustInput(TpmRh.TPM_RH_OWNER, TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER);

        Assert.AreEqual(5, input.GetSerializedSize());
    }

    /// <summary>
    /// "If session-based encryption is allowed, only the first parameter in the parameter area of a request or
    /// response can be encrypted. That parameter must have an explicit size field." (Part 1, clause 18.1) —
    /// <c>rateAdjust</c> is a bare <c>INT8</c> with no size field, so nothing in this command's parameter area
    /// is encryptable; and the single handle names a hierarchy rather than a hash or HMAC sequence object, so
    /// it is no sequence handle either.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 29.3, Table 236</see>.
    /// </summary>
    [TestMethod]
    public void ClockRateAdjustInputMarksNoParameterEncryptableAndItsHandleNoSequence()
    {
        ITpmCommandInput input = new ClockRateAdjustInput(TpmRh.TPM_RH_OWNER, TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE);

        Assert.IsFalse(input.FirstCommandParameterIsEncryptable, "rateAdjust is a bare INT8 with no size field, so it is not encryptable.");
        Assert.IsFalse(input.HandleIsSequence(0), "@auth names a hierarchy, never a sequence object.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_ClockRateAdjust</c> takes the one handle
    /// of Table 236, is NOT <c>{NV}</c> — the table's <c>commandCode</c> row carries no such decoration — is
    /// not flushed, and returns no response handle; its COMMAND_INDEX is the low 16 bits of 0x00000130.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 29.3, Table 236</see>.
    /// </summary>
    [TestMethod]
    public void ClockRateAdjustCommandAttributesCarryOneHandleAndNoNvBit()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_ClockRateAdjust.GetCommandAttributes();

        Assert.AreEqual((byte)1, attributes.C_HANDLES);
        Assert.IsFalse(attributes.NV, "Table 236's commandCode row carries no {NV} decoration.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.IsFalse(attributes.R_HANDLE, "TPM2_ClockRateAdjust returns no response handle.");
        Assert.AreEqual((ushort)0x0130, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response is the 10-byte header alone (Table 237 lists <c>tag</c>, <c>responseSize</c> and
    /// <c>responseCode</c> only): the codec declares zero output handles, no parser, and
    /// <see cref="ClockRateAdjustResponse.Instance"/> as the value a header-only success response resolves to.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 29.3, Table 237</see>.
    /// </summary>
    [TestMethod]
    public void ClockRateAdjustCodecResolvesAHeaderOnlySuccessResponseToItsOwnSingleton()
    {
        TpmResponseCodec codec = TpmResponseCodec.ClockRateAdjust;

        Assert.AreEqual(0, codec.OutHandleCount, "A header-only response declares no output handles.");
        Assert.IsFalse(codec.HasResponseParameters, "A header-only response has no parser.");
        Assert.AreSame(ClockRateAdjustResponse.Instance, codec.EmptyResponse, "The codec must resolve to TPM2_ClockRateAdjust's own parameterless singleton.");
    }

    /// <summary>
    /// "Table 19: Definition of (INT8) TPM_CLOCK_ADJUST Constants" defines exactly seven members whose values
    /// run from <c>-3</c> to <c>3</c> in the order COARSE_SLOWER, MEDIUM_SLOWER, FINE_SLOWER, NO_CHANGE,
    /// FINE_FASTER, MEDIUM_FASTER, COARSE_FASTER — the whole of the table, with no eighth value and no gap.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    [TestMethod]
    public void ClockAdjustConstantsCarryTable19WholeWithItsSevenSignedValues()
    {
        TpmClockAdjustConstants[] members = Enum.GetValues<TpmClockAdjustConstants>();
        sbyte[] rawValues = Array.ConvertAll(members, member => (sbyte)member);
        Array.Sort(rawValues);

        Assert.HasCount(7, members, "Table 19 defines exactly seven TPM_CLOCK_ADJUST values.");
        Assert.AreSequenceEqual(
            new sbyte[] { -3, -2, -1, 0, 1, 2, 3 },
            rawValues,
            "Table 19 assigns its members the contiguous signed values -3 through 3, with no gap and no eighth value.");
    }

    /// <summary>
    /// Table 19's rows in order, each raw signed octet paired with the name the table gives it: the three
    /// SLOWER steps run <c>-3</c>, <c>-2</c>, <c>-1</c>, <c>TPM_CLOCK_NO_CHANGE</c> is the zero at the centre,
    /// and the three FASTER steps mirror them at <c>1</c>, <c>2</c>, <c>3</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 6.7, Table 19</see>.
    /// </summary>
    /// <param name="rawValue">The raw signed octet Table 19 assigns.</param>
    /// <param name="expectedName">The name Table 19 gives that value.</param>
    [TestMethod]
    [DataRow((sbyte)(-3), nameof(TpmClockAdjustConstants.TPM_CLOCK_COARSE_SLOWER), DisplayName = "-3 names the coarse slower step")]
    [DataRow((sbyte)(-2), nameof(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_SLOWER), DisplayName = "-2 names the medium slower step")]
    [DataRow((sbyte)(-1), nameof(TpmClockAdjustConstants.TPM_CLOCK_FINE_SLOWER), DisplayName = "-1 names the fine slower step")]
    [DataRow((sbyte)0, nameof(TpmClockAdjustConstants.TPM_CLOCK_NO_CHANGE), DisplayName = "0 names the no-change step")]
    [DataRow((sbyte)1, nameof(TpmClockAdjustConstants.TPM_CLOCK_FINE_FASTER), DisplayName = "1 names the fine faster step")]
    [DataRow((sbyte)2, nameof(TpmClockAdjustConstants.TPM_CLOCK_MEDIUM_FASTER), DisplayName = "2 names the medium faster step")]
    [DataRow((sbyte)3, nameof(TpmClockAdjustConstants.TPM_CLOCK_COARSE_FASTER), DisplayName = "3 names the coarse faster step")]
    public void EachTable19RawValueNamesItsOwnStep(sbyte rawValue, string expectedName)
    {
        var member = (TpmClockAdjustConstants)rawValue;

        Assert.AreEqual(expectedName, member.ToString(), $"Table 19 assigns '{rawValue}' to '{expectedName}'.");
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle and parameter areas into freshly-sized buffers and asserts each
    /// reproduces the hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for precisely the two areas combined.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(ClockRateAdjustInput input, byte[] expectedHandles, byte[] expectedParameters)
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
