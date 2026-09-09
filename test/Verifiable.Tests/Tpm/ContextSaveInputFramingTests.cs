using System;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_ContextSave()</c>'s input against its published table (TPM 2.0 Library Part 3,
/// clause 28.2, Table 224) — one handle (<c>saveHandle</c>, Auth Index None) and no parameters at all — plus its
/// raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row, and its response's parse (Table 225: one <c>TPMS_CONTEXT</c>).
/// </summary>
[TestClass]
internal sealed class ContextSaveInputFramingTests
{
    /// <summary>
    /// Table 224's handle area is <c>saveHandle</c> alone, a four-octet <c>TPMI_DH_CONTEXT</c>; the command
    /// carries no parameters at all — <c>saveHandle</c> is its only content.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.2, Table 224</see>.
    /// </summary>
    [TestMethod]
    public void ContextSaveInputFramesTheHandleAreaByteExactlyPerTable224WithNoParameters()
    {
        var input = new ContextSaveInput(TpmiDhContext.FromValue(0x8000_0001u));

        AssertFraming(input, [0x80, 0x00, 0x00, 0x01], []);
    }

    /// <summary>
    /// Table 224's <c>commandCode</c> row is <c>TPM_CC_ContextSave</c>, whose assigned value is 0x00000162; the
    /// row carries no <c>{NV}</c> decoration.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.2, Table 224</see>.
    /// </summary>
    [TestMethod]
    public void ContextSaveCommandCodeEqualsTheRawValueListedInTable224()
    {
        var input = new ContextSaveInput(TpmiDhContext.FromValue(0x8000_0001u));

        Assert.AreEqual(TpmCcConstants.TPM_CC_ContextSave, input.CommandCode);
        Assert.AreEqual(0x00000162u, (uint)input.CommandCode, "TPM_CC_ContextSave must equal Table 224's raw value 0x00000162.");
    }

    /// <summary>
    /// "Any first parameter can be encrypted as long as the parameter has a size field" (Part 1, clause 18.1):
    /// <c>TPM2_ContextSave()</c> carries no parameters at all, so no first parameter exists to encrypt.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 28.2, Table 224</see>.
    /// </summary>
    [TestMethod]
    public void ContextSaveInputMarksItsFirstParameterNotEncryptable()
    {
        ITpmCommandInput input = new ContextSaveInput(TpmiDhContext.FromValue(0x8000_0001u));

        Assert.IsFalse(input.FirstCommandParameterIsEncryptable, "TPM2_ContextSave() has no parameter area at all, so its first parameter cannot be encrypted.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_ContextSave</c> takes the one handle of
    /// Table 224 with Auth Index None, is not <c>{NV}</c>, is not flushed, and returns no response handle (Table
    /// 225); its COMMAND_INDEX is the low 16 bits of 0x00000162.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 28.2</see>.
    /// </summary>
    [TestMethod]
    public void ContextSaveCommandAttributesCarryOneHandleAndNoResponseHandle()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_ContextSave.GetCommandAttributes();

        Assert.AreEqual((byte)1, attributes.C_HANDLES, "Table 224 lists saveHandle alone.");
        Assert.IsFalse(attributes.R_HANDLE, "Table 225 returns no handle — the whole parameter area is the TPMS_CONTEXT.");
        Assert.IsFalse(attributes.NV, "TPM2_ContextSave carries no {NV} decoration.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.AreEqual((ushort)0x0162, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response codec declares Table 225's shape: no output handle, a parameter area (<c>context</c>), and —
    /// since <c>TPMS_CONTEXT</c> does not begin with a plain size field — a response no encrypt session may
    /// protect (Part 1, clause 18.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.2, Table 225; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void ContextSaveCodecDeclaresNoHandleAndANonEncryptableContextResponse()
    {
        TpmResponseCodec codec = TpmResponseCodec.ContextSave;

        Assert.AreEqual(0, codec.OutHandleCount, "Table 225 returns no handle.");
        Assert.IsTrue(codec.HasResponseParameters, "Table 225 returns context.");
        Assert.IsFalse(codec.ResponseFirstParameterIsEncryptable, "TPMS_CONTEXT begins with a UINT64 sequence, not a size field, so it is not eligible for parameter encryption.");
    }

    /// <summary>
    /// Table 225's response parses to the <c>TPMS_CONTEXT</c> the wire carried, field by field — the parser
    /// <see cref="TpmResponseCodec.ContextSave"/> installs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.2, Table 225</see>.
    /// </summary>
    [TestMethod]
    public void ContextSaveResponseParsesTheContextFieldByFieldPerTable225()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] parameters =
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
            0x80, 0x00, 0x00, 0x01,
            0x40, 0x00, 0x00, 0x07,
            0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF
        ];
        var reader = new TpmReader(parameters);

        using ContextSaveResponse response = ContextSaveResponse.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "The parse must consume exactly the TPMS_CONTEXT.");
        Assert.AreEqual(7UL, response.Context.Sequence, "sequence must parse from the leading UINT64.");
        Assert.AreEqual(0x8000_0001u, response.Context.SavedHandle.Value, "savedHandle must parse from the second field.");
        Assert.AreEqual(0x4000_0007u, response.Context.Hierarchy.Value, "hierarchy must parse from the third field.");
        Assert.AreEqual(4, response.Context.ContextBlob.Size, "contextBlob's size field must parse to the declared octet count.");
        ReadOnlySpan<byte> expectedBlob = [0xDE, 0xAD, 0xBE, 0xEF];
        Assert.IsTrue(response.Context.ContextBlob.Span.SequenceEqual(expectedBlob), "contextBlob's octets must be the wire's.");
    }

    /// <summary>
    /// <see cref="ContextSaveResponse.Dispose"/> releases the owned <c>TPMS_CONTEXT</c>'s blob rental.
    /// </summary>
    [TestMethod]
    public void ContextSaveResponseDisposeReleasesTheBlob()
    {
        byte[] parameters =
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x80, 0x00, 0x00, 0x00,
            0x40, 0x00, 0x00, 0x01,
            0x00, 0x02, 0x11, 0x22
        ];
        using var trackingPool = new MeteredHousePool();
        long baseline = trackingPool.OutstandingCount;
        var reader = new TpmReader(parameters);
        ContextSaveResponse response = ContextSaveResponse.Parse(ref reader, trackingPool.Pool);
        Assert.AreEqual(baseline + 1, trackingPool.OutstandingCount, "The parsed blob's rental must be outstanding while the response is alive.");

        response.Dispose();

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the response must release the blob's rental.");
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle area and parameter area into freshly-sized buffers and asserts
    /// each reproduces its hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for both together.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(ContextSaveInput input, byte[] expectedHandles, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(), "GetSerializedSize must account for the handle area and the parameter area together.");

        byte[] handles = new byte[expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the handle area.");
        Assert.AreSequenceEqual(expectedHandles, handles, "The handle area must reproduce the hand-computed octets exactly.");

        byte[] parameters = new byte[expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must write nothing — Table 224 carries no parameters.");
        Assert.AreSequenceEqual(expectedParameters, parameters, "The parameter area must be empty.");
    }
}
