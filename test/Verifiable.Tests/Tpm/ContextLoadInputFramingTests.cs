using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_ContextLoad()</c>'s input against its published table (TPM 2.0 Library Part 3,
/// clause 28.3, Table 226) — the whole <c>TPMS_CONTEXT</c> as the sole parameter, no handle area at all — plus
/// its raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row, its response's handle-only parse (Table 227), and the
/// borrow contract <see cref="ContextLoadInput"/> keeps over the caller's <see cref="TpmsContext"/>.
/// </summary>
[TestClass]
internal sealed class ContextLoadInputFramingTests
{
    /// <summary>
    /// Table 226 has no handle area at all: the whole command content is <c>context</c>, a <c>TPMS_CONTEXT</c>,
    /// framed in the parameter area by <see cref="TpmsContext.WriteTo"/>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3, Table 226</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The context takes ownership of the blob passed to its constructor and is itself disposed by the using declaration.")]
    public void ContextLoadInputFramesTheParameterAreaByteExactlyPerTable226WithNoHandles()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using var context = new TpmsContext(5UL, TpmiDhSaved.FromValue(0x0200_0000u), TpmiRhHierarchy.Null, Tpm2bContextData.Create([0xAA, 0xBB, 0xCC], pool));
        var input = new ContextLoadInput(context);

        AssertFraming(
            input,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x07, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    /// <summary>
    /// Table 226's <c>commandCode</c> row is <c>TPM_CC_ContextLoad</c>, whose assigned value is 0x00000161.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3, Table 226</see>.
    /// </summary>
    [TestMethod]
    public void ContextLoadCommandCodeEqualsTheRawValueListedInTable226()
    {
        using var context = new TpmsContext(1UL, TpmiDhSaved.FromValue(TpmiDhSaved.OrdinaryTransientObject), TpmiRhHierarchy.Owner, Tpm2bContextData.Empty);
        var input = new ContextLoadInput(context);

        Assert.AreEqual(TpmCcConstants.TPM_CC_ContextLoad, input.CommandCode);
        Assert.AreEqual(0x00000161u, (uint)input.CommandCode, "TPM_CC_ContextLoad must equal Table 226's raw value 0x00000161.");
    }

    /// <summary>
    /// "Any first parameter can be encrypted as long as the parameter has a size field" (Part 1, clause 18.1):
    /// <c>context</c> is a <c>TPMS_CONTEXT</c> beginning with a <c>UINT64 sequence</c>, not a size field, so it
    /// is not eligible for parameter encryption.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 28.3, Table 226</see>.
    /// </summary>
    [TestMethod]
    public void ContextLoadInputMarksItsFirstParameterNotEncryptable()
    {
        using var context = new TpmsContext(1UL, TpmiDhSaved.FromValue(TpmiDhSaved.OrdinaryTransientObject), TpmiRhHierarchy.Owner, Tpm2bContextData.Empty);
        ITpmCommandInput input = new ContextLoadInput(context);

        Assert.IsFalse(input.FirstCommandParameterIsEncryptable, "TPMS_CONTEXT begins with sequence, a UINT64 with no size field, so its parameter area is not eligible for encryption.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_ContextLoad</c> takes none of Table 226's
    /// handles, is not <c>{NV}</c>, is not flushed, and returns the one response handle of Table 227; its
    /// COMMAND_INDEX is the low 16 bits of 0x00000161.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 28.3</see>.
    /// </summary>
    [TestMethod]
    public void ContextLoadCommandAttributesCarryNoHandlesAndOneResponseHandle()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_ContextLoad.GetCommandAttributes();

        Assert.AreEqual((byte)0, attributes.C_HANDLES, "Table 226 lists no handles.");
        Assert.IsTrue(attributes.R_HANDLE, "Table 227 returns loadedHandle.");
        Assert.IsFalse(attributes.NV, "TPM2_ContextLoad carries no {NV} decoration.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.AreEqual((ushort)0x0161, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// Table 227's <c>loadedHandle</c> — "the handle assigned to the resource after it has been successfully
    /// loaded" — rides the response handle area alone; the codec binds it into
    /// <see cref="ContextLoadResponse.LoadedHandle"/> for a session handle and for a freshly drawn object handle
    /// alike, since the response carries no parameters to distinguish them.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3, Table 227</see>.
    /// </summary>
    /// <param name="handle">The response handle area value under test.</param>
    [TestMethod]
    [DataRow(0x8000_0002u, DisplayName = "a freshly drawn transient object handle")]
    [DataRow(0x0200_0001u, DisplayName = "a session reinstalled at its own saved handle")]
    public void ContextLoadCodecBindsTheHandleAreaHandleIntoLoadedHandle(uint handle)
    {
        TpmResponseCodec codec = TpmResponseCodec.ContextLoad;

        Assert.AreEqual(1, codec.OutHandleCount, "Table 227 returns loadedHandle alone.");

        ContextLoadResponse response = ContextLoadResponse.Parse(handle);

        Assert.AreEqual(handle, response.LoadedHandle.Value, "The codec must bind the response handle area's value into LoadedHandle unchanged.");
    }

    /// <summary>
    /// <see cref="ContextLoadInput"/> BORROWS the caller's <see cref="TpmsContext"/>: after
    /// <see cref="ContextLoadInput.WriteParameters"/> has framed it, the caller's structure remains readable and
    /// disposable, exactly as <see cref="RsaEncryptInput"/>'s own non-owning carriers keep for the caller.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 28.3, Table 226</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The context takes ownership of the blob passed to its constructor and is disposed explicitly at the end of the test.")]
    public void ContextLoadInputBorrowsTheCallersContextAndLeavesItUsableAfterWriteParameters()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var context = new TpmsContext(3UL, TpmiDhSaved.FromValue(TpmiDhSaved.OrdinaryTransientObject), TpmiRhHierarchy.Owner, Tpm2bContextData.Create([0x01, 0x02], pool));
        var input = new ContextLoadInput(context);

        byte[] wire = new byte[input.GetSerializedSize()];
        var writer = new TpmWriter(wire);
        input.WriteParameters(ref writer);

        ReadOnlySpan<byte> expectedBlob = [0x01, 0x02];
        Assert.AreEqual(3UL, context.Sequence, "WriteParameters must not dispose or otherwise alter the caller's context.");
        Assert.IsTrue(context.ContextBlob.Span.SequenceEqual(expectedBlob), "The caller's blob must remain readable — the input never took ownership.");

        context.Dispose();
    }

    /// <summary>
    /// A type that borrows rather than owns must not itself implement <see cref="IDisposable"/> — the caller
    /// alone owns and disposes the <see cref="TpmsContext"/> <see cref="ContextLoadInput"/> carries.
    /// </summary>
    [TestMethod]
    public void ContextLoadInputExposesNoDisposeUnlikeTheContextItBorrows()
    {
        Assert.IsFalse(typeof(IDisposable).IsAssignableFrom(typeof(ContextLoadInput)), "ContextLoadInput borrows the caller's TpmsContext and must not itself implement IDisposable.");
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s empty handle area and its parameter area into freshly-sized buffers and
    /// asserts the parameter octets reproduce the hand-computed frame exactly, and that
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for precisely those octets — no handle area
    /// exists to add.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(ContextLoadInput input, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedParameters.Length, input.GetSerializedSize(), "GetSerializedSize must equal the borrowed context's own SerializedSize, since TPM2_ContextLoad has no handles.");

        byte[] handles = [];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(0, handleWriter.Written, "Table 226 lists no handles, so WriteHandles must write nothing.");

        byte[] parameters = new byte[expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.AreSequenceEqual(expectedParameters, parameters, "The parameter area must reproduce the hand-computed Table 260 frame exactly.");
    }
}
