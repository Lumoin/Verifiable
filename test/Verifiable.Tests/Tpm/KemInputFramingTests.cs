using System;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire-format tests for <see cref="EncapsulateInput"/> (TPM2_Encapsulate, Table 60) and
/// <see cref="DecapsulateInput"/> (TPM2_Decapsulate, Table 62), asserting the handle and parameter areas each
/// frames against hand-computed big-endian octets, mirroring <see cref="SignDigestInputFramingTests"/>'s
/// wire-format style for <see cref="ITpmCommandInput"/> types.
/// </summary>
[TestClass]
internal sealed class KemInputFramingTests
{
    /// <summary>
    /// <see cref="EncapsulateInput.ForHandle"/> frames ONLY <c>keyHandle</c> — Table 60 carries no command
    /// parameters at all, so the parameter area is empty
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.10, Table 60). The command's own tag is chosen by the
    /// executor from whatever sessions the caller attaches (ordinarily <c>TPM_ST_NO_SESSIONS</c>, since
    /// <c>keyHandle</c> needs no authorization at all — Auth Index None) and is not part of what this type
    /// frames.
    /// </summary>
    [TestMethod]
    public void EncapsulateInputForHandleFramesTheKeyHandleOnlyByteExactly()
    {
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000005u);

        EncapsulateInput input = EncapsulateInput.ForHandle(keyHandle);

        Assert.AreEqual(TpmCcConstants.TPM_CC_Encapsulate, input.CommandCode);
        Assert.IsFalse(input.FirstCommandParameterIsEncryptable, "Table 60 carries no parameters at all, so there is no first parameter to be encryption-eligible.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x05];
        byte[] expectedParameters = [];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="DecapsulateInput.Create"/> frames <c>@keyHandle</c> then <c>ciphertext</c>
    /// (<c>TPM2B_KEM_CIPHERTEXT</c>) as its whole parameter area
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.11, Table 62). Table 62 pins the command's tag to
    /// <c>TPM_ST_SESSIONS</c> because <c>@keyHandle</c> requires authorization, but that tag is the
    /// executor's choice once the caller supplies the session — not part of what this type frames itself
    /// (contrast <see cref="EncapsulateInputForHandleFramesTheKeyHandleOnlyByteExactly"/>).
    /// </summary>
    [TestMethod]
    public void DecapsulateInputCreateFramesTheKeyHandleAndCiphertextByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000006u);
        byte[] ciphertext = [0x04, 0xAA, 0xBB, 0xCC, 0xDD]; //A stand-in ciphertext; framing does not validate point shape.

        using DecapsulateInput input = DecapsulateInput.Create(keyHandle, ciphertext, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_Decapsulate, input.CommandCode);
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "ciphertext is the first (and only) parameter and carries an explicit size field.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x06];
        byte[] expectedParameters =
        [
            0x00, 0x05, 0x04, 0xAA, 0xBB, 0xCC, 0xDD //ciphertext: TPM2B_KEM_CIPHERTEXT, size 5.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="DecapsulateInput.Create"/> admits an empty ciphertext, framing a zero-length TPM2B — the
    /// wire is still well-formed even though no real ciphertext this simulator produces is ever empty (a
    /// real one is always 65 octets, the SEC 1 uncompressed P-256 point width)
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 14.11, Table 62).
    /// </summary>
    [TestMethod]
    public void DecapsulateInputCreateFramesAnEmptyCiphertextByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000007u);

        using DecapsulateInput input = DecapsulateInput.Create(keyHandle, ReadOnlySpan<byte>.Empty, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x07];
        byte[] expectedParameters = [0x00, 0x00]; //ciphertext: TPM2B_KEM_CIPHERTEXT, size 0.

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle and parameter areas into freshly-sized buffers and asserts
    /// each reproduces the hand-computed octets exactly, and that
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for precisely the two areas combined.
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
        var paramWriter = new TpmWriter(parameters);
        input.WriteParameters(ref paramWriter);
        Assert.AreEqual(parameters.Length, paramWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.AreSequenceEqual(expectedParameters, parameters);
    }
}
