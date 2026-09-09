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
/// Byte-exact framing of <c>TPM2_RSA_Encrypt()</c>'s input against its published table (TPM 2.0 Library Part 3,
/// clause 14.2, Table 44) — one handle (<c>keyHandle</c>, Auth Index None) followed by <c>message</c> as a
/// <c>TPM2B_PUBLIC_KEY_RSA</c>, <c>inScheme</c> as a <c>TPMT_RSA_DECRYPT</c>, and <c>label</c> as a
/// <c>TPM2B_DATA</c> — plus its raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row, and its response's parse (Table
/// 45: one <c>TPM2B_PUBLIC_KEY_RSA</c>).
/// </summary>
[TestClass]
internal sealed class RsaEncryptInputFramingTests
{
    /// <summary>The <c>keyHandle</c> the frames carry.</summary>
    private static TpmiDhObject KeyHandle { get; } = TpmiDhObject.FromValue(0x8000_0001);

    /// <summary>
    /// Table 44's handle area is <c>keyHandle</c> alone, a four-octet <c>TPMI_DH_OBJECT</c>; its parameter area
    /// under an OAEP <c>inScheme</c> is <c>message</c> then the four-octet OAEP(SHA-256) scheme then a
    /// non-empty <c>label</c> — "The label parameter is optional. If provided (label.size != 0) then the TPM
    /// shall return TPM_RC_VALUE if the last octet in label is not zero. The terminating octet of zero is
    /// included in the label used in the padding scheme."
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public void RsaEncryptInputFramesTheOaepFormByteExactlyPerTable44()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa message = Tpm2bPublicKeyRsa.Create([0x11, 0x22, 0x33], pool);
        using Tpm2bData label = Tpm2bData.Create([0x54, 0x45, 0x53, 0x54, 0x00], pool);
        var input = new RsaEncryptInput(KeyHandle, message, TpmtRsaDecrypt.Oaep(TpmAlgIdConstants.TPM_ALG_SHA256), label);

        AssertFraming(
            input,
            [0x80, 0x00, 0x00, 0x01],
            [0x00, 0x03, 0x11, 0x22, 0x33, 0x00, 0x17, 0x00, 0x0B, 0x00, 0x05, 0x54, 0x45, 0x53, 0x54, 0x00]);
    }

    /// <summary>
    /// The RSAES form: Table 190's <c>rsaes</c> arm is <c>TPMS_EMPTY</c>, so <c>inScheme</c> frames as the bare
    /// two-octet selector, and an absent <c>label</c> frames as its size field alone ("The label parameter is
    /// optional").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public void RsaEncryptInputFramesTheRsaesFormWithNoLabelByteExactlyPerTable44()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa message = Tpm2bPublicKeyRsa.Create([0xAA, 0xBB], pool);
        var input = new RsaEncryptInput(KeyHandle, message, TpmtRsaDecrypt.RsaEs, Tpm2bData.Empty);

        AssertFraming(input, [0x80, 0x00, 0x00, 0x01], [0x00, 0x02, 0xAA, 0xBB, 0x00, 0x15, 0x00, 0x00]);
    }

    /// <summary>
    /// The NULL form: "TPM_ALG_NULL - Data is not padded by the TPM and the TPM will treat message as an
    /// unsigned integer and perform a modular exponentiation of message using the public exponent of the key
    /// referenced by keyHandle" — <c>inScheme</c> frames as the bare selector, and <c>label</c> is absent.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public void RsaEncryptInputFramesTheNullFormWithNoLabelByteExactlyPerTable44()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa message = Tpm2bPublicKeyRsa.Create([0xCC], pool);
        var input = new RsaEncryptInput(KeyHandle, message, TpmtRsaDecrypt.Null, Tpm2bData.Empty);

        AssertFraming(input, [0x80, 0x00, 0x00, 0x01], [0x00, 0x01, 0xCC, 0x00, 0x10, 0x00, 0x00]);
    }

    /// <summary>
    /// Table 44's <c>commandCode</c> row is <c>TPM_CC_RSA_Encrypt</c>, whose assigned value in Part 2's listing
    /// of command codes is 0x00000174; the row carries no <c>{NV}</c> decoration.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public void RsaEncryptCommandCodeEqualsTheRawValueListedInTable12()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa message = Tpm2bPublicKeyRsa.Create([0xAA], pool);
        var input = new RsaEncryptInput(KeyHandle, message, TpmtRsaDecrypt.RsaEs, Tpm2bData.Empty);

        Assert.AreEqual(TpmCcConstants.TPM_CC_RSA_Encrypt, input.CommandCode);
        Assert.AreEqual(0x00000174u, (uint)input.CommandCode, "TPM_CC_RSA_Encrypt must equal Table 12's raw value 0x00000174.");
    }

    /// <summary>
    /// "Any first parameter can be encrypted as long as the parameter has a size field" (Part 1, clause 18.1):
    /// <c>message</c> is a <c>TPM2B_PUBLIC_KEY_RSA</c>, so the command's first parameter is encryptable; and
    /// <c>keyHandle</c> names an RSA key, never a sequence context.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public void RsaEncryptInputMarksItsFirstParameterEncryptableAndItsHandleNeverNamesASequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa message = Tpm2bPublicKeyRsa.Create([0xAA], pool);
        ITpmCommandInput input = new RsaEncryptInput(KeyHandle, message, TpmtRsaDecrypt.RsaEs, Tpm2bData.Empty);

        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "message is a TPM2B_PUBLIC_KEY_RSA, a sized first parameter a decrypt session may protect.");
        Assert.IsFalse(input.HandleIsSequence(0), "keyHandle names an RSA key, never a sequence object.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_RSA_Encrypt</c> takes the one handle of
    /// Table 44 with Auth Index None, is not <c>{NV}</c>, is not flushed, and returns no response handle (Table
    /// 45); its COMMAND_INDEX is the low 16 bits of 0x00000174.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public void RsaEncryptCommandAttributesCarryOneHandleAndNoResponseHandle()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_RSA_Encrypt.GetCommandAttributes();

        Assert.AreEqual((byte)1, attributes.C_HANDLES, "Table 44 lists keyHandle alone.");
        Assert.IsFalse(attributes.R_HANDLE, "Table 45 returns no handle.");
        Assert.IsFalse(attributes.NV, "TPM2_RSA_Encrypt carries no {NV} decoration.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.AreEqual((ushort)0x0174, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response codec declares Table 45's shape: no output handle, a parameter area (<c>outData</c>), and —
    /// since <c>outData</c> is a sized buffer — a response an encrypt session may protect (Part 1, clause 18.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void RsaEncryptCodecDeclaresNoHandleAndAnEncryptableOutData()
    {
        TpmResponseCodec codec = TpmResponseCodec.RsaEncrypt;

        Assert.AreEqual(0, codec.OutHandleCount, "Table 45 returns no handle.");
        Assert.IsTrue(codec.HasResponseParameters, "Table 45 returns outData.");
        Assert.IsTrue(codec.ResponseFirstParameterIsEncryptable, "outData is a TPM2B_PUBLIC_KEY_RSA, a sized first response parameter an encrypt session may protect.");
    }

    /// <summary>
    /// Table 45's response parses to the <c>TPM2B_PUBLIC_KEY_RSA</c> the wire carried, octet for octet — the
    /// parser <see cref="TpmResponseCodec.RsaEncrypt"/> installs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.2</see>.
    /// </summary>
    [TestMethod]
    public void RsaEncryptResponseParsesOutDataByteExactlyPerTable45()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] parameters = [0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        var reader = new TpmReader(parameters);

        using RsaEncryptResponse response = RsaEncryptResponse.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "The parse consumes exactly the TPM2B_PUBLIC_KEY_RSA.");
        Assert.AreEqual(4, response.OutData.Size, "outData carries the four wire octets.");
        ReadOnlySpan<byte> expectedOctets = [0xDE, 0xAD, 0xBE, 0xEF];
        Assert.IsTrue(response.OutData.Buffer.SequenceEqual(expectedOctets), "outData's octets are the wire's.");
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle area and parameter area into freshly-sized buffers and asserts
    /// each reproduces its hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for both together.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(RsaEncryptInput input, byte[] expectedHandles, byte[] expectedParameters)
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
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.AreSequenceEqual(expectedParameters, parameters, "The parameter area must reproduce the hand-computed octets exactly.");
    }
}
