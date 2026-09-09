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
/// Byte-exact framing of <c>TPM2_RSA_Decrypt()</c>'s input against its published table (TPM 2.0 Library Part 3,
/// clause 14.3, Table 46) — one handle (<c>@keyHandle</c>, Auth Index 1, Auth Role USER) followed by
/// <c>cipherText</c> as a <c>TPM2B_PUBLIC_KEY_RSA</c>, <c>inScheme</c> as a <c>TPMT_RSA_DECRYPT</c>, and
/// <c>label</c> as a <c>TPM2B_DATA</c> — plus its raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row, and its
/// response's parse (Table 47: one <c>TPM2B_PUBLIC_KEY_RSA</c>).
/// </summary>
[TestClass]
internal sealed class RsaDecryptInputFramingTests
{
    /// <summary>The <c>keyHandle</c> the frames carry.</summary>
    private static TpmiDhObject KeyHandle { get; } = TpmiDhObject.FromValue(0x8000_0001);

    /// <summary>
    /// Table 46's handle area is <c>@keyHandle</c> alone, a four-octet <c>TPMI_DH_OBJECT</c>; its parameter
    /// area under an OAEP <c>inScheme</c> is <c>cipherText</c> then the four-octet OAEP(SHA-256) scheme then a
    /// non-empty <c>label</c> — "the label whose association with the message is to be verified" carries the
    /// same terminating-zero rule as the encrypt side.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.3</see>.
    /// </summary>
    [TestMethod]
    public void RsaDecryptInputFramesTheOaepFormByteExactlyPerTable46()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa cipherText = Tpm2bPublicKeyRsa.Create([0x11, 0x22, 0x33], pool);
        using Tpm2bData label = Tpm2bData.Create([0x54, 0x45, 0x53, 0x54, 0x00], pool);
        var input = new RsaDecryptInput(KeyHandle, cipherText, TpmtRsaDecrypt.Oaep(TpmAlgIdConstants.TPM_ALG_SHA256), label);

        AssertFraming(
            input,
            [0x80, 0x00, 0x00, 0x01],
            [0x00, 0x03, 0x11, 0x22, 0x33, 0x00, 0x17, 0x00, 0x0B, 0x00, 0x05, 0x54, 0x45, 0x53, 0x54, 0x00]);
    }

    /// <summary>
    /// The RSAES form: Table 190's <c>rsaes</c> arm is <c>TPMS_EMPTY</c>, so <c>inScheme</c> frames as the bare
    /// two-octet selector, and an absent <c>label</c> frames as its size field alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.3</see>.
    /// </summary>
    [TestMethod]
    public void RsaDecryptInputFramesTheRsaesFormWithNoLabelByteExactlyPerTable46()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa cipherText = Tpm2bPublicKeyRsa.Create([0xAA, 0xBB], pool);
        var input = new RsaDecryptInput(KeyHandle, cipherText, TpmtRsaDecrypt.RsaEs, Tpm2bData.Empty);

        AssertFraming(input, [0x80, 0x00, 0x00, 0x01], [0x00, 0x02, 0xAA, 0xBB, 0x00, 0x15, 0x00, 0x00]);
    }

    /// <summary>
    /// The NULL form: "the returned value is an unsigned integer value that is the result of the modular
    /// exponentiation of cipherText using the private exponent of keyHandle" — <c>inScheme</c> frames as the
    /// bare selector, and <c>label</c> is absent.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.3</see>.
    /// </summary>
    [TestMethod]
    public void RsaDecryptInputFramesTheNullFormWithNoLabelByteExactlyPerTable46()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa cipherText = Tpm2bPublicKeyRsa.Create([0xCC], pool);
        var input = new RsaDecryptInput(KeyHandle, cipherText, TpmtRsaDecrypt.Null, Tpm2bData.Empty);

        AssertFraming(input, [0x80, 0x00, 0x00, 0x01], [0x00, 0x01, 0xCC, 0x00, 0x10, 0x00, 0x00]);
    }

    /// <summary>
    /// Table 46's <c>commandCode</c> row is <c>TPM_CC_RSA_Decrypt</c>, whose assigned value in Part 2's listing
    /// of command codes is 0x00000159; the row carries no <c>{NV}</c> decoration.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 14.3</see>.
    /// </summary>
    [TestMethod]
    public void RsaDecryptCommandCodeEqualsTheRawValueListedInTable12()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa cipherText = Tpm2bPublicKeyRsa.Create([0xAA], pool);
        var input = new RsaDecryptInput(KeyHandle, cipherText, TpmtRsaDecrypt.RsaEs, Tpm2bData.Empty);

        Assert.AreEqual(TpmCcConstants.TPM_CC_RSA_Decrypt, input.CommandCode);
        Assert.AreEqual(0x00000159u, (uint)input.CommandCode, "TPM_CC_RSA_Decrypt must equal Table 12's raw value 0x00000159.");
    }

    /// <summary>
    /// "Any first parameter can be encrypted as long as the parameter has a size field" (Part 1, clause 18.1):
    /// <c>cipherText</c> is a <c>TPM2B_PUBLIC_KEY_RSA</c>, so the command's first parameter is encryptable; and
    /// <c>keyHandle</c> names an RSA key, never a sequence context.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 14.3</see>.
    /// </summary>
    [TestMethod]
    public void RsaDecryptInputMarksItsFirstParameterEncryptableAndItsHandleNeverNamesASequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using Tpm2bPublicKeyRsa cipherText = Tpm2bPublicKeyRsa.Create([0xAA], pool);
        ITpmCommandInput input = new RsaDecryptInput(KeyHandle, cipherText, TpmtRsaDecrypt.RsaEs, Tpm2bData.Empty);

        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "cipherText is a TPM2B_PUBLIC_KEY_RSA, a sized first parameter a decrypt session may protect.");
        Assert.IsFalse(input.HandleIsSequence(0), "keyHandle names an RSA key, never a sequence object.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_RSA_Decrypt</c> takes the one handle of
    /// Table 46 with Auth Index 1, is not <c>{NV}</c>, is not flushed, and returns no response handle (Table
    /// 47); its COMMAND_INDEX is the low 16 bits of 0x00000159.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 14.3</see>.
    /// </summary>
    [TestMethod]
    public void RsaDecryptCommandAttributesCarryOneHandleAndNoResponseHandle()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_RSA_Decrypt.GetCommandAttributes();

        Assert.AreEqual((byte)1, attributes.C_HANDLES, "Table 46 lists @keyHandle alone.");
        Assert.IsFalse(attributes.R_HANDLE, "Table 47 returns no handle.");
        Assert.IsFalse(attributes.NV, "TPM2_RSA_Decrypt carries no {NV} decoration.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.AreEqual((ushort)0x0159, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response codec declares Table 47's shape: no output handle, a parameter area (<c>message</c>), and —
    /// since <c>message</c> is a sized buffer — a response an encrypt session may protect (Part 1, clause 18.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.3; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void RsaDecryptCodecDeclaresNoHandleAndAnEncryptableMessage()
    {
        TpmResponseCodec codec = TpmResponseCodec.RsaDecrypt;

        Assert.AreEqual(0, codec.OutHandleCount, "Table 47 returns no handle.");
        Assert.IsTrue(codec.HasResponseParameters, "Table 47 returns message.");
        Assert.IsTrue(codec.ResponseFirstParameterIsEncryptable, "message is a TPM2B_PUBLIC_KEY_RSA, a sized first response parameter an encrypt session may protect.");
    }

    /// <summary>
    /// Table 47's response parses to the <c>TPM2B_PUBLIC_KEY_RSA</c> the wire carried, octet for octet — the
    /// parser <see cref="TpmResponseCodec.RsaDecrypt"/> installs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.3</see>.
    /// </summary>
    [TestMethod]
    public void RsaDecryptResponseParsesMessageByteExactlyPerTable47()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] parameters = [0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        var reader = new TpmReader(parameters);

        using RsaDecryptResponse response = RsaDecryptResponse.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "The parse consumes exactly the TPM2B_PUBLIC_KEY_RSA.");
        Assert.AreEqual(4, response.Message.Size, "message carries the four wire octets.");
        ReadOnlySpan<byte> expectedOctets = [0xDE, 0xAD, 0xBE, 0xEF];
        Assert.IsTrue(response.Message.Buffer.SequenceEqual(expectedOctets), "message's octets are the wire's.");
    }

    /// <summary>
    /// <see cref="RsaDecryptResponse.Dispose"/> releases <see cref="RsaDecryptResponse.Message"/>'s rental back
    /// to the pool it was parsed from — the recovered plaintext is cleared ahead of its release, a discipline
    /// proved directly on the underlying carrier by <c>Tpm2bPublicKeyRsaClearZeroesTheOctetsInPlace</c> in
    /// <c>TpmtRsaDecryptTests</c>, and the pool itself zeroes every returned rental regardless — observed here
    /// through a metered pool's rented and outstanding counts: disposing twice is safe, and the size a disposed
    /// <see cref="Tpm2bPublicKeyRsa"/> last reported stays readable, since only its content accessors gate on
    /// disposal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 14.3</see>.
    /// </summary>
    [TestMethod]
    public void RsaDecryptResponseDisposeReleasesTheMessageAndIsIdempotent()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        byte[] parameters = [0x00, 0x02, 0x01, 0x02];
        var reader = new TpmReader(parameters);
        long baseline = trackingPool.OutstandingCount;
        RsaDecryptResponse response = RsaDecryptResponse.Parse(ref reader, pool);

        Assert.IsGreaterThanOrEqualTo(1, trackingPool.RentedCountOfSize(2), "Parsing must rent message's two octets from the injected house pool.");
        Assert.AreEqual(baseline + 1, trackingPool.OutstandingCount, "The parsed message is outstanding until the response is disposed.");

        response.Dispose();
        response.Dispose();

        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "Disposing the response releases message's rental; the second Dispose() call above is the idempotence this test proves and must not throw.");
        Assert.AreEqual(2, response.Message.Size, "Size stays reportable after disposal.");
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle area and parameter area into freshly-sized buffers and asserts
    /// each reproduces its hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for both together.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(RsaDecryptInput input, byte[] expectedHandles, byte[] expectedParameters)
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
