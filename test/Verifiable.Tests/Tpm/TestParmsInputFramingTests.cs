using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_TestParms()</c>'s input against its published table (TPM 2.0 Library Part 3,
/// clause 30.3, Table 240), plus its raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row and its response codec's
/// header-only parse (Table 241). The command carries no handles at all: the whole command body is one
/// <c>TPMT_PUBLIC_PARMS</c> — a <c>TPMI_ALG_PUBLIC</c> selector followed by the union arm that selector chooses
/// (Part 2, clause 12.2.3.10, Table 234) — and the response is the header alone.
/// </summary>
[TestClass]
internal sealed class TestParmsInputFramingTests
{
    /// <summary>
    /// Table 234's <c>type</c> is <c>TPM_ALG_RSA</c> (0x0001) and its <c>[type]parameters</c> is a
    /// <c>TPMS_RSA_PARMS</c> in Table 228's field order: <c>symmetric</c> (NULL, 0x0010, no key size or mode
    /// follows), <c>scheme</c> (RSASSA 0x0014 with hashAlg SHA-256 0x000B), <c>keyBits</c> (2048 = 0x0800) and
    /// <c>exponent</c> (a plain UINT32).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 30.3, Table 240; Part 2, clause 12.2.3.10, Table 234; clause 12.2.3.4, Table 228</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputFramesTheRsaSelectorAndItsParametersByteExactlyPerTable234()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256)))));

        Assert.AreEqual(TpmCcConstants.TPM_CC_TestParms, input.CommandCode);

        //type TPM_ALG_RSA | symmetric TPM_ALG_NULL | scheme TPM_ALG_RSASSA, SHA-256 | keyBits 2048 | exponent 0.
        AssertFraming(input, [0x00, 0x01, 0x00, 0x10, 0x00, 0x14, 0x00, 0x0B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    /// <summary>
    /// The storage-parent shape of the same selector: a non-NULL <c>symmetric</c> in Table 163's three fields
    /// (algorithm AES 0x0006, keyBits 128 = 0x0080, mode CFB 0x0043) and a NULL <c>scheme</c>, proving the
    /// symmetric union arms occupy the wire only when the algorithm is not <c>TPM_ALG_NULL</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.7, Table 163; clause 12.2.3.4, Table 228</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputFramesTheRsaStorageParentSymmetricFieldsByteExactlyPerTable163()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForStorage(2048, TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)))));

        //type TPM_ALG_RSA | symmetric AES, 128, CFB | scheme TPM_ALG_NULL | keyBits 2048 | exponent 0.
        AssertFraming(input, [0x00, 0x01, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    /// <summary>
    /// Table 234's <c>type</c> is <c>TPM_ALG_ECC</c> (0x0023) and its <c>[type]parameters</c> is a
    /// <c>TPMS_ECC_PARMS</c> in Table 229's field order: <c>symmetric</c> (NULL), <c>scheme</c> (ECDSA 0x0018
    /// with hashAlg SHA-256), <c>curveID</c> (NIST P-256 = 0x0003) and <c>kdf</c> (NULL).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234; clause 12.2.3.5, Table 229; clause 11.2.5.5, Table 201</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputFramesTheEccSelectorAndItsParametersByteExactlyPerTable234()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_ECC,
            TpmuPublicParms.Ecc(TpmsEccParms.ForSigning(
                TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256)))));

        //type TPM_ALG_ECC | symmetric TPM_ALG_NULL | scheme TPM_ALG_ECDSA, SHA-256 | curveID P-256 | kdf TPM_ALG_NULL.
        AssertFraming(input, [0x00, 0x23, 0x00, 0x10, 0x00, 0x18, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x10]);
    }

    /// <summary>
    /// Table 234's <c>type</c> is <c>TPM_ALG_KEYEDHASH</c> (0x0008) and its <c>[type]parameters</c> is a
    /// <c>TPMS_KEYEDHASH_PARMS</c> whose <c>scheme</c> selector (HMAC 0x0005) chooses a <c>TPMS_SCHEME_HMAC</c>
    /// carrying its <c>hashAlg</c> alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234; clause 11.1.19, Table 175; clause 12.2.3.3, Table 227</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputFramesTheKeyedHashSelectorAndItsHmacSchemeByteExactlyPerTable234()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH,
            TpmuPublicParms.KeyedHash(TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA256))));

        //type TPM_ALG_KEYEDHASH | scheme TPM_ALG_HMAC | hashAlg SHA-256.
        AssertFraming(input, [0x00, 0x08, 0x00, 0x05, 0x00, 0x0B]);
    }

    /// <summary>
    /// "The TPM_ALG_NULL hashAlg now returns TPM_RC_HASH" belongs to the XOR scheme's judgment, not to its
    /// framing: Table 177's <c>TPMS_SCHEME_XOR</c> puts <c>hashAlg</c> and then <c>kdf</c> on the wire, so the
    /// XOR arm is three octet pairs after the selector — the third being the <c>TPMI_ALG_KDF+</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.21, Table 177; clause 9.36, Table 82</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputFramesTheKeyedHashXorSchemeWithItsHashAndKdfByteExactlyPerTable177()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH,
            TpmuPublicParms.KeyedHash(TpmsKeyedHashParms.Xor(
                TpmAlgIdConstants.TPM_ALG_SHA256, TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108))));

        //type TPM_ALG_KEYEDHASH | scheme TPM_ALG_XOR | hashAlg SHA-256 | kdf TPM_ALG_KDF1_SP800_108.
        AssertFraming(input, [0x00, 0x08, 0x00, 0x0A, 0x00, 0x0B, 0x00, 0x22]);
    }

    /// <summary>
    /// The <c>TPM_ALG_NULL</c> keyed-hash scheme is a sealed data object: Table 175 carries the leading <c>+</c>,
    /// so the selector is admitted and chooses an empty union arm — the parameter area is the two selector pairs
    /// alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.19, Table 175; clause 12.2.3.3, Table 227</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputFramesTheKeyedHashNullSchemeAsTheSelectorsAloneByteExactly()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH,
            TpmuPublicParms.KeyedHash(TpmsKeyedHashParms.SealedData)));

        //type TPM_ALG_KEYEDHASH | scheme TPM_ALG_NULL, with no details.
        AssertFraming(input, [0x00, 0x08, 0x00, 0x10]);
    }

    /// <summary>
    /// Table 234's <c>type</c> is <c>TPM_ALG_SYMCIPHER</c> (0x0025) and its <c>[type]parameters</c> is a
    /// <c>TPMS_SYMCIPHER_PARMS</c> — "the parameters for a symmetric block cipher object" — whose single
    /// <c>TPMT_SYM_DEF_OBJECT</c> field frames the algorithm, key size and mode. The selector is a member of
    /// Table 225 whatever a given TPM implements, so a caller can always frame the question.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234; clause 11.1.9, Table 165; clause 12.2.2, Table 225</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputFramesTheSymCipherSelectorAndItsParametersByteExactlyPerTable165()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_SYMCIPHER,
            TpmuPublicParms.SymCipher(TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB)))));

        //type TPM_ALG_SYMCIPHER | sym AES, 128, CFB.
        AssertFraming(input, [0x00, 0x25, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43]);
    }

    /// <summary>
    /// Table 234's <c>type</c> is <c>TPM_ALG_MLDSA</c> (0x00A1) and its <c>[type]parameters</c> is a
    /// <c>TPMS_MLDSA_PARMS</c>: the parameter set (ML-DSA-65 = 0x0002) then the single external-mu octet.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234; clause 12.2.2, Table 225</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputFramesTheMlDsaSelectorAndItsParametersByteExactlyPerTable234()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_MLDSA, TpmuPublicParms.MlDsa(TpmsMlDsaParms.MlDsa65())));

        //type TPM_ALG_MLDSA | parameterSet ML-DSA-65 | allowExternalMu CLEAR.
        AssertFraming(input, [0x00, 0xA1, 0x00, 0x02, 0x00]);
    }

    /// <summary>
    /// Table 234's <c>type</c> is <c>TPM_ALG_HASH_MLDSA</c> (0x00A2) and its <c>[type]parameters</c> is a
    /// <c>TPMS_HASH_MLDSA_PARMS</c>: the parameter set then the pre-hash algorithm (SHA-384 = 0x000C).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234; clause 12.2.2, Table 225</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputFramesTheHashMlDsaSelectorAndItsParametersByteExactlyPerTable234()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_HASH_MLDSA, TpmuPublicParms.HashMlDsa(TpmsHashMlDsaParms.HashMlDsa65Sha384())));

        //type TPM_ALG_HASH_MLDSA | parameterSet ML-DSA-65 | hashAlg SHA-384.
        AssertFraming(input, [0x00, 0xA2, 0x00, 0x02, 0x00, 0x0C]);
    }

    /// <summary>
    /// Table 234's <c>type</c> is <c>TPM_ALG_MLKEM</c> (0x00A0) and its <c>[type]parameters</c> is a
    /// <c>TPMS_MLKEM_PARMS</c>: the <c>TPMT_SYM_DEF_OBJECT</c> first, then the parameter set (ML-KEM-768 =
    /// 0x0002).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234; clause 12.2.2, Table 225</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputFramesTheMlKemSelectorAndItsParametersByteExactlyPerTable234()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_MLKEM,
            TpmuPublicParms.MlKem(TpmsMlKemParms.Create(TpmtSymDefObject.Null, TpmMlKemParameterSet.TPM_MLKEM_768))));

        //type TPM_ALG_MLKEM | symmetric TPM_ALG_NULL | parameterSet ML-KEM-768.
        AssertFraming(input, [0x00, 0xA0, 0x00, 0x10, 0x00, 0x02]);
    }

    /// <summary>
    /// Table 240's <c>commandCode</c> row is <c>TPM_CC_TestParms</c> — with no <c>{NV}</c> decoration — whose
    /// assigned value in Part 2's listing of command codes is 0x0000018A.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 30.3, Table 240</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsCommandCodeEqualsTheRawValueListedInTable12()
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH, TpmuPublicParms.KeyedHash(TpmsKeyedHashParms.SealedData)));

        Assert.AreEqual(TpmCcConstants.TPM_CC_TestParms, input.CommandCode);
        Assert.AreEqual(0x0000018Au, (uint)input.CommandCode, "TPM_CC_TestParms must equal Table 12's raw value 0x0000018A.");
    }

    /// <summary>
    /// Table 240 lists no handles at all, so the handle area is empty and
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for the <c>TPMT_PUBLIC_PARMS</c> alone —
    /// exactly the selector plus the union arm the selector chooses, for every selector Table 225 admits.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 30.3, Table 240; Part 2, clause 12.2.3.10, Table 234</see>.
    /// </summary>
    /// <param name="type">The <c>TPMI_ALG_PUBLIC</c> selector under test.</param>
    /// <param name="expectedSize">The hand-computed width of the whole parameter area.</param>
    [TestMethod]
    [DataRow(TpmAlgIdConstants.TPM_ALG_RSA, 14)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_KEYEDHASH, 6)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_ECC, 12)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_SYMCIPHER, 8)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_MLDSA, 5)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_HASH_MLDSA, 6)]
    [DataRow(TpmAlgIdConstants.TPM_ALG_MLKEM, 6)]
    public void TestParmsInputGetSerializedSizeAccountsForTheParametersAloneForEverySelector(TpmAlgIdConstants type, int expectedSize)
    {
        var input = new TestParmsInput(TpmtPublicParms.Create(type, CreateParametersFor(type)));

        Assert.AreEqual(expectedSize, input.GetSerializedSize(),
            $"TPM2_TestParms has no handle area, so its serialized size for '{type}' is the TPMT_PUBLIC_PARMS alone.");

        byte[] handles = [];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);

        Assert.AreEqual(0, handleWriter.Written, "Table 240 lists no handles, so WriteHandles must write nothing.");
    }

    /// <summary>
    /// "If session-based encryption is allowed, only the first parameter in the parameter area of a request or
    /// response can be encrypted. That parameter must have an explicit size field." (Part 1, clause 18.1) —
    /// Part 2's Table 234's <c>TPMT_PUBLIC_PARMS</c> is a plain structure with no size field, so the command's first
    /// parameter is not encryptable, and no handle exists that could name a sequence object.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 30.3, Table 240</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsInputMarksNoParameterEncryptableAndHasNoSequenceHandle()
    {
        ITpmCommandInput input = new TestParmsInput(TpmtPublicParms.Create(
            TpmAlgIdConstants.TPM_ALG_RSA,
            TpmuPublicParms.Rsa(TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256)))));

        Assert.IsFalse(input.FirstCommandParameterIsEncryptable, "TPMT_PUBLIC_PARMS has no size field, so it cannot be encrypted.");
        Assert.IsFalse(input.HandleIsSequence(0), "TPM2_TestParms has no handles, so no handle names a sequence object.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_TestParms</c> takes the zero handles of
    /// Table 240, is not <c>{NV}</c> — Table 240's <c>commandCode</c> row carries no such decoration, unlike
    /// <c>TPM_CC_ClockSet {NV}</c> — is not flushed, and returns no response handle; its COMMAND_INDEX is the
    /// low 16 bits of 0x0000018A.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 30.3, Table 240</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsCommandAttributesCarryNoHandlesAndNoNvBit()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_TestParms.GetCommandAttributes();

        Assert.AreEqual((byte)0, attributes.C_HANDLES, "Table 240 lists no handles.");
        Assert.IsFalse(attributes.NV, "TPM2_TestParms carries no {NV} decoration.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.IsFalse(attributes.R_HANDLE, "TPM2_TestParms returns no response handle.");
        Assert.AreEqual((ushort)0x018A, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response is the 10-byte header alone (Table 241 lists <c>tag</c>, <c>responseSize</c> and
    /// <c>responseCode</c> only): the codec declares zero output handles, no parser, and
    /// <see cref="TestParmsResponse.Instance"/> as the value a header-only success response resolves to.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 30.3, Table 241</see>.
    /// </summary>
    [TestMethod]
    public void TestParmsCodecResolvesAHeaderOnlySuccessResponseToItsOwnSingleton()
    {
        TpmResponseCodec codec = TpmResponseCodec.TestParms;

        Assert.AreEqual(0, codec.OutHandleCount, "A header-only response declares no output handles.");
        Assert.IsFalse(codec.HasResponseParameters, "A header-only response has no parser.");
        Assert.AreSame(TestParmsResponse.Instance, codec.EmptyResponse, "The codec must resolve to TPM2_TestParms's own parameterless singleton.");
    }

    /// <summary>
    /// Builds the union arm Table 233 pairs with <paramref name="type"/>, matching the combination the
    /// byte-exact cases above frame, so the size matrix and the octet matrix describe the same inputs.
    /// </summary>
    /// <param name="type">The <c>TPMI_ALG_PUBLIC</c> selector to build an arm for.</param>
    /// <returns>The union carrying that selector's arm.</returns>
    private static TpmuPublicParms CreateParametersFor(TpmAlgIdConstants type) => type switch
    {
        TpmAlgIdConstants.TPM_ALG_RSA => TpmuPublicParms.Rsa(
            TpmsRsaParms.ForSigning(2048, TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256))),
        TpmAlgIdConstants.TPM_ALG_KEYEDHASH => TpmuPublicParms.KeyedHash(
            TpmsKeyedHashParms.Hmac(TpmAlgIdConstants.TPM_ALG_SHA256)),
        TpmAlgIdConstants.TPM_ALG_ECC => TpmuPublicParms.Ecc(
            TpmsEccParms.ForSigning(TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256))),
        TpmAlgIdConstants.TPM_ALG_SYMCIPHER => TpmuPublicParms.SymCipher(
            TpmsSymcipherParms.Create(TpmtSymDefObject.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB))),
        TpmAlgIdConstants.TPM_ALG_MLDSA => TpmuPublicParms.MlDsa(TpmsMlDsaParms.MlDsa65()),
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => TpmuPublicParms.HashMlDsa(TpmsHashMlDsaParms.HashMlDsa65Sha384()),
        _ => TpmuPublicParms.MlKem(TpmsMlKemParms.Create(TpmtSymDefObject.Null, TpmMlKemParameterSet.TPM_MLKEM_768))
    };

    /// <summary>
    /// Frames <paramref name="input"/>'s empty handle area and its parameter area into freshly-sized buffers and
    /// asserts the parameter octets reproduce the hand-computed frame exactly, and that
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for precisely those octets — no handle area
    /// exists to add.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(TestParmsInput input, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedParameters.Length, input.GetSerializedSize(),
            "GetSerializedSize must account for exactly the parameter area, since TPM2_TestParms has no handles.");

        byte[] parameters = new byte[expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.AreSequenceEqual(expectedParameters, parameters, "The parameter area must reproduce the hand-computed octets exactly.");
    }
}
