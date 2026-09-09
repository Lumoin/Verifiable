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
/// Byte-exact framing of <c>TPM2_LoadExternal()</c>'s input against its published table (TPM 2.0 Library Part 3,
/// clause 12.3, Table 22) — <c>inPrivate</c> as a <c>TPM2B_SENSITIVE</c> (size 0 for the public-only form),
/// <c>inPublic</c> as a <c>TPM2B_PUBLIC</c>, <c>hierarchy</c> as a <c>TPMI_RH_HIERARCHY</c>, and no handle area
/// at all — plus its raw <c>TPM_CC</c> pin, its <c>TPMA_CC</c> row, and its response's parse (Table 23: a handle
/// and a <c>TPM2B_NAME</c>).
/// </summary>
[TestClass]
internal sealed class LoadExternalInputFramingTests
{
    /// <summary>The Name algorithm the framed public areas name.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The attribute word of a sealed data object: <c>userWithAuth</c> and <c>noDA</c> (0x00000440).</summary>
    private const TpmaObject SealedAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA;

    /// <summary>The attribute word of an unrestricted signing key: <c>userWithAuth</c>, <c>noDA</c> and <c>sign</c> (0x00040440).</summary>
    private const TpmaObject SigningAttributes = TpmaObject.USER_WITH_AUTH | TpmaObject.NO_DA | TpmaObject.SIGN_ENCRYPT;

    /// <summary>
    /// The <c>TPM2B_PUBLIC</c> octets of a sealed data template (Part 2, clause 12.2.4, Table 235): size 14, type
    /// <c>TPM_ALG_KEYEDHASH</c> (0x0008), nameAlg SHA-256 (0x000B), the attribute word, an empty
    /// <c>authPolicy</c>, a NULL keyed-hash scheme (0x0010), and an empty <c>unique</c>.
    /// </summary>
    private static byte[] SealedPublicOctets { get; } = [0x00, 0x0E, 0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x04, 0x40, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00];

    /// <summary>
    /// The <c>TPM2B_PUBLIC</c> octets of an RSA-2048 unrestricted signing template with a NULL scheme (Part 2,
    /// Table 235; Table 228's <c>TPMS_RSA_PARMS</c>): size 22, type <c>TPM_ALG_RSA</c> (0x0001), nameAlg SHA-256,
    /// the attribute word, an empty <c>authPolicy</c>, symmetric NULL, scheme NULL, keyBits 2048, exponent 0,
    /// and an empty <c>unique</c>.
    /// </summary>
    private static byte[] RsaPublicOctets { get; } = [0x00, 0x16, 0x00, 0x01, 0x00, 0x0B, 0x00, 0x04, 0x04, 0x40, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    /// <summary>
    /// The <c>TPM2B_PUBLIC</c> octets of an ECC P-256 ECDSA-SHA-256 signing template (Part 2, Table 235; Table
    /// 229's <c>TPMS_ECC_PARMS</c>): size 24, type <c>TPM_ALG_ECC</c> (0x0023), nameAlg SHA-256, the attribute
    /// word, an empty <c>authPolicy</c>, symmetric NULL, scheme ECDSA (0x0018) with SHA-256, curveID P-256
    /// (0x0003), kdf NULL, and an empty <c>unique</c> point (two empty coordinates).
    /// </summary>
    private static byte[] EccPublicOctets { get; } = [0x00, 0x18, 0x00, 0x23, 0x00, 0x0B, 0x00, 0x04, 0x04, 0x40, 0x00, 0x00, 0x00, 0x10, 0x00, 0x18, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00];

    /// <summary>
    /// Table 22's public-only form: <c>inPrivate</c> is a <c>TPM2B_SENSITIVE</c> of size zero (<c>00 00</c>),
    /// then <c>inPublic</c> whole, then <c>hierarchy</c> as the four octets of <c>TPM_RH_OWNER</c> (0x40000001,
    /// Part 2, clause 7.4, Table 34) — and no handle area precedes them.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 22; Part 2, clause 12.3.3, Table 241</see>.
    /// </summary>
    [TestMethod]
    public void LoadExternalInputFramesThePublicOnlyFormByteExactlyPerTable22()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using LoadExternalInput input = PublicOnlySealedInput(pool);

        Assert.IsNull(input.InPrivate, "The public-only factory carries no sensitive area.");
        AssertFraming(input, [0x00, 0x00, .. SealedPublicOctets, 0x40, 0x00, 0x00, 0x01]);
    }

    /// <summary>
    /// Table 22's full form with a KEYEDHASH sensitive area (Part 2, clause 12.3.2, Table 240):
    /// <c>inPrivate</c> is <c>TPM2B_SENSITIVE(size 12 ‖ sensitiveType KEYEDHASH ‖ TPM2B_AUTH(empty) ‖
    /// TPM2B_DIGEST(empty) ‖ TPM2B_SENSITIVE_DATA(01 02 03 04))</c>, then <c>inPublic</c>, then
    /// <c>TPM_RH_NULL</c> (0x40000007).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 22; Part 2, clause 12.3.2, Table 240</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the sensitive area's carriers transfers to the input, disposed at the end of the test.")]
    public void LoadExternalInputFramesTheKeyedHashSensitiveFormByteExactlyPerTable240()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmtSensitive inPrivate = TpmtSensitive.ForKeyedHash(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, Tpm2bSensitiveData.Create([0x01, 0x02, 0x03, 0x04], pool));
        using var input = new LoadExternalInput(inPrivate, SealedTemplate(pool), TpmiRhHierarchy.Null);

        AssertFraming(input, [0x00, 0x0C, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, .. SealedPublicOctets, 0x40, 0x00, 0x00, 0x07]);
    }

    /// <summary>
    /// Table 22's full form with an RSA sensitive area: the <c>TPMU_SENSITIVE_COMPOSITE</c> arm is a
    /// <c>TPM2B_PRIVATE_KEY_RSA</c> (Part 2, clause 11.2.4.8, Table 196) — here two octets, the framing knowing
    /// nothing of the prime rules — under the <c>TPM_ALG_RSA</c> selector (0x0001).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 22; Part 2, clause 12.3.2, Tables 239 and 240</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the sensitive area's carriers transfers to the input, disposed at the end of the test.")]
    public void LoadExternalInputFramesTheRsaSensitiveFormByteExactlyPerTable240()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var inPrivate = new TpmtSensitive(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, TpmuSensitiveComposite.FromRsa(Tpm2bPrivateKeyRsa.Create([0xCC, 0xDD], pool)));
        using var input = new LoadExternalInput(inPrivate, Tpm2bPublic.CreateRsaSigningTemplate(NameAlg, SigningAttributes, 2048, TpmtRsaScheme.Null), TpmiRhHierarchy.Null);

        AssertFraming(input, [0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xCC, 0xDD, .. RsaPublicOctets, 0x40, 0x00, 0x00, 0x07]);
    }

    /// <summary>
    /// Table 22's full form with an ECC sensitive area: the <c>TPMU_SENSITIVE_COMPOSITE</c> arm is a
    /// <c>TPM2B_ECC_PARAMETER</c> (Part 2, clause 11.2.5.1, Table 197) under the <c>TPM_ALG_ECC</c> selector
    /// (0x0023).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 22; Part 2, clause 12.3.2, Tables 239 and 240</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the sensitive area's carriers transfers to the input, disposed at the end of the test.")]
    public void LoadExternalInputFramesTheEccSensitiveFormByteExactlyPerTable240()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var inPrivate = new TpmtSensitive(Tpm2bAuth.CreateEmpty(pool), Tpm2bDigest.Empty, TpmuSensitiveComposite.FromEcc(Tpm2bEccParameter.Create([0xAA, 0xBB], pool)));
        using var input = new LoadExternalInput(inPrivate, Tpm2bPublic.CreateEccSigningTemplate(NameAlg, SigningAttributes, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(NameAlg)), TpmiRhHierarchy.Null);

        AssertFraming(input, [0x00, 0x0A, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, .. EccPublicOctets, 0x40, 0x00, 0x00, 0x07]);
    }

    /// <summary>
    /// Table 22's <c>commandCode</c> row is <c>TPM_CC_LoadExternal</c>, whose assigned value in Part 2's listing
    /// of command codes is 0x00000167; the row carries no <c>{NV}</c> decoration.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 12.3, Table 22</see>.
    /// </summary>
    [TestMethod]
    public void LoadExternalCommandCodeEqualsTheRawValueListedInTable12()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using LoadExternalInput input = PublicOnlySealedInput(pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_LoadExternal, input.CommandCode);
        Assert.AreEqual(0x00000167u, (uint)input.CommandCode, "TPM_CC_LoadExternal must equal Table 12's raw value 0x00000167.");
    }

    /// <summary>
    /// "Any first parameter can be encrypted as long as the parameter has a size field" (Part 1, clause 18.1):
    /// <c>inPrivate</c> is a <c>TPM2B_SENSITIVE</c>, a sized buffer, so the command's first parameter is
    /// encryptable; and the command has no handle that could name a sequence object.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 12.3, Table 22</see>.
    /// </summary>
    [TestMethod]
    public void LoadExternalInputMarksItsFirstParameterEncryptableAndHasNoSequenceHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using LoadExternalInput input = PublicOnlySealedInput(pool);
        ITpmCommandInput commandInput = input;

        Assert.IsTrue(commandInput.FirstCommandParameterIsEncryptable, "inPrivate is a TPM2B_SENSITIVE, a sized first parameter a decrypt session may protect.");
        Assert.IsFalse(commandInput.HandleIsSequence(0), "TPM2_LoadExternal() has no handles, so no handle names a sequence object.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> row (Part 2, clause 8.9, Table 43): <c>TPM2_LoadExternal</c> takes the zero handles of
    /// Table 22, is not <c>{NV}</c>, is not flushed, and returns the one handle of Table 23; its COMMAND_INDEX is
    /// the low 16 bits of 0x00000167.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 12.3, Tables 22 and 23</see>.
    /// </summary>
    [TestMethod]
    public void LoadExternalCommandAttributesCarryNoHandlesAndOneResponseHandle()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_LoadExternal.GetCommandAttributes();

        Assert.AreEqual((byte)0, attributes.C_HANDLES, "Table 22 lists no handles.");
        Assert.IsTrue(attributes.R_HANDLE, "Table 23 returns objectHandle.");
        Assert.IsFalse(attributes.NV, "TPM2_LoadExternal carries no {NV} decoration.");
        Assert.IsFalse(attributes.FLUSHED);
        Assert.AreEqual((ushort)0x0167, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response codec declares Table 23's shape: one output handle, a parameter area (<c>name</c>), and —
    /// since <c>name</c> is a sized buffer — a response an encrypt session may protect (Part 1, clause 18.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 23; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void LoadExternalCodecDeclaresOneHandleAndAnEncryptableName()
    {
        TpmResponseCodec codec = TpmResponseCodec.LoadExternal;

        Assert.AreEqual(1, codec.OutHandleCount, "Table 23 returns objectHandle.");
        Assert.IsTrue(codec.HasResponseParameters, "Table 23 returns name.");
        Assert.IsTrue(codec.ResponseFirstParameterIsEncryptable, "name is a TPM2B_NAME, a sized first response parameter an encrypt session may protect.");
    }

    /// <summary>
    /// Table 23's response parses to the echoed handle and the <c>TPM2B_NAME</c> — a 34-octet SHA-256 Name, or the
    /// Empty Buffer of a NULL <c>nameAlg</c> load ("If nameAlg is TPM_ALG_NULL, then the Name is the Empty
    /// Buffer", clause 12.3.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.3, Table 23</see>.
    /// </summary>
    /// <param name="isNameEmpty">Whether the framed name is the Empty Buffer.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public void LoadExternalResponseParsesTheHandleAndTheName(bool isNameEmpty)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] name = isNameEmpty ? [] : NameOctets();
        byte[] parameters = [(byte)(name.Length >> 8), (byte)name.Length, .. name];
        var reader = new TpmReader(parameters);

        using LoadExternalResponse response = LoadExternalResponse.Parse(ref reader, TpmiDhObject.FromValue(0x8000_0002), pool);

        Assert.AreEqual(0, reader.Remaining, "The parse consumes exactly the TPM2B_NAME.");
        Assert.AreEqual(0x8000_0002u, response.ObjectHandle.Value, "The response echoes the handle the response handle area carried.");
        Assert.AreEqual(isNameEmpty, response.Name.IsEmpty, "The Name is empty exactly when the wire carried a size-zero TPM2B_NAME.");
        Assert.IsTrue(response.Name.Span.SequenceEqual(name), "The Name octets are the wire's.");
    }

    /// <summary>The public-only form over the sealed data template under the owner hierarchy.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The input; the caller disposes it, and the template with it.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the template transfers to the returned input, which the caller disposes.")]
    private static LoadExternalInput PublicOnlySealedInput(BaseMemoryPool pool)
    {
        return LoadExternalInput.PublicOnly(SealedTemplate(pool), TpmiRhHierarchy.Owner);
    }

    /// <summary>A sealed data template over the memory pool.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The template; ownership transfers to the caller.</returns>
    private static Tpm2bPublic SealedTemplate(BaseMemoryPool pool) =>
        Tpm2bPublic.CreateKeyedHashTemplate(NameAlg, SealedAttributes, TpmsKeyedHashParms.SealedData, default, pool);

    /// <summary>A 34-octet SHA-256 Name: the algorithm prefix and 32 distinct digest octets.</summary>
    /// <returns>The Name octets.</returns>
    private static byte[] NameOctets()
    {
        byte[] name = new byte[2 + 32];
        name[0] = 0x00;
        name[1] = 0x0B;
        for(int index = 2; index < name.Length; index++)
        {
            name[index] = (byte)index;
        }

        return name;
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s empty handle area and its parameter area into freshly-sized buffers and
    /// asserts the parameter octets reproduce the hand-computed frame exactly, and that
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for precisely those octets — no handle area
    /// exists to add.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(LoadExternalInput input, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedParameters.Length, input.GetSerializedSize(), "GetSerializedSize must account for exactly the parameter area, since TPM2_LoadExternal has no handles.");

        byte[] handles = [];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(0, handleWriter.Written, "Table 22 lists no handles, so WriteHandles must write nothing.");

        byte[] parameters = new byte[expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.AreSequenceEqual(expectedParameters, parameters, "The parameter area must reproduce the hand-computed octets exactly.");
    }
}
