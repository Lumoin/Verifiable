using System;
using System.Threading;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of the ten policy-assertion commands' inputs against their published tables —
/// <c>TPM2_PolicyPassword()</c> (Table 174), <c>TPM2_PolicyRestart()</c> (Table 16),
/// <c>TPM2_PolicyLocality()</c> (Table 154), <c>TPM2_PolicyCpHash()</c> (Table 164),
/// <c>TPM2_PolicyNameHash()</c> (Table 166), <c>TPM2_PolicyDuplicationSelect()</c> (Table 168),
/// <c>TPM2_PolicyTemplate()</c> (Table 180), <c>TPM2_PolicyNvWritten()</c> (Table 178),
/// <c>TPM2_PolicyAuthorizeNV()</c> (Table 182), and <c>TPM2_PolicyParameters()</c> (Table 187) — plus the
/// commands' raw <c>TPM_CC</c> pins, their <c>TPMA_CC</c> rows, their response codecs' header-only parse, and
/// the password-carrying policy session's <c>WriteAuthCommand</c> framing. Each test's own doc comment carries
/// its clause anchor, per the house conformance pattern (one test per normative case, no shared matrix).
/// </summary>
[TestClass]
internal sealed class PolicyCommandInputFramingTests
{
    /// <summary>
    /// Table 174: <c>policySession</c> (TPMI_SH_POLICY) alone, no parameters; the raw command code is
    /// 0x0000018C (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.18, Table 174</see>.
    /// </summary>
    [TestMethod]
    public void PolicyPasswordInputFramesTheHandleAloneByteExactlyPerTable174()
    {
        PolicyPasswordInput input = PolicyPasswordInput.ForSession(0x03000000u);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PolicyPassword, input.CommandCode);
        Assert.AreEqual(0x0000018Cu, (uint)input.CommandCode, "TPM_CC_PolicyPassword must equal Table 12's raw value 0x0000018C.");
        Assert.IsFalse(((ITpmCommandInput)input).FirstCommandParameterIsEncryptable, "TPM2_PolicyPassword has no parameters, so none is encryptable.");

        AssertFraming(input, [0x03, 0x00, 0x00, 0x00], []);
    }

    /// <summary>
    /// Table 16: <c>sessionHandle</c> (TPMI_HMAC_POLICY_SESSION) alone, no parameters; the raw command code is
    /// 0x00000180 (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 11.2, Table 16</see>.
    /// </summary>
    [TestMethod]
    public void PolicyRestartInputFramesTheHandleAloneByteExactlyPerTable16()
    {
        var input = new PolicyRestartInput(0x03000001u);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PolicyRestart, input.CommandCode);
        Assert.AreEqual(0x00000180u, (uint)input.CommandCode, "TPM_CC_PolicyRestart must equal Table 12's raw value 0x00000180.");
        ITpmCommandInput asInput = input;
        Assert.IsFalse(asInput.FirstCommandParameterIsEncryptable, "TPM2_PolicyRestart has no parameters, so none is encryptable.");

        AssertFraming(input, [0x03, 0x00, 0x00, 0x01], []);
    }

    /// <summary>
    /// Table 154: <c>policySession</c> (TPMI_SH_POLICY) then <c>locality</c> (TPMA_LOCALITY, one octet); the raw
    /// command code is 0x0000016F (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.8, Table 154</see>.
    /// </summary>
    [TestMethod]
    public void PolicyLocalityInputFramesTheHandleAndLocalityByteExactlyPerTable154()
    {
        var input = new PolicyLocalityInput(0x03000002u, TpmaLocality.TPM_LOC_ONE);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PolicyLocality, input.CommandCode);
        Assert.AreEqual(0x0000016Fu, (uint)input.CommandCode, "TPM_CC_PolicyLocality must equal Table 12's raw value 0x0000016F.");
        ITpmCommandInput asInput = input;
        Assert.IsFalse(asInput.FirstCommandParameterIsEncryptable, "locality is a fixed-size TPMA_LOCALITY octet, not a TPM2B, so it must not be marked encryptable.");

        AssertFraming(input, [0x03, 0x00, 0x00, 0x02], [0x02]);
    }

    /// <summary>
    /// Table 164: <c>policySession</c> (TPMI_SH_POLICY) then <c>cpHashA</c> (TPM2B_DIGEST); the raw command code
    /// is 0x0000016E (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.13, Table 164</see>.
    /// </summary>
    [TestMethod]
    public void PolicyCpHashInputFramesTheHandleAndDigestByteExactlyPerTable164()
    {
        byte[] cpHashA = new byte[32];
        for(int i = 0; i < cpHashA.Length; i++)
        {
            cpHashA[i] = (byte)(0xA0 + i);
        }

        var input = new PolicyCpHashInput(0x03000003u, cpHashA);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PolicyCpHash, input.CommandCode);
        Assert.AreEqual(0x0000016Eu, (uint)input.CommandCode, "TPM_CC_PolicyCpHash must equal Table 12's raw value 0x0000016E.");
        ITpmCommandInput asInput = input;
        Assert.IsFalse(asInput.FirstCommandParameterIsEncryptable, "cpHashA is not marked encryptable in this library's command surface.");

        byte[] expectedParameters = [0x00, 0x20, .. cpHashA];
        AssertFraming(input, [0x03, 0x00, 0x00, 0x03], expectedParameters);
    }

    /// <summary>
    /// Table 166: <c>policySession</c> (TPMI_SH_POLICY) then <c>nameHash</c> (TPM2B_DIGEST); the raw command
    /// code is 0x00000170 (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.14, Table 166</see>.
    /// </summary>
    [TestMethod]
    public void PolicyNameHashInputFramesTheHandleAndDigestByteExactlyPerTable166()
    {
        byte[] nameHash = new byte[32];
        for(int i = 0; i < nameHash.Length; i++)
        {
            nameHash[i] = (byte)(0xB0 + i);
        }

        var input = new PolicyNameHashInput(0x03000004u, nameHash);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PolicyNameHash, input.CommandCode);
        Assert.AreEqual(0x00000170u, (uint)input.CommandCode, "TPM_CC_PolicyNameHash must equal Table 12's raw value 0x00000170.");

        byte[] expectedParameters = [0x00, 0x20, .. nameHash];
        AssertFraming(input, [0x03, 0x00, 0x00, 0x04], expectedParameters);
    }

    /// <summary>
    /// Table 180: <c>policySession</c> (TPMI_SH_POLICY) then <c>templateHash</c> (TPM2B_DIGEST); the raw command
    /// code is 0x00000190 (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.21, Table 180</see>.
    /// </summary>
    [TestMethod]
    public void PolicyTemplateInputFramesTheHandleAndDigestByteExactlyPerTable180()
    {
        byte[] templateHash = new byte[32];
        for(int i = 0; i < templateHash.Length; i++)
        {
            templateHash[i] = (byte)(0xC0 + i);
        }

        var input = new PolicyTemplateInput(0x03000005u, templateHash);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PolicyTemplate, input.CommandCode);
        Assert.AreEqual(0x00000190u, (uint)input.CommandCode, "TPM_CC_PolicyTemplate must equal Table 12's raw value 0x00000190.");

        byte[] expectedParameters = [0x00, 0x20, .. templateHash];
        AssertFraming(input, [0x03, 0x00, 0x00, 0x05], expectedParameters);
    }

    /// <summary>
    /// Table 178: <c>policySession</c> (TPMI_SH_POLICY) then <c>writtenSet</c> (TPMI_YES_NO, one octet); the raw
    /// command code is 0x0000018F (Part 2, Table 12). YES frames as 0x01, NO as 0x00.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.20, Table 178</see>.
    /// </summary>
    [TestMethod]
    public void PolicyNvWrittenInputFramesTheHandleAndWrittenSetByteExactlyPerTable178()
    {
        var yes = new PolicyNvWrittenInput(0x03000006u, IsWrittenSet: true);
        Assert.AreEqual(TpmCcConstants.TPM_CC_PolicyNvWritten, yes.CommandCode);
        Assert.AreEqual(0x0000018Fu, (uint)yes.CommandCode, "TPM_CC_PolicyNvWritten must equal Table 12's raw value 0x0000018F.");
        AssertFraming(yes, [0x03, 0x00, 0x00, 0x06], [0x01]);

        var no = new PolicyNvWrittenInput(0x03000006u, IsWrittenSet: false);
        AssertFraming(no, [0x03, 0x00, 0x00, 0x06], [0x00]);
    }

    /// <summary>
    /// Table 182: <c>@authHandle</c> (TPMI_RH_NV_AUTH), <c>nvIndex</c> (TPMI_RH_NV_INDEX), then
    /// <c>policySession</c> (TPMI_SH_POLICY) — three handles, no parameters; the raw command code is 0x00000192
    /// (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.22, Table 182</see>.
    /// </summary>
    [TestMethod]
    public void PolicyAuthorizeNvInputFramesTheThreeHandlesByteExactlyPerTable182()
    {
        var input = new PolicyAuthorizeNvInput(0x40000001u, 0x01500020u, 0x03000007u);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PolicyAuthorizeNV, input.CommandCode);
        Assert.AreEqual(0x00000192u, (uint)input.CommandCode, "TPM_CC_PolicyAuthorizeNV must equal Table 12's raw value 0x00000192.");
        ITpmCommandInput asInput = input;
        Assert.IsFalse(asInput.FirstCommandParameterIsEncryptable, "TPM2_PolicyAuthorizeNV has no parameters, so none is encryptable.");

        byte[] expectedHandles =
        [
            0x40, 0x00, 0x00, 0x01, //@authHandle.
            0x01, 0x50, 0x00, 0x20, //nvIndex.
            0x03, 0x00, 0x00, 0x07  //policySession.
        ];

        AssertFraming(input, expectedHandles, []);
    }

    /// <summary>
    /// Table 168: <c>policySession</c> (TPMI_SH_POLICY) then <c>objectName</c> (TPM2B_NAME), <c>newParentName</c>
    /// (TPM2B_NAME) and <c>includeObject</c> (TPMI_YES_NO, one octet); the raw command code is 0x00000188 (Part 2,
    /// Table 12). YES frames as 0x01, NO as 0x00; the Names frame with their two-octet sizes on the wire even
    /// though the policyDigest folds them without.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.15, Table 168</see>.
    /// </summary>
    [TestMethod]
    public void PolicyDuplicationSelectInputFramesTheHandleTwoNamesAndIncludeObjectByteExactlyPerTable168()
    {
        byte[] objectName = new byte[34];
        byte[] newParentName = new byte[34];
        objectName[1] = 0x0B;
        newParentName[1] = 0x0B;
        for(int i = 2; i < objectName.Length; i++)
        {
            objectName[i] = (byte)(0xD0 + i);
            newParentName[i] = (byte)(0xE0 + i);
        }

        var yes = new PolicyDuplicationSelectInput(0x03000008u, objectName, newParentName, IsObjectIncluded: true);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PolicyDuplicationSelect, yes.CommandCode);
        Assert.AreEqual(0x00000188u, (uint)yes.CommandCode, "TPM_CC_PolicyDuplicationSelect must equal Table 12's raw value 0x00000188.");

        byte[] expectedYes = [0x00, 0x22, .. objectName, 0x00, 0x22, .. newParentName, 0x01];
        AssertFraming(yes, [0x03, 0x00, 0x00, 0x08], expectedYes);

        var no = new PolicyDuplicationSelectInput(0x03000008u, objectName, newParentName, IsObjectIncluded: false);
        byte[] expectedNo = [0x00, 0x22, .. objectName, 0x00, 0x22, .. newParentName, 0x00];
        AssertFraming(no, [0x03, 0x00, 0x00, 0x08], expectedNo);
    }

    /// <summary>
    /// Table 187: <c>policySession</c> (TPMI_SH_POLICY) then <c>pHash</c> (TPM2B_DIGEST); the raw command code
    /// is 0x0000019C (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.24, Table 187</see>.
    /// </summary>
    [TestMethod]
    public void PolicyParametersInputFramesTheHandleAndDigestByteExactlyPerTable187()
    {
        byte[] parametersHash = new byte[32];
        for(int i = 0; i < parametersHash.Length; i++)
        {
            parametersHash[i] = (byte)(0xF0 + i);
        }

        var input = new PolicyParametersInput(0x03000009u, parametersHash);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PolicyParameters, input.CommandCode);
        Assert.AreEqual(0x0000019Cu, (uint)input.CommandCode, "TPM_CC_PolicyParameters must equal Table 12's raw value 0x0000019C.");

        byte[] expectedParameters = [0x00, 0x20, .. parametersHash];
        AssertFraming(input, [0x03, 0x00, 0x00, 0x09], expectedParameters);
    }

    /// <summary>
    /// Part 2, clause 10.3.5, Table 93: <c>TPM2B_DIGEST</c> is bounded at
    /// <see cref="Tpm2bDigest.MaxSize"/> (64 octets) — <c>PolicyCpHashInput</c>, <c>PolicyNameHashInput</c>,
    /// <c>PolicyTemplateInput</c> and <c>PolicyParametersInput</c> each refuse a 65-octet digest at construction,
    /// before any rent.
    /// </summary>
    [TestMethod]
    public void DigestCarryingPolicyInputsRefuseADigestOverTpm2bDigestMaxSizePerTable93()
    {
        byte[] oversized = new byte[Tpm2bDigest.MaxSize + 1];

        _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyCpHashInput(0x03000000u, oversized));
        _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyNameHashInput(0x03000000u, oversized));
        _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyTemplateInput(0x03000000u, oversized));
        _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyParametersInput(0x03000000u, oversized));
    }

    /// <summary>
    /// Part 2, clause 10.4.3, Table 105: <c>TPM2B_NAME</c> is bounded at <see cref="Tpm2bName.MaxSize"/> (a
    /// two-octet nameAlg plus the widest digest, 66 octets) — <c>PolicyDuplicationSelectInput</c> refuses a
    /// 67-octet Name in either position at construction, before any rent.
    /// </summary>
    [TestMethod]
    public void PolicyDuplicationSelectInputRefusesANameOverTpm2bNameMaxSizePerTable105()
    {
        byte[] oversized = new byte[Tpm2bName.MaxSize + 1];
        byte[] name = new byte[34];

        _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyDuplicationSelectInput(0x03000000u, oversized, name, IsObjectIncluded: false));
        _ = Assert.ThrowsExactly<ArgumentException>(() => new PolicyDuplicationSelectInput(0x03000000u, name, oversized, IsObjectIncluded: false));
    }

    /// <summary>
    /// The <c>TPMA_CC</c> rows (Part 2, clause 8.9): the nine single-session assertions each take one handle;
    /// <c>TPM2_PolicyAuthorizeNV</c> takes three. None is <c>{NV}</c>, <c>{E}</c>, or <c>{F}</c>, and none
    /// returns a response handle.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, Tables 16, 154, 164, 166, 168, 174, 178, 180, 182, 187</see>.
    /// </summary>
    [TestMethod]
    public void PolicyCommandAttributesCarryTheirHandleCountsWithNoNvExtensiveOrFlushedBits()
    {
        AssertOneHandleNoModifiers(TpmCcConstants.TPM_CC_PolicyPassword);
        AssertOneHandleNoModifiers(TpmCcConstants.TPM_CC_PolicyRestart);
        AssertOneHandleNoModifiers(TpmCcConstants.TPM_CC_PolicyLocality);
        AssertOneHandleNoModifiers(TpmCcConstants.TPM_CC_PolicyCpHash);
        AssertOneHandleNoModifiers(TpmCcConstants.TPM_CC_PolicyNameHash);
        AssertOneHandleNoModifiers(TpmCcConstants.TPM_CC_PolicyDuplicationSelect);
        AssertOneHandleNoModifiers(TpmCcConstants.TPM_CC_PolicyTemplate);
        AssertOneHandleNoModifiers(TpmCcConstants.TPM_CC_PolicyNvWritten);
        AssertOneHandleNoModifiers(TpmCcConstants.TPM_CC_PolicyParameters);

        TpmaCc authorizeNv = TpmCcConstants.TPM_CC_PolicyAuthorizeNV.GetCommandAttributes();
        Assert.AreEqual((byte)3, authorizeNv.C_HANDLES);
        Assert.IsFalse(authorizeNv.NV);
        Assert.IsFalse(authorizeNv.FLUSHED);
        Assert.IsFalse(authorizeNv.R_HANDLE);

        static void AssertOneHandleNoModifiers(TpmCcConstants commandCode)
        {
            TpmaCc attributes = commandCode.GetCommandAttributes();
            Assert.AreEqual((byte)1, attributes.C_HANDLES, $"'{commandCode}' must take exactly one handle.");
            Assert.IsFalse(attributes.NV, $"'{commandCode}' is not {{NV}}.");
            Assert.IsFalse(attributes.FLUSHED, $"'{commandCode}' is not {{F}}.");
            Assert.IsFalse(attributes.R_HANDLE, $"'{commandCode}' returns no response handle.");
        }
    }

    /// <summary>
    /// Each of the ten commands' responses is the 10-byte header alone (no response handles, no response
    /// parameters), so each codec declares zero output handles, no parser, and the command's own parameterless
    /// singleton as the value a header-only success response resolves to.
    /// </summary>
    [TestMethod]
    public void PolicyCommandCodecsResolveAHeaderOnlySuccessResponseToTheirOwnSingleton()
    {
        AssertHeaderOnlyCodec(TpmResponseCodec.PolicyPassword, PolicyPasswordResponse.Instance);
        AssertHeaderOnlyCodec(TpmResponseCodec.PolicyRestart, PolicyRestartResponse.Instance);
        AssertHeaderOnlyCodec(TpmResponseCodec.PolicyLocality, PolicyLocalityResponse.Instance);
        AssertHeaderOnlyCodec(TpmResponseCodec.PolicyCpHash, PolicyCpHashResponse.Instance);
        AssertHeaderOnlyCodec(TpmResponseCodec.PolicyNameHash, PolicyNameHashResponse.Instance);
        AssertHeaderOnlyCodec(TpmResponseCodec.PolicyDuplicationSelect, PolicyDuplicationSelectResponse.Instance);
        AssertHeaderOnlyCodec(TpmResponseCodec.PolicyTemplate, PolicyTemplateResponse.Instance);
        AssertHeaderOnlyCodec(TpmResponseCodec.PolicyNvWritten, PolicyNvWrittenResponse.Instance);
        AssertHeaderOnlyCodec(TpmResponseCodec.PolicyAuthorizeNv, PolicyAuthorizeNvResponse.Instance);
        AssertHeaderOnlyCodec(TpmResponseCodec.PolicyParameters, PolicyParametersResponse.Instance);

        static void AssertHeaderOnlyCodec(TpmResponseCodec codec, ITpmWireType expectedSingleton)
        {
            Assert.AreEqual(0, codec.OutHandleCount, "A header-only response declares no output handles.");
            Assert.IsFalse(codec.HasResponseParameters, "A header-only response has no parser.");
            Assert.AreSame(expectedSingleton, codec.EmptyResponse, "The codec must resolve to the command's own parameterless singleton.");
        }
    }

    /// <summary>
    /// <see cref="TpmPolicySession.ForSessionWithPassword"/>'s <c>WriteAuthCommand</c> frames
    /// <c>sessionHandle ‖ nonceCaller (TPM2B) ‖ sessionAttributes ‖ hmac (TPM2B = the password)</c> — the same
    /// TPMS_AUTH_COMMAND shape <see cref="TpmPolicySession.ForSession"/> uses, except the hmac field carries the
    /// authorized object's authValue in the clear instead of an empty buffer (TPM 2.0 Library Part 1, clause
    /// 16.6.16: "the password takes precedence and must be present in hmac").
    /// </summary>
    [TestMethod]
    public async Task PasswordCarryingPolicySessionFramesThePasswordAsTheHmacField()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] password = [0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64]; //"password".
        const uint SessionHandle = 0x03000010u;

        using TpmPolicySession session = TpmPolicySession.ForSessionWithPassword(
            SessionHandle, TpmAlgIdConstants.TPM_ALG_SHA256, password, TestEntropy.NewCounterStream(), pool);

        Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
            ReadOnlyMemory<byte>.Empty, pool, CancellationToken.None).ConfigureAwait(false);
        Assert.IsNotNull(hmac, "A password-carrying session must produce a non-null hmac.");

        try
        {
            int expectedSize = session.GetAuthCommandSize();
            byte[] frame = new byte[expectedSize];
            var writer = new TpmWriter(frame);
            session.WriteAuthCommand(ref writer, hmac);
            Assert.AreEqual(expectedSize, writer.Written, "WriteAuthCommand must fill exactly GetAuthCommandSize's octets.");

            var reader = new TpmReader(frame);
            Assert.AreEqual(SessionHandle, reader.ReadUInt32(), "The sessionHandle must frame first.");

            ReadOnlySpan<byte> nonceCaller = reader.ReadTpm2b();
            int nonceCallerLength = nonceCaller.Length;
            Assert.AreEqual(32, nonceCallerLength, "nonceCaller is sized to the SHA-256 session's digest width.");

            Assert.AreEqual((byte)TpmaSession.CONTINUE_SESSION, reader.ReadByte(), "sessionAttributes must carry CONTINUE_SESSION.");

            ReadOnlySpan<byte> hmacBytes = reader.ReadTpm2b();
            Assert.AreSequenceEqual(password, hmacBytes.ToArray(), "The hmac field must carry the password verbatim.");
            Assert.AreEqual(0, reader.Remaining, "WriteAuthCommand must fill exactly the auth command area.");
        }
        finally
        {
            hmac?.Dispose();
        }
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle and parameter areas into freshly-sized buffers and asserts each
    /// reproduces the hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for precisely the two areas combined.
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
