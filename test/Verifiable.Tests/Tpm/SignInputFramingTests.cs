using System;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire-format tests for <see cref="SignInput"/> (TPM2_Sign, Table 122), asserting the handle and parameter areas
/// it frames against hand-computed big-endian octets, mirroring <see cref="SignDigestInputFramingTests"/>'s
/// wire-format style for <see cref="ITpmCommandInput"/> types, plus the input's parameter-encryption declaration.
/// </summary>
[TestClass]
internal sealed class SignInputFramingTests
{
    /// <summary>
    /// <see cref="SignInput.ForEcdsa"/> frames <c>TPM_CC_Sign</c>, the key handle, the digest, an
    /// <c>inScheme</c> of <c>TPM_ALG_ECDSA</c> with its <c>hashAlg</c> detail, and a NULL <c>TPMT_TK_HASHCHECK</c>
    /// validation ticket — Table 122's four members in order
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.5, Table 122; Part 2: Structures, clause 11.2.1.5, Table
    /// 183 for the scheme's <c>[scheme]details</c>).
    /// </summary>
    [TestMethod]
    public void SignInputForEcdsaFramesTable122ByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000001u);
        byte[] digest = [0xDE, 0xAD, 0xBE, 0xEF];

        using SignInput input = SignInput.ForEcdsa(keyHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_Sign, input.CommandCode);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x01];
        byte[] expectedParameters =
        [
            0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, //digest: TPM2B_DIGEST, size 4.
            0x00, 0x18, //inScheme.scheme = TPM_ALG_ECDSA.
            0x00, 0x0B, //inScheme.details.hashAlg = TPM_ALG_SHA256.
            0x80, 0x24, //validation.tag = TPM_ST_HASHCHECK.
            0x40, 0x00, 0x00, 0x07, //validation.hierarchy = TPM_RH_NULL.
            0x00, 0x00 //validation.digest: empty (the NULL Hashcheck Ticket).
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="SignInput.Create"/> with <c>TPM_ALG_NULL</c> frames the bare two-octet scheme selector and no
    /// <c>hashAlg</c> detail — Table 183's <c>[scheme]details</c> is absent entirely for the NULL scheme, which
    /// requests the key's own default
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 2: Structures, clause 11.2.1.5, Table 183; Part 3: Commands, clause 20.5.1).
    /// </summary>
    [TestMethod]
    public void SignInputWithANullSchemeFramesTheBareSelectorByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x81000002u);
        byte[] digest = [0x01, 0x02];

        using SignInput input = SignInput.Create(keyHandle, digest, TpmAlgIdConstants.TPM_ALG_NULL, TpmAlgIdConstants.TPM_ALG_NULL, pool);

        byte[] expectedHandles = [0x81, 0x00, 0x00, 0x02];
        byte[] expectedParameters =
        [
            0x00, 0x02, 0x01, 0x02, //digest: TPM2B_DIGEST, size 2.
            0x00, 0x10, //inScheme.scheme = TPM_ALG_NULL, no details follow.
            0x80, 0x24, //validation.tag = TPM_ST_HASHCHECK.
            0x40, 0x00, 0x00, 0x07, //validation.hierarchy = TPM_RH_NULL.
            0x00, 0x00 //validation.digest: empty.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="SignInput.Create"/> with <c>TPM_ALG_HMAC</c> frames the HMAC selector with its <c>hashAlg</c>
    /// detail — Table 115's "Signs/verifies the digest" row for a KEYEDHASH key
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.1, Table 115; Part 2: Structures, clause 11.2.1.5, Table 183).
    /// </summary>
    [TestMethod]
    public void SignInputWithAnHmacSchemeFramesTheSelectorAndHashByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000003u);
        byte[] digest = [0xAA];

        using SignInput input = SignInput.Create(keyHandle, digest, TpmAlgIdConstants.TPM_ALG_HMAC, TpmAlgIdConstants.TPM_ALG_SHA384, pool);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x03];
        byte[] expectedParameters =
        [
            0x00, 0x01, 0xAA, //digest: TPM2B_DIGEST, size 1.
            0x00, 0x05, //inScheme.scheme = TPM_ALG_HMAC.
            0x00, 0x0C, //inScheme.details.hashAlg = TPM_ALG_SHA384.
            0x80, 0x24, //validation.tag = TPM_ST_HASHCHECK.
            0x40, 0x00, 0x00, 0x07, //validation.hierarchy = TPM_RH_NULL.
            0x00, 0x00 //validation.digest: empty.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="SignInput"/> declares its first parameter encryptable: <c>digest</c> is a sized
    /// <c>TPM2B_DIGEST</c> and the first parameter of Table 122, so a session carrying the <c>decrypt</c>
    /// attribute may protect it — "Any first parameter can be encrypted as long as the parameter has a size field"
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 1: Architecture, clause 18.1; Part 3: Commands, clause 20.5, Table 122).
    /// </summary>
    [TestMethod]
    public void SignInputDeclaresItsDigestParameterEncryptable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using SignInput input = SignInput.ForEcdsa(TpmiDhObject.FromValue(0x80000001u), [0x00], TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        Assert.IsTrue(((ITpmCommandInput)input).FirstCommandParameterIsEncryptable, "digest is a sized first parameter, so a decrypt session may protect it.");
    }

    /// <summary>
    /// Asserts an input's framed handle and parameter areas against the expected octets, and that
    /// <see cref="ITpmCommandInput.GetSerializedSize"/> accounts for exactly both.
    /// </summary>
    /// <param name="input">The input under test.</param>
    /// <param name="expectedHandles">The expected handle-area octets.</param>
    /// <param name="expectedParameters">The expected parameter-area octets.</param>
    private static void AssertFraming(SignInput input, byte[] expectedHandles, byte[] expectedParameters)
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
