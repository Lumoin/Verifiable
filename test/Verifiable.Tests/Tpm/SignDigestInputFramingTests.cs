using System;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire-format tests for <see cref="SignDigestInput"/> (TPM2_SignDigest, Table 126) and
/// <see cref="VerifyDigestSignatureInput"/> (TPM2_VerifyDigestSignature, Table 120), asserting the handle and
/// parameter areas each frames against hand-computed big-endian octets, mirroring
/// <see cref="StartAuthSessionInputTests"/>'s wire-format style for <see cref="ITpmCommandInput"/> types.
/// </summary>
[TestClass]
internal sealed class SignDigestInputFramingTests
{
    /// <summary>
    /// <see cref="SignDigestInput.Create"/> frames <c>TPM_CC_SignDigest</c>, the key handle, an empty
    /// <c>context</c>, the digest, and a NULL <c>TPMT_TK_HASHCHECK</c> validation ticket — the shape Table 126's
    /// note admits when <c>keyHandle</c> is not a restricted signing key
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7, Table 126). The command's own tag,
    /// <c>TPM_ST_SESSIONS</c>, is chosen by the executor from the sessions supplied (Table 126's Auth Index 1,
    /// Auth Role USER on <c>keyHandle</c>) and is not part of what this type frames.
    /// </summary>
    [TestMethod]
    public void SignDigestInputCreateFramesTheUnrestrictedKeyPathByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000001u);
        byte[] digest = [0xDE, 0xAD, 0xBE, 0xEF];

        using SignDigestInput input = SignDigestInput.Create(keyHandle, digest, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_SignDigest, input.CommandCode);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x01];
        byte[] expectedParameters =
        [
            0x00, 0x00, //context: TPM2B_SIGNATURE_CTX, empty.
            0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, //digest: TPM2B_DIGEST, size 4.
            0x80, 0x24, //validation.tag = TPM_ST_HASHCHECK.
            0x40, 0x00, 0x00, 0x07, //validation.hierarchy = TPM_RH_NULL.
            0x00, 0x00 //validation.digest: empty (the NULL Hashcheck Ticket).
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="SignDigestInput.CreateForRestrictedKey"/> frames a caller-supplied, non-NULL
    /// <c>TPMT_TK_HASHCHECK</c> validation ticket — the shape a restricted signing key requires
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7, Table 126).
    /// </summary>
    [TestMethod]
    public void SignDigestInputCreateForRestrictedKeyFramesARealHashcheckTicketByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x81000002u);
        byte[] digest = [0x11, 0x22];
        using TpmtTkHashcheck validation = TpmtTkHashcheck.Create(TpmiRhHierarchy.Owner, [0xAA, 0xBB, 0xCC], pool);

        using SignDigestInput input = SignDigestInput.CreateForRestrictedKey(keyHandle, digest, validation, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_SignDigest, input.CommandCode);

        byte[] expectedHandles = [0x81, 0x00, 0x00, 0x02];
        byte[] expectedParameters =
        [
            0x00, 0x00, //context: TPM2B_SIGNATURE_CTX, empty.
            0x00, 0x02, 0x11, 0x22, //digest: TPM2B_DIGEST, size 2.
            0x80, 0x24, //validation.tag = TPM_ST_HASHCHECK.
            0x40, 0x00, 0x00, 0x01, //validation.hierarchy = TPM_RH_OWNER.
            0x00, 0x03, 0xAA, 0xBB, 0xCC //validation.digest: size 3.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="VerifyDigestSignatureInput.ForEcdsa"/> frames the key handle, an empty <c>context</c>, the
    /// digest, and a <c>TPMT_SIGNATURE</c> whose ECDSA arm carries <c>signatureR</c> then <c>signatureS</c> as
    /// separate <c>TPM2B_ECC_PARAMETER</c> fields
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.4, Table 120; Part 2: Structures, clause 11.3.2,
    /// Table 214).
    /// </summary>
    [TestMethod]
    public void VerifyDigestSignatureInputForEcdsaFramesByteExactlyPerTable120()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x80000003u);
        byte[] digest = [0x01, 0x02];
        byte[] signature = [0xAA, 0xBB, 0xCC, 0xDD]; //r = AA BB, s = CC DD.

        using VerifyDigestSignatureInput input = VerifyDigestSignatureInput.ForEcdsa(
            keyHandle, digest, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_VerifyDigestSignature, input.CommandCode);

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x03];
        byte[] expectedParameters =
        [
            0x00, 0x00, //context: TPM2B_SIGNATURE_CTX, empty.
            0x00, 0x02, 0x01, 0x02, //digest: TPM2B_DIGEST, size 2.
            0x00, 0x18, //signature.sigAlg = TPM_ALG_ECDSA.
            0x00, 0x0B, //signature.signature.hash = TPM_ALG_SHA256.
            0x00, 0x02, 0xAA, 0xBB, //signature.signature.signatureR.
            0x00, 0x02, 0xCC, 0xDD //signature.signature.signatureS.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// <see cref="VerifyDigestSignatureInput.ForRsaSsa"/> frames the key handle, an empty <c>context</c>, the
    /// digest, and a <c>TPMT_SIGNATURE</c> whose RSA arm carries the whole signature as one
    /// <c>TPM2B_PUBLIC_KEY_RSA</c>
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.4, Table 120; Part 2: Structures, clause 11.3.1,
    /// Table 212).
    /// </summary>
    [TestMethod]
    public void VerifyDigestSignatureInputForRsaSsaFramesByteExactlyPerTable120()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject keyHandle = TpmiDhObject.FromValue(0x81000004u);
        byte[] digest = [0x01, 0x02, 0x03];
        byte[] signature = [0xDE, 0xAD, 0xBE, 0xEF];

        using VerifyDigestSignatureInput input = VerifyDigestSignatureInput.ForRsaSsa(
            keyHandle, digest, signature, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_VerifyDigestSignature, input.CommandCode);

        byte[] expectedHandles = [0x81, 0x00, 0x00, 0x04];
        byte[] expectedParameters =
        [
            0x00, 0x00, //context: TPM2B_SIGNATURE_CTX, empty.
            0x00, 0x03, 0x01, 0x02, 0x03, //digest: TPM2B_DIGEST, size 3.
            0x00, 0x14, //signature.sigAlg = TPM_ALG_RSASSA.
            0x00, 0x0B, //signature.signature.hash = TPM_ALG_SHA256.
            0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF //signature.signature.sig.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
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
