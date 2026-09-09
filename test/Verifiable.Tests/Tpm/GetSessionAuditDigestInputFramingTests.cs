using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of <c>TPM2_GetSessionAuditDigest()</c>'s input against its published table (TPM 2.0
/// Library Part 3, clause 18.5, Table 103) — three handles (<c>privacyAdminHandle</c>, <c>signHandle</c>,
/// <c>sessionHandle</c>) and a parameter area of <c>qualifyingData</c> (TPM2B_DATA) plus <c>inScheme</c>
/// (scheme/hashAlg) — plus its raw TPM_CC pin, its TPMA_CC row, and its response's parse of a hand-built
/// TPM2B_ATTEST ‖ TPMT_SIGNATURE (Table 104).
/// </summary>
[TestClass]
internal sealed class GetSessionAuditDigestInputFramingTests
{
    /// <summary>A stand-in loaded signing key's handle (a transient object).</summary>
    private static TpmiDhObject SampleSignHandle { get; } = TpmiDhObject.FromValue(0x8000_0001);

    /// <summary>A stand-in loaded audit session's handle (within the HMAC session range).</summary>
    private static TpmiShHmac SampleSessionHandle { get; } = TpmiShHmac.FromValue(0x0200_0001);

    /// <summary>A stand-in TPM2B_NAME (SHA-256 nameAlg prefix + 32-byte digest) for the attesting key.</summary>
    private static byte[] SampleQualifiedSigner { get; } =
    [
        0x00, 0x0B,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
    ];

    /// <summary>A stand-in caller nonce echoed into extraData.</summary>
    private static byte[] SampleQualifyingDataEcho { get; } = [0x11, 0x22, 0x33, 0x44];

    /// <summary>A stand-in 32-octet session audit digest.</summary>
    private static byte[] SampleSessionDigest { get; } =
    [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF
    ];

    /// <summary>A stand-in 32-octet ECDSA signature component.</summary>
    private static byte[] SampleSignatureComponent { get; } =
    [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F
    ];

    /// <summary>
    /// Table 103's handle order (<c>privacyAdminHandle</c> then <c>signHandle</c> then <c>sessionHandle</c>) and
    /// parameter order (<c>qualifyingData</c> as TPM2B_DATA then <c>inScheme</c> as scheme/hashAlg UINT16 pair)
    /// for an ECDSA signer, with <c>GetSerializedSize</c> accounting for both areas.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5, Table 103</see>.
    /// </summary>
    [TestMethod]
    public void GetSessionAuditDigestInputFramesTheEcdsaFormByteExactlyPerTable103()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] qualifyingData = [0xAA, 0xBB, 0xCC];
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForEcdsa(
            SampleSignHandle, SampleSessionHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        byte[] expectedHandles = [0x40, 0x00, 0x00, 0x0B, 0x80, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x01];
        byte[] expectedParameters = [0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x00, 0x18, 0x00, 0x0B];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// The NULL-signer form (Part 3, clause 18.1: "the attestation block is 'signed' with the NULL Signature"):
    /// <c>signHandle</c> is <c>TPM_RH_NULL</c> (0x40000007) and <c>inScheme</c> is the bare TPM_ALG_NULL selector
    /// with no trailing hashAlg octets — Table 182's "null" row carries an empty Type column against selector
    /// TPM_ALG_NULL, so Table 183's <c>[scheme]details</c> is absent entirely and the whole TPMT_SIG_SCHEME is
    /// two octets.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.2.1.4/11.2.1.5, Tables 182/183; Part 3, clause 18.1, clause 18.5, Table 103</see>.
    /// </summary>
    [TestMethod]
    public void GetSessionAuditDigestInputForNullSignerFramesTheNullHandleAndTheNullSchemeByteExactlyPerTable103()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(SampleSessionHandle, ReadOnlySpan<byte>.Empty, pool);

        byte[] expectedHandles = [0x40, 0x00, 0x00, 0x0B, 0x40, 0x00, 0x00, 0x07, 0x02, 0x00, 0x00, 0x01];
        byte[] expectedParameters = [0x00, 0x00, 0x00, 0x10];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// Table 12's assigned value for <c>TPM_CC_GetSessionAuditDigest</c> is 0x0000014D.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, Table 12; Part 3, clause 18.5, Table 103</see>.
    /// </summary>
    [TestMethod]
    public void GetSessionAuditDigestCommandCodeEqualsTheRawValueListedInTable12()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(SampleSessionHandle, ReadOnlySpan<byte>.Empty, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_GetSessionAuditDigest, input.CommandCode);
        Assert.AreEqual(0x0000014Du, (uint)input.CommandCode, "TPM_CC_GetSessionAuditDigest must equal Table 12's raw value 0x0000014D.");
    }

    /// <summary>
    /// <c>qualifyingData</c> is the first parameter-area entry and a sized TPM2B type, so it is eligible for
    /// session-based parameter encryption ("for a command or response parameter to be encrypted, it must be the
    /// first parameter and it must be a TPM2B type").
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1; Part 3, clause 18.5, Table 103</see>.
    /// </summary>
    [TestMethod]
    public void GetSessionAuditDigestInputMarksItsFirstParameterEncryptable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using GetSessionAuditDigestInput input = GetSessionAuditDigestInput.ForNullSigner(SampleSessionHandle, ReadOnlySpan<byte>.Empty, pool);
        ITpmCommandInput commandInput = input;

        Assert.IsTrue(commandInput.FirstCommandParameterIsEncryptable, "qualifyingData is a TPM2B_DATA, a sized first parameter a decrypt session may protect.");
    }

    /// <summary>
    /// The TPMA_CC row (Part 2, clause 8.9, Table 43): Table 103 lists three handles, none of them named in a
    /// response handle area (Table 104 returns no handle), and the command carries no <c>{NV}</c> decoration.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, clause 18.5, Tables 103 and 104</see>.
    /// </summary>
    [TestMethod]
    public void GetSessionAuditDigestCommandAttributesCarryThreeHandlesAndNoResponseHandle()
    {
        TpmaCc attributes = TpmCcConstants.TPM_CC_GetSessionAuditDigest.GetCommandAttributes();

        Assert.AreEqual((byte)3, attributes.C_HANDLES, "Table 103 lists three handles.");
        Assert.IsFalse(attributes.R_HANDLE, "Table 104 returns no handle.");
        Assert.IsFalse(attributes.NV, "TPM2_GetSessionAuditDigest carries no {NV} decoration.");
        Assert.AreEqual((ushort)0x014D, attributes.COMMAND_INDEX);
    }

    /// <summary>
    /// The response codec declares Table 104's shape: no output handle, a parameter area (<c>auditInfo</c> then
    /// <c>signature</c>), and — since <c>auditInfo</c> is a sized TPM2B_ATTEST — a response an encrypt session
    /// may protect.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5, Table 104; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void GetSessionAuditDigestCodecDeclaresNoOutputHandlesAndAnEncryptableAttestation()
    {
        TpmResponseCodec codec = TpmResponseCodec.GetSessionAuditDigest;

        Assert.AreEqual(0, codec.OutHandleCount, "Table 104 returns no handle.");
        Assert.IsTrue(codec.HasResponseParameters, "Table 104 returns auditInfo and signature.");
        Assert.IsTrue(codec.ResponseFirstParameterIsEncryptable, "auditInfo is a TPM2B_ATTEST, a sized first response parameter an encrypt session may protect.");
    }

    /// <summary>
    /// Table 104's response — <c>auditInfo</c> (TPM2B_ATTEST) then <c>signature</c> (TPMT_SIGNATURE) — parses
    /// into <see cref="GetSessionAuditDigestResponse"/> with its attested fields readable, for the NULL Signature
    /// (Part 3, clause 18.1).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5, Table 104; clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public void GetSessionAuditDigestResponseParsesAHandBuiltAttestationSignedWithTheNullSignature()
    {
        using var housePool = new MeteredHousePool();
        byte[] response = [.. BuildSessionAuditAttestImage(TpmiYesNo.Yes, housePool.Pool), 0x00, 0x10];

        var reader = new TpmReader(response);
        using GetSessionAuditDigestResponse parsed = GetSessionAuditDigestResponse.Parse(ref reader, housePool.Pool);

        Assert.AreEqual(0, reader.Remaining, "Parse must consume exactly the response octets.");
        Assert.IsTrue(parsed.SessionAudit.ExclusiveSession.IsYes, "exclusiveSession must read back YES.");
        Assert.IsTrue(parsed.SessionAudit.SessionDigest.AsReadOnlySpan().SequenceEqual(SampleSessionDigest), "sessionDigest must read back the wire octets.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_NULL, parsed.SignatureAlgorithm, "sigAlg TPM_ALG_NULL must read back as the NULL Signature.");
        Assert.IsTrue(parsed.Signature.IsNull, "The parsed signature member must be the NULL Signature.");

        parsed.Dispose();
        Assert.AreEqual(0L, housePool.OutstandingCount, "Dispose must release every rental the response and its attestation hold.");
    }

    /// <summary>
    /// The same Table 104 response shape for a real (ECDSA) signature: <c>signature</c> selects the ECDSA
    /// TPMU_SIGNATURE member with its hash field and r/s components.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5, Table 104</see>.
    /// </summary>
    [TestMethod]
    public void GetSessionAuditDigestResponseParsesAHandBuiltAttestationSignedWithAnEcdsaSignature()
    {
        using var housePool = new MeteredHousePool();
        byte[] signature =
        [
            0x00, 0x18,
            0x00, 0x0B,
            0x00, 0x20, .. SampleSignatureComponent,
            0x00, 0x20, .. SampleSignatureComponent
        ];
        byte[] response = [.. BuildSessionAuditAttestImage(TpmiYesNo.No, housePool.Pool), .. signature];

        var reader = new TpmReader(response);
        using GetSessionAuditDigestResponse parsed = GetSessionAuditDigestResponse.Parse(ref reader, housePool.Pool);

        Assert.AreEqual(0, reader.Remaining, "Parse must consume exactly the response octets.");
        Assert.IsTrue(parsed.SessionAudit.ExclusiveSession.IsNo, "exclusiveSession must read back NO.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, parsed.SignatureAlgorithm, "sigAlg must read back ECDSA.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, parsed.HashAlgorithm, "The signature's hash field must read back SHA-256.");
        Assert.IsTrue(parsed.Signature.SignatureR!.AsReadOnlySpan().SequenceEqual(SampleSignatureComponent), "signatureR must read back the wire octets.");

        parsed.Dispose();
        Assert.AreEqual(0L, housePool.OutstandingCount, "Dispose must release every rental the response, its attestation and its signature hold.");
    }

    /// <summary>
    /// A response whose attestation type is TPM_ST_ATTEST_TIME (a different command's attestation) must be
    /// refused rather than surfaced as success with a null <see cref="GetSessionAuditDigestResponse.SessionAudit"/> —
    /// the same type guard the sibling <c>GetTimeResponse</c> parser applies.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 18.5, Table 104</see>.
    /// </summary>
    [TestMethod]
    public void GetSessionAuditDigestResponseWithAttestTypeTimeThrowsAndReleasesThePooledAttestation()
    {
        using var housePool = new MeteredHousePool();
        byte[] response = [.. BuildTimeAttestImage(housePool.Pool), 0x00, 0x10];

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => ParseGetSessionAuditDigestResponse(response, housePool.Pool),
            "A TPM_ST_ATTEST_TIME body must be refused as a TPM2_GetSessionAuditDigest response.");
        Assert.AreEqual(0L, housePool.OutstandingCount, "The type-mismatch path must release the pooled attestation before the exception leaves.");
    }

    /// <summary>Parses a get-session-audit-digest response from <paramref name="data"/>; isolates the ref-struct reader from the throwing assertion's lambda.</summary>
    /// <param name="data">The wire octets.</param>
    /// <param name="pool">The memory pool.</param>
    private static void ParseGetSessionAuditDigestResponse(byte[] data, BaseMemoryPool pool)
    {
        var reader = new TpmReader(data);
        using GetSessionAuditDigestResponse _ = GetSessionAuditDigestResponse.Parse(ref reader, pool);
    }

    /// <summary>
    /// Frames <paramref name="input"/>'s handle and parameter areas into freshly-sized buffers and asserts each
    /// reproduces the hand-computed octets exactly, and that <see cref="ITpmCommandInput.GetSerializedSize"/>
    /// accounts for precisely their combined length.
    /// </summary>
    /// <param name="input">The command input under test.</param>
    /// <param name="expectedHandles">The hand-computed handle area.</param>
    /// <param name="expectedParameters">The hand-computed parameter area.</param>
    private static void AssertFraming(GetSessionAuditDigestInput input, byte[] expectedHandles, byte[] expectedParameters)
    {
        Assert.AreEqual(expectedHandles.Length + expectedParameters.Length, input.GetSerializedSize(), "GetSerializedSize must account for exactly the handle area plus the parameter area.");

        byte[] handles = new byte[expectedHandles.Length];
        var handleWriter = new TpmWriter(handles);
        input.WriteHandles(ref handleWriter);
        Assert.AreEqual(handles.Length, handleWriter.Written, "WriteHandles must fill exactly the three-handle area.");
        Assert.IsTrue(handles.AsSpan().SequenceEqual(expectedHandles), "The handle area must reproduce the hand-computed octets exactly.");

        byte[] parameters = new byte[expectedParameters.Length];
        var parameterWriter = new TpmWriter(parameters);
        input.WriteParameters(ref parameterWriter);
        Assert.AreEqual(parameters.Length, parameterWriter.Written, "WriteParameters must fill exactly the parameter area.");
        Assert.IsTrue(parameters.AsSpan().SequenceEqual(expectedParameters), "The parameter area must reproduce the hand-computed octets exactly.");
    }

    /// <summary>
    /// Builds a TPM2B_ATTEST wire image (2-octet size prefix + marshaled TPMS_ATTEST) of type
    /// TPM_ST_ATTEST_SESSION_AUDIT, for feeding a hand-built <c>TPM2_GetSessionAuditDigest()</c> response.
    /// </summary>
    /// <param name="exclusiveSession">The exclusive-session flag to attest.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The TPM2B_ATTEST wire bytes.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "The attestation is disposed inside this method once its bytes have been copied out.")]
    private static byte[] BuildSessionAuditAttestImage(TpmiYesNo exclusiveSession, BaseMemoryPool pool)
    {
        TpmuAttest attested = TpmuAttest.ForSessionAudit(TpmsSessionAuditInfo.Create(exclusiveSession, Tpm2bDigest.Create(SampleSessionDigest, pool)));
        using TpmsAttest attest = TpmsAttest.Create(
            TpmConstants32.TPM_GENERATED_VALUE,
            TpmStConstants.TPM_ST_ATTEST_SESSION_AUDIT,
            Tpm2bName.Create(SampleQualifiedSigner, pool),
            Tpm2bData.Create(SampleQualifyingDataEcho, pool),
            new TpmsClockInfo(Clock: 0x1122334455667788UL, ResetCount: 5, RestartCount: 3, Safe: TpmiYesNo.Yes),
            firmwareVersion: 0x0001000200030004UL,
            attested);

        return FrameAsTpm2bAttest(attest, pool);
    }

    /// <summary>
    /// Builds a TPM2B_ATTEST wire image of type TPM_ST_ATTEST_TIME — a well-formed attestation of the WRONG type
    /// for a <c>TPM2_GetSessionAuditDigest()</c> response, for the type-guard rejection test.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The TPM2B_ATTEST wire bytes.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "The attestation is disposed inside this method once its bytes have been copied out.")]
    private static byte[] BuildTimeAttestImage(BaseMemoryPool pool)
    {
        TpmuAttest attested = TpmuAttest.ForTime(new TpmsTimeAttestInfo(
            new TpmsTimeInfo(0x1000UL, new TpmsClockInfo(Clock: 0x1122334455667788UL, ResetCount: 5, RestartCount: 3, Safe: TpmiYesNo.Yes)),
            FirmwareVersion: 0x0001000200030004UL));
        using TpmsAttest attest = TpmsAttest.Create(
            TpmConstants32.TPM_GENERATED_VALUE,
            TpmStConstants.TPM_ST_ATTEST_TIME,
            Tpm2bName.Create(SampleQualifiedSigner, pool),
            Tpm2bData.Create(SampleQualifyingDataEcho, pool),
            new TpmsClockInfo(Clock: 0x1122334455667788UL, ResetCount: 5, RestartCount: 3, Safe: TpmiYesNo.Yes),
            firmwareVersion: 0x0001000200030004UL,
            attested);

        return FrameAsTpm2bAttest(attest, pool);
    }

    /// <summary>Marshals <paramref name="attest"/> and wraps it in the TPM2B_ATTEST 2-octet size prefix.</summary>
    /// <param name="attest">The attestation structure.</param>
    /// <param name="pool">The memory pool for the scratch marshal buffer.</param>
    /// <returns>The TPM2B_ATTEST wire bytes.</returns>
    private static byte[] FrameAsTpm2bAttest(TpmsAttest attest, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> innerOwner = pool.Rent(attest.GetSerializedSize());
        var innerWriter = new TpmWriter(innerOwner.Memory.Span);
        attest.WriteTo(ref innerWriter);
        byte[] attestImage = innerOwner.Memory.Span[..innerWriter.Written].ToArray();

        byte[] framed = new byte[sizeof(ushort) + attestImage.Length];
        framed[0] = (byte)(attestImage.Length >> 8);
        framed[1] = (byte)(attestImage.Length & 0xFF);
        attestImage.CopyTo(framed, sizeof(ushort));

        return framed;
    }
}
