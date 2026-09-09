using System;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of the hash-sequence family's command inputs against their published tables —
/// <c>TPM2_HashSequenceStart()</c> (TPM 2.0 Library Part 3, Table 85), <c>TPM2_SequenceComplete()</c> (Table
/// 93), and <c>TPM2_Hash()</c> (Table 69) — plus the response codecs' parse of Tables 86, 94 and 70, and the
/// commands' <c>TPMA_CC</c> rows.
/// </summary>
[TestClass]
internal sealed class HashSequenceInputFramingTests
{
    /// <summary>
    /// Table 85: no handles; <c>auth</c> (TPM2B_AUTH) then <c>hashAlg</c> (TPMI_ALG_HASH+); the raw command
    /// code is 0x00000186 (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.4.2, Table 85</see>.
    /// </summary>
    [TestMethod]
    public void HashSequenceStartInputCreateFramesTheParametersByteExactlyPerTable85()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] sequenceAuth = [0xA1, 0xA2, 0xA3];

        using HashSequenceStartInput input = HashSequenceStartInput.Create(sequenceAuth, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA384), pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_HashSequenceStart, input.CommandCode);
        Assert.AreEqual(0x00000186u, (uint)input.CommandCode, "TPM_CC_HashSequenceStart must equal Table 12's raw value 0x00000186.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "auth is the first TPM2B parameter, so it must be marked encryptable.");

        byte[] expectedHandles = [];
        byte[] expectedParameters =
        [
            0x00, 0x03, 0xA1, 0xA2, 0xA3, //auth: TPM2B_AUTH, size 3.
            0x00, 0x0C //hashAlg: TPM_ALG_SHA384.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// Table 85: <c>hashAlg</c> = <c>TPM_ALG_NULL</c> starts an Event Sequence; an empty <c>auth</c> frames as
    /// the empty TPM2B.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.4.2, Table 85</see>.
    /// </summary>
    [TestMethod]
    public void HashSequenceStartInputCreateFromPasswordWithNullHashFramesAnEventSequenceStartByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const string SequencePassword = "ev";

        using HashSequenceStartInput input = HashSequenceStartInput.CreateFromPassword(SequencePassword, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL), pool);

        byte[] expectedParameters =
        [
            0x00, 0x02, (byte)'e', (byte)'v', //auth: TPM2B_AUTH, the UTF-8 password.
            0x00, 0x10 //hashAlg: TPM_ALG_NULL.
        ];

        AssertFraming(input, [], expectedParameters);
    }

    /// <summary>
    /// Table 93: <c>@sequenceHandle</c>; <c>buffer</c> (TPM2B_MAX_BUFFER) then <c>hierarchy</c>
    /// (TPMI_RH_HIERARCHY); the raw command code is 0x0000013E (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.8.2, Table 93</see>.
    /// </summary>
    [TestMethod]
    public void SequenceCompleteInputCreateFramesTheHandleAndParametersByteExactlyPerTable93()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        TpmiDhObject sequenceHandle = TpmiDhObject.FromValue(0x80000003u);
        byte[] buffer = [0xB1, 0xB2];

        using SequenceCompleteInput input = SequenceCompleteInput.Create(sequenceHandle, buffer, TpmiRhHierarchy.Endorsement, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_SequenceComplete, input.CommandCode);
        Assert.AreEqual(0x0000013Eu, (uint)input.CommandCode, "TPM_CC_SequenceComplete must equal Table 12's raw value 0x0000013E.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "buffer is the first TPM2B parameter, so it must be marked encryptable.");

        byte[] expectedHandles = [0x80, 0x00, 0x00, 0x03];
        byte[] expectedParameters =
        [
            0x00, 0x02, 0xB1, 0xB2, //buffer: TPM2B_MAX_BUFFER, size 2.
            0x40, 0x00, 0x00, 0x0B //hierarchy: TPM_RH_ENDORSEMENT.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// Table 93: an empty <c>buffer</c> ("the last part of data, if any") frames as the empty TPM2B, and
    /// <c>TPM_RH_NULL</c> is a legal <c>hierarchy</c> (Part 2, Table 59).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.8.2, Table 93; Part 2, clause 9.13, Table 59</see>.
    /// </summary>
    [TestMethod]
    public void SequenceCompleteInputCreateWithAnEmptyBufferAndTheNullHierarchyFramesByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using SequenceCompleteInput input = SequenceCompleteInput.Create(TpmiDhObject.FromValue(0x80000000u), [], TpmiRhHierarchy.Null, pool);

        byte[] expectedParameters =
        [
            0x00, 0x00, //buffer: empty TPM2B_MAX_BUFFER.
            0x40, 0x00, 0x00, 0x07 //hierarchy: TPM_RH_NULL.
        ];

        AssertFraming(input, [0x80, 0x00, 0x00, 0x00], expectedParameters);
    }

    /// <summary>
    /// Table 69: no handles; <c>data</c> (TPM2B_MAX_BUFFER), <c>hashAlg</c> (TPMI_ALG_HASH), <c>hierarchy</c>
    /// (TPMI_RH_HIERARCHY+); the raw command code is 0x0000017D (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 15.4.2, Table 69</see>.
    /// </summary>
    [TestMethod]
    public void HashInputCreateFramesTheParametersByteExactlyPerTable69()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] data = [0xD1, 0xD2, 0xD3, 0xD4, 0xD5];

        using HashInput input = HashInput.Create(data, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), TpmiRhHierarchy.Owner, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_Hash, input.CommandCode);
        Assert.AreEqual(0x0000017Du, (uint)input.CommandCode, "TPM_CC_Hash must equal Table 12's raw value 0x0000017D.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "data is the first TPM2B parameter, so it must be marked encryptable.");

        byte[] expectedParameters =
        [
            0x00, 0x05, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, //data: TPM2B_MAX_BUFFER, size 5.
            0x00, 0x0B, //hashAlg: TPM_ALG_SHA256.
            0x40, 0x00, 0x00, 0x01 //hierarchy: TPM_RH_OWNER.
        ];

        AssertFraming(input, [], expectedParameters);
    }

    /// <summary>
    /// Part 2, Table 96: <c>TPM2B_MAX_BUFFER</c> is bounded by <c>MAX_2B_BUFFER_SIZE</c> — both inputs refuse a
    /// larger buffer at construction, before any rent.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.3.8, Table 96</see>.
    /// </summary>
    [TestMethod]
    public void SequenceCompleteAndHashInputsOverMaxSizeThrowArgumentException()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] oversized = new byte[Tpm2bMaxBuffer.MaxSize + 1];

        _ = Assert.ThrowsExactly<ArgumentException>(() => SequenceCompleteInput.Create(TpmiDhObject.FromValue(0x80000000u), oversized, TpmiRhHierarchy.Null, pool));
        _ = Assert.ThrowsExactly<ArgumentException>(() => HashInput.Create(oversized, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256), TpmiRhHierarchy.Null, pool));
    }

    /// <summary>
    /// Tables 94 and 70 share one response shape: <c>TPM2B_DIGEST</c> then <c>TPMT_TK_HASHCHECK</c> — both
    /// codecs parse a hand-built frame to the same digest and a ticket whose hierarchy and HMAC round-trip, and
    /// parse the NULL ticket (hierarchy <c>TPM_RH_NULL</c>, empty digest) as <c>IsNull</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, Tables 70 and 94; Part 2, clause 10.6.7, Table 115</see>.
    /// </summary>
    [TestMethod]
    public void SequenceCompleteAndHashResponsesParseTheDigestAndTheTicketPerTables94And70()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] frame =
        [
            0x00, 0x02, 0xEE, 0xFF, //result / outHash: TPM2B_DIGEST, size 2.
            0x80, 0x24, //validation.tag: TPM_ST_HASHCHECK.
            0x40, 0x00, 0x00, 0x01, //validation.hierarchy: TPM_RH_OWNER.
            0x00, 0x03, 0x01, 0x02, 0x03 //validation.digest: TPM2B_DIGEST, size 3.
        ];

        var completeReader = new TpmReader(frame);
        using SequenceCompleteResponse complete = SequenceCompleteResponse.Parse(ref completeReader, pool);
        Assert.AreSequenceEqual(new byte[] { 0xEE, 0xFF }, complete.Result.AsReadOnlySpan().ToArray());
        Assert.AreEqual(TpmiRhHierarchy.Owner, complete.Validation.Hierarchy);
        Assert.AreSequenceEqual(new byte[] { 0x01, 0x02, 0x03 }, complete.Validation.Digest.ToArray());
        Assert.IsFalse(complete.Validation.IsNull);
        Assert.AreEqual(0, completeReader.Remaining, "The parse must consume the whole frame.");

        var hashReader = new TpmReader(frame);
        using HashResponse hash = HashResponse.Parse(ref hashReader, pool);
        Assert.AreSequenceEqual(new byte[] { 0xEE, 0xFF }, hash.OutHash.AsReadOnlySpan().ToArray());
        Assert.AreEqual(TpmiRhHierarchy.Owner, hash.Validation.Hierarchy);
        Assert.AreEqual(0, hashReader.Remaining, "The parse must consume the whole frame.");

        byte[] nullTicketFrame =
        [
            0x00, 0x01, 0x7A, //outHash: TPM2B_DIGEST, size 1.
            0x80, 0x24, //validation.tag: TPM_ST_HASHCHECK.
            0x40, 0x00, 0x00, 0x07, //validation.hierarchy: TPM_RH_NULL.
            0x00, 0x00 //validation.digest: empty.
        ];

        var nullReader = new TpmReader(nullTicketFrame);
        using HashResponse nullTicketed = HashResponse.Parse(ref nullReader, pool);
        Assert.IsTrue(nullTicketed.Validation.IsNull, "Hierarchy TPM_RH_NULL with an empty digest is the NULL ticket.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> rows (Part 2, clause 8.9): <c>TPM2_Hash</c> and <c>TPM2_HashSequenceStart</c> take no
    /// handles, the latter returns one (<c>rHandle</c>); <c>TPM2_SequenceComplete</c> takes one and is
    /// <c>{F}</c> (<c>flushed</c>).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, Tables 69, 85, 93</see>.
    /// </summary>
    [TestMethod]
    public void HashFamilyCommandAttributesCarryTheirHandleCountsFlushedAndResponseHandleBits()
    {
        TpmaCc hash = TpmCcConstants.TPM_CC_Hash.GetCommandAttributes();
        Assert.AreEqual((byte)0, hash.C_HANDLES);
        Assert.IsFalse(hash.R_HANDLE);
        Assert.IsFalse(hash.FLUSHED);

        TpmaCc start = TpmCcConstants.TPM_CC_HashSequenceStart.GetCommandAttributes();
        Assert.AreEqual((byte)0, start.C_HANDLES);
        Assert.IsTrue(start.R_HANDLE, "TPM2_HashSequenceStart returns sequenceHandle in the response handle area.");
        Assert.IsFalse(start.FLUSHED);

        TpmaCc complete = TpmCcConstants.TPM_CC_SequenceComplete.GetCommandAttributes();
        Assert.AreEqual((byte)1, complete.C_HANDLES);
        Assert.IsTrue(complete.FLUSHED, "TPM2_SequenceComplete is {F}: the sequence is flushed on success.");
        Assert.IsFalse(complete.R_HANDLE);
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
