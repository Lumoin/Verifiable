using System;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact framing of the PCR-modifying commands' inputs against their published tables —
/// <c>TPM2_PCR_Extend()</c> (TPM 2.0 Library Part 3, Table 130), <c>TPM2_PCR_Event()</c> (Table 132),
/// <c>TPM2_PCR_Reset()</c> (Table 142) and <c>TPM2_EventSequenceComplete()</c> (Table 95) — plus the response
/// codecs' parse of Tables 133 and 96, the <c>TPML_DIGEST_VALUES</c> and <c>TPM2B_EVENT</c> structures' own
/// bounds, and the commands' <c>TPMA_CC</c> rows.
/// </summary>
[TestClass]
internal sealed class PcrCommandInputFramingTests
{
    private static TpmiAlgHash Sha1 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA1);

    private static TpmiAlgHash Sha256 => TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256);

    private static TpmiDhPcr NullPcr => TpmiDhPcr.FromValue((uint)TpmRh.TPM_RH_NULL);

    /// <summary>
    /// Table 130: <c>@pcrHandle</c> (TPMI_DH_PCR+); <c>digests</c> (TPML_DIGEST_VALUES: UINT32 count then each
    /// TPMT_HA as hashAlg followed by a digest of the algorithm's width, no size field); the raw command code is
    /// 0x00000182 (Part 2, Table 12). The first parameter is a list, so nothing is encryptable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.2.2, Table 130; Part 2, clause 10.8.6, Table 127</see>.
    /// </summary>
    [TestMethod]
    public void PcrExtendInputCreateFramesTheHandleAndTheDigestListByteExactlyPerTable130()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] digest = new byte[32];
        for(int i = 0; i < digest.Length; i++)
        {
            digest[i] = (byte)(0xD0 + i);
        }

        using PcrExtendInput input = PcrExtendInput.Create(TpmiDhPcr.FromValue(7), Sha256, digest, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PCR_Extend, input.CommandCode);
        Assert.AreEqual(0x00000182u, (uint)input.CommandCode, "TPM_CC_PCR_Extend must equal Table 12's raw value 0x00000182.");
        ITpmCommandInput asInput = input;
        Assert.IsFalse(asInput.FirstCommandParameterIsEncryptable, "digests is a TPML, not a TPM2B, so it must not be marked encryptable.");

        byte[] expectedHandles = [0x00, 0x00, 0x00, 0x07];
        byte[] expectedParameters =
        [
            0x00, 0x00, 0x00, 0x01, //digests.count = 1.
            0x00, 0x0B,             //digests[0].hashAlg: TPM_ALG_SHA256.
            .. digest               //digests[0].digest: 32 octets, no size field.
        ];

        AssertFraming(input, expectedHandles, expectedParameters);
    }

    /// <summary>
    /// Table 127: entries of different algorithms carry digests of their own widths and are framed in list
    /// order — a SHA-1 entry (20 octets) followed by a SHA-256 entry (32 octets).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.8.6, Table 127; clause 10.2.2, Table 89</see>.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both TPMT_HA entries transfers to the adopted list, then to the input, whose using declaration releases them.")]
    public void PcrExtendInputWithTwoBanksFramesBothEntriesInListOrder()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] sha1Digest = new byte[20];
        sha1Digest.AsSpan().Fill(0x11);
        byte[] sha256Digest = new byte[32];
        sha256Digest.AsSpan().Fill(0x22);

        TpmlDigestValues digests = TpmlDigestValues.Adopt([TpmtHa.Create(Sha1, sha1Digest, pool), TpmtHa.Create(Sha256, sha256Digest, pool)]);
        using PcrExtendInput input = PcrExtendInput.Create(TpmiDhPcr.FromValue(0), digests);

        byte[] expectedParameters =
        [
            0x00, 0x00, 0x00, 0x02, //digests.count = 2.
            0x00, 0x04, .. sha1Digest,   //TPM_ALG_SHA1 + 20 octets.
            0x00, 0x0B, .. sha256Digest  //TPM_ALG_SHA256 + 32 octets.
        ];

        AssertFraming(input, [0x00, 0x00, 0x00, 0x00], expectedParameters);
    }

    /// <summary>
    /// Table 132: <c>@pcrHandle</c> (TPMI_DH_PCR+); <c>eventData</c> (TPM2B_EVENT); the raw command code is
    /// 0x0000013C (Part 2, Table 12). <c>eventData</c> is the first parameter and a TPM2B, so encryptable; a
    /// <c>TPM_RH_NULL</c> handle frames as 0x40000007.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.3.2, Table 132; Part 2, clause 10.3.7, Table 95</see>.
    /// </summary>
    [TestMethod]
    public void PcrEventInputCreateFramesTheHandleAndTheEventByteExactlyPerTable132()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] eventData = [0xE1, 0xE2, 0xE3];

        using PcrEventInput input = PcrEventInput.Create(TpmiDhPcr.FromValue(23), eventData, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_PCR_Event, input.CommandCode);
        Assert.AreEqual(0x0000013Cu, (uint)input.CommandCode, "TPM_CC_PCR_Event must equal Table 12's raw value 0x0000013C.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "eventData is the first TPM2B parameter, so it must be marked encryptable.");

        AssertFraming(input, [0x00, 0x00, 0x00, 0x17], [0x00, 0x03, 0xE1, 0xE2, 0xE3]);

        using PcrEventInput nullForm = PcrEventInput.Create(NullPcr, [], pool);
        AssertFraming(nullForm, [0x40, 0x00, 0x00, 0x07], [0x00, 0x00]);
    }

    /// <summary>
    /// Table 142: <c>@pcrHandle</c> (TPMI_DH_PCR) and no parameters at all; the raw command code is 0x0000013D
    /// (Part 2, Table 12).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 22.8.2, Table 142</see>.
    /// </summary>
    [TestMethod]
    public void PcrResetInputFramesTheHandleAloneByteExactlyPerTable142()
    {
        var input = new PcrResetInput(TpmiDhPcr.FromValue(16));

        Assert.AreEqual(TpmCcConstants.TPM_CC_PCR_Reset, input.CommandCode);
        Assert.AreEqual(0x0000013Du, (uint)input.CommandCode, "TPM_CC_PCR_Reset must equal Table 12's raw value 0x0000013D.");
        ITpmCommandInput asInput = input;
        Assert.IsFalse(asInput.FirstCommandParameterIsEncryptable, "TPM2_PCR_Reset has no parameters, so none is encryptable.");

        AssertFraming(input, [0x00, 0x00, 0x00, 0x10], []);
    }

    /// <summary>
    /// Table 95: <c>@pcrHandle</c> (TPMI_DH_PCR+) then <c>@sequenceHandle</c> (TPMI_DH_OBJECT); <c>buffer</c>
    /// (TPM2B_MAX_BUFFER); the raw command code is 0x00000185 (Part 2, Table 12). <c>buffer</c> is the first
    /// parameter and a TPM2B, so encryptable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 17.9.2, Table 95</see>.
    /// </summary>
    [TestMethod]
    public void EventSequenceCompleteInputCreateFramesBothHandlesAndTheBufferByteExactlyPerTable95()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] buffer = [0xB1, 0xB2];

        using EventSequenceCompleteInput input = EventSequenceCompleteInput.Create(TpmiDhPcr.FromValue(7), TpmiDhObject.FromValue(0x80000002u), buffer, pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_EventSequenceComplete, input.CommandCode);
        Assert.AreEqual(0x00000185u, (uint)input.CommandCode, "TPM_CC_EventSequenceComplete must equal Table 12's raw value 0x00000185.");
        Assert.IsTrue(input.FirstCommandParameterIsEncryptable, "buffer is the first TPM2B parameter, so it must be marked encryptable.");

        byte[] expectedHandles =
        [
            0x00, 0x00, 0x00, 0x07, //@pcrHandle: PCR 7.
            0x80, 0x00, 0x00, 0x02  //@sequenceHandle.
        ];

        AssertFraming(input, expectedHandles, [0x00, 0x02, 0xB1, 0xB2]);
    }

    /// <summary>
    /// Part 2, Table 95: <c>TPM2B_EVENT</c> is bounded at 1,024 octets — the input refuses a larger event at
    /// construction, before any rent, and the structure's parse refuses a larger wire size.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.3.7, Table 95; Part 3, clause 22.3.1</see>.
    /// </summary>
    [TestMethod]
    public void PcrEventInputAndTpm2bEventRefuseAnEventOverOneThousandTwentyFourOctets()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] oversized = new byte[Tpm2bEvent.MaxSize + 1];

        _ = Assert.ThrowsExactly<ArgumentException>(() => PcrEventInput.Create(TpmiDhPcr.FromValue(0), oversized, pool));

        byte[] oversizedFrame = [0x04, 0x01, .. oversized];
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => ParseEvent(oversizedFrame, pool));

        using Tpm2bEvent atBound = Tpm2bEvent.Create(new byte[Tpm2bEvent.MaxSize], pool);
        Assert.AreEqual(Tpm2bEvent.MaxSize, atBound.Length, "An event of exactly 1,024 octets is within Table 95's bound.");
    }

    /// <summary>
    /// Table 127: a <c>TPML_DIGEST_VALUES</c> parses each entry's digest at its algorithm's width and re-marshals
    /// byte-identically; a count above <c>HASH_COUNT</c> is <c>#TPM_RC_SIZE</c>, refused at parse before any
    /// entry is rented.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.8.6, Table 127</see>.
    /// </summary>
    [TestMethod]
    public void TpmlDigestValuesParsesEntriesAtTheirAlgorithmWidthsRoundTripsAndRefusesACountOverTheBound()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] sha1Digest = new byte[20];
        sha1Digest.AsSpan().Fill(0xA1);
        byte[] sha256Digest = new byte[32];
        sha256Digest.AsSpan().Fill(0xB2);
        byte[] frame =
        [
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x04, .. sha1Digest,
            0x00, 0x0B, .. sha256Digest
        ];

        var reader = new TpmReader(frame);
        using TpmlDigestValues parsed = TpmlDigestValues.Parse(ref reader, pool);
        Assert.AreEqual(0, reader.Remaining, "The parse must consume the whole list.");
        Assert.AreEqual(2, parsed.Count);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA1, parsed[0].HashAlg.Value);
        Assert.AreSequenceEqual(sha1Digest, parsed[0].Digest.ToArray());
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, parsed[1].HashAlg.Value);
        Assert.AreSequenceEqual(sha256Digest, parsed[1].Digest.ToArray());

        byte[] written = new byte[parsed.GetSerializedSize()];
        var writer = new TpmWriter(written);
        parsed.WriteTo(ref writer);
        Assert.AreEqual(frame.Length, writer.Written, "The re-marshal must be exactly as long as the parsed frame.");
        Assert.AreSequenceEqual(frame, written);

        byte[] overBound = [0x00, 0x00, 0x00, (byte)(TpmlDigestValues.MaxDigests + 1)];
        _ = Assert.ThrowsExactly<InvalidOperationException>(() => ParseDigestValues(overBound, pool));
    }

    /// <summary>
    /// Tables 133 and 96 share one response shape — a <c>TPML_DIGEST_VALUES</c> — so both codecs parse a
    /// hand-built frame to the same tagged digests.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, Tables 96 and 133; Part 2, clause 10.8.6, Table 127</see>.
    /// </summary>
    [TestMethod]
    public void PcrEventAndEventSequenceCompleteResponsesParseTheDigestListPerTables133And96()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] digest = new byte[32];
        digest.AsSpan().Fill(0xC3);
        byte[] frame = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, .. digest];

        var eventReader = new TpmReader(frame);
        using PcrEventResponse eventResponse = PcrEventResponse.Parse(ref eventReader, pool);
        Assert.AreEqual(1, eventResponse.Digests.Count);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, eventResponse.Digests[0].HashAlg.Value);
        Assert.AreSequenceEqual(digest, eventResponse.Digests[0].Digest.ToArray());
        Assert.AreEqual(0, eventReader.Remaining, "The parse must consume the whole frame.");

        var completeReader = new TpmReader(frame);
        using EventSequenceCompleteResponse completeResponse = EventSequenceCompleteResponse.Parse(ref completeReader, pool);
        Assert.AreEqual(1, completeResponse.Results.Count);
        Assert.AreSequenceEqual(digest, completeResponse.Results[0].Digest.ToArray());
        Assert.AreEqual(0, completeReader.Remaining, "The parse must consume the whole frame.");
    }

    /// <summary>
    /// The <c>TPMA_CC</c> rows (Part 2, clause 8.9): <c>TPM2_PCR_Extend</c>, <c>TPM2_PCR_Event</c> and
    /// <c>TPM2_PCR_Reset</c> take one handle and are <c>{NV}</c>; <c>TPM2_EventSequenceComplete</c> takes two and
    /// is <c>{NV F}</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 8.9, Table 43; Part 3, Tables 95, 130, 132, 142</see>.
    /// </summary>
    [TestMethod]
    public void PcrCommandAttributesCarryTheirHandleCountsNvAndFlushedBits()
    {
        TpmaCc extend = TpmCcConstants.TPM_CC_PCR_Extend.GetCommandAttributes();
        Assert.AreEqual((byte)1, extend.C_HANDLES);
        Assert.IsTrue(extend.NV, "TPM2_PCR_Extend is {NV}.");
        Assert.IsFalse(extend.FLUSHED);
        Assert.IsFalse(extend.R_HANDLE);

        TpmaCc pcrEvent = TpmCcConstants.TPM_CC_PCR_Event.GetCommandAttributes();
        Assert.AreEqual((byte)1, pcrEvent.C_HANDLES);
        Assert.IsTrue(pcrEvent.NV, "TPM2_PCR_Event is {NV}.");
        Assert.IsFalse(pcrEvent.FLUSHED);

        TpmaCc reset = TpmCcConstants.TPM_CC_PCR_Reset.GetCommandAttributes();
        Assert.AreEqual((byte)1, reset.C_HANDLES);
        Assert.IsTrue(reset.NV, "TPM2_PCR_Reset is {NV}.");
        Assert.IsFalse(reset.FLUSHED);

        TpmaCc complete = TpmCcConstants.TPM_CC_EventSequenceComplete.GetCommandAttributes();
        Assert.AreEqual((byte)2, complete.C_HANDLES);
        Assert.IsTrue(complete.NV, "TPM2_EventSequenceComplete is {NV F}.");
        Assert.IsTrue(complete.FLUSHED, "TPM2_EventSequenceComplete is {F}: the sequence is flushed on success.");
        Assert.IsFalse(complete.R_HANDLE);
    }

    /// <summary>Parses a <c>TPM2B_EVENT</c> frame and releases the result, for a throw assertion.</summary>
    /// <param name="frame">The wire frame.</param>
    /// <param name="pool">The memory pool.</param>
    private static void ParseEvent(byte[] frame, BaseMemoryPool pool)
    {
        var reader = new TpmReader(frame);
        Tpm2bEvent.Parse(ref reader, pool).Dispose();
    }

    /// <summary>Parses a <c>TPML_DIGEST_VALUES</c> frame and releases the result, for a throw assertion.</summary>
    /// <param name="frame">The wire frame.</param>
    /// <param name="pool">The memory pool.</param>
    private static void ParseDigestValues(byte[] frame, BaseMemoryPool pool)
    {
        var reader = new TpmReader(frame);
        TpmlDigestValues.Parse(ref reader, pool).Dispose();
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
