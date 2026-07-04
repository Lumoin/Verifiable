using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Adversarial-input coverage for the TPM response-parsing surface: a malicious, buggy, or MITM'd TPM returns
/// crafted response bytes and every parser must fail closed rather than pre-allocate from a lying length, read
/// out of bounds, or surface a type-confused attestation as success. Each test is the regression proof for a
/// specific hardening (the count guard, the response-envelope bounds, and the attestation-type gate).
/// </summary>
[TestClass]
internal sealed class TpmResponseHardeningTests
{
    //TPM command/response header: tag (UINT16) + size (UINT32) + responseCode (UINT32).
    private const int HeaderSize = 10;
    private const ushort TpmStNoSessions = 0x8001;
    private const ushort TpmStSessions = 0x8002;

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void ReaderEnsureCountRejectsCountLargerThanRemainingBuffer()
    {
        //Eight bytes remaining; a declared count of ~one billion four-byte elements cannot fit and is rejected
        //before it can size any collection.
        Assert.ThrowsExactly<InvalidOperationException>(static () => EnsureCount(new byte[8], 0x40000000u, sizeof(uint)));
    }

    [TestMethod]
    public void ReaderEnsureCountAcceptsCountThatFits()
    {
        //Eight bytes remaining hold exactly two four-byte elements; the exact-fit count is accepted.
        var reader = new TpmReader(new byte[8]);

        reader.EnsureCount(2u, sizeof(uint));
    }

    [TestMethod]
    public void TpmlDigestParseRejectsCountLargerThanBuffer()
    {
        //TPML_DIGEST: count (UINT32) then that many TPM2B_DIGEST. A count of ~1 billion with no digest bytes
        //following must be rejected before 'new List<Tpm2bDigest>((int)count)' pre-allocates gigabytes.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] data = [0x40, 0x00, 0x00, 0x00]; //count = 0x40000000.

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseTpmlDigest(data, pool));
    }

    [TestMethod]
    public void TpmsCapabilityDataParseRejectsUnboundedCountForEveryArm()
    {
        //Every TPMS_CAPABILITY_DATA arm reads a UINT32 count and then an array of fixed-size elements; a count
        //the remaining buffer cannot possibly hold must be rejected before the array is sized (TPM2_GetCapability
        //is answered by an untrusted TPM). The buffer carries only capability + count, so any non-zero count
        //overruns and must throw.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmCapConstants[] arms =
        [
            TpmCapConstants.TPM_CAP_ALGS,
            TpmCapConstants.TPM_CAP_HANDLES,
            TpmCapConstants.TPM_CAP_COMMANDS,
            TpmCapConstants.TPM_CAP_TPM_PROPERTIES,
            TpmCapConstants.TPM_CAP_ECC_CURVES
        ];

        foreach(TpmCapConstants capability in arms)
        {
            byte[] data = new byte[sizeof(uint) + sizeof(uint)];
            WriteUInt32BigEndian(data, 0, (uint)capability);
            WriteUInt32BigEndian(data, sizeof(uint), 0x40000000u); //count = ~1 billion.

            Assert.ThrowsExactly<InvalidOperationException>(() => ParseCapabilityData(data, pool),
                $"Capability arm '{capability}' must reject an unbounded element count.");
        }
    }

    [TestMethod]
    public void QuoteResponseParseRejectsCertifyTypedAttestation()
    {
        //A TPM2_Quote response whose attestation is a (replayed) TPM_ST_ATTEST_CERTIFY structure must be rejected:
        //its type does not match the command, and surfacing it as success leaves Attested.Quote null for the first
        //consumer that dereferences it (Part 3, §18.4 fixes the type to TPM_ST_ATTEST_QUOTE).
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] certifyAttest = BuildTpm2bAttestImage(TpmStConstants.TPM_ST_ATTEST_CERTIFY, pool);

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseQuoteResponse(certifyAttest, pool));
    }

    [TestMethod]
    public void CertifyResponseParseRejectsQuoteTypedAttestation()
    {
        //Symmetric to the quote case: a TPM2_Certify response whose attestation is a TPM_ST_ATTEST_QUOTE structure
        //must be rejected rather than surfaced with a null Attested.Certify (Part 3, §18.2).
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] quoteAttest = BuildTpm2bAttestImage(TpmStConstants.TPM_ST_ATTEST_QUOTE, pool);

        Assert.ThrowsExactly<InvalidOperationException>(() => ParseCertifyResponse(quoteAttest, pool));
    }

    [TestMethod]
    public async Task ExecutorRejectsResponseParameterSizeLargerThanResponse()
    {
        //A TPM_ST_SESSIONS response whose parameterSize field claims more bytes than the response contains must be
        //answered with TPM_RC_SIZE, not pre-allocate that many bytes nor, once cast to int, go negative and throw
        //past the fail-closed TpmResult contract (Part 1, §16.10 parameter/auth split).
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            //Header + a single 4-byte parameterSize field = 14 bytes, but parameterSize claims 0xFFFFFFFF.
            byte[] frame = new byte[HeaderSize + sizeof(uint)];
            WriteHeader(frame, TpmStSessions, (uint)frame.Length, (uint)TpmRcConstants.TPM_RC_SUCCESS);
            WriteUInt32BigEndian(frame, HeaderSize, 0xFFFFFFFFu);

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        var input = new GetRandomInput(8);

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, $"Expected a TPM error, got success={result.IsSuccess}.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode);
    }

    [TestMethod]
    public async Task ExecutorRejectsResponseTruncatedBeforeOutputHandles()
    {
        //A handle-returning command (StartAuthSession has one output handle) whose response is only a header must
        //be answered with TPM_RC_SIZE, not read an output handle out of the empty remainder and throw an
        //out-of-range exception past the fail-closed contract.
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            //A header-only success response: too short to hold the promised output handle.
            byte[] frame = new byte[HeaderSize];
            WriteHeader(frame, TpmStNoSessions, (uint)frame.Length, (uint)TpmRcConstants.TPM_RC_SUCCESS);

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);

        var input = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256);

        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, $"Expected a TPM error, got success={result.IsSuccess}.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode);
    }

    /// <summary>
    /// Builds a fresh reader over <paramref name="data"/> and validates the count against the remaining buffer;
    /// isolates the ref-struct reader from the throwing assertion's lambda.
    /// </summary>
    private static void EnsureCount(byte[] data, uint count, int minBytesPerElement)
    {
        var reader = new TpmReader(data);
        reader.EnsureCount(count, minBytesPerElement);
    }

    /// <summary>
    /// Parses a TPML_DIGEST from <paramref name="data"/>; isolates the ref-struct reader from the assertion lambda.
    /// </summary>
    private static void ParseTpmlDigest(byte[] data, MemoryPool<byte> pool)
    {
        var reader = new TpmReader(data);
        using TpmlDigest _ = TpmlDigest.Parse(ref reader, pool);
    }

    /// <summary>
    /// Parses a TPMS_CAPABILITY_DATA from <paramref name="data"/>; isolates the ref-struct reader from the lambda.
    /// </summary>
    private static void ParseCapabilityData(byte[] data, MemoryPool<byte> pool)
    {
        var reader = new TpmReader(data);
        using TpmsCapabilityData _ = TpmsCapabilityData.Parse(ref reader, pool);
    }

    /// <summary>
    /// Parses a TPM2_Quote response from <paramref name="data"/>; isolates the ref-struct reader from the lambda.
    /// </summary>
    private static void ParseQuoteResponse(byte[] data, MemoryPool<byte> pool)
    {
        var reader = new TpmReader(data);
        using QuoteResponse _ = QuoteResponse.Parse(ref reader, pool);
    }

    /// <summary>
    /// Parses a TPM2_Certify response from <paramref name="data"/>; isolates the ref-struct reader from the lambda.
    /// </summary>
    private static void ParseCertifyResponse(byte[] data, MemoryPool<byte> pool)
    {
        var reader = new TpmReader(data);
        using CertifyResponse _ = CertifyResponse.Parse(ref reader, pool);
    }

    /// <summary>
    /// Builds a TPM2B_ATTEST wire image (2-byte size prefix + marshaled TPMS_ATTEST) for the requested attestation
    /// type, used to feed a type-confused attestation into a response parser.
    /// </summary>
    /// <param name="type">The attestation type to stamp into the TPMS_ATTEST.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The TPM2B_ATTEST wire bytes.</returns>
    private static byte[] BuildTpm2bAttestImage(TpmStConstants type, MemoryPool<byte> pool)
    {
        byte[] attestImage;
        using(TpmsAttest attest = BuildSampleAttest(type, pool))
        using(IMemoryOwner<byte> innerOwner = pool.Rent(attest.GetSerializedSize()))
        {
            var innerWriter = new TpmWriter(innerOwner.Memory.Span);
            attest.WriteTo(ref innerWriter);
            attestImage = innerOwner.Memory.Span[..innerWriter.Written].ToArray();
        }

        byte[] framed = new byte[sizeof(ushort) + attestImage.Length];
        framed[0] = (byte)(attestImage.Length >> 8);
        framed[1] = (byte)(attestImage.Length & 0xFF);
        attestImage.CopyTo(framed, sizeof(ushort));

        return framed;
    }

    /// <summary>
    /// Builds a well-formed TPMS_ATTEST of the requested type (a quote or a certify body) with representative
    /// stand-in fields; ownership of the created structures transfers to the returned attestation.
    /// </summary>
    /// <param name="type">The attestation type.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The attestation structure (the caller owns it).</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the created structures transfers to the returned TpmsAttest, which the caller disposes.")]
    private static TpmsAttest BuildSampleAttest(TpmStConstants type, MemoryPool<byte> pool)
    {
        byte[] name = new byte[sizeof(ushort) + 32];
        name[1] = 0x0B; //TPM_ALG_SHA256 nameAlg prefix.
        for(int i = 0; i < 32; i++)
        {
            name[sizeof(ushort) + i] = (byte)(0xA0 + i);
        }

        byte[] nonce = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        byte[] pcrDigest = new byte[32];
        for(int i = 0; i < pcrDigest.Length; i++)
        {
            pcrDigest[i] = (byte)i;
        }

        TpmuAttest attested = type == TpmStConstants.TPM_ST_ATTEST_QUOTE
            ? TpmuAttest.ForQuote(TpmsQuoteInfo.Create(
                TpmlPcrSelection.Create(TpmAlgIdConstants.TPM_ALG_SHA256, [0, 7], pool),
                Tpm2bDigest.Create(pcrDigest, pool)))
            : TpmuAttest.ForCertify(TpmsCertifyInfo.Create(
                Tpm2bName.Create(name, pool),
                Tpm2bName.Create(name, pool)));

        return TpmsAttest.Create(
            TpmConstants32.TPM_GENERATED_VALUE,
            type,
            Tpm2bName.Create(name, pool),
            Tpm2bData.Create(nonce, pool),
            new TpmsClockInfo(Clock: 0x1122334455667788UL, ResetCount: 5, RestartCount: 3, Safe: TpmiYesNo.Yes),
            firmwareVersion: 0x0001000200030004UL,
            attested);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> SuccessFrame(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, bytes.Length));
    }

    private static void WriteHeader(byte[] frame, ushort tag, uint size, uint code)
    {
        frame[0] = (byte)(tag >> 8);
        frame[1] = (byte)(tag & 0xFF);
        WriteUInt32BigEndian(frame, 2, size);
        WriteUInt32BigEndian(frame, 6, code);
    }

    private static void WriteUInt32BigEndian(byte[] buffer, int offset, uint value)
    {
        buffer[offset] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)(value & 0xFF);
    }
}
