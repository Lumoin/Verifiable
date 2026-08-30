using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Executor-level hardening for <see cref="TpmCommandExecutor.ExecuteAsync"/>'s response-shape handling,
/// driven entirely through a scripted <see cref="TpmDevice.Create"/> stub device — no simulator, no
/// hardware. A parser-bearing codec parses an empty response parameter area only when the codec also
/// declares an output handle (<see cref="TpmResponseCodec.OutHandleCount"/> greater than zero); a reader
/// underrun inside a response parser — a genuinely truncated field — is mapped to
/// <see cref="TpmRcConstants.TPM_RC_SIZE"/> rather than allowed to escape as a thrown exception, keeping
/// every malformed device response inside the <see cref="TpmResult{T}"/> fail-closed contract
/// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3: Commands, clause 6.2; Part 2: Structures, Table 17).
/// </summary>
[TestClass]
internal sealed class TpmCommandExecutorResponseShapeTests
{
    //TPM response header: tag (UINT16) + size (UINT32) + responseCode (UINT32).
    private const int HeaderSize = 10;
    private const ushort TpmStNoSessions = 0x8001;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A device answering a bare 10-octet <c>TPM_RC_SUCCESS</c> header — no handle, no parameters — to a
    /// parser-bearing, handle-less codec (<c>TPM2_SignDigest()</c>'s) must yield a <see cref="TpmResult{T}"/>
    /// carrying <c>TPM_RC_FAILURE</c>, never a thrown exception: with <see cref="TpmResponseCodec.OutHandleCount"/>
    /// zero and a genuinely empty parameter area, the executor falls to its parameterless branch, and the codec
    /// declares no parameterless singleton for a response that always carries a signature
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 20.7, Table 127).
    /// </summary>
    [TestMethod]
    public async Task DeviceAnsweringABareSuccessHeaderToASignDigestCodecReturnsTpmErrorFailure()
    {
        ValueTask<TpmResult<TpmResponse>> Handler(ReadOnlyMemory<byte> command, BaseMemoryPool handlerPool, CancellationToken cancellationToken)
        {
            byte[] frame = BuildNoSessionsFrame((uint)TpmRcConstants.TPM_RC_SUCCESS, ReadOnlySpan<byte>.Empty);

            return ValueTask.FromResult(SuccessFrame(frame, handlerPool));
        }

        using var device = TpmDevice.Create(Handler);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);

        byte[] digest = new byte[32];
        using SignDigestInput input = SignDigestInput.Create(TpmiDhObject.FromValue(0x8000_0001u), digest, pool);

        TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, "A bare success header to a parser-bearing, handle-less codec must surface as a TpmResult error, never a thrown exception.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_FAILURE, result.ResponseCode, "The parameterless branch's codec.EmptyResponse is null for TPM2_SignDigest(), so the executor must answer TPM_RC_FAILURE.");
    }

    /// <summary>
    /// A device answering a 14-octet <c>TPM_RC_SUCCESS</c> header carrying one output handle and NO
    /// parameters — Table 88's exact shape — to <see cref="TpmResponseCodec.SignSequenceStart"/> must yield a
    /// successful, correctly-bound response: a handle-returning codec with
    /// <see cref="TpmResponseCodec.OutHandleCount"/> greater than zero parses over the (genuinely empty)
    /// parameter area so the parser can bind the handle into the typed response
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 17.5, Table 88).
    /// </summary>
    [TestMethod]
    public async Task DeviceAnsweringAHeaderPlusHandleToSignSequenceStartCodecBindsTheHandle()
    {
        const uint SequenceHandle = 0x8000_1234u;

        ValueTask<TpmResult<TpmResponse>> Handler(ReadOnlyMemory<byte> command, BaseMemoryPool handlerPool, CancellationToken cancellationToken)
        {
            byte[] handleBytes = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(handleBytes, SequenceHandle);
            byte[] frame = BuildNoSessionsFrame((uint)TpmRcConstants.TPM_RC_SUCCESS, handleBytes);

            return ValueTask.FromResult(SuccessFrame(frame, handlerPool));
        }

        using var device = TpmDevice.Create(Handler);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);

        using SignSequenceStartInput input = SignSequenceStartInput.Create(TpmiDhObject.FromValue(0x8000_0001u), [], pool);

        TpmResult<SignSequenceStartResponse> result = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"A header-plus-handle, no-parameters response to a handle-returning codec must succeed: '{result.ResponseCode}'.");
        Assert.AreEqual(SequenceHandle, result.Value.SequenceHandle.Value, "The parsed response must carry exactly the handle the device's response frame declared.");
    }

    /// <summary>
    /// A device answering a <c>TPMT_SIGNATURE</c> truncated to 3 octets — enough for the response envelope to
    /// pass its own length checks, too short for the codec's own parser to complete — must yield
    /// <c>TPM_RC_SIZE</c>: the reader underrun the truncated field causes is a size fault, not an escape from
    /// the <see cref="TpmResult{T}"/> contract
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, clause 6.2; Part 2: Structures, Table 17: "TPM_RC_SIZE structure
    /// is the wrong size").
    /// </summary>
    [TestMethod]
    public async Task DeviceAnsweringATruncatedSignatureToASignDigestCodecReturnsSize()
    {
        ValueTask<TpmResult<TpmResponse>> Handler(ReadOnlyMemory<byte> command, BaseMemoryPool handlerPool, CancellationToken cancellationToken)
        {
            //Three octets: nowhere near a complete TPMT_SIGNATURE (sigAlg UINT16 + a hash algorithm UINT16 at
            //minimum), so the parser underruns partway through the second field.
            byte[] truncatedSignature = [0x00, 0x18, 0x00];
            byte[] frame = BuildNoSessionsFrame((uint)TpmRcConstants.TPM_RC_SUCCESS, truncatedSignature);

            return ValueTask.FromResult(SuccessFrame(frame, handlerPool));
        }

        using var device = TpmDevice.Create(Handler);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_SignDigest, TpmResponseCodec.SignDigest);

        byte[] digest = new byte[32];
        using SignDigestInput input = SignDigestInput.Create(TpmiDhObject.FromValue(0x8000_0001u), digest, pool);

        TpmResult<SignDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<SignDigestResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, "A truncated TPMT_SIGNATURE must surface as a TpmResult error, never a thrown exception.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode, "A reader underrun inside a response parser must map to TPM_RC_SIZE.");
    }

    /// <summary>
    /// A device answering a 14-octet <c>TPM_RC_SUCCESS</c> header carrying one output handle and NO
    /// parameters to <see cref="TpmResponseCodec.Load"/> — a handle-returning codec whose response ALSO
    /// carries a parameter (the object's Name, TPM2B_NAME) — must yield <c>TPM_RC_SIZE</c>, not a thrown
    /// exception: parsing runs (OutHandleCount is greater than zero) but the parser's own read of the Name
    /// field underruns the empty parameter area
    /// (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
    /// Specification</see>, Part 3: Commands, Section 12.2, Table 22).
    /// </summary>
    [TestMethod]
    public async Task DeviceAnsweringAHeaderPlusHandleWithNoParametersToLoadCodecReturnsSize()
    {
        const uint LoadedObjectHandle = 0x8000_5678u;

        ValueTask<TpmResult<TpmResponse>> Handler(ReadOnlyMemory<byte> command, BaseMemoryPool handlerPool, CancellationToken cancellationToken)
        {
            byte[] handleBytes = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(handleBytes, LoadedObjectHandle);
            byte[] frame = BuildNoSessionsFrame((uint)TpmRcConstants.TPM_RC_SUCCESS, handleBytes);

            return ValueTask.FromResult(SuccessFrame(frame, handlerPool));
        }

        using var device = TpmDevice.Create(Handler);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);

        using Tpm2bPublic dummyPublic = Tpm2bPublic.CreateSealedDataTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, pool, noDa: true);
        using var input = new LoadInput(0x8000_0001u, Tpm2bPrivate.Empty, dummyPublic);

        TpmResult<LoadResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, "A handle-plus-parameters codec answered with only the handle must surface as a TpmResult error, never a thrown exception.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, result.ResponseCode, "The parser's own read of the Name parameter must underrun the empty parameter area and map to TPM_RC_SIZE.");
    }

    /// <summary>Wraps a raw response frame into the <see cref="TpmResult{T}"/> shape a device handler returns.</summary>
    /// <param name="bytes">The complete response frame, header included.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>A successful transport-level result carrying the framed response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> SuccessFrame(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, bytes.Length));
    }

    /// <summary>Builds a <c>TPM_ST_NO_SESSIONS</c>-tagged response frame carrying the given response code and parameter bytes.</summary>
    /// <param name="responseCode">The response code to frame.</param>
    /// <param name="parameters">The parameter-area octets (a handle area, a parameter area, or both concatenated).</param>
    /// <returns>The complete response frame, header included.</returns>
    private static byte[] BuildNoSessionsFrame(uint responseCode, ReadOnlySpan<byte> parameters)
    {
        int total = HeaderSize + parameters.Length;
        byte[] frame = new byte[total];

        frame[0] = (byte)(TpmStNoSessions >> 8);
        frame[1] = (byte)(TpmStNoSessions & 0xFF);
        frame[2] = (byte)(total >> 24);
        frame[3] = (byte)(total >> 16);
        frame[4] = (byte)(total >> 8);
        frame[5] = (byte)(total & 0xFF);
        frame[6] = (byte)(responseCode >> 24);
        frame[7] = (byte)(responseCode >> 16);
        frame[8] = (byte)(responseCode >> 8);
        frame[9] = (byte)(responseCode & 0xFF);
        parameters.CopyTo(frame.AsSpan(HeaderSize));

        return frame;
    }
}
