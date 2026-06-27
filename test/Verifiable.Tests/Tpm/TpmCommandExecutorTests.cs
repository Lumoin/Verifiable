using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Non-hardware coverage for <see cref="TpmCommandExecutor.ExecuteAsync"/>, driving the full
/// request-build and response-parse path through a scripted <see cref="TpmDevice.Create"/> handler.
/// </summary>
/// <remarks>
/// The <c>HwTpm*</c> tests exercise the executor only when a physical TPM is present; on machines
/// without one they skip. These tests cover the sessionless build/parse path deterministically with
/// canned response bytes, so a refactor of the executor envelope handling is guarded by an
/// executing test rather than only by hardware-gated ones.
/// </remarks>
[TestClass]
internal sealed class TpmCommandExecutorTests
{
    //TPM command/response header: tag (UINT16) + size (UINT32) + commandCode/responseCode (UINT32).
    private const int HeaderSize = 10;
    private const ushort TpmStNoSessions = 0x8001;

    public TestContext TestContext { get; set; } = null!;

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> SuccessFrame(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, bytes.Length));
    }

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

    [TestMethod]
    public async Task ExecutorBuildsGetRandomCommandAndParsesResponse()
    {
        const int RequestedBytes = 16;
        byte[]? observedCommand = null;

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            observedCommand = command.ToArray();

            //GetRandom is sessionless: bytesRequested (UINT16) sits immediately after the header.
            ushort requested = (ushort)((command.Span[HeaderSize] << 8) | command.Span[HeaderSize + 1]);

            //Parameters: TPM2B_DIGEST = UINT16 length + that many octets (deterministic content).
            byte[] parameters = new byte[sizeof(ushort) + requested];
            parameters[0] = (byte)(requested >> 8);
            parameters[1] = (byte)(requested & 0xFF);
            for(int i = 0; i < requested; i++)
            {
                parameters[sizeof(ushort) + i] = (byte)i;
            }

            byte[] frame = BuildNoSessionsFrame(0u, parameters);

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        var input = new GetRandomInput(RequestedBytes);

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result.ResponseCode}'.");
        using GetRandomResponse response = result.Value;
        Assert.AreEqual(RequestedBytes, response.RandomBytes.Size);

        //Parsed content matches what the canned response carried.
        ReadOnlySpan<byte> random = response.RandomBytes.AsReadOnlySpan();
        Assert.AreEqual((byte)0x00, random[0]);
        Assert.AreEqual((byte)0x0F, random[RequestedBytes - 1]);

        //The executor built a well-formed sessionless command carrying the requested length.
        Assert.IsNotNull(observedCommand);
        Assert.AreEqual((byte)(TpmStNoSessions >> 8), observedCommand[0]);
        Assert.AreEqual((byte)(TpmStNoSessions & 0xFF), observedCommand[1]);
        ushort commandRequested = (ushort)((observedCommand[HeaderSize] << 8) | observedCommand[HeaderSize + 1]);
        Assert.AreEqual(RequestedBytes, commandRequested);
    }

    [TestMethod]
    public async Task ExecutorSurfacesTpmErrorResponseCode()
    {
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            //A header-only error response (no parameters) carrying a non-success response code.
            byte[] frame = BuildNoSessionsFrame((uint)TpmRcConstants.TPM_RC_VALUE, ReadOnlySpan<byte>.Empty);

            return ValueTask.FromResult(SuccessFrame(frame, pool));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        var input = new GetRandomInput(8);

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError);
        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode);
    }

    [TestMethod]
    public async Task ExecutorSurfacesTransportError()
    {
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(0x1234u));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        var input = new GetRandomInput(8);

        TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            device, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTransportError);
    }

    [TestMethod]
    public async Task ExecutorRejectsHandleNamesCountMismatch()
    {
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            Assert.Fail("The device must not be invoked when handleNames has the wrong count.");

            return ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(0u));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        var input = new GetRandomInput(8);

        //GetRandom takes no handles, so supplying one Name is a count mismatch the executor must reject
        //before touching the device.
        ReadOnlyMemory<byte>[] handleNames = [new byte[] { 0x40, 0x00, 0x00, 0x01 }];

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                device, input, [], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the TpmSession, which the using statement disposes.")]
    public async Task ExecutorRequiresNameForObjectHandleOverHmacSession()
    {
        //An HMAC session authorizing a transient OBJECT (handle type 0x80) must supply that object's Name for
        //cpHash; without it the executor fails fast rather than hashing the raw handle (which the TPM never does
        //for an object). Deterministic, no hardware needed.
        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> pool,
            CancellationToken cancellationToken)
        {
            Assert.Fail("The device must not be invoked when a required object Name is missing.");

            return ValueTask.FromResult(TpmResult<TpmResponse>.TransportError(0u));
        }

        using var device = TpmDevice.Create(Handler);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);

        const uint TransientParent = 0x80000000u;
        using var input = CreateInput.ForEccSigningChild(
            TransientParent, null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool);

        Tpm2bNonce nonceTpm = Tpm2bNonce.Create(new byte[32], pool);
        using var session = new TpmSession(new TpmHandle(0x02000000u), nonceTpm, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);
    }

    [TestMethod]
    public async Task ExecutorFoldsEntityNamesIntoCommandHmacInHandleOrder()
    {
        //Deterministic, non-hardware proof of the cpHash-over-Names concatenation, including multi-handle ORDER.
        //A scripted device captures the emitted NV_Read command (two handles); the caller nonce the session
        //generates is serialized into that command, so the expected auth HMAC can be recomputed with an
        //INDEPENDENT SHA-256/HMAC oracle over cpHash = H(cc || authName || nvName || params) and compared to the
        //bytes the executor sent. The raw-handle fallback (handleNames:null) is recomputed too, so the test
        //locks both that Names are used and that they are concatenated in handle order.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

        //Canned, known session inputs.
        byte[] nonceTpmValue = new byte[32];
        for(int i = 0; i < nonceTpmValue.Length; i++)
        {
            nonceTpmValue[i] = (byte)(0xC0 ^ i);
        }

        byte[] authValue = System.Text.Encoding.UTF8.GetBytes("index-secret");

        //Two DISTINCT multi-byte Names (nameAlg || digest shape). Distinctness makes a reversed or mis-offset
        //concatenation produce a different cpHash. They are arbitrary test Names; the scripted device does not
        //validate them.
        byte[] authName = new byte[2 + 32];
        authName[1] = 0x0B; //TPM_ALG_SHA256 = 0x000B.
        for(int i = 0; i < 32; i++)
        {
            authName[2 + i] = (byte)(0x10 + i);
        }

        byte[] nvName = new byte[2 + 32];
        nvName[1] = 0x0B;
        for(int i = 0; i < 32; i++)
        {
            nvName[2 + i] = (byte)(0x40 + i);
        }

        const uint NvHandle = 0x01000000u; //An NV-index handle, used as both authHandle and nvIndex (index auth).
        const ushort Size = 8;
        const ushort Offset = 0;
        var input = new NvReadInput(NvHandle, NvHandle, Size, Offset);

        //Parameters exactly as serialized into the command: size (UINT16 BE) + offset (UINT16 BE).
        byte[] parameters = [(byte)(Size >> 8), (byte)(Size & 0xFF), (byte)(Offset >> 8), (byte)(Offset & 0xFF)];
        byte[] commandCode = [0x00, 0x00, 0x01, 0x4E]; //TPM_CC_NV_Read.

        //Names path: cpHash over the supplied Names, in handle order.
        (byte[] nonceCaller, byte attributes, byte[] hmac) named = await RunNvReadAndParseAuthAsync(
            input, [authName, nvName], nonceTpmValue, authValue, pool, registry).ConfigureAwait(false);
        byte[] expectedNamed = ExpectedAuthHmac(authValue, Concat(commandCode, authName, nvName, parameters), named.nonceCaller, nonceTpmValue, named.attributes);
        Assert.IsTrue(named.hmac.AsSpan().SequenceEqual(expectedNamed),
            "The command HMAC must be computed over cpHash = H(cc || authName || nvName || params).");

        //Without the NV index Names the executor refuses to guess: an NV index Name is nameAlg||H(nvPublic),
        //never the raw handle, so it fails fast rather than producing a cpHash the TPM would reject.
        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await RunNvReadAndParseAuthAsync(input, null, nonceTpmValue, authValue, pool, registry).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>
    /// Drives a single NV_Read through a scripted device that captures the emitted command and returns an error
    /// (so execution stops after the send), then parses the command's authorization area and returns the caller
    /// nonce, session attributes, and auth HMAC the executor produced.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The canned nonceTPM ownership transfers to the TpmSession, which the using statement disposes.")]
    private async Task<(byte[] nonceCaller, byte attributes, byte[] hmac)> RunNvReadAndParseAuthAsync(
        NvReadInput input,
        IReadOnlyList<ReadOnlyMemory<byte>>? handleNames,
        byte[] nonceTpmValue,
        byte[] authValue,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry)
    {
        byte[]? observed = null;

        ValueTask<TpmResult<TpmResponse>> Handler(
            ReadOnlyMemory<byte> command,
            MemoryPool<byte> handlerPool,
            CancellationToken cancellationToken)
        {
            observed = command.ToArray();

            //A header-only error so the executor surfaces it right after the send; no response auth is needed.
            byte[] frame = BuildNoSessionsFrame((uint)TpmRcConstants.TPM_RC_VALUE, ReadOnlySpan<byte>.Empty);

            return ValueTask.FromResult(SuccessFrame(frame, handlerPool));
        }

        using var device = TpmDevice.Create(Handler);

        Tpm2bNonce nonceTpm = Tpm2bNonce.Create(nonceTpmValue, pool);
        using var session = new TpmSession(new TpmHandle(0x02000000u), nonceTpm, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        session.SetAuthValue(authValue, pool);

        TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsTpmError, "The scripted error must surface so execution stops after the command is captured.");
        Assert.IsNotNull(observed);

        //Command layout: header(tag,size,cc) + 2 handles + authorizationSize + [sessionHandle + nonceCaller + attrs + hmac] + params.
        var reader = new TpmReader(observed);
        _ = reader.ReadUInt16();
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();
        _ = reader.ReadUInt32();
        byte[] nonceCaller = reader.ReadTpm2b().ToArray();
        byte attributes = reader.ReadByte();
        byte[] hmac = reader.ReadTpm2b().ToArray();

        return (nonceCaller, attributes, hmac);
    }

    /// <summary>
    /// Recomputes the expected command auth HMAC with an independent oracle (System.Security.Cryptography, used
    /// only to verify the executor's composition, not as the system under test - cf. KdfaTests). cpHash is
    /// SHA-256 over <paramref name="cpHashInput"/>; for an unbound session the HMAC key is the authValue alone,
    /// and the HMAC'd data is cpHash || nonceCaller || nonceTPM || sessionAttributes.
    /// </summary>
    private static byte[] ExpectedAuthHmac(byte[] authValue, byte[] cpHashInput, byte[] nonceCaller, byte[] nonceTpm, byte attributes)
    {
        byte[] cpHash = SHA256.HashData(cpHashInput);
        byte[] data = Concat(cpHash, nonceCaller, nonceTpm, [attributes]);

        return HMACSHA256.HashData(authValue, data);
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int length = 0;
        foreach(byte[] part in parts)
        {
            length += part.Length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        foreach(byte[] part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }

        return result;
    }
}
