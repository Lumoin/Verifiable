using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Shared TPM command execution engine.
/// </summary>
/// <remarks>
/// <para>
/// The executor handles all envelope mechanics for TPM command execution:
/// </para>
/// <list type="bullet">
///   <item><description>Building request: header, handles, auth area, parameters.</description></item>
///   <item><description>Computing cpHash for request HMAC via the registered digest primitive.</description></item>
///   <item><description>Submitting to TPM device asynchronously.</description></item>
///   <item><description>Parsing response: header, handles, parameterSize split, auth area.</description></item>
///   <item><description>Computing rpHash for response verification via the registered digest primitive.</description></item>
///   <item><description>Invoking codec parser on parameters only.</description></item>
///   <item><description>Verifying session HMACs via the registered HMAC primitive.</description></item>
/// </list>
/// <para>
/// <b>Design:</b>
/// </para>
/// <para>
/// The executor uses a "fold" pattern with <see cref="TpmParseContext"/> as internal
/// accumulator state. The codec's parser delegate produces a strongly-typed response
/// object. The executor returns <see cref="TpmResult{T}"/> containing the typed response.
/// </para>
/// <para>
/// <b>Async surface:</b> Every TPM operation is asynchronous because the underlying
/// transport is — Linux <c>/dev/tpmrm0</c> supports kernel-level async I/O, network
/// HSM/KMS backends are inherently round-trip-bound, and the future TPM2_HMAC backend
/// will be hardware-bound. Software-only digest and HMAC paths complete synchronously
/// at the registered backend, so the async overhead is bounded to a state-machine
/// elision.
/// </para>
/// <para>
/// <b>Key invariant:</b> Codec parsers receive only the parameter area bytes.
/// They never see header, handles, or auth data.
/// </para>
/// </remarks>
public static class TpmCommandExecutor
{
    /// <summary>
    /// Asynchronously executes a TPM command and returns a strongly-typed response.
    /// </summary>
    /// <typeparam name="TResponse">The response type.</typeparam>
    /// <param name="device">The TPM device.</param>
    /// <param name="input">The command input.</param>
    /// <param name="sessions">The sessions (empty for no auth).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="cancellationToken">Token to observe across the device round-trip and crypto primitives.</param>
    /// <returns>The result containing the typed response, TPM error, or transport error.</returns>
    public static async ValueTask<TpmResult<TResponse>> ExecuteAsync<TResponse>(
        TpmDevice device,
        ITpmCommandInput input,
        IReadOnlyList<TpmSessionBase> sessions,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry,
        CancellationToken cancellationToken = default)
        where TResponse : ITpmWireType
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(sessions);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(registry);
        TpmCcConstants commandCode = input.CommandCode;

        //Look up codec first to fail fast.
        if(!registry.TryGet(commandCode, out var codec))
        {
            return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_COMMAND_CODE);
        }

        //Get command attributes for handle count.
        TpmaCc commandAttributes = commandCode.GetCommandAttributes();
        int inputHandleCount = commandAttributes.C_HANDLES;
        int inputHandleSize = inputHandleCount * sizeof(uint);

        //Determine request tag.
        bool hasSessions = sessions.Count > 0;
        ushort requestTag = hasSessions
            ? (ushort)TpmStConstants.TPM_ST_SESSIONS
            : (ushort)TpmStConstants.TPM_ST_NO_SESSIONS;

        //Compute exact request size.
        int inputSize = input.GetSerializedSize();
        int parametersSize = inputSize - inputHandleSize;

        //Pre-serialize handles and parameters into pool-rented buffers so they survive
        //across awaits (cpHash + per-session auth HMAC precompute) before being copied
        //into the request buffer.
        using IMemoryOwner<byte> handlesOwner = pool.Rent(Math.Max(inputHandleSize, 1));
        Memory<byte> handlesMemory = handlesOwner.Memory[..inputHandleSize];
        if(inputHandleSize > 0)
        {
            var handleWriter = new TpmWriter(handlesMemory.Span);
            input.WriteHandles(ref handleWriter);

            if(handleWriter.Written != inputHandleSize)
            {
                return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
            }
        }

        using IMemoryOwner<byte> parametersOwner = pool.Rent(Math.Max(parametersSize, 1));
        Memory<byte> parametersMemory = parametersOwner.Memory[..parametersSize];
        if(parametersSize > 0)
        {
            var paramWriter = new TpmWriter(parametersMemory.Span);
            input.WriteParameters(ref paramWriter);

            if(paramWriter.Written != parametersSize)
            {
                return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
            }
        }

        //Compute cpHash if sessions that need it are present.
        //Password sessions (TPM_ALG_NULL) don't need cpHash.
        TpmAlgIdConstants sessionHashAlg = TpmAlgIdConstants.TPM_ALG_NULL;
        IMemoryOwner<byte>? cpHashOwner = null;
        Memory<byte> cpHashMemory = Memory<byte>.Empty;

        try
        {
            if(hasSessions)
            {
                //Find first session with a real hash algorithm.
                foreach(var session in sessions)
                {
                    if(session.HashAlgorithm != TpmAlgIdConstants.TPM_ALG_NULL)
                    {
                        sessionHashAlg = session.HashAlgorithm;
                        break;
                    }
                }

                if(sessionHashAlg != TpmAlgIdConstants.TPM_ALG_NULL)
                {
                    int cpHashSize = GetDigestSize(sessionHashAlg);
                    cpHashOwner = pool.Rent(cpHashSize);
                    cpHashMemory = cpHashOwner.Memory[..cpHashSize];
                    await ComputeCpHashAsync(
                        sessionHashAlg, commandCode, handlesMemory, parametersMemory, cpHashMemory, pool, cancellationToken).ConfigureAwait(false);
                }
            }

            //Precompute per-session auth HMACs before writing the auth area. The writer
            //is a ref struct and cannot cross await boundaries.
            Tpm2bAuth?[] preparedAuthHmacs = new Tpm2bAuth?[sessions.Count];
            try
            {
                for(int i = 0; i < sessions.Count; i++)
                {
                    preparedAuthHmacs[i] = await sessions[i].PrepareAuthHmacAsync(
                        cpHashMemory, pool, cancellationToken).ConfigureAwait(false);
                }

                //Compute auth area size.
                int authAreaSize = 0;
                if(hasSessions)
                {
                    authAreaSize = 4; //authorizationSize field.
                    foreach(var session in sessions)
                    {
                        authAreaSize += session.GetAuthCommandSize();
                    }
                }

                int totalRequestSize = TpmConstants.HeaderSize + inputHandleSize + authAreaSize + parametersSize;

                //Rent request buffer.
                using IMemoryOwner<byte> requestOwner = pool.Rent(totalRequestSize);
                Memory<byte> requestMemory = requestOwner.Memory[..totalRequestSize];

                //Build request synchronously inside this scope; the writer is a ref struct.
                {
                    var writer = new TpmWriter(requestMemory.Span);

                    //Write header.
                    writer.WriteUInt16(requestTag);
                    writer.WriteUInt32((uint)totalRequestSize);
                    writer.WriteUInt32((uint)commandCode);

                    //Write handles.
                    if(inputHandleSize > 0)
                    {
                        writer.WriteBytes(handlesMemory.Span);
                    }

                    //Write auth area if sessions present.
                    if(hasSessions)
                    {
                        int authBodySize = authAreaSize - 4;
                        writer.WriteUInt32((uint)authBodySize);

                        for(int i = 0; i < sessions.Count; i++)
                        {
                            sessions[i].WriteAuthCommand(ref writer, preparedAuthHmacs[i]);
                        }
                    }

                    //Write parameters.
                    if(parametersSize > 0)
                    {
                        writer.WriteBytes(parametersMemory.Span);
                    }
                }

                //Submit to TPM.
                TpmResult<TpmResponse> transportResult = await device.SubmitAsync(
                    requestMemory, pool, cancellationToken).ConfigureAwait(false);

                if(transportResult.IsTransportError)
                {
                    return TpmResult<TResponse>.TransportError(transportResult.TransportErrorCode);
                }

                if(!transportResult.IsSuccess)
                {
                    return TpmResult<TResponse>.TransportError(0u);
                }

                using TpmResponse response = transportResult.Value;
                int responseLength = response.Length;

                //Validate minimum response size.
                if(responseLength < TpmConstants.HeaderSize)
                {
                    return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
                }

                //Parse response synchronously inside this scope; the reader is a ref struct.
                ushort responseTag;
                uint responseSize;
                uint responseCode;
                uint[] outHandles;
                int parametersStart;
                int parametersLength;
                int authStart;
                int authLength;
                bool responseHasSessions;

                {
                    ReadOnlySpan<byte> actualResponse = response.AsReadOnlySpan();

                    //Parse response header.
                    var headerReader = new TpmReader(actualResponse);
                    responseTag = headerReader.ReadUInt16();
                    responseSize = headerReader.ReadUInt32();
                    responseCode = headerReader.ReadUInt32();

                    //Validate response size.
                    if(responseSize < TpmConstants.HeaderSize || responseSize > TpmConstants.MaxResponseSize || responseSize != responseLength)
                    {
                        return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
                    }

                    //Check for TPM error.
                    if(responseCode != (uint)TpmRcConstants.TPM_RC_SUCCESS)
                    {
                        return TpmResult<TResponse>.TpmError((TpmRcConstants)responseCode);
                    }

                    //Parse output handles.
                    int handlesStartOffset = TpmConstants.HeaderSize;
                    var reader = new TpmReader(actualResponse[handlesStartOffset..]);

                    outHandles = new uint[codec.OutHandleCount];
                    for(int i = 0; i < codec.OutHandleCount; i++)
                    {
                        outHandles[i] = reader.ReadUInt32();
                    }

                    //Split parameters and auth.
                    int currentOffset = TpmConstants.HeaderSize + (codec.OutHandleCount * sizeof(uint));
                    responseHasSessions = responseTag == (ushort)TpmStConstants.TPM_ST_SESSIONS;

                    if(responseHasSessions)
                    {
                        uint parameterSize = reader.ReadUInt32();
                        currentOffset += sizeof(uint);

                        parametersStart = currentOffset;
                        parametersLength = (int)parameterSize;

                        authStart = parametersStart + parametersLength;
                        authLength = (int)responseSize - authStart;
                    }
                    else
                    {
                        parametersStart = currentOffset;
                        parametersLength = (int)responseSize - parametersStart;

                        authStart = 0;
                        authLength = 0;
                    }
                }

                //Parse response parameters using codec.
                TResponse typedResponse;
                if(codec.HasResponseParameters && parametersLength > 0)
                {
                    ReadOnlySpan<byte> parametersArea = response.AsReadOnlySpan().Slice(parametersStart, parametersLength);
                    var paramReader = new TpmReader(parametersArea);

                    ITpmWireType parsed = codec.ParseResponse(ref paramReader, outHandles, pool);

                    if(parsed is not TResponse typed)
                    {
                        return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_FAILURE);
                    }

                    typedResponse = typed;

                    //Verify no trailing bytes.
                    if(paramReader.Remaining > 0)
                    {
                        return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
                    }
                }
                else
                {
                    //Command has no response parameters - use default/singleton.
                    if(typeof(TResponse) == typeof(FlushContextResponse))
                    {
                        typedResponse = (TResponse)(ITpmWireType)FlushContextResponse.Instance;
                    }
                    else
                    {
                        return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_FAILURE);
                    }
                }

                //Parse and verify sessions.
                if(responseHasSessions && sessions.Count > 0)
                {
                    //Compute rpHash only if we have sessions that need it.
                    IMemoryOwner<byte>? rpHashOwner = null;
                    Memory<byte> rpHashMemory = Memory<byte>.Empty;

                    try
                    {
                        if(sessionHashAlg != TpmAlgIdConstants.TPM_ALG_NULL)
                        {
                            int rpHashSize = GetDigestSize(sessionHashAlg);
                            rpHashOwner = pool.Rent(rpHashSize);
                            rpHashMemory = rpHashOwner.Memory[..rpHashSize];

                            //Copy the response parameters into a pool-rented buffer so the
                            //bytes survive across the async digest computation; the response
                            //buffer is borrowed from the pool already, but slicing through
                            //a Memory reference keeps the lifetime explicit.
                            using IMemoryOwner<byte> responseParamsOwner = pool.Rent(Math.Max(parametersLength, 1));
                            Memory<byte> responseParamsMemory = responseParamsOwner.Memory[..parametersLength];
                            response.AsReadOnlySpan().Slice(parametersStart, parametersLength).CopyTo(responseParamsMemory.Span);

                            await ComputeRpHashAsync(
                                sessionHashAlg, responseCode, commandCode, responseParamsMemory, rpHashMemory, pool, cancellationToken).ConfigureAwait(false);
                        }

                        //Auth area parsing must happen on the response span; copy out to
                        //pool-backed memory before any further awaits.
                        IMemoryOwner<byte> authOwner = pool.Rent(Math.Max(authLength, 1));
                        Memory<byte> authMemory = authOwner.Memory[..authLength];
                        response.AsReadOnlySpan().Slice(authStart, authLength).CopyTo(authMemory.Span);

                        try
                        {
                            int authReaderRemaining;
                            List<TpmsAuthResponse> parsedAuthResponses = new(sessions.Count);
                            try
                            {
                                {
                                    var authReader = new TpmReader(authMemory.Span);
                                    for(int i = 0; i < sessions.Count; i++)
                                    {
                                        parsedAuthResponses.Add(TpmsAuthResponse.Parse(ref authReader, pool));
                                    }
                                    authReaderRemaining = authReader.Remaining;
                                }

                                for(int i = 0; i < sessions.Count; i++)
                                {
                                    bool ok = await sessions[i].VerifyAndUpdateAsync(
                                        parsedAuthResponses[i], rpHashMemory, pool, cancellationToken).ConfigureAwait(false);
                                    if(!ok)
                                    {
                                        return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_AUTH_FAIL);
                                    }
                                }

                                //Verify no trailing bytes in auth.
                                if(authReaderRemaining > 0)
                                {
                                    return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
                                }
                            }
                            finally
                            {
                                foreach(var ar in parsedAuthResponses)
                                {
                                    ar.Dispose();
                                }
                            }
                        }
                        finally
                        {
                            authOwner.Dispose();
                        }
                    }
                    finally
                    {
                        rpHashOwner?.Dispose();
                    }
                }

                return TpmResult<TResponse>.Success(typedResponse);
            }
            finally
            {
                for(int i = 0; i < preparedAuthHmacs.Length; i++)
                {
                    preparedAuthHmacs[i]?.Dispose();
                }
            }
        }
        finally
        {
            cpHashOwner?.Dispose();
        }
    }

    /// <summary>
    /// Asynchronously computes cpHash per TPM 2.0 Part 1, Section 16.7.
    /// </summary>
    private static async ValueTask ComputeCpHashAsync(
        TpmAlgIdConstants hashAlg,
        TpmCcConstants commandCode,
        ReadOnlyMemory<byte> handleNames,
        ReadOnlyMemory<byte> parameters,
        Memory<byte> destination,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> ccOwner = pool.Rent(sizeof(uint));
        Memory<byte> ccMemory = ccOwner.Memory[..sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(ccMemory.Span, (uint)commandCode);

        BufferSegment first = new(ccMemory);
        BufferSegment last = first;
        if(handleNames.Length > 0)
        {
            last = last.Append(handleNames);
        }
        if(parameters.Length > 0)
        {
            last = last.Append(parameters);
        }

        ReadOnlySequence<byte> input = new(first, 0, last, last.Memory.Length);

        Tag tag = BuildDigestTag(hashAlg);
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input,
            outputByteLength: destination.Length,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        digest.AsReadOnlySpan().CopyTo(destination.Span);
    }

    /// <summary>
    /// Asynchronously computes rpHash per TPM 2.0 Part 1, Section 16.8.
    /// </summary>
    private static async ValueTask ComputeRpHashAsync(
        TpmAlgIdConstants hashAlg,
        uint responseCode,
        TpmCcConstants commandCode,
        ReadOnlyMemory<byte> parameters,
        Memory<byte> destination,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> rcOwner = pool.Rent(sizeof(uint));
        Memory<byte> rcMemory = rcOwner.Memory[..sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(rcMemory.Span, responseCode);

        using IMemoryOwner<byte> ccOwner = pool.Rent(sizeof(uint));
        Memory<byte> ccMemory = ccOwner.Memory[..sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(ccMemory.Span, (uint)commandCode);

        BufferSegment first = new(rcMemory);
        BufferSegment last = first.Append(ccMemory);
        if(parameters.Length > 0)
        {
            last = last.Append(parameters);
        }

        ReadOnlySequence<byte> input = new(first, 0, last, last.Memory.Length);

        Tag tag = BuildDigestTag(hashAlg);
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input,
            outputByteLength: destination.Length,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        digest.AsReadOnlySpan().CopyTo(destination.Span);
    }

    private static Tag BuildDigestTag(TpmAlgIdConstants hashAlg)
    {
        HashAlgorithmName algorithmName = ToHashAlgorithmName(hashAlg);
        return new Tag(new Dictionary<Type, object>
        {
            [typeof(HashAlgorithmName)] = algorithmName,
            [typeof(Purpose)] = Purpose.Digest,
            [typeof(EncodingScheme)] = EncodingScheme.Raw,
            [typeof(MaterialSemantics)] = MaterialSemantics.Direct
        });
    }

    private static HashAlgorithmName ToHashAlgorithmName(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => HashAlgorithmName.SHA1,
        TpmAlgIdConstants.TPM_ALG_SHA256 => HashAlgorithmName.SHA256,
        TpmAlgIdConstants.TPM_ALG_SHA384 => HashAlgorithmName.SHA384,
        TpmAlgIdConstants.TPM_ALG_SHA512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Hash algorithm '{hashAlg}' is not supported.")
    };

    private static int GetDigestSize(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => 20,
        TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
        TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
        TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
        _ => throw new NotSupportedException($"Hash algorithm '{hashAlg}' is not supported.")
    };
}
