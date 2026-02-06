using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
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
///   <item><description>Computing cpHash for request HMAC.</description></item>
///   <item><description>Submitting to TPM device.</description></item>
///   <item><description>Parsing response: header, handles, parameterSize split, auth area.</description></item>
///   <item><description>Computing rpHash for response verification.</description></item>
///   <item><description>Invoking codec parser on parameters only.</description></item>
///   <item><description>Verifying session HMACs.</description></item>
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
/// <b>Key invariant:</b> Codec parsers receive only the parameter area bytes.
/// They never see header, handles, or auth data.
/// </para>
/// </remarks>
public static class TpmCommandExecutor
{
    /// <summary>
    /// Executes a TPM command and returns a strongly-typed response.
    /// </summary>
    /// <typeparam name="TResponse">The response type.</typeparam>
    /// <param name="device">The TPM device.</param>
    /// <param name="input">The command input.</param>
    /// <param name="sessions">The sessions (empty for no auth).</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <returns>The result containing the typed response, TPM error, or transport error.</returns>
    public static TpmResult<TResponse> Execute<TResponse>(
        TpmDevice device,
        ITpmCommandInput input,
        IReadOnlyList<TpmSessionBase> sessions,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry)
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

        //Pre-serialize handles and parameters to compute cpHash before writing auth.
        Span<byte> handlesBuffer = stackalloc byte[inputHandleSize];
        if(inputHandleSize > 0)
        {
            var handleWriter = new TpmWriter(handlesBuffer);
            input.WriteHandles(ref handleWriter);

            if(handleWriter.Written != inputHandleSize)
            {
                return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
            }
        }

        Span<byte> parametersBuffer = stackalloc byte[parametersSize];
        if(parametersSize > 0)
        {
            var paramWriter = new TpmWriter(parametersBuffer);
            input.WriteParameters(ref paramWriter);

            if(paramWriter.Written != parametersSize)
            {
                return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
            }
        }

        //Compute cpHash if sessions that need it are present.
        //Password sessions (TPM_ALG_NULL) don't need cpHash.
        Span<byte> cpHashBuffer = stackalloc byte[64]; //Max digest size (SHA-512).
        int cpHashSize = 0;
        TpmAlgIdConstants sessionHashAlg = TpmAlgIdConstants.TPM_ALG_NULL;

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
                cpHashSize = GetDigestSize(sessionHashAlg);
                ComputeCpHash(sessionHashAlg, commandCode, handlesBuffer, parametersBuffer, cpHashBuffer.Slice(0, cpHashSize));
            }
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
        Memory<byte> requestMemory = requestOwner.Memory.Slice(0, totalRequestSize);
        Span<byte> requestSpan = requestMemory.Span;

        //Build request.
        var writer = new TpmWriter(requestSpan);

        //Write header.
        writer.WriteUInt16(requestTag);
        writer.WriteUInt32((uint)totalRequestSize);
        writer.WriteUInt32((uint)commandCode);

        //Write handles.
        if(inputHandleSize > 0)
        {
            writer.WriteBytes(handlesBuffer);
        }

        //Write auth area if sessions present.
        if(hasSessions)
        {
            int authBodySize = authAreaSize - 4;
            writer.WriteUInt32((uint)authBodySize);

            ReadOnlySpan<byte> cpHash = cpHashBuffer.Slice(0, cpHashSize);
            foreach(var session in sessions)
            {
                session.WriteAuthCommand(ref writer, cpHash, pool);
            }
        }

        //Write parameters.
        if(parametersSize > 0)
        {
            writer.WriteBytes(parametersBuffer);
        }

        //Submit to TPM.
        TpmResult<TpmResponse> transportResult = device.Submit(requestSpan, pool);

        if(transportResult.IsTransportError)
        {
            return TpmResult<TResponse>.TransportError(transportResult.TransportErrorCode);
        }

        if(!transportResult.IsSuccess)
        {
            return TpmResult<TResponse>.TransportError(0u);
        }

        using TpmResponse response = transportResult.Value;
        ReadOnlySpan<byte> actualResponse = response.AsReadOnlySpan();
        int responseLength = response.Length;

        //Validate minimum response size.
        if(responseLength < TpmConstants.HeaderSize)
        {
            return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
        }

        //Parse response header.
        var headerReader = new TpmReader(actualResponse);
        ushort responseTag = headerReader.ReadUInt16();
        uint responseSize = headerReader.ReadUInt32();
        uint responseCode = headerReader.ReadUInt32();

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
        var reader = new TpmReader(actualResponse.Slice(handlesStartOffset));

        var outHandles = new uint[codec.OutHandleCount];
        for(int i = 0; i < codec.OutHandleCount; i++)
        {
            outHandles[i] = reader.ReadUInt32();
        }

        //Split parameters and auth.
        int currentOffset = TpmConstants.HeaderSize + (codec.OutHandleCount * sizeof(uint));
        bool responseHasSessions = responseTag == (ushort)TpmStConstants.TPM_ST_SESSIONS;

        int parametersStart;
        int parametersLength;
        int authStart;
        int authLength;

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

        //Parse response parameters using codec.
        TResponse typedResponse;
        if(codec.HasResponseParameters && parametersLength > 0)
        {
            ReadOnlySpan<byte> parametersArea = actualResponse.Slice(parametersStart, parametersLength);
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
            Span<byte> rpHashBuffer = stackalloc byte[64]; //Max digest size.
            int rpHashSize = 0;

            if(sessionHashAlg != TpmAlgIdConstants.TPM_ALG_NULL)
            {
                rpHashSize = GetDigestSize(sessionHashAlg);
                ReadOnlySpan<byte> responseParameters = actualResponse.Slice(parametersStart, parametersLength);
                ComputeRpHash(sessionHashAlg, responseCode, commandCode, responseParameters, rpHashBuffer.Slice(0, rpHashSize));
            }

            ReadOnlySpan<byte> authArea = actualResponse.Slice(authStart, authLength);
            var authReader = new TpmReader(authArea);

            for(int i = 0; i < sessions.Count; i++)
            {
                using TpmsAuthResponse authResponse = TpmsAuthResponse.Parse(ref authReader, pool);
                if(!sessions[i].VerifyAndUpdate(authResponse, rpHashBuffer.Slice(0, rpHashSize), pool))
                {
                    return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_AUTH_FAIL);
                }
            }

            //Verify no trailing bytes in auth.
            if(authReader.Remaining > 0)
            {
                return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
            }
        }

        return TpmResult<TResponse>.Success(typedResponse);
    }

    /// <summary>
    /// Computes cpHash per TPM 2.0 Part 1, Section 16.7.
    /// </summary>
    private static void ComputeCpHash(
        TpmAlgIdConstants hashAlg,
        TpmCcConstants commandCode,
        ReadOnlySpan<byte> handleNames,
        ReadOnlySpan<byte> parameters,
        Span<byte> destination)
    {
        using IncrementalHash hash = CreateIncrementalHash(hashAlg);

        Span<byte> ccBytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(ccBytes, (uint)commandCode);
        hash.AppendData(ccBytes);

        if(handleNames.Length > 0)
        {
            hash.AppendData(handleNames);
        }

        if(parameters.Length > 0)
        {
            hash.AppendData(parameters);
        }

        hash.GetHashAndReset(destination);
    }

    /// <summary>
    /// Computes rpHash per TPM 2.0 Part 1, Section 16.8.
    /// </summary>
    private static void ComputeRpHash(
        TpmAlgIdConstants hashAlg,
        uint responseCode,
        TpmCcConstants commandCode,
        ReadOnlySpan<byte> parameters,
        Span<byte> destination)
    {
        using IncrementalHash hash = CreateIncrementalHash(hashAlg);

        Span<byte> rcBytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(rcBytes, responseCode);
        hash.AppendData(rcBytes);

        Span<byte> ccBytes = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(ccBytes, (uint)commandCode);
        hash.AppendData(ccBytes);

        if(parameters.Length > 0)
        {
            hash.AppendData(parameters);
        }

        hash.GetHashAndReset(destination);
    }

    private static IncrementalHash CreateIncrementalHash(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => IncrementalHash.CreateHash(HashAlgorithmName.SHA1),
        TpmAlgIdConstants.TPM_ALG_SHA256 => IncrementalHash.CreateHash(HashAlgorithmName.SHA256),
        TpmAlgIdConstants.TPM_ALG_SHA384 => IncrementalHash.CreateHash(HashAlgorithmName.SHA384),
        TpmAlgIdConstants.TPM_ALG_SHA512 => IncrementalHash.CreateHash(HashAlgorithmName.SHA512),
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