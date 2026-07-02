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
using Verifiable.Tpm.Infrastructure.Spec.Handles;
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
///   <item><description>Verifying session HMACs via the registered HMAC primitive.</description></item>
///   <item><description>Invoking codec parser on parameters only, after the session HMACs verify.</description></item>
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
    /// <param name="handleNames">
    /// The Name of each command handle, in handle order, or <see langword="null"/> when no handle needs an
    /// explicit Name. Per TPM 2.0 Part 1 equation 15 cpHash is computed over entity Names, not handle values.
    /// The executor derives the Name of a permanent, PCR, or session handle itself (its Name is the 4-byte
    /// handle value), so the corresponding entry may be left empty (or the whole argument left
    /// <see langword="null"/> when every handle is of those kinds). The Name of a transient or persistent
    /// object or an NV index is <c>nameAlg || H(publicArea)</c> - a value only the caller has, from a
    /// Load/CreatePrimary response or computed from the NV public area - so its entry MUST be supplied;
    /// authorizing such an entity over an HMAC session without its Name throws <see cref="ArgumentException"/>
    /// rather than producing a cpHash the TPM would reject. When non-null the count must equal the command's
    /// handle count.
    /// </param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="cancellationToken">Token to observe across the device round-trip and crypto primitives.</param>
    /// <returns>The result containing the typed response, TPM error, or transport error.</returns>
    public static async ValueTask<TpmResult<TResponse>> ExecuteAsync<TResponse>(
        TpmDevice device,
        ITpmCommandInput input,
        IReadOnlyList<TpmSessionBase> sessions,
        IReadOnlyList<ReadOnlyMemory<byte>>? handleNames,
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

        if(handleNames is not null && handleNames.Count != inputHandleCount)
        {
            throw new ArgumentException(
                $"handleNames must supply exactly {inputHandleCount} name(s) for command '{commandCode}'; got {handleNames.Count}.",
                nameof(handleNames));
        }

        //Determine request tag.
        bool hasSessions = sessions.Count > 0;
        ushort requestTag = hasSessions
            ? (ushort)TpmStConstants.TPM_ST_SESSIONS
            : (ushort)TpmStConstants.TPM_ST_NO_SESSIONS;

        //Discover the (at most one each) decrypt and encrypt sessions for session-based parameter encryption
        //(TPM 2.0 Part 1, Section 19.1: the encrypt/decrypt attribute may be set in at most one session each).
        FindParameterEncryptionSessions(sessions, out TpmSessionBase? decryptSession, out TpmSessionBase? encryptSession);

        //Fail fast when a session requests parameter encryption the command or codec cannot satisfy, mirroring
        //the TPM's own TPM_RC_ATTRIBUTES/TPM_RC_SYMMETRIC rejection rather than emitting a request the TPM would
        //reject (and which the response path could not correctly interpret).
        if(decryptSession is not null && (!input.FirstCommandParameterIsEncryptable || decryptSession.Symmetric.IsNull))
        {
            throw new ArgumentException(
                $"A session sets the decrypt attribute, but command '{commandCode}' has no encryptable first parameter or the session negotiated no symmetric algorithm.",
                nameof(sessions));
        }

        if(encryptSession is not null && (!codec.ResponseFirstParameterIsEncryptable || encryptSession.Symmetric.IsNull))
        {
            throw new ArgumentException(
                $"A session sets the encrypt attribute, but command '{commandCode}' has no encryptable first response parameter or the session negotiated no symmetric algorithm.",
                nameof(sessions));
        }

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
        IMemoryOwner<byte>? namesOwner = null;

        try
        {
            if(hasSessions)
            {
                //Roll a fresh caller nonce for each session at the start of the command (no-op for password
                //sessions). This precedes parameter encryption, cpHash, and the auth HMAC so all observe the
                //same nonceCaller, and that nonce stays available to decrypt the response (which is keyed on it).
                foreach(var session in sessions)
                {
                    session.RollNonceCaller(pool);
                }

                //Encrypt the data portion of the first command parameter (Part 1 §19) before cpHash is computed
                //(§19.1) when a session carries the decrypt attribute. Admissibility was validated above, so the
                //first parameter is a sized buffer; only its data (after the 2-octet size field) is encrypted.
                if(decryptSession is not null)
                {
                    if(parametersSize < sizeof(ushort))
                    {
                        return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
                    }

                    ushort firstParamSize = BinaryPrimitives.ReadUInt16BigEndian(parametersMemory.Span[..sizeof(ushort)]);
                    if(firstParamSize > parametersSize - sizeof(ushort))
                    {
                        return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
                    }

                    await decryptSession.EncryptFirstParameterAsync(
                        parametersMemory.Slice(sizeof(ushort), firstParamSize), pool, cancellationToken).ConfigureAwait(false);
                }

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
                    //cpHash is computed over entity Names (Part 1 eq 15), not handle values. The executor derives
                    //the Name of a permanent/PCR/session handle (Name == handle); an object or NV index Name must
                    //come from handleNames or this throws rather than producing a cpHash the TPM would reject.
                    ReadOnlyMemory<byte> cpHashHandleArea = ResolveCpHashHandleArea(
                        handlesMemory, inputHandleCount, handleNames, pool, out namesOwner);

                    int cpHashSize = GetDigestSize(sessionHashAlg);
                    cpHashOwner = pool.Rent(cpHashSize);
                    cpHashMemory = cpHashOwner.Memory[..cpHashSize];
                    await ComputeCpHashAsync(
                        sessionHashAlg, commandCode, cpHashHandleArea, parametersMemory, cpHashMemory, pool, cancellationToken).ConfigureAwait(false);
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

                //Build request synchronously; the writer is a ref struct contained inside the helper.
                WriteRequest(
                    requestMemory.Span,
                    requestTag,
                    totalRequestSize,
                    commandCode,
                    inputHandleSize,
                    handlesMemory,
                    hasSessions,
                    authAreaSize,
                    sessions,
                    preparedAuthHmacs,
                    parametersSize,
                    parametersMemory);

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

                //Parse the response envelope synchronously; the reader is a ref struct contained inside the helper.
                TpmResult<TpmResponseLayout> layoutResult = ParseResponseLayout(response.AsReadOnlySpan(), responseLength, codec.OutHandleCount);
                if(!layoutResult.IsSuccess)
                {
                    return TpmResult<TResponse>.TpmError(layoutResult.ResponseCode);
                }

                TpmResponseLayout layout = layoutResult.Value;

                bool hasResponseSessions = layout.HasSessions && sessions.Count > 0;

                //When sessions are present, copy the response parameters once into a mutable pooled buffer. That
                //single copy is the rpHash input (computed over the still-encrypted bytes), the buffer in which
                //the first response parameter is decrypted after the HMAC verifies, and the source the codec
                //parses. Without sessions the codec parses directly from the response span.
                IMemoryOwner<byte>? responseParamsOwner = null;
                Memory<byte> responseParamsMemory = Memory<byte>.Empty;

                try
                {
                    if(hasResponseSessions)
                    {
                        responseParamsOwner = pool.Rent(Math.Max(layout.ParametersLength, 1));
                        responseParamsMemory = responseParamsOwner.Memory[..layout.ParametersLength];
                        response.AsReadOnlySpan().Slice(layout.ParametersStart, layout.ParametersLength).CopyTo(responseParamsMemory.Span);

                        //Verify the session HMAC(s) BEFORE interpreting or decrypting the response parameters.
                        //rpHash is computed over the response parameter bytes as received (still encrypted, per
                        //Part 1 §19.1), so verification does not need the typed parse; deferring both the parse
                        //and the decryption until after verification keeps a forged or corrupt response from
                        //being interpreted. This mirrors ms-tpm-20-ref: the TPM encrypts the first response
                        //parameter before computing rpHash, so on the caller side the first parameter is
                        //decrypted only after the response HMAC verifies.
                        IMemoryOwner<byte>? rpHashOwner = null;
                        Memory<byte> rpHashMemory = Memory<byte>.Empty;

                        try
                        {
                            if(sessionHashAlg != TpmAlgIdConstants.TPM_ALG_NULL)
                            {
                                int rpHashSize = GetDigestSize(sessionHashAlg);
                                rpHashOwner = pool.Rent(rpHashSize);
                                rpHashMemory = rpHashOwner.Memory[..rpHashSize];

                                await ComputeRpHashAsync(
                                    sessionHashAlg, layout.ResponseCode, commandCode, responseParamsMemory, rpHashMemory, pool, cancellationToken).ConfigureAwait(false);
                            }

                            //Auth area parsing must happen on the response span; copy out to
                            //pool-backed memory before any further awaits.
                            IMemoryOwner<byte> authOwner = pool.Rent(Math.Max(layout.AuthLength, 1));
                            Memory<byte> authMemory = authOwner.Memory[..layout.AuthLength];
                            response.AsReadOnlySpan().Slice(layout.AuthStart, layout.AuthLength).CopyTo(authMemory.Span);

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

                        //Decrypt the data portion of the first response parameter (Part 1 §19), now that the
                        //response HMAC has verified and the encrypt session has adopted the new nonceTPM. Only
                        //its data (after the 2-octet size field) is encrypted.
                        if(encryptSession is not null && codec.ResponseFirstParameterIsEncryptable && !encryptSession.Symmetric.IsNull)
                        {
                            if(layout.ParametersLength < sizeof(ushort))
                            {
                                return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
                            }

                            ushort firstParamSize = BinaryPrimitives.ReadUInt16BigEndian(responseParamsMemory.Span[..sizeof(ushort)]);
                            if(firstParamSize > layout.ParametersLength - sizeof(ushort))
                            {
                                return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_SIZE);
                            }

                            await encryptSession.DecryptFirstParameterAsync(
                                responseParamsMemory.Slice(sizeof(ushort), firstParamSize), pool, cancellationToken).ConfigureAwait(false);
                        }
                    }

                    //Interpret the response parameters with the codec, after verification and decryption.
                    TResponse typedResponse;
                    if(codec.HasResponseParameters && layout.ParametersLength > 0)
                    {
                        ReadOnlySpan<byte> parametersArea = hasResponseSessions
                            ? responseParamsMemory.Span
                            : response.AsReadOnlySpan().Slice(layout.ParametersStart, layout.ParametersLength);
                        var paramReader = new TpmReader(parametersArea);

                        ITpmWireType parsed = codec.ParseResponse(ref paramReader, layout.OutHandles, pool);

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
                        //Command has no response parameters - use the codec's parameterless response singleton.
                        if(codec.EmptyResponse is TResponse emptyResponse)
                        {
                            typedResponse = emptyResponse;
                        }
                        else
                        {
                            return TpmResult<TResponse>.TpmError(TpmRcConstants.TPM_RC_FAILURE);
                        }
                    }

                    return TpmResult<TResponse>.Success(typedResponse);
                }
                finally
                {
                    //When an encrypt session decrypted the first response parameter, this pooled buffer now holds
                    //the recovered plaintext (the confidential value parameter encryption exists to protect). Zero
                    //the used region before returning it to the pool, matching the clear-before-dispose discipline
                    //used for the mask, sessionValue, and HMAC-key buffers. Harmless when the buffer held only
                    //ciphertext (no encrypt session).
                    if(responseParamsOwner is not null)
                    {
                        responseParamsMemory.Span.Clear();
                        responseParamsOwner.Dispose();
                    }
                }
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
            namesOwner?.Dispose();
        }
    }

    /// <summary>
    /// Finds the session carrying the <c>decrypt</c> attribute and the session carrying the <c>encrypt</c>
    /// attribute for session-based parameter encryption.
    /// </summary>
    /// <param name="sessions">The command sessions.</param>
    /// <param name="decryptSession">Receives the decrypt session, or <see langword="null"/> when none sets it.</param>
    /// <param name="encryptSession">Receives the encrypt session, or <see langword="null"/> when none sets it.</param>
    /// <exception cref="ArgumentException">
    /// More than one session sets the <c>decrypt</c> attribute, or more than one sets the <c>encrypt</c>
    /// attribute. Per TPM 2.0 Part 1, Section 19.1 each attribute may be set in at most one session per command.
    /// </exception>
    private static void FindParameterEncryptionSessions(
        IReadOnlyList<TpmSessionBase> sessions,
        out TpmSessionBase? decryptSession,
        out TpmSessionBase? encryptSession)
    {
        decryptSession = null;
        encryptSession = null;

        for(int i = 0; i < sessions.Count; i++)
        {
            TpmSessionBase session = sessions[i];

            if((session.SessionAttributes & TpmaSession.DECRYPT) != 0)
            {
                if(decryptSession is not null)
                {
                    throw new ArgumentException(
                        "At most one session may set the decrypt attribute.", nameof(sessions));
                }

                decryptSession = session;
            }

            if((session.SessionAttributes & TpmaSession.ENCRYPT) != 0)
            {
                if(encryptSession is not null)
                {
                    throw new ArgumentException(
                        "At most one session may set the encrypt attribute.", nameof(sessions));
                }

                encryptSession = session;
            }
        }
    }

    /// <summary>
    /// Resolves the handle-area input to cpHash: the concatenation of each handle's entity Name in handle
    /// order (TPM 2.0 Part 1, equation 15). A permanent, PCR, or session handle's Name is its 4-byte handle
    /// value (derived here); a transient or persistent object or an NV index has Name <c>nameAlg ||
    /// H(publicArea)</c>, which only the caller knows, so it must be supplied in <paramref name="handleNames"/>.
    /// </summary>
    /// <param name="handlesMemory">The pre-serialized big-endian handle values.</param>
    /// <param name="handleCount">The number of command handles.</param>
    /// <param name="handleNames">The caller-supplied per-handle Names, or <see langword="null"/>.</param>
    /// <param name="pool">The memory pool for the concatenated Names buffer.</param>
    /// <param name="namesOwner">
    /// Receives the rented buffer backing the returned memory (or <see langword="null"/> when no buffer is
    /// rented); the caller owns and disposes it.
    /// </param>
    /// <returns>The concatenated Names to feed into cpHash.</returns>
    /// <exception cref="ArgumentException">
    /// An object or NV-index handle has no supplied Name, so cpHash cannot be computed correctly.
    /// </exception>
    private static ReadOnlyMemory<byte> ResolveCpHashHandleArea(
        ReadOnlyMemory<byte> handlesMemory,
        int handleCount,
        IReadOnlyList<ReadOnlyMemory<byte>>? handleNames,
        MemoryPool<byte> pool,
        out IMemoryOwner<byte>? namesOwner)
    {
        namesOwner = null;
        if(handleCount == 0)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        ReadOnlyMemory<byte>[] names = new ReadOnlyMemory<byte>[handleCount];
        int namesLength = 0;
        for(int i = 0; i < handleCount; i++)
        {
            ReadOnlyMemory<byte> handleBytes = handlesMemory.Slice(i * sizeof(uint), sizeof(uint));

            //The most-significant octet of a handle is its TPM_HT handle type.
            byte handleType = handleBytes.Span[0];
            bool isNamedEntity =
                handleType == (byte)TpmHt.TPM_HT_TRANSIENT
                || handleType == (byte)TpmHt.TPM_HT_PERSISTENT
                || handleType == (byte)TpmHt.TPM_HT_NV_INDEX;

            ReadOnlyMemory<byte> name;
            if(handleNames is not null && !handleNames[i].IsEmpty)
            {
                name = handleNames[i];
            }
            else if(isNamedEntity)
            {
                uint handle = BinaryPrimitives.ReadUInt32BigEndian(handleBytes.Span);

                throw new ArgumentException(
                    $"Handle {i} (0x{handle:X8}) is an object or NV index; its cpHash Name must be supplied in handleNames to authorize it over an HMAC session.",
                    nameof(handleNames));
            }
            else
            {
                name = handleBytes;
            }

            names[i] = name;
            namesLength += name.Length;
        }

        namesOwner = pool.Rent(Math.Max(namesLength, 1));
        Memory<byte> namesMemory = namesOwner.Memory[..namesLength];
        int offset = 0;
        for(int i = 0; i < handleCount; i++)
        {
            names[i].Span.CopyTo(namesMemory.Span[offset..]);
            offset += names[i].Length;
        }

        return namesMemory;
    }

    /// <summary>
    /// Writes the full TPM command request (header, handles, auth area, parameters) into the
    /// supplied buffer. The <see cref="TpmWriter"/> is a ref struct, so it is born and buried
    /// inside this synchronous method and never crosses an await boundary.
    /// </summary>
    /// <param name="request">The request buffer to write into.</param>
    /// <param name="requestTag">The request tag (TPM_ST value).</param>
    /// <param name="totalRequestSize">The total request size including the header.</param>
    /// <param name="commandCode">The command code.</param>
    /// <param name="inputHandleSize">The size in bytes of the input handle area.</param>
    /// <param name="handles">The pre-serialized input handle bytes.</param>
    /// <param name="hasSessions">Whether an authorization (session) area is present.</param>
    /// <param name="authAreaSize">The total auth area size including the authorizationSize field.</param>
    /// <param name="sessions">The sessions whose auth commands are written.</param>
    /// <param name="preparedAuthHmacs">The precomputed per-session auth HMACs.</param>
    /// <param name="parametersSize">The size in bytes of the parameter area.</param>
    /// <param name="parameters">The pre-serialized parameter bytes.</param>
    private static void WriteRequest(
        Span<byte> request,
        ushort requestTag,
        int totalRequestSize,
        TpmCcConstants commandCode,
        int inputHandleSize,
        ReadOnlyMemory<byte> handles,
        bool hasSessions,
        int authAreaSize,
        IReadOnlyList<TpmSessionBase> sessions,
        Tpm2bAuth?[] preparedAuthHmacs,
        int parametersSize,
        ReadOnlyMemory<byte> parameters)
    {
        var writer = new TpmWriter(request);

        //Write header.
        writer.WriteUInt16(requestTag);
        writer.WriteUInt32((uint)totalRequestSize);
        writer.WriteUInt32((uint)commandCode);

        //Write handles.
        if(inputHandleSize > 0)
        {
            writer.WriteBytes(handles.Span);
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
            writer.WriteBytes(parameters.Span);
        }
    }

    /// <summary>
    /// Parses the TPM response envelope (header, output handles, parameter/auth split) into a
    /// <see cref="TpmResponseLayout"/>. The <see cref="TpmReader"/> is a ref struct, so it is
    /// born and buried inside this synchronous method; only offsets, lengths, and the output
    /// handle array flow back to the caller.
    /// </summary>
    /// <param name="response">The full response buffer.</param>
    /// <param name="responseLength">The actual response length in bytes.</param>
    /// <param name="outHandleCount">The number of output handles the codec expects.</param>
    /// <returns>
    /// The parsed layout on success, a <see cref="TpmRcConstants.TPM_RC_SIZE"/> TPM error on a
    /// size violation, or the TPM error carried by the response header.
    /// </returns>
    private static TpmResult<TpmResponseLayout> ParseResponseLayout(
        ReadOnlySpan<byte> response,
        int responseLength,
        int outHandleCount)
    {
        //Parse response header.
        var headerReader = new TpmReader(response);
        ushort responseTag = headerReader.ReadUInt16();
        uint responseSize = headerReader.ReadUInt32();
        uint responseCode = headerReader.ReadUInt32();

        //Validate response size.
        if(responseSize < TpmConstants.HeaderSize || responseSize > TpmConstants.MaxResponseSize || responseSize != responseLength)
        {
            return TpmResult<TpmResponseLayout>.TpmError(TpmRcConstants.TPM_RC_SIZE);
        }

        //Check for TPM error.
        if(responseCode != (uint)TpmRcConstants.TPM_RC_SUCCESS)
        {
            return TpmResult<TpmResponseLayout>.TpmError((TpmRcConstants)responseCode);
        }

        //Parse output handles.
        int handlesStartOffset = TpmConstants.HeaderSize;
        var reader = new TpmReader(response[handlesStartOffset..]);

        uint[] outHandles = new uint[outHandleCount];
        for(int i = 0; i < outHandleCount; i++)
        {
            outHandles[i] = reader.ReadUInt32();
        }

        //Split parameters and auth.
        int currentOffset = TpmConstants.HeaderSize + (outHandleCount * sizeof(uint));
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

        TpmResponseLayout layout = new(
            responseTag,
            responseSize,
            responseCode,
            outHandles,
            parametersStart,
            parametersLength,
            authStart,
            authLength,
            responseHasSessions);

        return TpmResult<TpmResponseLayout>.Success(layout);
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
        return Tag.Create(algorithmName)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);
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
