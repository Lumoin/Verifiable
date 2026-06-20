using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Sessions;

/// <summary>
/// TPM session for command authorization and integrity protection.
/// </summary>
/// <remarks>
/// <para>
/// A TPM session provides authorization and integrity protection for TPM commands.
/// Sessions are created via <c>TPM2_StartAuthSession</c> and can be used for HMAC-based
/// authorization, policy-based authorization, or trial policy computation.
/// </para>
/// <para>
/// <b>Session types:</b>
/// </para>
/// <list type="bullet">
///   <item><description><b>HMAC session</b> - Integrity protection via cpHash/rpHash HMAC.</description></item>
///   <item><description><b>Policy session</b> - Authorization via policy digest.</description></item>
///   <item><description><b>Trial session</b> - Policy digest computation without authorization.</description></item>
/// </list>
/// <para>
/// <b>Session state (per spec):</b>
/// </para>
/// <list type="bullet">
///   <item><description>sessionHandle - Handle returned by StartAuthSession.</description></item>
///   <item><description>nonceTPM (TPM2B_NONCE) - TPM's nonce, updated each response.</description></item>
///   <item><description>nonceCaller (TPM2B_NONCE) - Caller's nonce, updated each command.</description></item>
///   <item><description>sessionKey - Derived key for HMAC computation.</description></item>
///   <item><description>authValue (TPM2B_AUTH) - Authorization value for the entity.</description></item>
///   <item><description>sessionAttributes (TPMA_SESSION) - Session behavior flags.</description></item>
/// </list>
/// <para>
/// <b>Lifecycle:</b>
/// </para>
/// <list type="number">
///   <item><description>Create session with <c>TPM2_StartAuthSession</c>.</description></item>
///   <item><description>Create <see cref="TpmSession"/> from the response.</description></item>
///   <item><description>Use session in commands - session produces TPMS_AUTH_COMMAND.</description></item>
///   <item><description>Session verifies TPMS_AUTH_RESPONSE and updates nonces.</description></item>
///   <item><description>Flush session with <c>TPM2_FlushContext</c> when done.</description></item>
///   <item><description>Dispose the <see cref="TpmSession"/> to release memory.</description></item>
/// </list>
/// <para>
/// <b>HMAC computation (spec Part 1, Section 17.6.5):</b>
/// </para>
/// <code>
/// data := pHash || nonceNewer || nonceOlder || sessionAttributes
/// authHMAC := HMAC_sessionAlg((sessionKey || authValue), data)
/// </code>
/// <para>
/// For commands, nonceNewer is nonceCaller and nonceOlder is nonceTPM.
/// For responses, nonceNewer is nonceTPM and nonceOlder is nonceCaller.
/// </para>
/// <para>
/// HMAC routes through the registered <see cref="ComputeHmacDelegate"/>. The
/// algorithm is carried inline in the <see cref="Tag"/> via
/// <see cref="HashAlgorithmName"/> because TPM session-key compatibility requires
/// dispatching SHA-1 alongside SHA-256/384/512; the convenience HMAC tags in
/// <see cref="CryptoTags"/> deliberately omit SHA-1 for new protocol code.
/// </para>
/// <para>
/// See TPM 2.0 Part 1, Section 17 - Sessions.
/// </para>
/// </remarks>
public sealed class TpmSession: TpmSessionBase, IDisposable
{
    private readonly TpmHandle sessionHandle;
    private readonly TpmAlgIdConstants sessionAlg;
    private readonly int digestSize;
    private Tpm2bNonce nonceTPM;
    private Tpm2bNonce nonceCaller;
    private Tpm2bAuth sessionKey;
    private Tpm2bAuth authValue;
    private bool disposed;

    /// <summary>
    /// Initializes a new session from StartAuthSession response.
    /// </summary>
    /// <param name="sessionHandle">The session handle from StartAuthSession.</param>
    /// <param name="nonceTPM">The TPM's nonce from StartAuthSession response. Ownership is transferred.</param>
    /// <param name="sessionAlg">The hash algorithm for this session.</param>
    /// <param name="pool">The memory pool for allocating nonces.</param>
    /// <param name="symmetric">
    /// The symmetric algorithm negotiated at <c>TPM2_StartAuthSession</c> for parameter encryption, or
    /// <see langword="null"/> for none (<see cref="TpmtSymDef.Null"/>). It must match the symmetric definition
    /// sent in the StartAuthSession command, since the TPM keys parameter encryption on it.
    /// </param>
    /// <remarks>
    /// The <paramref name="nonceTPM"/> ownership is transferred to this session.
    /// Do not dispose it separately.
    /// </remarks>
    public TpmSession(
        TpmHandle sessionHandle,
        Tpm2bNonce nonceTPM,
        TpmAlgIdConstants sessionAlg,
        MemoryPool<byte> pool,
        TpmtSymDef? symmetric = null)
        : this(sessionHandle, nonceTPM, sessionAlg, Tpm2bAuth.CreateEmpty(pool), pool, symmetric)
    {
    }

    private TpmSession(
        TpmHandle sessionHandle,
        Tpm2bNonce nonceTPM,
        TpmAlgIdConstants sessionAlg,
        Tpm2bAuth sessionKey,
        MemoryPool<byte> pool,
        TpmtSymDef? symmetric)
    {
        this.sessionHandle = sessionHandle;
        this.sessionAlg = sessionAlg;
        digestSize = GetDigestSize(sessionAlg);

        //Take ownership of nonceTPM from caller.
        this.nonceTPM = nonceTPM;

        //Generate initial nonceCaller. The executor rolls a fresh caller nonce at the start of each command;
        //this initial value keeps the session well-formed for size/auth queries before the first command.
        nonceCaller = Tpm2bNonce.CreateRandom(digestSize, pool);

        //The session key is empty for an unbound/unsalted session and the KDFa-derived key for a
        //bound or salted session; authValue starts empty (the caller sets the authorized entity's value).
        this.sessionKey = sessionKey;
        authValue = Tpm2bAuth.CreateEmpty(pool);

        Symmetric = symmetric ?? TpmtSymDef.Null;
        SessionAttributes = TpmaSession.CONTINUE_SESSION;
    }

    /// <summary>
    /// Creates a bound HMAC session from a <c>TPM2_StartAuthSession</c> response, deriving the session key
    /// from the bind entity's authorization value.
    /// </summary>
    /// <param name="sessionHandle">The session handle from StartAuthSession.</param>
    /// <param name="bindAuthValue">
    /// The bind entity's authorization value (trailing zeros already removed per TPM 2.0 Library Part 1,
    /// Section 17.6.4). The session key incorporates it, so when this session authorizes the bind entity the
    /// caller supplies no per-command authorization value (the binding covers it).
    /// </param>
    /// <param name="startNonceCaller">The caller nonce sent in the StartAuthSession command.</param>
    /// <param name="nonceTPM">
    /// The TPM nonce from the StartAuthSession response. Ownership transfers to the returned session; if key
    /// derivation fails this method disposes it before the exception propagates, so the caller never disposes
    /// it after a successful argument check.
    /// </param>
    /// <param name="sessionAlg">The session hash algorithm.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">
    /// The symmetric algorithm negotiated at <c>TPM2_StartAuthSession</c> for parameter encryption, or
    /// <see langword="null"/> for none. It must match the symmetric definition sent in the StartAuthSession
    /// command.
    /// </param>
    /// <param name="cancellationToken">A token observed across the key-derivation HMACs.</param>
    /// <returns>The established bound session.</returns>
    /// <remarks>
    /// <para>
    /// Per TPM 2.0 Library Part 1, Section 17.6.10 (equation 20) and Section 17.6.12 (equation 25) the session
    /// key is <c>KDFa(sessionAlg, (bindAuthValue || salt), "ATH", nonceTPM, nonceCaller, bits)</c> — the bind
    /// authorization value first, then the salt. This bound (unsalted) path has no salt, so the KDF key is the
    /// bind authorization value alone; the salted path appends the salt after it. The context values are the
    /// initial StartAuthSession nonces (nonceTPM then nonceCaller), not the rolling per-command ones.
    /// </para>
    /// </remarks>
    public static async ValueTask<TpmSession> CreateBoundAsync(
        TpmHandle sessionHandle,
        ReadOnlyMemory<byte> bindAuthValue,
        ReadOnlyMemory<byte> startNonceCaller,
        Tpm2bNonce nonceTPM,
        TpmAlgIdConstants sessionAlg,
        MemoryPool<byte> pool,
        TpmtSymDef? symmetric = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(nonceTPM);
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bAuth sessionKey;
        try
        {
            int size = GetDigestSize(sessionAlg);

            IMemoryOwner<byte> derived = await Kdfa.DeriveAsync(
                ToHashAlgorithmName(sessionAlg),
                bindAuthValue,
                "ATH",
                nonceTPM.AsReadOnlyMemory(),
                startNonceCaller,
                size * 8,
                pool,
                cancellationToken).ConfigureAwait(false);

            try
            {
                sessionKey = Tpm2bAuth.Create(derived.Memory.Span[..size], pool);
            }
            finally
            {
                derived.Memory.Span[..size].Clear();
                derived.Dispose();
            }
        }
        catch
        {
            //nonceTPM ownership has not yet passed to a session, so a derivation failure disposes it here
            //rather than leaking the pooled buffer (the project forbids leaks on exception paths).
            nonceTPM.Dispose();

            throw;
        }

        return new TpmSession(sessionHandle, nonceTPM, sessionAlg, sessionKey, pool, symmetric);
    }

    /// <inheritdoc/>
    public override TpmHandle SessionHandle => sessionHandle;

    /// <inheritdoc/>
    public override TpmAlgIdConstants HashAlgorithm => sessionAlg;

    /// <summary>
    /// Sets the authorization value for entities requiring authorization.
    /// </summary>
    /// <param name="value">The authorization value.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <remarks>
    /// Per spec Part 1, Section 17.6.4, trailing zeros should be removed from
    /// password-based authValues before use.
    /// </remarks>
    public void SetAuthValue(ReadOnlySpan<byte> value, MemoryPool<byte> pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        authValue.Dispose();
        authValue = Tpm2bAuth.Create(value, pool);
    }

    /// <inheritdoc/>
    public override int GetAuthCommandSize()
    {
        //TPMS_AUTH_COMMAND: sessionHandle + nonceCaller + sessionAttributes + hmac.
        return sizeof(uint) +
               nonceCaller.SerializedSize +
               sizeof(byte) +
               sizeof(ushort) + digestSize;
    }

    /// <inheritdoc/>
    public override async ValueTask<Tpm2bAuth?> PrepareAuthHmacAsync(
        ReadOnlyMemory<byte> cpHash,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //data = cpHash || nonceNewer || nonceOlder || sessionAttributes.
        //For command: nonceNewer = nonceCaller, nonceOlder = nonceTPM.
        ReadOnlyMemory<byte> nonceCallerMem = nonceCaller.AsReadOnlyMemory();
        ReadOnlyMemory<byte> nonceTPMMem = nonceTPM.AsReadOnlyMemory();

        int dataSize = cpHash.Length + nonceCallerMem.Length + nonceTPMMem.Length + sizeof(byte);
        using IMemoryOwner<byte> dataOwner = pool.Rent(dataSize);
        Memory<byte> dataMemory = dataOwner.Memory[..dataSize];
        Span<byte> dataSpan = dataMemory.Span;

        int offset = 0;
        cpHash.Span.CopyTo(dataSpan[offset..]);
        offset += cpHash.Length;

        nonceCallerMem.Span.CopyTo(dataSpan[offset..]);
        offset += nonceCallerMem.Length;

        nonceTPMMem.Span.CopyTo(dataSpan[offset..]);
        offset += nonceTPMMem.Length;

        dataSpan[offset] = (byte)SessionAttributes;

        using IMemoryOwner<byte> hmacOwner = pool.Rent(digestSize);
        Memory<byte> hmacBuffer = hmacOwner.Memory[..digestSize];
        await ComputeSessionHmacAsync(dataMemory, hmacBuffer, pool, cancellationToken).ConfigureAwait(false);

        return Tpm2bAuth.Create(hmacBuffer.Span, pool);
    }

    /// <inheritdoc/>
    public override void WriteAuthCommand(ref TpmWriter writer, Tpm2bAuth? precomputedHmac)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(precomputedHmac is null)
        {
            throw new InvalidOperationException(
                "TpmSession requires a precomputed HMAC produced by PrepareAuthHmacAsync.");
        }

        var authCommand = new TpmsAuthCommand(
            sessionHandle,
            new Tpm2bRef<Tpm2bNonce>(nonceCaller),
            SessionAttributes,
            new Tpm2bRef<Tpm2bAuth>(precomputedHmac));

        authCommand.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// On successful verification, this method takes ownership of the nonce from
    /// <paramref name="response"/> via <see cref="TpmsAuthResponse.TakeNonceTPM"/>, adopting it as the new
    /// nonceTPM. It deliberately does <b>not</b> roll nonceCaller: the command's caller nonce must remain
    /// available to decrypt an encrypted first response parameter (which is keyed on it). The next command's
    /// <see cref="RollNonceCaller"/> produces the fresh caller nonce. The caller should still dispose the
    /// response to release the HMAC.
    /// </remarks>
    public override async ValueTask<bool> VerifyAndUpdateAsync(
        TpmsAuthResponse response,
        ReadOnlyMemory<byte> rpHash,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(response.NonceTPM is null || response.Hmac is null)
        {
            throw new InvalidOperationException("Response nonce or HMAC has already been taken.");
        }

        //data = rpHash || nonceNewer || nonceOlder || sessionAttributes.
        //For response: nonceNewer = nonceTPM (new), nonceOlder = nonceCaller.
        ReadOnlyMemory<byte> newNonceTPMMem = response.NonceTPM.AsReadOnlyMemory();
        ReadOnlyMemory<byte> nonceCallerMem = nonceCaller.AsReadOnlyMemory();

        int dataSize = rpHash.Length + newNonceTPMMem.Length + nonceCallerMem.Length + sizeof(byte);
        using IMemoryOwner<byte> dataOwner = pool.Rent(dataSize);
        Memory<byte> dataMemory = dataOwner.Memory[..dataSize];
        Span<byte> dataSpan = dataMemory.Span;

        int offset = 0;
        rpHash.Span.CopyTo(dataSpan[offset..]);
        offset += rpHash.Length;

        newNonceTPMMem.Span.CopyTo(dataSpan[offset..]);
        offset += newNonceTPMMem.Length;

        nonceCallerMem.Span.CopyTo(dataSpan[offset..]);
        offset += nonceCallerMem.Length;

        dataSpan[offset] = (byte)response.SessionAttributes;

        using IMemoryOwner<byte> expectedOwner = pool.Rent(digestSize);
        Memory<byte> expectedHmac = expectedOwner.Memory[..digestSize];
        await ComputeSessionHmacAsync(dataMemory, expectedHmac, pool, cancellationToken).ConfigureAwait(false);

        if(!CryptographicOperations.FixedTimeEquals(expectedHmac.Span, response.Hmac.AsReadOnlySpan()))
        {
            return false;
        }

        //Take ownership of nonceTPM from response (zero-copy transfer). This becomes nonceNewer for any
        //response-parameter decryption the executor performs next. nonceCaller is left as the command's caller
        //nonce (nonceOlder for that decryption) and is rolled by RollNonceCaller at the next command.
        Tpm2bNonce newNonceTPM = response.TakeNonceTPM();
        nonceTPM.Dispose();
        nonceTPM = newNonceTPM;

        return true;
    }

    /// <inheritdoc/>
    public override void RollNonceCaller(MemoryPool<byte> pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        Tpm2bNonce freshNonceCaller = Tpm2bNonce.CreateRandom(digestSize, pool);
        nonceCaller.Dispose();
        nonceCaller = freshNonceCaller;
    }

    /// <inheritdoc/>
    public override async ValueTask EncryptFirstParameterAsync(
        Memory<byte> firstParameterData,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //Command direction (Part 1 §19.2): nonceNewer = nonceCaller, nonceOlder = nonceTPM.
        await ApplyParameterEncryptionAsync(
            firstParameterData, nonceCaller, nonceTPM, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override async ValueTask DecryptFirstParameterAsync(
        Memory<byte> firstParameterData,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //Response direction (Part 1 §19.2): nonceNewer = nonceTPM (the value adopted in VerifyAndUpdateAsync),
        //nonceOlder = nonceCaller (this command's caller nonce, not yet rolled).
        await ApplyParameterEncryptionAsync(
            firstParameterData, nonceTPM, nonceCaller, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Applies the session's parameter-encryption scheme over the first-parameter data in place, with the
    /// supplied nonce ordering. XOR is self-inverse, so the same routine serves command encryption and response
    /// decryption.
    /// </summary>
    private async ValueTask ApplyParameterEncryptionAsync(
        Memory<byte> data,
        Tpm2bNonce nonceNewer,
        Tpm2bNonce nonceOlder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        if(Symmetric.IsNull)
        {
            throw new InvalidOperationException(
                "Parameter encryption was requested on a session with no symmetric algorithm (TPM_ALG_NULL).");
        }

        if(!Symmetric.IsXor)
        {
            throw new NotSupportedException(
                $"Session parameter encryption with symmetric algorithm '{Symmetric.Algorithm}' is not supported; only XOR obfuscation is implemented.");
        }

        //sessionValue = sessionKey || authValue (Part 1 §19.1). For a session that does not authorize an
        //entity the authValue is empty, so sessionValue reduces to sessionKey.
        (IMemoryOwner<byte>? sessionValueOwner, ReadOnlyMemory<byte> sessionValue) = BuildSessionValue(pool);

        try
        {
            await TpmParameterEncryption.XorAsync(
                ToHashAlgorithmName(sessionAlg),
                sessionValue,
                nonceNewer.AsReadOnlyMemory(),
                nonceOlder.AsReadOnlyMemory(),
                data,
                pool,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if(sessionValueOwner is not null)
            {
                sessionValueOwner.Memory.Span[..sessionValue.Length].Clear();
                sessionValueOwner.Dispose();
            }
        }
    }

    /// <summary>
    /// Builds <c>sessionValue = sessionKey || authValue</c> (TPM 2.0 Part 1, used as both the auth HMAC key and
    /// the parameter-encryption key). Returns an empty value with no owner when both are empty.
    /// </summary>
    private (IMemoryOwner<byte>? Owner, ReadOnlyMemory<byte> Value) BuildSessionValue(MemoryPool<byte> pool)
    {
        ReadOnlyMemory<byte> sessionKeyMem = sessionKey.AsReadOnlyMemory();
        ReadOnlyMemory<byte> authValueMem = authValue.AsReadOnlyMemory();

        int size = sessionKeyMem.Length + authValueMem.Length;
        if(size == 0)
        {
            return (null, ReadOnlyMemory<byte>.Empty);
        }

        IMemoryOwner<byte> owner = pool.Rent(size);
        Memory<byte> buffer = owner.Memory[..size];
        sessionKeyMem.CopyTo(buffer);
        authValueMem.CopyTo(buffer[sessionKeyMem.Length..]);

        return (owner, buffer);
    }

    private async ValueTask ComputeSessionHmacAsync(
        ReadOnlyMemory<byte> data,
        Memory<byte> destination,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        //HMAC key = sessionValue = sessionKey || authValue (concatenated without size fields).
        //For unbound/unsalted sessions with no authValue, the key is empty (length 0);
        //HMAC is still well-defined over an empty key per RFC 2104.
        (IMemoryOwner<byte>? keyOwner, ReadOnlyMemory<byte> keyMemory) = BuildSessionValue(pool);

        try
        {
            HashAlgorithmName algorithmName = ToHashAlgorithmName(sessionAlg);
            Tag tag = new Tag(new System.Collections.Generic.Dictionary<Type, object>
            {
                [typeof(HashAlgorithmName)] = algorithmName,
                [typeof(Purpose)] = Purpose.Hmac,
                [typeof(EncodingScheme)] = EncodingScheme.Raw,
                [typeof(MaterialSemantics)] = MaterialSemantics.Direct
            });

            using HmacValue result = await CryptographicKeyEvents.ComputeHmacAsync(
                data,
                keyMemory,
                outputByteLength: digestSize,
                tag: tag,
                pool: pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            result.AsReadOnlySpan().CopyTo(destination.Span);
        }
        finally
        {
            if(keyOwner is not null)
            {
                keyOwner.Memory.Span[..keyMemory.Length].Clear();
                keyOwner.Dispose();
            }
        }
    }

    /// <summary>
    /// Releases all memory owned by this session.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            nonceTPM.Dispose();
            nonceCaller.Dispose();
            sessionKey.Dispose();
            authValue.Dispose();
            disposed = true;
        }
    }

    private static int GetDigestSize(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => 20,
        TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
        TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
        TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
        _ => throw new NotSupportedException($"Hash algorithm '{hashAlg}' is not supported.")
    };

    private static HashAlgorithmName ToHashAlgorithmName(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => HashAlgorithmName.SHA1,
        TpmAlgIdConstants.TPM_ALG_SHA256 => HashAlgorithmName.SHA256,
        TpmAlgIdConstants.TPM_ALG_SHA384 => HashAlgorithmName.SHA384,
        TpmAlgIdConstants.TPM_ALG_SHA512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Hash algorithm '{hashAlg}' is not supported.")
    };
}
