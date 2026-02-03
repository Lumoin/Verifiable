using System;
using System.Buffers;
using System.Security.Cryptography;
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
    /// <remarks>
    /// The <paramref name="nonceTPM"/> ownership is transferred to this session.
    /// Do not dispose it separately.
    /// </remarks>
    public TpmSession(
        TpmHandle sessionHandle,
        Tpm2bNonce nonceTPM,
        TpmAlgIdConstants sessionAlg,
        MemoryPool<byte> pool)
    {
        this.sessionHandle = sessionHandle;
        this.sessionAlg = sessionAlg;
        digestSize = GetDigestSize(sessionAlg);

        //Take ownership of nonceTPM from caller.
        this.nonceTPM = nonceTPM;

        //Generate initial nonceCaller for first command.
        nonceCaller = Tpm2bNonce.CreateRandom(digestSize, pool);

        //Initialize sessionKey and authValue as empty.
        sessionKey = Tpm2bAuth.CreateEmpty(pool);
        authValue = Tpm2bAuth.CreateEmpty(pool);

        SessionAttributes = TpmaSession.CONTINUE_SESSION;
    }

    /// <inheritdoc/>
    public override TpmHandle SessionHandle => sessionHandle;

    /// <inheritdoc/>
    public override TpmAlgIdConstants HashAlgorithm => sessionAlg;

    /// <summary>
    /// Gets or sets the session attributes (TPMA_SESSION).
    /// </summary>
    /// <remarks>
    /// See TPM 2.0 Part 2, Section 8.4 - TPMA_SESSION.
    /// </remarks>
    public TpmaSession SessionAttributes { get; set; }

    /// <summary>
    /// Sets the authorization value for entities requiring authorization.
    /// </summary>
    /// <param name="value">The authorization value.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <remarks>
    /// Per spec Part 1, Section 19.6.4, trailing zeros should be removed from
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
               nonceCaller.GetSerializedSize() +
               sizeof(byte) +
               (sizeof(ushort) + digestSize);
    }

    /// <inheritdoc/>
    public override void WriteAuthCommand(ref TpmWriter writer, scoped ReadOnlySpan<byte> cpHash, MemoryPool<byte> pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //Compute HMAC into stack buffer.
        Span<byte> hmacBuffer = stackalloc byte[digestSize];
        ComputeCommandHmac(cpHash, hmacBuffer);

        //Create Tpm2bAuth from computed HMAC.
        using Tpm2bAuth hmac = Tpm2bAuth.Create(hmacBuffer, pool);

        //Build and write the auth command using proper TPM structure.
        var authCommand = new TpmsAuthCommand(
            sessionHandle,
            new Tpm2bRef<Tpm2bNonce>(nonceCaller),
            SessionAttributes,
            new Tpm2bRef<Tpm2bAuth>(hmac));

        authCommand.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// On successful verification, this method takes ownership of the nonce from
    /// <paramref name="response"/> via <see cref="TpmsAuthResponse.TakeNonceTPM"/>.
    /// The caller should still dispose the response to release the HMAC.
    /// </remarks>
    public override bool VerifyAndUpdate(TpmsAuthResponse response, scoped ReadOnlySpan<byte> rpHash, MemoryPool<byte> pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(response.NonceTPM is null || response.Hmac is null)
        {
            throw new InvalidOperationException("Response nonce or HMAC has already been taken.");
        }

        //Compute expected HMAC using the new nonce from response.
        Span<byte> expectedHmac = stackalloc byte[digestSize];
        ComputeResponseHmac(rpHash, response.NonceTPM.AsReadOnlySpan(), response.SessionAttributes, expectedHmac);

        //Verify with constant-time comparison.
        if(!CryptographicOperations.FixedTimeEquals(expectedHmac, response.Hmac.AsReadOnlySpan()))
        {
            return false;
        }

        //Take ownership of nonceTPM from response (zero-copy transfer).
        Tpm2bNonce newNonceTPM = response.TakeNonceTPM();
        nonceTPM.Dispose();
        nonceTPM = newNonceTPM;

        //Generate new nonceCaller for next command.
        Tpm2bNonce newNonceCaller = Tpm2bNonce.CreateRandom(digestSize, pool);
        nonceCaller.Dispose();
        nonceCaller = newNonceCaller;

        return true;
    }

    /// <summary>
    /// Computes the command HMAC per spec Part 1, Section 17.6.5.
    /// </summary>
    /// <param name="cpHash">The command parameter hash.</param>
    /// <param name="destination">The destination buffer for the HMAC.</param>
    /// <remarks>
    /// <code>
    /// data := cpHash || nonceCaller || nonceTPM || sessionAttributes
    /// authHMAC := HMAC_sessionAlg((sessionKey || authValue), data)
    /// </code>
    /// For commands, nonceNewer is nonceCaller and nonceOlder is nonceTPM.
    /// </remarks>
    private void ComputeCommandHmac(ReadOnlySpan<byte> cpHash, Span<byte> destination)
    {
        //data = cpHash || nonceNewer || nonceOlder || sessionAttributes.
        //For command: nonceNewer = nonceCaller, nonceOlder = nonceTPM.
        ReadOnlySpan<byte> nonceCallerSpan = nonceCaller.AsReadOnlySpan();
        ReadOnlySpan<byte> nonceTPMSpan = nonceTPM.AsReadOnlySpan();

        int dataSize = cpHash.Length + nonceCallerSpan.Length + nonceTPMSpan.Length + sizeof(byte);
        Span<byte> data = stackalloc byte[dataSize];

        int offset = 0;
        cpHash.CopyTo(data.Slice(offset));
        offset += cpHash.Length;

        nonceCallerSpan.CopyTo(data.Slice(offset));
        offset += nonceCallerSpan.Length;

        nonceTPMSpan.CopyTo(data.Slice(offset));
        offset += nonceTPMSpan.Length;

        data[offset] = (byte)SessionAttributes;

        ComputeHmac(data, destination);
    }

    /// <summary>
    /// Computes the response HMAC per spec Part 1, Section 17.6.5.
    /// </summary>
    /// <param name="rpHash">The response parameter hash.</param>
    /// <param name="newNonceTPM">The new nonceTPM from the response.</param>
    /// <param name="responseAttributes">The session attributes from the response.</param>
    /// <param name="destination">The destination buffer for the HMAC.</param>
    /// <remarks>
    /// <code>
    /// data := rpHash || nonceTPM || nonceCaller || sessionAttributes
    /// authHMAC := HMAC_sessionAlg((sessionKey || authValue), data)
    /// </code>
    /// For responses, nonceNewer is nonceTPM (the new one) and nonceOlder is nonceCaller.
    /// </remarks>
    private void ComputeResponseHmac(ReadOnlySpan<byte> rpHash, ReadOnlySpan<byte> newNonceTPM, TpmaSession responseAttributes, Span<byte> destination)
    {
        //data = rpHash || nonceNewer || nonceOlder || sessionAttributes.
        //For response: nonceNewer = nonceTPM (new), nonceOlder = nonceCaller.
        ReadOnlySpan<byte> nonceCallerSpan = nonceCaller.AsReadOnlySpan();

        int dataSize = rpHash.Length + newNonceTPM.Length + nonceCallerSpan.Length + sizeof(byte);
        Span<byte> data = stackalloc byte[dataSize];

        int offset = 0;
        rpHash.CopyTo(data.Slice(offset));
        offset += rpHash.Length;

        newNonceTPM.CopyTo(data.Slice(offset));
        offset += newNonceTPM.Length;

        nonceCallerSpan.CopyTo(data.Slice(offset));
        offset += nonceCallerSpan.Length;

        data[offset] = (byte)responseAttributes;

        ComputeHmac(data, destination);
    }

    /// <summary>
    /// Computes HMAC using sessionKey || authValue as the key.
    /// </summary>
    /// <param name="data">The data to HMAC.</param>
    /// <param name="destination">The destination buffer.</param>
    private void ComputeHmac(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        //HMAC key = sessionKey || authValue (concatenated without size fields).
        ReadOnlySpan<byte> sessionKeySpan = sessionKey.AsReadOnlySpan();
        ReadOnlySpan<byte> authValueSpan = authValue.AsReadOnlySpan();

        int keySize = sessionKeySpan.Length + authValueSpan.Length;
        Span<byte> hmacKey = stackalloc byte[keySize];
        sessionKeySpan.CopyTo(hmacKey);
        authValueSpan.CopyTo(hmacKey.Slice(sessionKeySpan.Length));

        using IncrementalHash hmac = sessionAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA1 => IncrementalHash.CreateHMAC(HashAlgorithmName.SHA1, hmacKey),
            TpmAlgIdConstants.TPM_ALG_SHA256 => IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, hmacKey),
            TpmAlgIdConstants.TPM_ALG_SHA384 => IncrementalHash.CreateHMAC(HashAlgorithmName.SHA384, hmacKey),
            TpmAlgIdConstants.TPM_ALG_SHA512 => IncrementalHash.CreateHMAC(HashAlgorithmName.SHA512, hmacKey),
            _ => throw new NotSupportedException($"Hash algorithm '{sessionAlg}' is not supported for sessions.")
        };

        hmac.AppendData(data);
        hmac.GetHashAndReset(destination);
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
}