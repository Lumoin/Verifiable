using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Sessions;

/// <summary>
/// A satisfied policy session (started with <c>TPM_SE_POLICY</c>) used to authorize a command, where the
/// policy itself is the authorization and no authorization value is proven.
/// </summary>
/// <remarks>
/// <para>
/// This represents the common case: an unbound, unsalted policy session whose accumulated policyDigest matches
/// the authorized object's authPolicy (for example after <c>TPM2_PolicyPCR</c>), with neither
/// <c>TPM2_PolicyAuthValue</c> nor <c>TPM2_PolicyPassword</c> invoked. Such a session has an empty HMAC key
/// (no session key, and the entity authValue is not folded in), so per TPM 2.0 Library Part 1, Section 19.6 the
/// authorization HMAC is an <b>empty buffer</b>: when both the HMAC key and the supplied auth value are
/// zero-length the TPM accepts the authorization without an HMAC, and the satisfied policy is what authorizes
/// the entity (confirmed against ms-tpm-20-ref <c>ComputeCommandHMAC</c>, which returns a zero-length HMAC in
/// that case and does not consult the session nonces).
/// </para>
/// <para>
/// <b>Confidentiality.</b> Because this session has no key, it cannot carry session-based parameter encryption.
/// When a command's response is confidential (for example the recovered secret of <c>TPM2_Unseal</c>), pair this
/// policy session (the authorizing session, supplied first) with a separate bound or salted HMAC session that
/// sets the <c>encrypt</c> attribute; the executor finds the encrypt session by attribute and that session's
/// HMAC also provides the response integrity this session does not.
/// </para>
/// <para>
/// <b>Not for PolicyAuthValue/PolicyPassword.</b> A policy that invoked <c>TPM2_PolicyAuthValue</c> (HMAC keyed
/// on the entity authValue) or <c>TPM2_PolicyPassword</c> (authValue sent in the clear) needs a different
/// authorization representation and is out of scope for this type.
/// </para>
/// <para>
/// Wire format (TPMS_AUTH_COMMAND): sessionHandle, a fresh nonceCaller (digest-sized, as the session's nonce),
/// sessionAttributes, and an empty hmac (size 0).
/// </para>
/// </remarks>
public sealed class TpmPolicySession: TpmSessionBase, IDisposable
{
    private readonly TpmHandle sessionHandle;
    private readonly TpmAlgIdConstants sessionAlg;
    private readonly int digestSize;
    private Tpm2bNonce nonceCaller;
    private bool disposed;

    private TpmPolicySession(TpmHandle sessionHandle, TpmAlgIdConstants sessionAlg, MemoryPool<byte> pool)
    {
        this.sessionHandle = sessionHandle;
        this.sessionAlg = sessionAlg;
        digestSize = GetDigestSize(sessionAlg);

        //A policy session has a rolling caller nonce sized to the session's hash; the executor rolls a fresh one
        //at the start of each command. This initial value keeps the session well-formed before the first command.
        nonceCaller = Tpm2bNonce.CreateRandom(digestSize, pool);
        SessionAttributes = TpmaSession.CONTINUE_SESSION;
    }

    /// <summary>
    /// Wraps a started, satisfied policy session for use as a command authorization session.
    /// </summary>
    /// <param name="sessionHandle">The policy session handle returned by <c>TPM2_StartAuthSession</c>.</param>
    /// <param name="sessionAlg">The policy session's hash algorithm (sizes the caller nonce and the cpHash).</param>
    /// <param name="pool">The memory pool for nonce allocation.</param>
    /// <returns>The policy authorization session.</returns>
    public static TpmPolicySession ForSession(uint sessionHandle, TpmAlgIdConstants sessionAlg, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new TpmPolicySession(new TpmHandle(sessionHandle), sessionAlg, pool);
    }

    /// <inheritdoc/>
    public override TpmHandle SessionHandle => sessionHandle;

    /// <inheritdoc/>
    public override TpmAlgIdConstants HashAlgorithm => sessionAlg;

    /// <inheritdoc/>
    public override void RollNonceCaller(MemoryPool<byte> pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        Tpm2bNonce fresh = Tpm2bNonce.CreateRandom(digestSize, pool);
        nonceCaller.Dispose();
        nonceCaller = fresh;
    }

    /// <inheritdoc/>
    public override int GetAuthCommandSize()
    {
        //sessionHandle + nonceCaller (size + bytes) + sessionAttributes + empty hmac (size field only).
        return sizeof(uint) +
               nonceCaller.SerializedSize +
               sizeof(byte) +
               sizeof(ushort);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// A satisfied plain policy session carries no HMAC, so this returns the shared empty
    /// <see cref="Tpm2bAuth"/> (size 0). The cpHash is unused.
    /// </remarks>
    public override ValueTask<Tpm2bAuth?> PrepareAuthHmacAsync(
        ReadOnlyMemory<byte> cpHash,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return ValueTask.FromResult<Tpm2bAuth?>(Tpm2bAuth.CreateEmpty(pool));
    }

    /// <inheritdoc/>
    public override void WriteAuthCommand(ref TpmWriter writer, Tpm2bAuth? precomputedHmac)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(precomputedHmac is null)
        {
            throw new InvalidOperationException(
                "TpmPolicySession requires the empty auth value produced by PrepareAuthHmacAsync.");
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
    /// A plain policy session has no key, so the TPM returns an empty response HMAC for it; there is nothing to
    /// verify here. Response integrity comes from the paired encrypt (HMAC) session that protects the confidential
    /// response parameter.
    /// </remarks>
    public override ValueTask<bool> VerifyAndUpdateAsync(
        TpmsAuthResponse response,
        ReadOnlyMemory<byte> rpHash,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return ValueTask.FromResult(true);
    }

    /// <summary>
    /// Releases the nonce memory owned by this session.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            nonceCaller.Dispose();
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
