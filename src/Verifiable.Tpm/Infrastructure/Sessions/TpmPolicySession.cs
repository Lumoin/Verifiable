using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

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
/// (no session key, and the entity authValue is not folded in), so per TPM 2.0 Library Part 1, clause 16.6.16 the
/// authorization HMAC is an <b>empty buffer</b>: when both the HMAC key and the supplied auth value are
/// zero-length the TPM accepts the authorization without an HMAC, and the satisfied policy is what authorizes
/// the entity (confirmed against TPM 2.0 Library Part 4's <c>ComputeCommandHMAC</c>, which returns a zero-length HMAC in
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
/// <b>PolicyPassword.</b> A policy that invoked <c>TPM2_PolicyPassword</c> is served by
/// <see cref="ForSessionWithPassword"/>, which carries the authorized object's authValue in the clear as the
/// hmac field instead of the empty buffer this type otherwise sends. <b>Not for PolicyAuthValue.</b> A policy
/// that invoked <c>TPM2_PolicyAuthValue</c> (HMAC keyed on the entity authValue) needs the HMAC-session shape
/// (<see cref="TpmSession"/>) instead and is out of scope for this type.
/// </para>
/// <para>
/// Wire format (TPMS_AUTH_COMMAND): sessionHandle, a fresh nonceCaller (digest-sized, as the session's nonce),
/// sessionAttributes, and an hmac field that is either empty (size 0, the plain <see cref="ForSession"/> shape)
/// or the cleartext password (<see cref="ForSessionWithPassword"/>).
/// </para>
/// </remarks>
public sealed class TpmPolicySession: TpmSessionBase, IDisposable
{
    private TpmAlgIdConstants SessionAlg { get; }
    private int DigestSize { get; }
    private Tpm2bNonce nonceCaller;
    private Tpm2bAuth? Password { get; }
    private bool disposed;

    /// <summary>The entropy this session mints its rolled caller nonces from.</summary>
    private FillEntropyDelegate Rng { get; }

    private TpmPolicySession(TpmHandle sessionHandle, TpmAlgIdConstants sessionAlg, FillEntropyDelegate rng, BaseMemoryPool pool, Tpm2bAuth? password)
    {
        ArgumentNullException.ThrowIfNull(rng);

        this.SessionHandle = sessionHandle;
        this.SessionAlg = sessionAlg;
        this.Rng = rng;
        DigestSize = GetDigestSize(sessionAlg);
        Password = password;

        //A policy session has a rolling caller nonce sized to the session's hash; the executor rolls a fresh one
        //at the start of each command. This initial value keeps the session well-formed before the first command.
        nonceCaller = Tpm2bNonce.CreateRandom(DigestSize, rng, pool);
        SessionAttributes = TpmaSession.CONTINUE_SESSION;
    }

    /// <summary>
    /// Wraps a started, satisfied policy session for use as a command authorization session.
    /// </summary>
    /// <param name="sessionHandle">The policy session handle returned by <c>TPM2_StartAuthSession</c>.</param>
    /// <param name="sessionAlg">The policy session's hash algorithm (sizes the caller nonce and the cpHash).</param>
    /// <param name="rng">The entropy the returned session mints its rolled caller nonces from.</param>
    /// <param name="pool">The memory pool for nonce allocation.</param>
    /// <returns>The policy authorization session.</returns>
    public static TpmPolicySession ForSession(uint sessionHandle, TpmAlgIdConstants sessionAlg, FillEntropyDelegate rng, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new TpmPolicySession(new TpmHandle(sessionHandle), sessionAlg, rng, pool, password: null);
    }

    /// <summary>
    /// Wraps a policy session whose policy asserted TPM2_PolicyPassword, so its hmac field must carry the
    /// authorized object's authValue in the clear rather than the empty buffer <see cref="ForSession"/> sends.
    /// </summary>
    /// <remarks>
    /// TPM 2.0 Library Part 3, clause 23.18 and Part 1, clause 16.6.16 ("the password takes precedence and
    /// must be present in hmac"): the TPM answers with an EMPTY response hmac for this session, exactly as it
    /// does for the plain policy session, so <see cref="VerifiesResponseAuthorization"/> stays
    /// <see langword="false"/>.
    /// </remarks>
    /// <param name="sessionHandle">The policy session handle returned by <c>TPM2_StartAuthSession</c>.</param>
    /// <param name="sessionAlg">The policy session's hash algorithm (sizes the caller nonce and the cpHash).</param>
    /// <param name="password">The authorized object's authValue, copied into a session-owned buffer.</param>
    /// <param name="rng">The entropy the returned session mints its rolled caller nonces from.</param>
    /// <param name="pool">The memory pool for nonce and password allocation.</param>
    /// <returns>The password-carrying policy authorization session.</returns>
    public static TpmPolicySession ForSessionWithPassword(uint sessionHandle, TpmAlgIdConstants sessionAlg, ReadOnlySpan<byte> password, FillEntropyDelegate rng, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new TpmPolicySession(new TpmHandle(sessionHandle), sessionAlg, rng, pool, Tpm2bAuth.Create(password, pool));
    }

    /// <inheritdoc/>
    public override TpmHandle SessionHandle { get; }

    /// <inheritdoc/>
    public override TpmAlgIdConstants HashAlgorithm => SessionAlg;

    /// <inheritdoc/>
    /// <remarks>
    /// This session has no key, so the TPM returns an empty response HMAC for it and
    /// <see cref="VerifyAndUpdateAsync"/> has nothing to check (TPM 2.0 Library Part 1, clause 16.6.16: "if hmac
    /// was an Empty Buffer in the command, it will be an Empty Buffer in the response"). Response
    /// integrity for a confidential parameter comes from the paired encrypt (HMAC) session, which carries the
    /// requirement itself.
    /// </remarks>
    public override bool VerifiesResponseAuthorization => false;

    /// <inheritdoc/>
    public override void RollNonceCaller(BaseMemoryPool pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        Tpm2bNonce fresh = Tpm2bNonce.CreateRandom(DigestSize, Rng, pool);
        nonceCaller.Dispose();
        nonceCaller = fresh;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// The hmac field is empty (size field only, <see cref="ForSession"/>) or the password's
    /// <see cref="Tpm2bAuth.SerializedSize"/> (<see cref="ForSessionWithPassword"/>).
    /// </remarks>
    public override int GetAuthCommandSize()
    {
        int hmacSize = Password?.SerializedSize ?? sizeof(ushort);

        //sessionHandle + nonceCaller (size + bytes) + sessionAttributes + hmac.
        return sizeof(uint) +
               nonceCaller.SerializedSize +
               sizeof(byte) +
               hmacSize;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// A satisfied plain policy session carries no HMAC, so this returns the shared empty
    /// <see cref="Tpm2bAuth"/> (size 0); a password-carrying session (<see cref="ForSessionWithPassword"/>)
    /// returns a fresh copy of the stored password, because the executor disposes whatever this method returns
    /// on every call and the stored password must survive to authorize later commands on the same
    /// CONTINUE_SESSION session. The cpHash is unused either way.
    /// </remarks>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Tpm2bAuth.CreateEmpty returns the shared, non-owned empty singleton (never a freshly rented buffer); the caller must not dispose it. The password branch returns a freshly rented copy whose ownership transfers to the caller (the executor), which disposes it.")]
    public override ValueTask<Tpm2bAuth?> PrepareAuthHmacAsync(
        ReadOnlyMemory<byte> cpHash,
        BaseMemoryPool pool,
        CancellationToken cancellationToken,
        ReadOnlyMemory<byte> foldedSessionNonces = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        Tpm2bAuth hmac = Password is null ? Tpm2bAuth.CreateEmpty(pool) : Tpm2bAuth.Create(Password.AsReadOnlySpan(), pool);

        return ValueTask.FromResult<Tpm2bAuth?>(hmac);
    }

    /// <inheritdoc/>
    public override void WriteAuthCommand(ref TpmWriter writer, Tpm2bAuth? precomputedHmac)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(precomputedHmac is null)
        {
            throw new InvalidOperationException(
                "TpmPolicySession requires the hmac value produced by PrepareAuthHmacAsync.");
        }

        var authCommand = new TpmsAuthCommand(
            SessionHandle,
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
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return ValueTask.FromResult(true);
    }

    /// <summary>
    /// Releases the nonce and, for a password-carrying session, the password memory owned by this session.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            nonceCaller.Dispose();
            Password?.Dispose();
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
