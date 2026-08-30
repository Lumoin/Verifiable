using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

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
/// <b>HMAC computation (spec Part 1, Section 16.6.5):</b>
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
/// One session derives two keys from that material. The authorization HMAC uses the key above, except that a
/// session declared <see cref="MarkBoundToAuthorizedEntity"/> keys on sessionKey alone (Section 16.6.10,
/// equation 22). Parameter encryption keys on sessionKey || authValue whenever the session authorizes an
/// entity, whatever the session is bound to (Section 18.1: "The binding of the session is ignored").
/// </para>
/// <para>
/// The two keys diverge only for a bound session, and only in the authorization direction, so a bound session
/// that also carries <c>decrypt</c> or <c>encrypt</c> still needs the entity's authorization value handed to it
/// through <see cref="SetAuthValue"/>. Omitting it keys the cipher on sessionKey alone while the TPM keys it on
/// sessionKey || authValue, and the mismatch surfaces as a parameter that decrypts to garbage rather than as an
/// authorization failure.
/// </para>
/// <para>
/// HMAC routes through the registered <see cref="ComputeHmacDelegate"/>. The
/// algorithm is carried inline in the <see cref="Tag"/> via
/// <see cref="HashAlgorithmName"/> because TPM session-key compatibility requires
/// dispatching SHA-1 alongside SHA-256/384/512; the convenience HMAC tags in
/// <see cref="CryptoTags"/> deliberately omit SHA-1 for new protocol code.
/// </para>
/// <para>
/// See TPM 2.0 Part 1, Section 16 - Sessions.
/// </para>
/// </remarks>
public sealed class TpmSession: TpmSessionBase, IDisposable
{
    private TpmAlgIdConstants SessionAlg { get; }
    private int DigestSize { get; }
    private Tpm2bNonce nonceTPM;
    private Tpm2bNonce nonceCaller;
    private Tpm2bAuth sessionKey;
    private Tpm2bAuth authValue;

    /// <summary>
    /// Whether this session's <c>bind</c> entity is the same entity the session authorizes, which is the one
    /// condition under which the authorization HMAC key drops the entity's authValue (TPM 2.0 Library Part 1,
    /// Section 16.6.10, equation 22). It never affects the parameter-encryption key, which folds the authValue
    /// regardless (Section 18.1: "The binding of the session is ignored").
    /// </summary>
    private bool isBoundToAuthorizedEntity;

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
        BaseMemoryPool pool,
        TpmtSymDef? symmetric = null)
        : this(sessionHandle, nonceTPM, sessionAlg, Tpm2bAuth.CreateEmpty(pool), pool, symmetric)
    {
    }

    private TpmSession(
        TpmHandle sessionHandle,
        Tpm2bNonce nonceTPM,
        TpmAlgIdConstants sessionAlg,
        Tpm2bAuth sessionKey,
        BaseMemoryPool pool,
        TpmtSymDef? symmetric)
    {
        this.SessionHandle = sessionHandle;
        this.SessionAlg = sessionAlg;
        DigestSize = GetDigestSize(sessionAlg);

        //Take ownership of nonceTPM from caller.
        this.nonceTPM = nonceTPM;

        //Generate initial nonceCaller. The executor rolls a fresh caller nonce at the start of each command;
        //this initial value keeps the session well-formed for size/auth queries before the first command.
        nonceCaller = Tpm2bNonce.CreateRandom(DigestSize, pool);

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
    /// Section 16.6.4), folded into the session key by the bound-session KDFa (Section 16.6.10, equation 20).
    /// The binding removes that value from the AUTHORIZATION HMAC key alone, and only once the caller declares
    /// the binding through <paramref name="isBoundToAuthorizedEntity"/> or
    /// <see cref="MarkBoundToAuthorizedEntity"/> (equation 22). It removes nothing from the
    /// parameter-encryption key: Section 18.1 keys the cipher on <c>sessionKey ∥ authValue</c> whenever the
    /// session authorizes an entity and states that "The binding of the session is ignored". A session that
    /// carries <c>decrypt</c> or <c>encrypt</c> therefore MUST still receive the entity's authorization value
    /// through <see cref="SetAuthValue"/>; omitting it yields a cipher keyed on <c>sessionKey</c> alone, which
    /// a TPM will not match unless the entity's authValue is genuinely empty.
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
    /// <param name="salt">
    /// The session salt recovered from a salted <c>TPM2_StartAuthSession</c> (the plaintext value the caller
    /// encrypted into <c>encryptedSalt</c> — for example via <see cref="Commands.StartAuthSessionInputExtensions"/>'s
    /// salted factories), or empty for an unsalted session. Folded after <paramref name="bindAuthValue"/> in the
    /// session-key KDFa (TPM 2.0 Library Part 1, Section 16.6.12, equation 25) — never reversed.
    /// </param>
    /// <param name="isBoundToAuthorizedEntity">
    /// <see langword="true"/> when the entity named by <paramref name="bindAuthValue"/> is the same entity this
    /// session will authorize, which makes the authorization HMAC key drop that entity's authValue (TPM 2.0
    /// Library Part 1, Section 16.6.10, equation 22). It is equivalent to calling
    /// <see cref="MarkBoundToAuthorizedEntity"/> on the returned session, and it leaves the
    /// parameter-encryption key alone (Section 18.1). Leave it <see langword="false"/> for a session bound to
    /// some other entity purely to raise the session key's entropy.
    /// </param>
    /// <param name="cancellationToken">A token observed across the key-derivation HMACs.</param>
    /// <returns>The established bound session.</returns>
    /// <remarks>
    /// <para>
    /// Per TPM 2.0 Library Part 1, Section 16.6.10 (equation 20) and Section 16.6.12 (equation 25) the session
    /// key is <c>KDFa(sessionAlg, (bindAuthValue || salt), "ATH", nonceTPM, nonceCaller, bits)</c> — the bind
    /// authorization value first, then the salt, each empty when absent. An unsalted BOUND session (bound to a
    /// real entity, whose own resolved authValue may itself be empty) leaves <paramref name="salt"/> empty, so
    /// the KDF key reduces to the bind authorization value alone — KDFa still runs, over a zero-length key when
    /// that value is empty (RFC 2104's well-defined empty-key HMAC); a salted session appends the recovered salt
    /// after it. The context values are the initial StartAuthSession nonces (nonceTPM then nonceCaller), not the
    /// rolling per-command ones.
    /// </para>
    /// <para>
    /// This factory always derives a KDFa-based key — it has no way to represent "no bind entity at all", since
    /// <paramref name="bindAuthValue"/> alone cannot distinguish an unbound session from one bound to an
    /// empty-auth entity. A session that is genuinely neither bound nor salted has sessionKey = an Empty Buffer
    /// with no KDFa run at all (Part 1, clause 16.6.9); construct that session with the plain
    /// <see cref="TpmSession(TpmHandle, Tpm2bNonce, TpmAlgIdConstants, BaseMemoryPool, TpmtSymDef?)"/> constructor
    /// instead of calling this factory with an empty <paramref name="bindAuthValue"/> and no
    /// <paramref name="salt"/>.
    /// </para>
    /// </remarks>
    public static async ValueTask<TpmSession> CreateBoundAsync(
        TpmHandle sessionHandle,
        ReadOnlyMemory<byte> bindAuthValue,
        ReadOnlyMemory<byte> startNonceCaller,
        Tpm2bNonce nonceTPM,
        TpmAlgIdConstants sessionAlg,
        BaseMemoryPool pool,
        TpmtSymDef? symmetric = null,
        ReadOnlyMemory<byte> salt = default,
        bool isBoundToAuthorizedEntity = false,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(nonceTPM);
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bAuth sessionKey;
        try
        {
            int size = GetDigestSize(sessionAlg);

            //KDFa key = bindAuthValue || salt (Part 1, Section 16.6.12 equation 25), concatenated into a pooled
            //buffer only when both are non-empty; the degenerate unsalted/unbound cases pass either term alone
            //with no extra allocation.
            int keyLength = bindAuthValue.Length + salt.Length;
            IMemoryOwner<byte>? keyOwner = null;
            ReadOnlyMemory<byte> key;
            if(keyLength == 0)
            {
                key = ReadOnlyMemory<byte>.Empty;
            }
            else if(salt.IsEmpty)
            {
                key = bindAuthValue;
            }
            else if(bindAuthValue.IsEmpty)
            {
                key = salt;
            }
            else
            {
                keyOwner = pool.Rent(keyLength, AllocationKind.Pinned);
                bindAuthValue.CopyTo(keyOwner.Memory);
                salt.CopyTo(keyOwner.Memory[bindAuthValue.Length..]);
                key = keyOwner.Memory[..keyLength];
            }

            IMemoryOwner<byte> derived;
            try
            {
                derived = await Kdfa.DeriveAsync(
                    ToHashAlgorithmName(sessionAlg),
                    key,
                    "ATH",
                    nonceTPM.AsReadOnlyMemory(),
                    startNonceCaller,
                    size * 8,
                    pool,
                    cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                if(keyOwner is not null)
                {
                    keyOwner.Memory.Span[..keyLength].Clear();
                    keyOwner.Dispose();
                }
            }

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

        var session = new TpmSession(sessionHandle, nonceTPM, sessionAlg, sessionKey, pool, symmetric);
        if(isBoundToAuthorizedEntity)
        {
            session.MarkBoundToAuthorizedEntity();
        }

        return session;
    }

    /// <summary>
    /// Declares that this session's <c>bind</c> entity is the entity the session authorizes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The declaration separates the two keys a session derives from the same material. The command and
    /// response authorization HMACs are keyed on <c>sessionKey</c> alone, because TPM 2.0 Library Part 1,
    /// Section 16.6.10 has the TPM omit the authValue of the bound entity from the HMAC key when the
    /// authorization is for that entity (equation 22, against equation 21's <c>sessionKey || authValue</c>) —
    /// the value is already folded into <c>sessionKey</c> by the bound-session KDFa (equation 20).
    /// </para>
    /// <para>
    /// Parameter encryption is unaffected: Section 18.1 keys the cipher on <c>sessionKey || authValue</c>
    /// whenever the session also authorizes an entity and states that "The binding of the session is ignored",
    /// so <see cref="EncryptFirstParameterAsync"/> and <see cref="DecryptFirstParameterAsync"/> keep folding the
    /// value supplied to <see cref="SetAuthValue"/>.
    /// </para>
    /// <para>
    /// The declaration is therefore not a substitute for <see cref="SetAuthValue"/> on a session that also
    /// carries <c>decrypt</c> or <c>encrypt</c>. Such a session MUST still be given the entity's authorization
    /// value: with the value omitted the cipher key is <c>sessionKey</c> alone while the TPM computes it as
    /// <c>sessionKey || authValue</c>, and the two keystreams diverge for every entity whose authValue is not
    /// genuinely empty. Nothing detects that divergence on the wire — a wrong cipher key is undetectable
    /// (Section 18.1's malleability property), so a command decrypts to garbage the TPM then acts on and signs.
    /// </para>
    /// </remarks>
    public void MarkBoundToAuthorizedEntity()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        isBoundToAuthorizedEntity = true;
    }

    /// <inheritdoc/>
    public override TpmHandle SessionHandle { get; }

    /// <inheritdoc/>
    public override TpmAlgIdConstants HashAlgorithm => SessionAlg;

    /// <inheritdoc/>
    public override ReadOnlyMemory<byte> NonceTpm => nonceTPM.AsReadOnlyMemory();

    /// <summary>
    /// Sets the authorization value for entities requiring authorization.
    /// </summary>
    /// <param name="value">The authorization value.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <remarks>
    /// Trailing zero octets are removed from <paramref name="value"/> before it is stored, because this is the
    /// authValue term of an authorization computation: TPM 2.0 Library Part 1, Section 16.6.4.3 ("Trailing octets
    /// of zero are to be removed from any string before it is used as an authValue") and Section 16.6.5's
    /// authValue term note. A TPM keys the command and response HMACs on the stripped form (the reference reaches
    /// every entity's authValue through <c>EntityGetAuthValue</c>, which strips unconditionally), so a session
    /// keyed on the unstripped bytes would fail its own authorization for a value the caller supplied correctly.
    /// The trimming happens here rather than in <see cref="Tpm2bAuth.Create(ReadOnlySpan{byte}, BaseMemoryPool)"/>,
    /// which is the verbatim carrier constructor and must stay so for values that are not authorization terms.
    /// The stored value feeds both keys this session derives; a session declared
    /// <see cref="MarkBoundToAuthorizedEntity"/> drops it from the authorization HMAC key only, never from the
    /// parameter-encryption key.
    /// </remarks>
    public void SetAuthValue(ReadOnlySpan<byte> value, BaseMemoryPool pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        int length = value.Length;
        while(length > 0 && value[length - 1] == 0)
        {
            length--;
        }

        authValue.Dispose();
        authValue = Tpm2bAuth.Create(value[..length], pool);
    }

    /// <inheritdoc/>
    public override int GetAuthCommandSize()
    {
        //TPMS_AUTH_COMMAND: sessionHandle + nonceCaller + sessionAttributes + hmac.
        return sizeof(uint) +
               nonceCaller.SerializedSize +
               sizeof(byte) +
               sizeof(ushort) + DigestSize;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// <paramref name="foldedSessionNonces"/> (TPM 2.0 Library Part 1, clause 16.6.3.4) is folded in, when
    /// non-empty, immediately after nonceOlder and before <see cref="SessionAttributes"/> — the caller is
    /// responsible for supplying it only when this session is the first in the command's authorization area and
    /// authorizes an entity, and only the OTHER (decrypt/encrypt) session's nonceTPM, never this session's own.
    /// </remarks>
    public override async ValueTask<Tpm2bAuth?> PrepareAuthHmacAsync(
        ReadOnlyMemory<byte> cpHash,
        BaseMemoryPool pool,
        CancellationToken cancellationToken,
        ReadOnlyMemory<byte> foldedSessionNonces = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //data = cpHash || nonceNewer || nonceOlder || foldedSessionNonces || sessionAttributes.
        //For command: nonceNewer = nonceCaller, nonceOlder = nonceTPM.
        ReadOnlyMemory<byte> nonceCallerMem = nonceCaller.AsReadOnlyMemory();
        ReadOnlyMemory<byte> nonceTPMMem = nonceTPM.AsReadOnlyMemory();

        int dataSize = cpHash.Length + nonceCallerMem.Length + nonceTPMMem.Length + foldedSessionNonces.Length + sizeof(byte);
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

        foldedSessionNonces.Span.CopyTo(dataSpan[offset..]);
        offset += foldedSessionNonces.Length;

        dataSpan[offset] = (byte)SessionAttributes;

        using IMemoryOwner<byte> hmacOwner = pool.Rent(DigestSize);
        Memory<byte> hmacBuffer = hmacOwner.Memory[..DigestSize];
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
            SessionHandle,
            new Tpm2bRef<Tpm2bNonce>(nonceCaller),
            SessionAttributes,
            new Tpm2bRef<Tpm2bAuth>(precomputedHmac));

        authCommand.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    /// <remarks>
    /// <para>
    /// On successful verification, this method takes ownership of the nonce from
    /// <paramref name="response"/> via <see cref="TpmsAuthResponse.TakeNonceTPM"/>, adopting it as the new
    /// nonceTPM. It deliberately does <b>not</b> roll nonceCaller: the command's caller nonce must remain
    /// available to decrypt an encrypted first response parameter (which is keyed on it). The next command's
    /// <see cref="RollNonceCaller"/> produces the fresh caller nonce. The caller should still dispose the
    /// response to release the HMAC.
    /// </para>
    /// <para>
    /// This adoption is what fulfils the per-use nonce roll TPM 2.0 Library Part 1, Section 16.6.3.1 requires:
    /// every subsequent <see cref="PrepareAuthHmacAsync"/> call folds this freshly adopted value as nonceOlder,
    /// so a byte-for-byte replay of an earlier command's authorization area carries a stale nonceTPM the TPM's
    /// own recomputed authHMAC will not match. The mechanism is session-type-agnostic — it applies identically
    /// whether this instance backs a salted/bound HMAC session or a salted/bound POLICY session (TPM 2.0 Library
    /// Part 3, Section 11.1.1: sessionKey derivation, and with it this nonce protocol, does not vary by
    /// sessionType).
    /// </para>
    /// <para>
    /// The nonceTPMdecrypt/nonceTPMencrypt fold (Part 1, clause 16.6.3.4) never applies here: its own defining text
    /// and the two named terms are scoped explicitly to "the command" ("but only in the command"), and there is no
    /// corresponding fold term in the response HMAC's own equation. A response verification composes only
    /// rpHash‖nonceNewer‖nonceOlder‖sessionAttributes, with no folded-nonces term, regardless of session position.
    /// </para>
    /// </remarks>
    public override async ValueTask<bool> VerifyAndUpdateAsync(
        TpmsAuthResponse response,
        ReadOnlyMemory<byte> rpHash,
        BaseMemoryPool pool,
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

        using IMemoryOwner<byte> expectedOwner = pool.Rent(DigestSize);
        Memory<byte> expectedHmac = expectedOwner.Memory[..DigestSize];
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
    public override void RollNonceCaller(BaseMemoryPool pool)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        Tpm2bNonce freshNonceCaller = Tpm2bNonce.CreateRandom(DigestSize, pool);
        nonceCaller.Dispose();
        nonceCaller = freshNonceCaller;
    }

    /// <inheritdoc/>
    public override async ValueTask EncryptFirstParameterAsync(
        Memory<byte> firstParameterData,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //Command direction (Part 1 §18.2): nonceNewer = nonceCaller, nonceOlder = nonceTPM.
        await ApplyParameterEncryptionAsync(
            firstParameterData, nonceCaller, nonceTPM, encrypting: true, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override async ValueTask DecryptFirstParameterAsync(
        Memory<byte> firstParameterData,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        //Response direction (Part 1 §18.2): nonceNewer = nonceTPM (the value adopted in VerifyAndUpdateAsync),
        //nonceOlder = nonceCaller (this command's caller nonce, not yet rolled).
        await ApplyParameterEncryptionAsync(
            firstParameterData, nonceTPM, nonceCaller, encrypting: false, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Applies the session's parameter-encryption scheme over the first-parameter data in place, with the
    /// supplied nonce ordering and direction.
    /// </summary>
    /// <remarks>
    /// XOR obfuscation is self-inverse so <paramref name="encrypting"/> does not affect it; AES-CFB is
    /// direction-dependent, so the flag selects encryption versus decryption.
    /// </remarks>
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
        Justification = "Although this method is statically reachable on browser, the AES-CFB branch is selected only when the session negotiated an AES TPMT_SYM_DEF, which can only be agreed with a real TPM (none exists on browser), so the browser-unsupported AES path is unreachable there at runtime. The XOR branch uses no browser-unsupported API and stays browser-clean.")]
    private async ValueTask ApplyParameterEncryptionAsync(
        Memory<byte> data,
        Tpm2bNonce nonceNewer,
        Tpm2bNonce nonceOlder,
        bool encrypting,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(Symmetric.IsNull)
        {
            throw new InvalidOperationException(
                "Parameter encryption was requested on a session with no symmetric algorithm (TPM_ALG_NULL).");
        }

        //sessionValue = sessionKey || authValue (Part 1, clause 18.1). The authValue is folded unconditionally:
        //clause 18.1 states that "The binding of the session is ignored" for the cipher key, so a session bound
        //to the entity it authorizes still folds that entity's authValue here even though its authorization
        //HMAC key omits it (clause 16.6.10, equation 22). For a session that authorizes no entity the caller
        //never sets an authValue, so sessionValue reduces to sessionKey by itself.
        (IMemoryOwner<byte>? sessionValueOwner, ReadOnlyMemory<byte> sessionValue) = BuildSessionValue(pool, foldsAuthValue: true);

        try
        {
            if(Symmetric.IsXor)
            {
                await TpmParameterEncryption.XorAsync(
                    ToHashAlgorithmName(SessionAlg),
                    sessionValue,
                    nonceNewer.AsReadOnlyMemory(),
                    nonceOlder.AsReadOnlyMemory(),
                    data,
                    pool,
                    cancellationToken).ConfigureAwait(false);
            }
            else if(Symmetric.Algorithm == TpmAlgIdConstants.TPM_ALG_AES && Symmetric.Mode == TpmAlgIdConstants.TPM_ALG_CFB)
            {
                await TpmParameterEncryption.CfbAsync(
                    ToHashAlgorithmName(SessionAlg),
                    Symmetric.KeyBits,
                    sessionValue,
                    nonceNewer.AsReadOnlyMemory(),
                    nonceOlder.AsReadOnlyMemory(),
                    data,
                    encrypting,
                    pool,
                    cancellationToken).ConfigureAwait(false);
            }
            else
            {
                throw new NotSupportedException(
                    $"Session parameter encryption with symmetric algorithm '{Symmetric.Algorithm}' mode '{Symmetric.Mode}' is not supported; only XOR obfuscation and AES-CFB are implemented.");
            }
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
    /// Builds <c>sessionValue = sessionKey || authValue</c> (TPM 2.0 Library Part 1, Section 16.6.5 equation 21
    /// for the authorization HMAC key, Section 18.1 for the parameter-encryption key), or <c>sessionKey</c>
    /// alone when <paramref name="foldsAuthValue"/> is <see langword="false"/>. Returns an empty value with no
    /// owner when the result would be zero-length.
    /// </summary>
    /// <param name="pool">The memory pool for the concatenation buffer.</param>
    /// <param name="foldsAuthValue">
    /// Whether the authorization value set by <see cref="SetAuthValue"/> is concatenated onto the session key.
    /// The two consumers answer this differently on the same session: the authorization HMAC omits it for a
    /// session bound to the entity it authorizes (Section 16.6.10, equation 22), while parameter encryption
    /// folds it regardless of the binding (Section 18.1).
    /// </param>
    /// <returns>
    /// The pooled owner of the concatenation (<see langword="null"/> when nothing was rented) and the value
    /// itself. The caller clears and disposes the owner.
    /// </returns>
    private (IMemoryOwner<byte>? Owner, ReadOnlyMemory<byte> Value) BuildSessionValue(BaseMemoryPool pool, bool foldsAuthValue)
    {
        ReadOnlyMemory<byte> sessionKeyMem = sessionKey.AsReadOnlyMemory();
        ReadOnlyMemory<byte> authValueMem = foldsAuthValue ? authValue.AsReadOnlyMemory() : ReadOnlyMemory<byte>.Empty;

        int size = sessionKeyMem.Length + authValueMem.Length;
        if(size == 0)
        {
            return (null, ReadOnlyMemory<byte>.Empty);
        }

        IMemoryOwner<byte> owner = pool.Rent(size, AllocationKind.Pinned);
        Memory<byte> buffer = owner.Memory[..size];
        sessionKeyMem.CopyTo(buffer);
        authValueMem.CopyTo(buffer[sessionKeyMem.Length..]);

        return (owner, buffer);
    }

    private async ValueTask ComputeSessionHmacAsync(
        ReadOnlyMemory<byte> data,
        Memory<byte> destination,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        //HMAC key = sessionValue = sessionKey || authValue (concatenated without size fields, Part 1 clause
        //17.6.5 equation 21). A session bound to the entity it authorizes drops the authValue term, because the
        //bound-session KDFa already folded it into sessionKey and the TPM keys equation 22 on sessionKey alone
        //(clause 16.6.10) — the cipher key built by ApplyParameterEncryptionAsync makes the opposite choice on
        //the same session, per clause 18.1. For unbound/unsalted sessions with no authValue, the key is empty
        //(length 0); HMAC is still well-defined over an empty key per RFC 2104.
        (IMemoryOwner<byte>? keyOwner, ReadOnlyMemory<byte> keyMemory) = BuildSessionValue(pool, foldsAuthValue: !isBoundToAuthorizedEntity);

        try
        {
            HashAlgorithmName algorithmName = ToHashAlgorithmName(SessionAlg);
            Tag tag = Tag.Create(algorithmName)
                .With(Purpose.Hmac)
                .With(EncodingScheme.Raw)
                .With(MaterialSemantics.Direct);

            using HmacValue result = await CryptographicKeyEvents.ComputeHmacAsync(
                data,
                keyMemory,
                outputByteLength: DigestSize,
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
