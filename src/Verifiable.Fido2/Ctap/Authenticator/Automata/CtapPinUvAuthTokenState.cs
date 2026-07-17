using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// One PIN/UV auth protocol's <c>pinUvAuthToken</c> lifecycle state (CTAP 2.3 §6.5.2.1/§6.5.3): the
/// token value itself plus every state variable §6.5.2.1 lists, held as one instance per protocol on
/// <see cref="CtapAuthenticatorState.ProtocolOneToken"/>/<see cref="CtapAuthenticatorState.ProtocolTwoToken"/>.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="CtapRememberedGetAssertionState"/>'s shape: an owned pooled secret
/// (<see cref="Token"/>) alongside plain scalars and <see cref="DateTimeOffset"/> stamps, all
/// immutable with-copy. §6.5.3's lifecycle functions (<see cref="BeginUsing"/>,
/// <see cref="StopUsing"/>, <see cref="GetUserPresentFlagValue"/>, <see cref="GetUserVerifiedFlagValue"/>,
/// <see cref="ClearUserPresentFlag"/>, <see cref="ClearUserVerifiedFlag"/>,
/// <see cref="ClearPinUvAuthTokenPermissionsExceptLbw"/>) are pure transforms over this record; the
/// one exception, <see cref="EvaluateExpiry"/>, stands in for §6.5.3's continuously-running
/// <c>pinUvAuthTokenUsageTimerObserver()</c> and takes a precomputed <see cref="DateTimeOffset"/>
/// rather than reading a clock itself, mirroring <c>CtapAuthenticatorTransitions</c>'s
/// <c>authenticatorGetNextAssertion</c> timer (the same "precompute outside, compare inside" shape).
/// </para>
/// <para>
/// <see cref="Token"/> is 32 random bytes for BOTH PIN/UV auth protocols: protocol one permits
/// 16-or-32 (CTAP 2.3 §6.5.6, line 6138/6171) and protocol two requires exactly 32 (§6.5.7, line
/// 6222) — this authenticator always chooses 32, uniformly. No timer object is ever running: the
/// rolling timer (§6.5.2.1, line 5042, a MAY) is deliberately not implemented, so
/// <see cref="BeginUsingAt"/> and <see cref="LastUsedAt"/> are the only facts
/// <see cref="EvaluateExpiry"/> needs.
/// </para>
/// </remarks>
/// <param name="Token">
/// The current 32-byte <c>pinUvAuthToken</c> value, pooled and owned by this record. Used directly as
/// an HMAC-SHA-256 key (<see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/>/
/// <see cref="CtapPinUvAuthProtocol.VerifyAsync"/>), never a nonce — it is deliberately reused across
/// every operation for as long as it remains <see cref="IsInUse"/>, the opposite of a nonce's
/// single-use invariant.
/// </param>
/// <param name="PermissionsRpId">The permissions RP ID (CTAP 2.3 §6.5.2.1, line 5019), initially <see langword="null"/>.</param>
/// <param name="Permissions">
/// The permissions set (line 5021) as a bitfield of <see cref="WellKnownCtapPinUvAuthTokenPermissions"/>
/// values, initially empty (0).
/// </param>
/// <param name="IsInUse">The in use flag (line 5026), initially <see langword="false"/>.</param>
/// <param name="UserVerified">The userVerified flag (line 5050), initially <see langword="false"/>.</param>
/// <param name="UserPresent">The userPresent flag (line 5052), initially <see langword="false"/>.</param>
/// <param name="BeginUsingAt">
/// When <see cref="BeginUsing"/> started the usage timer (line 5023's "usage timer", "initially not
/// running"), or <see langword="null"/> while not running.
/// </param>
/// <param name="LastUsedAt">
/// When the platform last used this token in an authenticator operation, or <see langword="null"/> if
/// it has not been used since <see cref="BeginUsingAt"/>. Backs the "without the platform using the
/// pinUvAuthToken in an authenticator operation" clause of line 5154 — stamped by
/// <c>CtapAuthenticatorTransitions</c>'s <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>
/// verify fold-back on every operation that presents and verifies this token.
/// </param>
public sealed record CtapPinUvAuthTokenState(
    SymmetricKeyMemory Token,
    string? PermissionsRpId,
    int Permissions,
    bool IsInUse,
    bool UserVerified,
    bool UserPresent,
    DateTimeOffset? BeginUsingAt,
    DateTimeOffset? LastUsedAt): IDisposable
{
    /// <summary>The <c>pinUvAuthToken</c> length this authenticator mints for both PIN/UV auth protocols.</summary>
    private const int TokenLength = 32;

    /// <summary>
    /// The initial usage time limit (CTAP 2.3 §6.5.2.1, line 5028-5033): "nfc: 19.8 seconds (16 bit
    /// counter with 3311hz clock: max time before overflow)" — the value this transport-agnostic
    /// simulator uses uniformly, since it has no way to know which transport carried a given request
    /// (mirroring <c>CtapAuthenticatorTransitions</c>'s own "no per-transport information" reasoning
    /// for <c>authenticatorGetNextAssertion</c>'s timer).
    /// </summary>
    public static TimeSpan InitialUsageTimeLimit => TimeSpan.FromSeconds(19.8);

    /// <summary>
    /// The user present time limit (line 5044-5046): defaults to the same per-transport value as
    /// <see cref="InitialUsageTimeLimit"/> — 19.8 seconds here, for the reason given there.
    /// </summary>
    public static TimeSpan UserPresentTimeLimit => TimeSpan.FromSeconds(19.8);

    /// <summary>
    /// The max usage time period (line 5048): "SHOULD default to a maximum of 10 minutes (600 seconds)".
    /// </summary>
    public static TimeSpan MaxUsageTimePeriod => TimeSpan.FromMinutes(10);


    /// <summary>
    /// Mints a freshly generated token with every state variable at its §6.5.2.1 initial value — CTAP
    /// 2.3's <c>resetPinUvAuthToken()</c> (§6.5.6 line 6171 / §6.5.7 line 6230-6237), also the shape
    /// <c>initialize()</c> (§6.5.5.1) uses at power-on.
    /// </summary>
    /// <param name="pool">The memory pool the token is minted from. Defaults to <see cref="BaseMemoryPool.Shared"/>.</param>
    /// <returns>A freshly minted, not-in-use token state.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the freshly minted SymmetricKeyMemory transfers to the returned CtapPinUvAuthTokenState's Token, which the record's Dispose releases.")]
    public static CtapPinUvAuthTokenState Initial(MemoryPool<byte>? pool = null) =>
        new(MintToken(pool ?? BaseMemoryPool.Shared), null, 0, false, false, false, null, null);


    /// <summary>
    /// Performs <c>resetPinUvAuthToken()</c> against an already-minted instance: mints a fresh token
    /// value and resets every state variable to its §6.5.2.1 initial value, disposing the token this
    /// instance previously held.
    /// </summary>
    /// <param name="pool">The memory pool the fresh token is minted from. Defaults to <see cref="BaseMemoryPool.Shared"/>.</param>
    /// <returns>The reset state, holding a brand-new token value.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the freshly minted SymmetricKeyMemory transfers to the returned CtapPinUvAuthTokenState's Token, which the record's Dispose releases.")]
    public CtapPinUvAuthTokenState ResetToken(MemoryPool<byte>? pool = null)
    {
        SymmetricKeyMemory freshToken = MintToken(pool ?? BaseMemoryPool.Shared);
        Token.Dispose();

        return this with
        {
            Token = freshToken,
            PermissionsRpId = null,
            Permissions = 0,
            IsInUse = false,
            UserVerified = false,
            UserPresent = false,
            BeginUsingAt = null,
            LastUsedAt = null
        };
    }


    /// <summary>
    /// <c>beginUsingPinUvAuthToken(userIsPresent)</c> (CTAP 2.3 §6.5.3, line 5129-5141): sets
    /// <see cref="UserPresent"/> to <paramref name="userIsPresent"/>, <see cref="UserVerified"/> to
    /// <see langword="true"/>, starts the usage timer at <paramref name="now"/>, and sets
    /// <see cref="IsInUse"/> to <see langword="true"/>. Does not touch <see cref="Permissions"/> or
    /// <see cref="PermissionsRpId"/> — the token-issuance tail assigns those separately, after this
    /// call (CTAP 2.3, line 5908-5915/6018-6026).
    /// </summary>
    /// <param name="userIsPresent">Whether the issuing operation collected user presence.</param>
    /// <param name="now">The current time, precomputed by the caller.</param>
    /// <returns>The state with the usage timer started and the token in use.</returns>
    public CtapPinUvAuthTokenState BeginUsing(bool userIsPresent, DateTimeOffset now) =>
        this with
        {
            UserPresent = userIsPresent,
            UserVerified = true,
            IsInUse = true,
            BeginUsingAt = now,
            LastUsedAt = null
        };


    /// <summary>
    /// <c>stopUsingPinUvAuthToken()</c> (CTAP 2.3 §6.5.3, line 5213-5225): "Set all of the
    /// pinUvAuthToken's state variables to their initial values as given in §6.5.2.1." Never
    /// regenerates <see cref="Token"/> itself — only <see cref="ResetToken"/> does that.
    /// </summary>
    /// <returns>The state with every §6.5.2.1 variable reset to its initial value.</returns>
    public CtapPinUvAuthTokenState StopUsing() =>
        this with
        {
            PermissionsRpId = null,
            Permissions = 0,
            IsInUse = false,
            UserVerified = false,
            UserPresent = false,
            BeginUsingAt = null,
            LastUsedAt = null
        };


    /// <summary>
    /// <c>getUserPresentFlagValue()</c> (CTAP 2.3 §6.5.3, line 5173-5183): the current
    /// <see cref="UserPresent"/> flag when <see cref="IsInUse"/>; otherwise <see langword="false"/>.
    /// </summary>
    /// <returns>The observable userPresent flag value.</returns>
    [SuppressMessage("Design", "CA1024:Use properties where appropriate",
        Justification = "Named after the CTAP 2.3 spec function getUserPresentFlagValue() verbatim, deliberately distinct in shape from the UserPresent state variable property it reads.")]
    public bool GetUserPresentFlagValue() => IsInUse && UserPresent;


    /// <summary>
    /// <c>getUserVerifiedFlagValue()</c> (CTAP 2.3 §6.5.3, line 5184-5194): the current
    /// <see cref="UserVerified"/> flag when <see cref="IsInUse"/>; otherwise <see langword="false"/>.
    /// </summary>
    /// <returns>The observable userVerified flag value.</returns>
    [SuppressMessage("Design", "CA1024:Use properties where appropriate",
        Justification = "Named after the CTAP 2.3 spec function getUserVerifiedFlagValue() verbatim, deliberately distinct in shape from the UserVerified state variable property it reads.")]
    public bool GetUserVerifiedFlagValue() => IsInUse && UserVerified;


    /// <summary>
    /// <c>clearUserPresentFlag()</c> (CTAP 2.3 §6.5.3, line 5195-5200): clears <see cref="UserPresent"/>
    /// only while <see cref="IsInUse"/>; a no-op otherwise.
    /// </summary>
    /// <returns>The state with <see cref="UserPresent"/> cleared, or this instance unchanged.</returns>
    public CtapPinUvAuthTokenState ClearUserPresentFlag() => IsInUse ? this with { UserPresent = false } : this;


    /// <summary>
    /// <c>clearUserVerifiedFlag()</c> (CTAP 2.3 §6.5.3, line 5201-5206): clears
    /// <see cref="UserVerified"/> only while <see cref="IsInUse"/>; a no-op otherwise.
    /// </summary>
    /// <returns>The state with <see cref="UserVerified"/> cleared, or this instance unchanged.</returns>
    public CtapPinUvAuthTokenState ClearUserVerifiedFlag() => IsInUse ? this with { UserVerified = false } : this;


    /// <summary>
    /// <c>clearPinUvAuthTokenPermissionsExceptLbw()</c> (CTAP 2.3 §6.5.3, line 5207-5212): clears
    /// every permission except <see cref="WellKnownCtapPinUvAuthTokenPermissions.Lbw"/> while
    /// <see cref="IsInUse"/>; a no-op otherwise.
    /// </summary>
    /// <returns>The state with only the <c>lbw</c> permission bit (if any) retained, or this instance unchanged.</returns>
    public CtapPinUvAuthTokenState ClearPinUvAuthTokenPermissionsExceptLbw() =>
        IsInUse ? this with { Permissions = Permissions & WellKnownCtapPinUvAuthTokenPermissions.Lbw } : this;


    /// <summary>
    /// Lazily evaluates §6.5.3's <c>pinUvAuthTokenUsageTimerObserver()</c> (line 5142-5172) as of
    /// <paramref name="now"/>, in place of a continuously-running timer: the max usage time period
    /// expiring stops the token unconditionally (line 5171); failing that, the initial usage time
    /// limit expiring without any recorded use stops it (line 5154 — the rolling timer branch, line
    /// 5156-5168, is not implemented, per this type's own declination in its type-level remarks);
    /// failing that, the user present time limit expiring clears only <see cref="UserPresent"/>
    /// (line 5152). A not-in-use token is returned unchanged.
    /// </summary>
    /// <param name="now">The current time, precomputed by the caller.</param>
    /// <returns>The state after applying whichever timer condition (if any) applies at <paramref name="now"/>.</returns>
    public CtapPinUvAuthTokenState EvaluateExpiry(DateTimeOffset now)
    {
        if(!IsInUse || BeginUsingAt is not DateTimeOffset beginUsingAt)
        {
            return this;
        }

        TimeSpan elapsedSinceBeginUsing = now - beginUsingAt;

        if(elapsedSinceBeginUsing >= MaxUsageTimePeriod)
        {
            return StopUsing();
        }

        if(LastUsedAt is null && elapsedSinceBeginUsing >= InitialUsageTimeLimit)
        {
            return StopUsing();
        }

        if(UserPresent && elapsedSinceBeginUsing >= UserPresentTimeLimit)
        {
            return ClearUserPresentFlag();
        }

        return this;
    }


    /// <summary>Releases the pooled <see cref="Token"/> this record owns.</summary>
    public void Dispose()
    {
        Token.Dispose();
    }


    /// <summary>
    /// Mints a fresh 32-byte <c>pinUvAuthToken</c> value via the registered entropy provider (the
    /// same registry-resolved <see cref="GenerateNonceDelegate"/> <see cref="CtapPinUvAuthProtocol"/>'s
    /// protocol-two <c>encrypt</c> uses for its random IV), copied into a <see cref="SymmetricKeyMemory"/>
    /// since the token is used as an HMAC key across many operations rather than once (see the
    /// <see cref="Token"/> parameter remark) — never a bare
    /// <see cref="System.Security.Cryptography.RandomNumberGenerator"/> call.
    /// </summary>
    private static SymmetricKeyMemory MintToken(MemoryPool<byte> pool)
    {
        using Nonce entropy = CryptographicKeyEvents.GenerateNonce(TokenLength, CryptoTags.HmacSha256Key, pool);

        IMemoryOwner<byte> owner = pool.Rent(TokenLength);
        try
        {
            entropy.AsReadOnlySpan().CopyTo(owner.Memory.Span);

            return new SymmetricKeyMemory(owner, CryptoTags.HmacSha256Key);
        }
        catch
        {
            owner.Memory.Span.Clear();
            owner.Dispose();
            throw;
        }
    }
}
