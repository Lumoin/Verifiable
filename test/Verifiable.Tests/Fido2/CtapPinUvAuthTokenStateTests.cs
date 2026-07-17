using System;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapPinUvAuthTokenState"/> (CTAP 2.3 §6.5.2.1/§6.5.3): minting, every §6.5.2.1
/// initial value, the §6.5.3 lifecycle functions, the lazily-evaluated timer semantics at their exact
/// 19.8-second/600-second boundaries, cross-protocol independence, and dispose-time zeroing.
/// </summary>
[TestClass]
internal sealed class CtapPinUvAuthTokenStateTests
{
    /// <summary>The <c>pinUvAuthToken</c> length this authenticator mints for both PIN/UV auth protocols.</summary>
    private const int TokenLength = 32;


    /// <summary>
    /// <see cref="CtapPinUvAuthTokenState.Initial"/> mints a 32-byte token and sets every §6.5.2.1 state
    /// variable to its initial value.
    /// </summary>
    [TestMethod]
    public void InitialMintsThirtyTwoByteTokenWithEverySpecInitialValue()
    {
        using CtapPinUvAuthTokenState state = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);

        Assert.AreEqual(TokenLength, state.Token.AsReadOnlySpan().Length, "The pinUvAuthToken must be 32 bytes for both PIN/UV auth protocols.");
        Assert.IsNull(state.PermissionsRpId, "The permissions RP ID is initially null (line 5019).");
        Assert.AreEqual(0, state.Permissions, "The permissions set is initially empty (line 5021).");
        Assert.IsFalse(state.IsInUse, "The in use flag is initially false (line 5026).");
        Assert.IsFalse(state.UserVerified, "The userVerified flag is initially false (line 5050).");
        Assert.IsFalse(state.UserPresent, "The userPresent flag is initially false (line 5052).");
        Assert.IsNull(state.BeginUsingAt, "The usage timer is initially not running (line 5023).");
        Assert.IsNull(state.LastUsedAt);
    }


    /// <summary>
    /// <see cref="CtapPinUvAuthTokenState.ResetToken"/> (<c>resetPinUvAuthToken()</c>) mints a
    /// byte-different 32-byte token and reinitializes every state variable, even starting from a
    /// heavily-mutated in-use instance.
    /// </summary>
    [TestMethod]
    public void ResetTokenMintsAFreshDifferentTokenAndReinitializesEveryStateVariable()
    {
        CtapPinUvAuthTokenState original = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        byte[] originalTokenBytes = original.Token.AsReadOnlySpan().ToArray();

        CtapPinUvAuthTokenState mutated = original.BeginUsing(userIsPresent: true, TestClock.CanonicalEpoch) with
        {
            PermissionsRpId = "example.com",
            Permissions = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga,
            LastUsedAt = TestClock.CanonicalEpoch
        };

        using CtapPinUvAuthTokenState reset = mutated.ResetToken(BaseMemoryPool.Shared);

        Assert.AreEqual(TokenLength, reset.Token.AsReadOnlySpan().Length);
        Assert.IsFalse(originalTokenBytes.AsSpan().SequenceEqual(reset.Token.AsReadOnlySpan()), "resetPinUvAuthToken() must mint a NEW random token value, not reuse the old bytes.");
        Assert.IsNull(reset.PermissionsRpId);
        Assert.AreEqual(0, reset.Permissions);
        Assert.IsFalse(reset.IsInUse);
        Assert.IsFalse(reset.UserVerified);
        Assert.IsFalse(reset.UserPresent);
        Assert.IsNull(reset.BeginUsingAt);
        Assert.IsNull(reset.LastUsedAt);
    }


    /// <summary>
    /// <c>beginUsingPinUvAuthToken(userIsPresent: false)</c> — the shape every PIN-path token-issuance
    /// tail uses (CTAP 2.3, line 5910/6020) — sets userVerified true, userPresent false, and in use true.
    /// </summary>
    [TestMethod]
    public void BeginUsingWithUserNotPresentSetsUserVerifiedTrueUserPresentFalseAndInUseTrue()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        DateTimeOffset now = TestClock.CanonicalEpoch;

        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: false, now);

        Assert.IsTrue(inUse.UserVerified, "beginUsingPinUvAuthToken() always sets userVerified to true (line 5136).");
        Assert.IsFalse(inUse.UserPresent, "userPresent is set to the userIsPresent parameter's value (line 5134).");
        Assert.IsTrue(inUse.IsInUse, "The token becomes in use (line 5140).");
        Assert.AreEqual(now, inUse.BeginUsingAt);
        Assert.IsNull(inUse.LastUsedAt);
        Assert.IsNull(inUse.PermissionsRpId, "beginUsingPinUvAuthToken() does not touch permissions or the permissions RP ID.");
        Assert.AreEqual(0, inUse.Permissions);
    }


    /// <summary><c>beginUsingPinUvAuthToken(userIsPresent: true)</c> sets userPresent to true, too.</summary>
    [TestMethod]
    public void BeginUsingWithUserPresentSetsUserPresentTrue()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);

        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: true, TestClock.CanonicalEpoch);

        Assert.IsTrue(inUse.UserPresent);
        Assert.IsTrue(inUse.UserVerified);
        Assert.IsTrue(inUse.IsInUse);
    }


    /// <summary>
    /// <c>stopUsingPinUvAuthToken()</c> sets every §6.5.2.1 state variable back to its initial value —
    /// even permissions and the permissions RP ID a token-issuance tail assigned after
    /// <see cref="CtapPinUvAuthTokenState.BeginUsing"/> — while never regenerating the token value itself.
    /// </summary>
    [TestMethod]
    public void StopUsingResetsAllStateVariablesButNeverRegeneratesTheToken()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        byte[] tokenBytes = initial.Token.AsReadOnlySpan().ToArray();

        CtapPinUvAuthTokenState mutated = initial.BeginUsing(userIsPresent: true, TestClock.CanonicalEpoch) with
        {
            PermissionsRpId = "example.com",
            Permissions = WellKnownCtapPinUvAuthTokenPermissions.Mc,
            LastUsedAt = TestClock.CanonicalEpoch
        };

        CtapPinUvAuthTokenState stopped = mutated.StopUsing();

        Assert.IsTrue(tokenBytes.AsSpan().SequenceEqual(stopped.Token.AsReadOnlySpan()), "stopUsingPinUvAuthToken() must not regenerate the token value.");
        Assert.IsNull(stopped.PermissionsRpId);
        Assert.AreEqual(0, stopped.Permissions);
        Assert.IsFalse(stopped.IsInUse);
        Assert.IsFalse(stopped.UserVerified);
        Assert.IsFalse(stopped.UserPresent);
        Assert.IsNull(stopped.BeginUsingAt);
        Assert.IsNull(stopped.LastUsedAt);
    }


    /// <summary><c>getUserPresentFlagValue()</c>/<c>getUserVerifiedFlagValue()</c> report false when the token is not in use, regardless of the underlying flag values.</summary>
    [TestMethod]
    public void GetFlagValuesReportFalseWhenTokenIsNotInUseEvenIfUnderlyingFlagsAreTrue()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState notInUseButFlagged = initial with { UserPresent = true, UserVerified = true };

        Assert.IsFalse(notInUseButFlagged.GetUserPresentFlagValue(), "Line 5179: not in use implies userPresentFlagValue is false regardless of the stored flag.");
        Assert.IsFalse(notInUseButFlagged.GetUserVerifiedFlagValue());
    }


    /// <summary><c>getUserPresentFlagValue()</c>/<c>getUserVerifiedFlagValue()</c> report the current flag value while in use.</summary>
    [TestMethod]
    public void GetFlagValuesReportTheCurrentFlagWhileInUse()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: false, TestClock.CanonicalEpoch);

        Assert.IsFalse(inUse.GetUserPresentFlagValue());
        Assert.IsTrue(inUse.GetUserVerifiedFlagValue());
    }


    /// <summary><c>clearUserPresentFlag()</c>/<c>clearUserVerifiedFlag()</c> are no-ops while the token is not in use.</summary>
    [TestMethod]
    public void ClearFlagsAreNoOpsWhenNotInUse()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);

        CtapPinUvAuthTokenState afterClearPresent = initial.ClearUserPresentFlag();
        CtapPinUvAuthTokenState afterClearVerified = initial.ClearUserVerifiedFlag();

        Assert.AreEqual(initial, afterClearPresent);
        Assert.AreEqual(initial, afterClearVerified);
    }


    /// <summary><c>clearUserPresentFlag()</c>/<c>clearUserVerifiedFlag()</c> clear only their own flag while the token is in use.</summary>
    [TestMethod]
    public void ClearFlagsClearOnlyTheirOwnFlagWhileInUse()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: true, TestClock.CanonicalEpoch);

        CtapPinUvAuthTokenState presentCleared = inUse.ClearUserPresentFlag();
        Assert.IsFalse(presentCleared.UserPresent);
        Assert.IsTrue(presentCleared.UserVerified, "clearUserPresentFlag() must not touch userVerified.");

        CtapPinUvAuthTokenState verifiedCleared = inUse.ClearUserVerifiedFlag();
        Assert.IsFalse(verifiedCleared.UserVerified);
        Assert.IsTrue(verifiedCleared.UserPresent, "clearUserVerifiedFlag() must not touch userPresent.");
    }


    /// <summary><c>clearPinUvAuthTokenPermissionsExceptLbw()</c> is a no-op while the token is not in use.</summary>
    [TestMethod]
    public void ClearPermissionsExceptLbwIsANoOpWhenNotInUse()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState flagged = initial with { Permissions = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Lbw };

        CtapPinUvAuthTokenState result = flagged.ClearPinUvAuthTokenPermissionsExceptLbw();

        Assert.AreEqual(flagged, result);
    }


    /// <summary><c>clearPinUvAuthTokenPermissionsExceptLbw()</c> retains only <c>lbw</c> while the token is in use.</summary>
    [TestMethod]
    public void ClearPermissionsExceptLbwRetainsOnlyLbwWhileInUse()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUseWithPermissions = initial.BeginUsing(userIsPresent: false, TestClock.CanonicalEpoch) with
        {
            Permissions = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga | WellKnownCtapPinUvAuthTokenPermissions.Lbw
        };

        CtapPinUvAuthTokenState cleared = inUseWithPermissions.ClearPinUvAuthTokenPermissionsExceptLbw();

        Assert.AreEqual(WellKnownCtapPinUvAuthTokenPermissions.Lbw, cleared.Permissions);
    }


    /// <summary><c>clearPinUvAuthTokenPermissionsExceptLbw()</c> becomes permission-less when <c>lbw</c> was never requested.</summary>
    [TestMethod]
    public void ClearPermissionsExceptLbwBecomesPermissionLessWhenLbwWasNotRequested()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUseWithPermissions = initial.BeginUsing(userIsPresent: false, TestClock.CanonicalEpoch) with
        {
            Permissions = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga
        };

        CtapPinUvAuthTokenState cleared = inUseWithPermissions.ClearPinUvAuthTokenPermissionsExceptLbw();

        Assert.AreEqual(0, cleared.Permissions, "Line 5828: with no lbw requested, the token becomes permission-less.");
    }


    /// <summary>A not-in-use token is unaffected by <see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/> regardless of the elapsed time.</summary>
    [TestMethod]
    public void EvaluateExpiryOnANotInUseTokenReturnsItUnchanged()
    {
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);

        CtapPinUvAuthTokenState result = initial.EvaluateExpiry(TestClock.CanonicalEpoch + TimeSpan.FromHours(1));

        Assert.AreEqual(initial, result);
    }


    /// <summary>Strictly before the 19.8-second initial usage time limit, an unused in-use token remains in use.</summary>
    [TestMethod]
    public void EvaluateExpiryBeforeInitialUsageTimeLimitStaysInUseWhenNeverUsed()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: false, timeProvider.GetUtcNow());

        timeProvider.Advance(CtapPinUvAuthTokenState.InitialUsageTimeLimit - TimeSpan.FromMilliseconds(1));
        CtapPinUvAuthTokenState result = inUse.EvaluateExpiry(timeProvider.GetUtcNow());

        Assert.IsTrue(result.IsInUse, "Strictly before the initial usage time limit, the token must remain in use.");
    }


    /// <summary>At the exact 19.8-second initial usage time limit, an unused token stops using (line 5154's "reached").</summary>
    [TestMethod]
    public void EvaluateExpiryAtInitialUsageTimeLimitStopsUsingWhenNeverUsed()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: false, timeProvider.GetUtcNow());

        timeProvider.Advance(CtapPinUvAuthTokenState.InitialUsageTimeLimit);
        CtapPinUvAuthTokenState result = inUse.EvaluateExpiry(timeProvider.GetUtcNow());

        Assert.IsFalse(result.IsInUse, "At the exact boundary, the limit is 'reached' and stopUsingPinUvAuthToken() applies.");
        Assert.IsFalse(result.UserVerified);
        Assert.IsFalse(result.UserPresent);
        Assert.IsNull(result.BeginUsingAt);
    }


    /// <summary>After the 19.8-second initial usage time limit, an unused token stays stopped.</summary>
    [TestMethod]
    public void EvaluateExpiryAfterInitialUsageTimeLimitStopsUsingWhenNeverUsed()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: false, timeProvider.GetUtcNow());

        timeProvider.Advance(CtapPinUvAuthTokenState.InitialUsageTimeLimit + TimeSpan.FromMilliseconds(1));
        CtapPinUvAuthTokenState result = inUse.EvaluateExpiry(timeProvider.GetUtcNow());

        Assert.IsFalse(result.IsInUse);
    }


    /// <summary>
    /// When the platform has already used the token (<c>LastUsedAt</c> set) before the initial usage
    /// time limit, reaching that limit no longer stops the token — only the max usage time period can,
    /// since the rolling timer (a MAY) is not implemented.
    /// </summary>
    [TestMethod]
    public void EvaluateExpiryAtInitialUsageTimeLimitDoesNotStopWhenAlreadyUsed()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: false, timeProvider.GetUtcNow()) with
        {
            LastUsedAt = timeProvider.GetUtcNow()
        };

        timeProvider.Advance(CtapPinUvAuthTokenState.InitialUsageTimeLimit + TimeSpan.FromSeconds(1));
        CtapPinUvAuthTokenState result = inUse.EvaluateExpiry(timeProvider.GetUtcNow());

        Assert.IsTrue(result.IsInUse, "Once used, the initial-usage-limit clause no longer applies (no rolling timer).");
    }


    /// <summary>Strictly before the 600-second max usage time period, an already-used in-use token remains in use.</summary>
    [TestMethod]
    public void EvaluateExpiryBeforeMaxUsageTimePeriodStaysInUseWhenAlreadyUsed()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: false, timeProvider.GetUtcNow()) with
        {
            LastUsedAt = timeProvider.GetUtcNow()
        };

        timeProvider.Advance(CtapPinUvAuthTokenState.MaxUsageTimePeriod - TimeSpan.FromMilliseconds(1));
        CtapPinUvAuthTokenState result = inUse.EvaluateExpiry(timeProvider.GetUtcNow());

        Assert.IsTrue(result.IsInUse);
    }


    /// <summary>At the exact 600-second max usage time period, the token stops using regardless of prior use.</summary>
    [TestMethod]
    public void EvaluateExpiryAtMaxUsageTimePeriodStopsUsingRegardlessOfUse()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: false, timeProvider.GetUtcNow()) with
        {
            LastUsedAt = timeProvider.GetUtcNow()
        };

        timeProvider.Advance(CtapPinUvAuthTokenState.MaxUsageTimePeriod);
        CtapPinUvAuthTokenState result = inUse.EvaluateExpiry(timeProvider.GetUtcNow());

        Assert.IsFalse(result.IsInUse, "Line 5171: the max usage time period expiring always stops the token.");
    }


    /// <summary>After the 600-second max usage time period, the token stays stopped.</summary>
    [TestMethod]
    public void EvaluateExpiryAfterMaxUsageTimePeriodStopsUsingRegardlessOfUse()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: false, timeProvider.GetUtcNow()) with
        {
            LastUsedAt = timeProvider.GetUtcNow()
        };

        timeProvider.Advance(CtapPinUvAuthTokenState.MaxUsageTimePeriod + TimeSpan.FromSeconds(1));
        CtapPinUvAuthTokenState result = inUse.EvaluateExpiry(timeProvider.GetUtcNow());

        Assert.IsFalse(result.IsInUse);
    }


    /// <summary>
    /// At the user present time limit, with the token already used (so the initial-usage-limit clause
    /// does not also fire), only the userPresent flag clears — the token stays in use.
    /// </summary>
    [TestMethod]
    public void EvaluateExpiryAtUserPresentTimeLimitClearsOnlyUserPresentFlag()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapPinUvAuthTokenState initial = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        CtapPinUvAuthTokenState inUse = initial.BeginUsing(userIsPresent: true, timeProvider.GetUtcNow()) with
        {
            LastUsedAt = timeProvider.GetUtcNow()
        };

        timeProvider.Advance(CtapPinUvAuthTokenState.UserPresentTimeLimit);
        CtapPinUvAuthTokenState result = inUse.EvaluateExpiry(timeProvider.GetUtcNow());

        Assert.IsTrue(result.IsInUse, "The token stays in use — only userPresent clears (line 5152).");
        Assert.IsFalse(result.UserPresent);
        Assert.IsTrue(result.UserVerified, "userVerified is unaffected by the user present time limit.");
    }


    /// <summary>Resetting one protocol's token never affects an independently held instance for another protocol.</summary>
    [TestMethod]
    public void ResetTokenOnOneProtocolDoesNotAffectAnIndependentInstance()
    {
        CtapPinUvAuthTokenState protocolOne = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        using CtapPinUvAuthTokenState protocolTwo = CtapPinUvAuthTokenState.Initial(BaseMemoryPool.Shared);
        byte[] protocolTwoOriginalBytes = protocolTwo.Token.AsReadOnlySpan().ToArray();

        using CtapPinUvAuthTokenState protocolOneReset = protocolOne.ResetToken(BaseMemoryPool.Shared);

        Assert.IsTrue(protocolTwoOriginalBytes.AsSpan().SequenceEqual(protocolTwo.Token.AsReadOnlySpan()),
            "Resetting protocol one's token must not touch protocol two's independently held instance.");
    }


    /// <summary>
    /// <see cref="CtapPinUvAuthTokenState.Initial"/> and <see cref="CtapPinUvAuthTokenState.Dispose"/>
    /// zero every pooled buffer they touch before it returns to the pool — the transient entropy draw
    /// and the final token buffer alike — observed through the tracking-pool public seam, without any
    /// test-only hook in production code.
    /// </summary>
    [TestMethod]
    public void InitialAndDisposeZeroEveryTrackedBufferBeforeReturningItToThePool()
    {
        using var trackingPool = new ZeroOnDisposeTrackingMemoryPool(TokenLength);

        CtapPinUvAuthTokenState state = CtapPinUvAuthTokenState.Initial(trackingPool);

        Assert.IsGreaterThanOrEqualTo(1, trackingPool.TrackedDisposalCount,
            "Minting draws a transient entropy buffer that is disposed within Initial() before it returns.");
        Assert.IsTrue(trackingPool.AllTrackedDisposalsWereZero);

        state.Dispose();

        Assert.IsGreaterThanOrEqualTo(2, trackingPool.TrackedDisposalCount,
            "Disposing the returned state must also zero and release the final Token buffer.");
        Assert.IsTrue(trackingPool.AllTrackedDisposalsWereZero);
    }
}
