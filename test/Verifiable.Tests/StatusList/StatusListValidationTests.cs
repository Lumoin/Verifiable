using System.Buffers;
using Lumoin.Base;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.StatusList;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusListValidation"/> using <see cref="FakeTimeProvider"/>
/// to demonstrate the intended integration pattern for time-dependent validation.
/// </summary>
[TestClass]
internal sealed class StatusListValidationTests
{
    /// <summary>
    /// Gets the index of the suspended credential used for testing purposes.
    /// </summary>
    private int SuspendedCredentialIndex { get; } = StatusListTestConstants.SuspendedCredentialIndex;
    
    /// <summary>
    /// Gets the default capacity for a medium-sized list used in status list tests.
    /// </summary>
    private int MediumListCapacity { get; } = StatusListTestConstants.MediumListCapacity;
    
    /// <summary>
    /// Gets the example subject value used for token generation in test scenarios.
    /// </summary>
    /// <remarks>This property is intended for use in testing contexts where a consistent token subject is
    /// required. The value is predefined and should not be modified.</remarks>
    private string ExampleTokenSubject { get; } = StatusListTestConstants.ExampleTokenSubject;
    
    /// <summary>
    /// Gets the subject value that does not match the expected criteria for testing purposes.
    /// </summary>
    private string MismatchedSubject { get; } = StatusListTestConstants.MismatchedSubject;
    
    /// <summary>
    /// Represents the base point in time used for status list tests.
    /// </summary>
    /// <remarks>This value is intended for use in test scenarios where a consistent reference time is
    /// required. The value is defined by StatusListTestConstants.BaseTime.</remarks>
    private static DateTimeOffset BaseTime { get; } = StatusListTestConstants.BaseTime;

    /// <summary>
    /// Gets a shared memory pool for managing buffers of bytes.
    /// </summary>
    /// <remarks>The returned memory pool is a singleton instance that can be used to efficiently rent and
    /// return byte buffers. Using a shared pool helps reduce memory allocations and improve performance in scenarios
    /// that require frequent buffer management.</remarks>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public void GetStatusReturnsCorrectValue()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.TwoBits, Pool, BitOrder.LeastSignificantFirst);
        list[SuspendedCredentialIndex] = StatusTypes.Suspended;

        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);
        var reference = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);

        byte status = StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow());

        Assert.AreEqual(StatusTypes.Suspended, status);
    }

    [TestMethod]
    public void GetStatusThrowsForSubjectMismatch()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);
        var reference = new StatusListReference(0, MismatchedSubject);

        Assert.ThrowsExactly<StatusListValidationException>(() =>
            StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow()));
    }

    [TestMethod]
    public void GetStatusThrowsWhenTokenHasExpired()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            ExpirationTime = BaseTime.AddHours(1)
        };
        var reference = new StatusListReference(0, ExampleTokenSubject);

        //Advance time past expiration.
        timeProvider.Advance(TimeSpan.FromHours(2));

        Assert.ThrowsExactly<StatusListValidationException>(() =>
            StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow()));
    }

    [TestMethod]
    public void GetStatusSucceedsBeforeExpiration()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            ExpirationTime = BaseTime.AddHours(1)
        };
        var reference = new StatusListReference(0, ExampleTokenSubject);

        //Advance time but stay within expiration window.
        timeProvider.Advance(TimeSpan.FromMinutes(30));

        byte status = StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow());

        Assert.AreEqual(StatusTypes.Valid, status);
    }

    [TestMethod]
    public void GetStatusThrowsForIndexOutOfBounds()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);
        var reference = new StatusListReference(10, ExampleTokenSubject);

        Assert.ThrowsExactly<StatusListValidationException>(() =>
            StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow()));
    }

    [TestMethod]
    public void GetStatusThrowsForNullToken()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        var reference = new StatusListReference(0, ExampleTokenSubject);

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            StatusListValidation.GetStatus(null!, reference, timeProvider.GetUtcNow()));
    }

    [TestMethod]
    public void ShouldRefreshReturnsFalseWhenNoTtl()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);

        var resolvedAt = timeProvider.GetUtcNow();
        timeProvider.Advance(TimeSpan.FromHours(1));

        bool result = StatusListValidation.ShouldRefresh(token, resolvedAt, timeProvider.GetUtcNow());

        Assert.IsFalse(result);
    }

    [TestMethod]
    public void ShouldRefreshReturnsTrueWhenTtlExceeded()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            TimeToLive = 60
        };

        var resolvedAt = timeProvider.GetUtcNow();

        //Advance past the TTL.
        timeProvider.Advance(TimeSpan.FromMinutes(2));

        bool result = StatusListValidation.ShouldRefresh(token, resolvedAt, timeProvider.GetUtcNow());

        Assert.IsTrue(result);
    }

    [TestMethod]
    public void ShouldRefreshReturnsFalseWhenWithinTtl()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            TimeToLive = 3600
        };

        var resolvedAt = timeProvider.GetUtcNow();

        //Advance but stay within TTL.
        timeProvider.Advance(TimeSpan.FromSeconds(30));

        bool result = StatusListValidation.ShouldRefresh(token, resolvedAt, timeProvider.GetUtcNow());

        Assert.IsFalse(result);
    }


    /// <summary>
    /// Step 4.b: "If the Relying Party has local policies regarding the freshness of the Status List
    /// Token, it SHOULD check the issued at claim (iat or 6)", and the closing SHOULD: "If any of
    /// these checks fails, no statement about the status of the Referenced Token can be made and the
    /// Referenced Token SHOULD be rejected."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// A Status List Token issued further in the past than the Relying Party's policy allows is such
    /// a failed check, so no status is returned from it — the refusal names the issued-at instant and
    /// the window it fell outside, since those are the two facts a caller needs to tell a stale list
    /// apart from a revoked credential.
    /// </summary>
    [TestMethod]
    public void GetStatusRefusesATokenIssuedFurtherInThePastThanTheFreshnessPolicyAllows()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);
        var reference = new StatusListReference(0, ExampleTokenSubject);
        var freshnessPolicy = new StatusListFreshnessPolicy(TimeSpan.FromHours(1));

        timeProvider.Advance(TimeSpan.FromHours(2));

        StatusListValidationException caught = Assert.ThrowsExactly<StatusListValidationException>(
            () => StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow(), freshnessPolicy),
            "A token issued two hours ago is outside a one-hour freshness window, so step 4.b fails and no status statement can be made.");

        Assert.IsTrue(caught.Message.Contains("issued at", StringComparison.Ordinal),
            "The refusal names the issued at claim step 4.b checks.");
        Assert.IsTrue(caught.Message.Contains(freshnessPolicy.MaximumAge.ToString(), StringComparison.Ordinal),
            "The refusal names the freshness window the token fell outside.");
    }


    /// <summary>
    /// Step 4.b: "If the Relying Party has local policies regarding the freshness of the Status List
    /// Token, it SHOULD check the issued at claim (iat or 6)".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// A configured maximum age is the age a token may still carry, not the age at which it is already
    /// too old: a token exactly that old is inside the window, and its status is read.
    /// </summary>
    [TestMethod]
    public void GetStatusAcceptsATokenExactlyAtTheFreshnessPolicyBoundary()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.TwoBits, Pool, BitOrder.LeastSignificantFirst);
        list[SuspendedCredentialIndex] = StatusTypes.Suspended;
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);
        var reference = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);
        var freshnessPolicy = new StatusListFreshnessPolicy(TimeSpan.FromHours(1));

        timeProvider.Advance(TimeSpan.FromHours(1));

        byte status = StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow(), freshnessPolicy);

        Assert.AreEqual(StatusTypes.Suspended, status,
            "A token exactly at the configured maximum age is still fresh, so its status is read.");
    }


    /// <summary>
    /// Step 4.b: "If the Relying Party has local policies regarding the freshness of the Status List
    /// Token, it SHOULD check the issued at claim (iat or 6)".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// A token issued well inside the window passes the check and its status is read unchanged.
    /// </summary>
    [TestMethod]
    public void GetStatusAcceptsATokenYoungerThanTheFreshnessPolicyMaximumAge()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        list[SuspendedCredentialIndex] = StatusTypes.Invalid;
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);
        var reference = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);
        var freshnessPolicy = new StatusListFreshnessPolicy(TimeSpan.FromHours(1));

        timeProvider.Advance(TimeSpan.FromMinutes(30));

        byte status = StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow(), freshnessPolicy);

        Assert.AreEqual(StatusTypes.Invalid, status,
            "A token half an hour old is inside a one-hour freshness window, so step 4.b does not stand in the way of the status.");
    }


    /// <summary>
    /// Step 4.b is conditional on the Relying Party having a policy at all: "If the Relying Party has
    /// local policies regarding the freshness of the Status List Token, it SHOULD check the issued at
    /// claim (iat or 6)".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// With no such policy there is nothing to check the <c>iat</c> against, so an arbitrarily old
    /// Status List Token still yields its status — the other steps, not this one, decide whether it
    /// may be trusted.
    /// </summary>
    [TestMethod]
    public void GetStatusWithoutAFreshnessPolicyAcceptsAnAncientIssuedAt()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        list[SuspendedCredentialIndex] = StatusTypes.Invalid;
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);
        var reference = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);

        timeProvider.Advance(TimeSpan.FromDays(3650));

        byte status = StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow());

        Assert.AreEqual(StatusTypes.Invalid, status,
            "Absent a local freshness policy there is no iat check to fail, so the status is read regardless of the token's age.");
    }


    /// <summary>
    /// Step 4.b: "If the Relying Party has local policies regarding the freshness of the Status List
    /// Token, it SHOULD check the issued at claim (iat or 6)".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// A freshness policy bounds how old a token may be, not how new: a token whose <c>iat</c> lies
    /// ahead of the check's own clock has a negative age, which is inside every window this policy can
    /// express, so it is not refused here. A future-dated issuance is a different concern from
    /// staleness and is not silently folded into it.
    /// </summary>
    [TestMethod]
    public void GetStatusAcceptsAFutureDatedIssuedAtUnderAFreshnessPolicy()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime.AddHours(1), list);
        var reference = new StatusListReference(0, ExampleTokenSubject);
        var freshnessPolicy = new StatusListFreshnessPolicy(TimeSpan.FromMinutes(5));

        byte status = StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow(), freshnessPolicy);

        Assert.AreEqual(StatusTypes.Valid, status,
            "An iat ahead of the current time yields a negative age, which no positive maximum age is exceeded by.");
    }


    /// <summary>
    /// Step 4 runs its sub-steps in the order the specification lists them: "a. The subject claim
    /// (sub or 2) of the Status List Token MUST be equal to the uri claim in the status_list object of
    /// the Referenced Token" precedes "b. If the Relying Party has local policies regarding the
    /// freshness of the Status List Token, it SHOULD check the issued at claim (iat or 6)".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// A token that is both the wrong list and too old is refused for being the wrong list: the
    /// freshness of a list that was never the one referenced is not a fact worth reporting.
    /// </summary>
    [TestMethod]
    public void GetStatusRefusesAMismatchedSubjectBeforeCheckingFreshness()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);
        var reference = new StatusListReference(0, MismatchedSubject);
        var freshnessPolicy = new StatusListFreshnessPolicy(TimeSpan.FromMinutes(5));

        timeProvider.Advance(TimeSpan.FromDays(1));

        StatusListValidationException caught = Assert.ThrowsExactly<StatusListValidationException>(
            () => StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow(), freshnessPolicy),
            "A token that is neither the referenced list nor fresh must still be refused.");

        Assert.IsTrue(caught.Message.Contains("Subject mismatch", StringComparison.Ordinal),
            "Step 4.a runs before step 4.b, so the subject mismatch is the reported failure.");
        Assert.IsFalse(caught.Message.Contains("issued at", StringComparison.Ordinal),
            "Step 4.b is never reached for a token that is not the referenced list at all.");
    }


    /// <summary>
    /// Step 4 runs its sub-steps in the order the specification lists them: "b. If the Relying Party
    /// has local policies regarding the freshness of the Status List Token, it SHOULD check the issued
    /// at claim (iat or 6)" precedes "c. If the expiration time is defined (exp or 4), it MUST be
    /// checked if the Status List Token is expired".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// A token that is both too old for the Relying Party's policy and past its own <c>exp</c> is
    /// refused on freshness, so the reported failure is the Relying Party's own policy rather than the
    /// Status Issuer's expiry.
    /// </summary>
    [TestMethod]
    public void GetStatusRefusesOnFreshnessBeforeCheckingExpiration()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            ExpirationTime = BaseTime.AddHours(1)
        };
        var reference = new StatusListReference(0, ExampleTokenSubject);
        var freshnessPolicy = new StatusListFreshnessPolicy(TimeSpan.FromMinutes(30));

        timeProvider.Advance(TimeSpan.FromHours(2));

        StatusListValidationException caught = Assert.ThrowsExactly<StatusListValidationException>(
            () => StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow(), freshnessPolicy),
            "A token that is both stale for the Relying Party and expired for the Status Issuer must be refused.");

        Assert.IsTrue(caught.Message.Contains("issued at", StringComparison.Ordinal),
            "Step 4.b runs before step 4.c, so the freshness policy is the reported failure.");
        Assert.IsFalse(caught.Message.Contains("expired", StringComparison.Ordinal),
            "Step 4.c is never reached once step 4.b has already refused the token.");
    }


    /// <summary>
    /// "Clients SHOULD check that both values are within reasonable ranges before requesting new
    /// Status List Tokens based on these values to prevent accidentally creating unreasonable amounts
    /// of requests for a specific URL."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5">Token Status List, Section 11.5</see>.
    /// A <c>ttl</c> below the client's configured floor is exactly the value that would drive that
    /// request storm, so the refresh decision holds the cached token for the floor instead: unrefreshed
    /// while the floor has not elapsed, refreshed once it has. Without bounds the same token and the
    /// same instants ask for a refresh immediately — the contrast is what the floor buys.
    /// </summary>
    [TestMethod]
    public void ShouldRefreshHoldsATtlBelowTheConfiguredFloorUntilTheFloorElapses()
    {
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            TimeToLive = 10
        };
        var cachingBounds = new StatusListCachingBounds(TimeSpan.FromSeconds(60), TimeSpan.FromHours(1));

        bool isRefreshedBeforeTheFloor = StatusListValidation.ShouldRefresh(token, BaseTime, BaseTime.AddSeconds(30), cachingBounds);
        bool isRefreshedAfterTheFloor = StatusListValidation.ShouldRefresh(token, BaseTime, BaseTime.AddSeconds(90), cachingBounds);
        bool isRefreshedUnbounded = StatusListValidation.ShouldRefresh(token, BaseTime, BaseTime.AddSeconds(30));

        Assert.IsFalse(isRefreshedBeforeTheFloor,
            "A ten-second ttl under a sixty-second floor must not request a new Status List Token after thirty seconds.");
        Assert.IsTrue(isRefreshedAfterTheFloor,
            "Once the configured floor has elapsed the cached Status List Token is due for a fresh copy.");
        Assert.IsTrue(isRefreshedUnbounded,
            "Unbounded, the same ttl asks for a refresh after thirty seconds — the floor is what prevents that request rate.");
    }


    /// <summary>
    /// "Reasonable values for both claims highly depend on the use-case requirements and clients
    /// should be configured with lower/upper bounds for these values that fit their respective
    /// use-cases."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5">Token Status List, Section 11.5</see>.
    /// A <c>ttl</c> above the client's configured ceiling would pin a cached Status List Token past
    /// what the client considers reasonable, so the refresh decision uses the ceiling: the copy is due
    /// once the ceiling has elapsed, even though the Status Issuer's own <c>ttl</c> has not.
    /// </summary>
    [TestMethod]
    public void ShouldRefreshDropsATtlAboveTheConfiguredCeilingToTheCeiling()
    {
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            TimeToLive = 7200
        };
        var cachingBounds = new StatusListCachingBounds(TimeSpan.FromSeconds(60), TimeSpan.FromHours(1));

        bool isRefreshedPastTheCeiling = StatusListValidation.ShouldRefresh(token, BaseTime, BaseTime.AddMinutes(90), cachingBounds);
        bool isRefreshedUnbounded = StatusListValidation.ShouldRefresh(token, BaseTime, BaseTime.AddMinutes(90));

        Assert.IsTrue(isRefreshedPastTheCeiling,
            "A two-hour ttl under a one-hour ceiling is due for a fresh copy ninety minutes after it was resolved.");
        Assert.IsFalse(isRefreshedUnbounded,
            "Unbounded, the same two-hour ttl would still pin the cached copy — the ceiling is what releases it.");
    }


    /// <summary>
    /// "Reasonable values for both claims highly depend on the use-case requirements and clients
    /// should be configured with lower/upper bounds for these values that fit their respective
    /// use-cases."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5">Token Status List, Section 11.5</see>.
    /// A <c>ttl</c> that already lies inside the configured bounds is reasonable by the client's own
    /// definition, so it is used as published — the bounds constrain unreasonable values, they do not
    /// replace the Status Issuer's caching hint.
    /// </summary>
    [TestMethod]
    public void ShouldRefreshUsesATtlWithinTheConfiguredBoundsUnchanged()
    {
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            TimeToLive = 300
        };
        var cachingBounds = new StatusListCachingBounds(TimeSpan.FromSeconds(60), TimeSpan.FromHours(1));

        bool isRefreshedWithinTheTtl = StatusListValidation.ShouldRefresh(token, BaseTime, BaseTime.AddMinutes(2), cachingBounds);
        bool isRefreshedPastTheTtl = StatusListValidation.ShouldRefresh(token, BaseTime, BaseTime.AddMinutes(6), cachingBounds);

        Assert.IsFalse(isRefreshedWithinTheTtl,
            "A five-minute ttl between a one-minute floor and a one-hour ceiling still holds two minutes after resolution.");
        Assert.IsTrue(isRefreshedPastTheTtl,
            "A five-minute ttl between a one-minute floor and a one-hour ceiling is due six minutes after resolution.");
    }


    /// <summary>
    /// "Expiration and caching information is conveyed via the exp and ttl claims as explained in
    /// Section 13.7. Clients SHOULD check that both values are within reasonable ranges before
    /// requesting new Status List Tokens based on these values."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5">Token Status List, Section 11.5</see>.
    /// Step 4.d is itself conditional on a <c>ttl</c> being there to check — "If the Relying Party is
    /// using a system for caching the Status List Token, it SHOULD check the ttl claim of the Status
    /// List Token and retrieve a fresh copy if (time status was resolved + ttl &lt; current time)".
    /// With no <c>ttl</c> published there is no value for the bounds to clamp, and configuring bounds
    /// must not invent a refresh interval the Status Issuer never conveyed.
    /// </summary>
    [TestMethod]
    public void ShouldRefreshReturnsFalseWithoutATtlRegardlessOfTheConfiguredBounds()
    {
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);
        var cachingBounds = new StatusListCachingBounds(TimeSpan.FromSeconds(60), TimeSpan.FromHours(1));

        bool isRefreshed = StatusListValidation.ShouldRefresh(token, BaseTime, BaseTime.AddDays(365), cachingBounds);

        Assert.IsFalse(isRefreshed,
            "A Status List Token conveying no ttl carries no caching interval for the configured bounds to clamp.");
    }


    /// <summary>
    /// Step 4.d's arithmetic — <c>resolvedAt + ttl</c> — must never fault: a <c>ttl</c> near
    /// <see cref="long.MaxValue"/> added to any resolution instant overflows the representable
    /// <see cref="DateTimeOffset"/> range, so an unrepresentable result must read as "never due for
    /// refresh" rather than throw out of the gate.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public void ShouldRefreshDoesNotThrowForATimeToLiveNearLongMaxValueWithoutBounds()
    {
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            TimeToLive = long.MaxValue
        };

        bool isRefreshed = StatusListValidation.ShouldRefresh(token, BaseTime, BaseTime.AddDays(365));

        Assert.IsFalse(isRefreshed,
            "A ttl this large added to the resolution instant is not representable, so the token is never due for refresh on that basis.");
    }


    /// <summary>
    /// The same unrepresentable-<c>ttl</c> shape under a configured Section 11.5 ceiling: the bound
    /// clamps the interval to something well within range, so the refresh decision is answered by the
    /// ceiling rather than by the raw, otherwise-overflowing <c>ttl</c>.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5">Token Status List, Section 11.5</see>.
    /// </summary>
    [TestMethod]
    public void ShouldRefreshClampsATimeToLiveNearLongMaxValueToTheConfiguredCeiling()
    {
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            TimeToLive = long.MaxValue
        };
        var cachingBounds = new StatusListCachingBounds(TimeSpan.FromSeconds(60), TimeSpan.FromHours(1));

        bool isRefreshed = StatusListValidation.ShouldRefresh(token, BaseTime, BaseTime.AddHours(2), cachingBounds);

        Assert.IsTrue(isRefreshed,
            "The configured one-hour ceiling decides the refresh verdict, so a resolution two hours old is due for a fresh copy.");
    }
}
