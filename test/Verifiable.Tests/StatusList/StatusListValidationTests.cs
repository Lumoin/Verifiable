using System.Buffers;
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
    private static readonly DateTimeOffset BaseTime = StatusListTestConstants.BaseTime;

    /// <summary>
    /// Gets a shared memory pool for managing buffers of bytes.
    /// </summary>
    /// <remarks>The returned memory pool is a singleton instance that can be used to efficiently rent and
    /// return byte buffers. Using a shared pool helps reduce memory allocations and improve performance in scenarios
    /// that require frequent buffer management.</remarks>
    private static MemoryPool<byte> Pool => MemoryPool<byte>.Shared;


    [TestMethod]
    public void GetStatusReturnsCorrectValue()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.TwoBits, Pool);
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
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool);
        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);
        var reference = new StatusListReference(0, MismatchedSubject);

        Assert.ThrowsExactly<StatusListValidationException>(() =>
            StatusListValidation.GetStatus(token, reference, timeProvider.GetUtcNow()));
    }

    [TestMethod]
    public void GetStatusThrowsWhenTokenHasExpired()
    {
        var timeProvider = new FakeTimeProvider(BaseTime);
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool);
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
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool);
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
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool);
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
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool);
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
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool);
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
        using var list = StatusListType.Create(10, StatusListBitSize.OneBit, Pool);
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
}