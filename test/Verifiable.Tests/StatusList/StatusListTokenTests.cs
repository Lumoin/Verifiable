using System.Buffers;
using Lumoin.Base;
using Verifiable.Core.StatusList;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusListToken"/>.
/// </summary>
[TestClass]
internal sealed class StatusListTokenTests
{
    /// <summary>
    /// Gets the capacity used for small status lists in test scenarios.
    /// </summary>
    private int SmallListCapacity { get; } = StatusListTestConstants.SmallListCapacity;
    
    /// <summary>
    /// Gets the example subject value used for token generation in test scenarios.
    /// </summary>
    /// <remarks>This property is intended for use in testing contexts where a consistent token subject is
    /// required. The value is derived from test constants and should not be used in production code.</remarks>
    private string ExampleTokenSubject { get; } = StatusListTestConstants.ExampleTokenSubject;
    
    /// <summary>
    /// Gets the base point in time used as a reference for time calculations or comparisons.
    /// </summary>
    private DateTimeOffset BaseTime { get; } = StatusListTestConstants.BaseTime;
    
    /// <summary>
    /// Gets a shared memory pool for efficient allocation and reuse of byte buffers.
    /// </summary>
    /// <remarks>The shared memory pool minimizes memory allocations by reusing buffers. This property is
    /// thread-safe and intended for scenarios where high-performance buffer management is required.</remarks>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public void ConstructorSetsRequiredProperties()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list);

        Assert.AreEqual(ExampleTokenSubject, token.Subject);
        Assert.AreEqual(BaseTime, token.IssuedAt);
        Assert.AreSame(list, token.StatusList);
        Assert.IsNull(token.ExpirationTime);
        Assert.IsNull(token.TimeToLive);
    }


    [TestMethod]
    public void OptionalPropertiesCanBeSet()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var expiration = BaseTime.AddHours(1);

        var token = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            ExpirationTime = expiration,
            TimeToLive = 3600
        };

        Assert.AreEqual(expiration, token.ExpirationTime);
        Assert.AreEqual(3600L, token.TimeToLive);
    }


    [TestMethod]
    public void ConstructorThrowsForNullSubject()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            new StatusListToken(null!, BaseTime, list));
    }


    [TestMethod]
    public void ConstructorThrowsForWhitespaceSubject()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        Assert.ThrowsExactly<ArgumentException>(() =>
            new StatusListToken("   ", BaseTime, list));
    }


    [TestMethod]
    public void ConstructorThrowsForNullStatusList()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            new StatusListToken(ExampleTokenSubject, BaseTime, null!));
    }


    /// <summary>
    /// "ttl: RECOMMENDED. … The value of the claim MUST be a positive number encoded in JSON as a
    /// number." — the one home for this rule on the write side is the model itself, so a non-positive
    /// value is refused at construction rather than only on a wire read.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    /// <param name="timeToLive">The non-positive value under test.</param>
    [TestMethod]
    [DataRow(0L)]
    [DataRow(-1L)]
    [DataRow(long.MinValue)]
    public void TimeToLiveThatIsNotPositiveIsRefusedAtConstruction(long timeToLive)
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            new StatusListToken(ExampleTokenSubject, BaseTime, list) { TimeToLive = timeToLive });
    }
}
