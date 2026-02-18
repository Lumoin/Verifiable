using System.Buffers;
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
    private static MemoryPool<byte> Pool => MemoryPool<byte>.Shared;


    [TestMethod]
    public void ConstructorSetsRequiredProperties()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);

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
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
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
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            new StatusListToken(null!, BaseTime, list));
    }


    [TestMethod]
    public void ConstructorThrowsForWhitespaceSubject()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);

        Assert.ThrowsExactly<ArgumentException>(() =>
            new StatusListToken("   ", BaseTime, list));
    }


    [TestMethod]
    public void ConstructorThrowsForNullStatusList()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            new StatusListToken(ExampleTokenSubject, BaseTime, null!));
    }    
}