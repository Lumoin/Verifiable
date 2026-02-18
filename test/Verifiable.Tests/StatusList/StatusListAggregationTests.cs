using Verifiable.Core.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusListAggregation"/>.
/// </summary>
[TestClass]
internal sealed class StatusListAggregationTests
{
    /// <summary>
    /// Gets the example subject value used for token generation in test scenarios. 
    /// </summary>
    private string ExampleTokenSubject { get; } = StatusListTestConstants.ExampleTokenSubject;
    
    /// <summary>
    /// Gets the subject identifier associated with the second token used in status list tests.
    /// </summary>
    private string SecondTokenSubject { get; } = StatusListTestConstants.SecondTokenSubject;


    [TestMethod]
    public void ConstructorSetsStatusLists()
    {
        string[] uris = [ExampleTokenSubject, SecondTokenSubject];
        var aggregation = new StatusListAggregation(uris);

        Assert.HasCount(2, aggregation.StatusLists);
    }


    [TestMethod]
    public void ConstructorThrowsForNullList()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new StatusListAggregation(null!));
    }

    [TestMethod]
    public void ConstructorThrowsForEmptyList()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new StatusListAggregation(Array.Empty<string>()));
    }    
}