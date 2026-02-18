using Verifiable.Core.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusClaim"/>.
/// </summary>
[TestClass]
internal sealed class StatusClaimTests
{
    /// <summary>
    /// Gets the index of the suspended credential used for testing purposes.
    /// </summary>
    private int SuspendedCredentialIndex { get; } = StatusListTestConstants.SuspendedCredentialIndex;
    
    /// <summary>
    /// Gets the example subject value used for token generation in test scenarios.
    /// </summary>
    private string ExampleTokenSubject { get; } = StatusListTestConstants.ExampleTokenSubject;


    [TestMethod]
    public void ConstructorSetsStatusListReference()
    {
        var reference = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);
        var claim = new StatusClaim(reference);

        Assert.IsTrue(claim.HasStatusList);
        Assert.AreEqual(SuspendedCredentialIndex, claim.StatusList!.Value.Index);
        Assert.AreEqual(ExampleTokenSubject, claim.StatusList.Value.Uri);
    }


    [TestMethod]
    public void FromStatusListCreatesClaimWithReference()
    {
        var claim = StatusClaim.FromStatusList(7, ExampleTokenSubject);

        Assert.IsTrue(claim.HasStatusList);
        Assert.AreEqual(7, claim.StatusList!.Value.Index);
        Assert.AreEqual(ExampleTokenSubject, claim.StatusList.Value.Uri);
    }    
}