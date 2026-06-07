using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

[TestClass]
internal sealed class ConfirmationMethodTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void IsEmptyReturnsTrueWhenAllMembersNull()
    {
        ConfirmationMethod cnf = new();
        Assert.IsTrue(cnf.IsEmpty);
    }


    [TestMethod]
    public void IsEmptyReturnsFalseWhenJwkThumbprintSet()
    {
        ConfirmationMethod cnf = new() { JwkThumbprint = "abc" };
        Assert.IsFalse(cnf.IsEmpty);
    }


    [TestMethod]
    public void RecordEqualitySemanticsHoldForValueComparison()
    {
        ConfirmationMethod a = new() { JwkThumbprint = "abc" };
        ConfirmationMethod b = new() { JwkThumbprint = "abc" };
        ConfirmationMethod c = new() { JwkThumbprint = "xyz" };

        Assert.AreEqual(a, b);
        Assert.AreNotEqual(a, c);
    }
}
