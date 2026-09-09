using Verifiable.Core;

namespace Verifiable.Tests;

/// <summary>
/// Tests that <see cref="ExchangeContext"/> equality is exact-type: a subtype adding further
/// identity-bearing members is never equal to a same-valued base instance, through either the
/// typed <see cref="System.IEquatable{T}"/> overload or the <see cref="object.Equals(object)"/>
/// override, in either comparison direction.
/// </summary>
[TestClass]
internal sealed class ExchangeContextEquatableTests
{
    /// <summary>An <see cref="ExchangeContext"/> subtype with no additional identity members.</summary>
    private sealed class DerivedExchangeContext: ExchangeContext
    {
    }


    /// <summary>
    /// Proves <see cref="ExchangeContext.Equals(ExchangeContext?)"/> and its
    /// <see cref="ExchangeContext.Equals(object?)"/> override are exact-type: a same-valued subtype
    /// instance is unequal to a base instance through both overloads in both directions.
    /// </summary>
    [TestMethod]
    public void DerivedInstanceWithSameEntriesIsNotEqualToBaseInstance()
    {
        var baseContext = new ExchangeContext { ["tenant"] = "acme" };
        ExchangeContext derived = new DerivedExchangeContext { ["tenant"] = "acme" };

        Assert.IsFalse(baseContext.Equals(derived));
        Assert.IsFalse(derived.Equals(baseContext));
        Assert.IsFalse(((object)baseContext).Equals(derived));
        Assert.IsFalse(((object)derived).Equals(baseContext));
    }


    /// <summary>
    /// Proves two same-typed, same-valued <see cref="ExchangeContext"/> instances compare equal through
    /// both <see cref="ExchangeContext.Equals(ExchangeContext?)"/> and
    /// <see cref="ExchangeContext.Equals(object?)"/>, in both comparison directions.
    /// </summary>
    [TestMethod]
    public void TwoBaseInstancesWithSameEntriesAreEqual()
    {
        var context1 = new ExchangeContext { ["tenant"] = "acme" };
        var context2 = new ExchangeContext { ["tenant"] = "acme" };

        Assert.IsTrue(context1.Equals(context2));
        Assert.IsTrue(context2.Equals(context1));
        Assert.IsTrue(((object)context1).Equals(context2));
        Assert.IsTrue(((object)context2).Equals(context1));
    }
}
