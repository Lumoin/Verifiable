using Verifiable.Core.Model.Did;

namespace Verifiable.Tests.Did;

/// <summary>
/// Tests that <see cref="Service"/> equality is exact-type: a subtype adding further
/// identity-bearing members is never equal to a same-valued base instance, through either the
/// typed <see cref="System.IEquatable{T}"/> overload or the <see cref="object.Equals(object)"/>
/// override, in either comparison direction.
/// </summary>
[TestClass]
internal sealed class ServiceEquatableTests
{
    /// <summary>A <see cref="Service"/> subtype with no additional identity members.</summary>
    private sealed class DerivedService: Service
    {
    }


    /// <summary>
    /// Proves <see cref="Service.Equals(Service?)"/> and its <see cref="Service.Equals(object?)"/>
    /// override are exact-type: a same-valued subtype instance is unequal to a base instance through
    /// both overloads in both directions.
    /// </summary>
    [TestMethod]
    public void DerivedInstanceWithSameMembersIsNotEqualToBaseInstance()
    {
        var baseService = new Service { Type = "DIDCommMessaging", ServiceEndpoint = "https://example.com" };
        Service derived = new DerivedService { Type = baseService.Type, ServiceEndpoint = baseService.ServiceEndpoint };

        Assert.IsFalse(baseService.Equals(derived));
        Assert.IsFalse(derived.Equals(baseService));
        Assert.IsFalse(((object)baseService).Equals(derived));
        Assert.IsFalse(((object)derived).Equals(baseService));
    }


    /// <summary>
    /// Proves two same-typed, same-valued <see cref="Service"/> instances compare equal through both
    /// <see cref="Service.Equals(Service?)"/> and <see cref="Service.Equals(object?)"/>, in both
    /// comparison directions.
    /// </summary>
    [TestMethod]
    public void TwoBaseInstancesWithSameMembersAreEqual()
    {
        var service1 = new Service { Type = "DIDCommMessaging", ServiceEndpoint = "https://example.com" };
        var service2 = new Service { Type = "DIDCommMessaging", ServiceEndpoint = "https://example.com" };

        Assert.IsTrue(service1.Equals(service2));
        Assert.IsTrue(service2.Equals(service1));
        Assert.IsTrue(((object)service1).Equals(service2));
        Assert.IsTrue(((object)service2).Equals(service1));
    }
}
