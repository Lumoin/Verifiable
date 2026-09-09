using System;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests that <see cref="SdToken{TEnvelope}"/> equality is exact-type: a subtype adding further
/// identity-bearing members is never equal to a same-valued base instance, through either the
/// typed <see cref="IEquatable{T}"/> overload or the <see cref="object.Equals(object)"/>
/// override, in either comparison direction.
/// </summary>
[TestClass]
internal sealed class SdTokenEquatableTests
{
    /// <summary>An <see cref="SdToken{TEnvelope}"/> subtype with no additional identity members.</summary>
    private sealed class DerivedSdToken: SdToken<string>
    {
        /// <summary>
        /// Creates a subtype instance carrying the same issuer-signed payload and no disclosures.
        /// </summary>
        /// <param name="issuerSigned">The issuer-signed payload.</param>
        public DerivedSdToken(string issuerSigned) : base(issuerSigned, Array.Empty<SdDisclosure>())
        {
        }
    }


    /// <summary>
    /// Proves <see cref="SdToken{TEnvelope}.Equals(SdToken{TEnvelope}?)"/> and its
    /// <see cref="SdToken{TEnvelope}.Equals(object?)"/> override are exact-type: a same-valued subtype
    /// instance is unequal to a base instance through both overloads in both directions.
    /// </summary>
    [TestMethod]
    public void DerivedInstanceWithSameMembersIsNotEqualToBaseInstance()
    {
        using var baseToken = new SdToken<string>("issuer-signed", Array.Empty<SdDisclosure>());
        using var derived = new DerivedSdToken("issuer-signed");

        Assert.IsFalse(baseToken.Equals(derived));
        Assert.IsFalse(derived.Equals(baseToken));
        Assert.IsFalse(((object)baseToken).Equals(derived));
        Assert.IsFalse(((object)derived).Equals(baseToken));
    }


    /// <summary>
    /// Proves two same-typed, same-valued <see cref="SdToken{TEnvelope}"/> instances compare equal
    /// through both <see cref="SdToken{TEnvelope}.Equals(SdToken{TEnvelope}?)"/> and
    /// <see cref="SdToken{TEnvelope}.Equals(object?)"/>, in both comparison directions.
    /// </summary>
    [TestMethod]
    public void TwoBaseInstancesWithSameMembersAreEqual()
    {
        using var token1 = new SdToken<string>("issuer-signed", Array.Empty<SdDisclosure>());
        using var token2 = new SdToken<string>("issuer-signed", Array.Empty<SdDisclosure>());

        Assert.IsTrue(token1.Equals(token2));
        Assert.IsTrue(token2.Equals(token1));
        Assert.IsTrue(((object)token1).Equals(token2));
        Assert.IsTrue(((object)token2).Equals(token1));
    }
}
