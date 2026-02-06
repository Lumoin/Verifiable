using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography.Context;

/// <summary>
/// Tests for <see cref="MaterialSemantics"/> and <see cref="MaterialSemanticsNames"/>.
/// </summary>
[TestClass]
internal sealed class MaterialSemanticsTests
{
    //Constants using nameof to tie test expectations to actual property names.
    private const string DirectName = nameof(MaterialSemantics.Direct);
    private const string TpmHandleName = nameof(MaterialSemantics.TpmHandle);

    private const int DirectCode = 0;
    private const int TpmHandleCode = 1;

    //Arbitrary code that does not conflict with predefined values.
    private const int UnknownCode = 9999;


    /// <summary>
    /// All predefined MaterialSemantics values with their expected names and codes.
    /// </summary>
    /// <remarks>
    /// Explicit enumeration ensures test updates when values are added or removed.
    /// </remarks>
    public static IEnumerable<object[]> GetAllValues()
    {
        yield return new object[] { MaterialSemantics.Direct, DirectName, DirectCode };
        yield return new object[] { MaterialSemantics.TpmHandle, TpmHandleName, TpmHandleCode };
    }


    /// <summary>
    /// Pairs of different values for inequality testing.
    /// </summary>
    public static IEnumerable<object[]> GetDistinctValuePairs()
    {
        yield return new object[] { MaterialSemantics.Direct, MaterialSemantics.TpmHandle };
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void ToStringReturnsExpectedName(MaterialSemantics value, string expectedName, int _)
    {
        ContextTypeTestHelpers.AssertToStringReturnsExpectedName(value, expectedName);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void NamesGetNameReturnsExpectedValue(MaterialSemantics _, string expectedName, int code)
    {
        ContextTypeTestHelpers.AssertNamesReturnsExpected(MaterialSemanticsNames.GetName, code, expectedName);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void NamesGetNameWithInstanceReturnsExpectedValue(MaterialSemantics value, string expectedName, int _)
    {
        Assert.AreEqual(expectedName, MaterialSemanticsNames.GetName(value));
    }


    [TestMethod]
    public void NamesGetNameReturnsCustomForUnknownCode()
    {
        ContextTypeTestHelpers.AssertNamesReturnsCustomForUnknown(MaterialSemanticsNames.GetName, UnknownCode);
    }


    [TestMethod]
    [DynamicData(nameof(GetDistinctValuePairs))]
    public void DifferentValuesAreNotEqual(MaterialSemantics value1, MaterialSemantics value2)
    {
        ContextTypeTestHelpers.AssertDifferentValuesAreNotEqual(
            value1,
            value2,
            static (a, b) => a == b,
            static (a, b) => a != b);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void SameValuesAreEqual(MaterialSemantics value, string _, int __)
    {
        ContextTypeTestHelpers.AssertSameValuesAreEqual(
            value,
            static (a, b) => a == b,
            static (a, b) => a != b);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void ObjectEqualityWorksForSameValue(MaterialSemantics value, string _, int __)
    {
        ContextTypeTestHelpers.AssertObjectEqualityWorks(
            value,
            static (a, b) => a == b,
            static (a, b) => a == b,
            static (a, b) => a != b,
            static (a, b) => a != b);
    }


    [TestMethod]
    [DynamicData(nameof(GetDistinctValuePairs))]
    public void ObjectInequalityWorksForDifferentValues(MaterialSemantics value1, MaterialSemantics value2)
    {
        ContextTypeTestHelpers.AssertObjectInequalityWorks(
            value1,
            value2,
            static (a, b) => a == b,
            static (a, b) => a == b,
            static (a, b) => a != b,
            static (a, b) => a != b);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void EqualsHandlesNullAndDifferentTypes(MaterialSemantics value, string _, int __)
    {
        ContextTypeTestHelpers.AssertEqualsHandlesNullAndDifferentTypes(value);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void HashCodeContractForEqualValues(MaterialSemantics value, string _, int __)
    {
        ContextTypeTestHelpers.AssertHashCodeContractForEqualValues(value);
    }


    [TestMethod]
    [DynamicData(nameof(GetDistinctValuePairs))]
    public void HashCodesAreDistinctForDifferentValues(MaterialSemantics value1, MaterialSemantics value2)
    {
        ContextTypeTestHelpers.AssertHashCodesAreDistinct(value1, value2);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void CodePropertyReturnsExpectedValue(MaterialSemantics value, string _, int expectedCode)
    {
        Assert.AreEqual(expectedCode, value.Code);
    }


    [TestMethod]
    public void SemanticsCollectionContainsAllPredefinedValues()
    {
        ContextTypeTestHelpers.AssertCollectionContainsAllValues(
            MaterialSemantics.Semantics,
            MaterialSemantics.Direct,
            MaterialSemantics.TpmHandle);
    }


    [TestMethod]
    public void SemanticsCollectionHasExpectedCount()
    {
        //Two predefined values: Direct and TpmHandle.
        ContextTypeTestHelpers.AssertCollectionHasExpectedCount(MaterialSemantics.Semantics, 2);
    }
}