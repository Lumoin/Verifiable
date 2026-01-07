using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography.Context;

/// <summary>
/// Tests for <see cref="EncodingScheme"/> and <see cref="EncodingSchemeNames"/>.
/// </summary>
[TestClass]
public sealed class EncodingSchemeTests
{
    //Constants using nameof to tie test expectations to actual property names.
    private const string DerName = nameof(EncodingScheme.Der);
    private const string PemName = nameof(EncodingScheme.Pem);
    private const string EcCompressedName = nameof(EncodingScheme.EcCompressed);
    private const string EcUncompressedName = nameof(EncodingScheme.EcUncompressed);
    private const string Pkcs1Name = nameof(EncodingScheme.Pkcs1);
    private const string Pkcs8Name = nameof(EncodingScheme.Pkcs8);
    private const string RawName = nameof(EncodingScheme.Raw);

    private const int DerCode = 0;
    private const int PemCode = 1;
    private const int EcCompressedCode = 2;
    private const int EcUncompressedCode = 3;
    private const int Pkcs1Code = 4;
    private const int Pkcs8Code = 5;
    private const int RawCode = 6;

    //Arbitrary code that does not conflict with predefined values.
    private const int UnknownCode = 9999;


    /// <summary>
    /// All predefined EncodingScheme values with their expected names and codes.
    /// </summary>
    /// <remarks>
    /// Explicit enumeration ensures test updates when values are added or removed.
    /// </remarks>
    public static IEnumerable<object[]> GetAllValues()
    {
        yield return new object[] { EncodingScheme.Der, DerName, DerCode };
        yield return new object[] { EncodingScheme.Pem, PemName, PemCode };
        yield return new object[] { EncodingScheme.EcCompressed, EcCompressedName, EcCompressedCode };
        yield return new object[] { EncodingScheme.EcUncompressed, EcUncompressedName, EcUncompressedCode };
        yield return new object[] { EncodingScheme.Pkcs1, Pkcs1Name, Pkcs1Code };
        yield return new object[] { EncodingScheme.Pkcs8, Pkcs8Name, Pkcs8Code };
        yield return new object[] { EncodingScheme.Raw, RawName, RawCode };
    }


    /// <summary>
    /// Pairs of different values for inequality testing.
    /// </summary>
    public static IEnumerable<object[]> GetDistinctValuePairs()
    {
        yield return new object[] { EncodingScheme.Der, EncodingScheme.Pem };
        yield return new object[] { EncodingScheme.EcCompressed, EncodingScheme.EcUncompressed };
        yield return new object[] { EncodingScheme.Pkcs1, EncodingScheme.Pkcs8 };
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void ToStringReturnsExpectedName(EncodingScheme value, string expectedName, int _)
    {
        ContextTypeTestHelpers.AssertToStringReturnsExpectedName(value, expectedName);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void NamesGetNameReturnsExpectedValue(EncodingScheme _, string expectedName, int code)
    {
        ContextTypeTestHelpers.AssertNamesReturnsExpected(EncodingSchemeNames.GetName, code, expectedName);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void NamesGetNameWithInstanceReturnsExpectedValue(EncodingScheme value, string expectedName, int _)
    {
        Assert.AreEqual(expectedName, EncodingSchemeNames.GetName(value));
    }


    [TestMethod]
    public void NamesGetNameReturnsCustomForUnknownCode()
    {
        ContextTypeTestHelpers.AssertNamesReturnsCustomForUnknown(EncodingSchemeNames.GetName, UnknownCode);
    }


    [TestMethod]
    [DynamicData(nameof(GetDistinctValuePairs))]
    public void DifferentValuesAreNotEqual(EncodingScheme value1, EncodingScheme value2)
    {
        ContextTypeTestHelpers.AssertDifferentValuesAreNotEqual(
            value1,
            value2,
            static (a, b) => a == b,
            static (a, b) => a != b);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void SameValuesAreEqual(EncodingScheme value, string _, int __)
    {
        ContextTypeTestHelpers.AssertSameValuesAreEqual(
            value,
            static (a, b) => a == b,
            static (a, b) => a != b);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void ObjectEqualityWorksForSameValue(EncodingScheme value, string _, int __)
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
    public void ObjectInequalityWorksForDifferentValues(EncodingScheme value1, EncodingScheme value2)
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
    public void EqualsHandlesNullAndDifferentTypes(EncodingScheme value, string _, int __)
    {
        ContextTypeTestHelpers.AssertEqualsHandlesNullAndDifferentTypes(value);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void HashCodeContractForEqualValues(EncodingScheme value, string _, int __)
    {
        ContextTypeTestHelpers.AssertHashCodeContractForEqualValues(value);
    }


    [TestMethod]
    [DynamicData(nameof(GetDistinctValuePairs))]
    public void HashCodesAreDistinctForDifferentValues(EncodingScheme value1, EncodingScheme value2)
    {
        ContextTypeTestHelpers.AssertHashCodesAreDistinct(value1, value2);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void SchemePropertyReturnsExpectedValue(EncodingScheme value, string _, int expectedCode)
    {
        Assert.AreEqual(expectedCode, value.Scheme);
    }


    [TestMethod]
    public void SchemesCollectionContainsAllPredefinedValues()
    {
        ContextTypeTestHelpers.AssertCollectionContainsAllValues(
            EncodingScheme.Schemes,
            EncodingScheme.Der,
            EncodingScheme.Pem,
            EncodingScheme.EcCompressed,
            EncodingScheme.EcUncompressed,
            EncodingScheme.Pkcs1,
            EncodingScheme.Pkcs8,
            EncodingScheme.Raw);
    }


    [TestMethod]
    public void SchemesCollectionHasExpectedCount()
    {
        //Seven predefined values.
        ContextTypeTestHelpers.AssertCollectionHasExpectedCount(EncodingScheme.Schemes, 7);
    }
}