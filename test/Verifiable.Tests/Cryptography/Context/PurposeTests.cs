using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography.Context;

/// <summary>
/// Tests for <see cref="Purpose"/> and <see cref="PurposeNames"/>.
/// </summary>
[TestClass]
public sealed class PurposeTests
{
    //Constants using nameof to tie test expectations to actual property names.
    private const string NoneName = nameof(Purpose.None);
    private const string VerificationName = nameof(Purpose.Verification);
    private const string SigningName = nameof(Purpose.Signing);
    private const string ExchangeName = nameof(Purpose.Exchange);
    private const string WrappedName = nameof(Purpose.Wrapped);
    private const string SignatureName = nameof(Purpose.Signature);
    private const string EncryptionName = nameof(Purpose.Encryption);

    private const int NoneCode = 0;
    private const int VerificationCode = 1;
    private const int SigningCode = 2;
    private const int ExchangeCode = 3;
    private const int WrappedCode = 4;
    private const int SignatureCode = 5;
    private const int EncryptionCode = 6;

    //Arbitrary code that does not conflict with predefined values.
    private const int UnknownCode = 9999;


    /// <summary>
    /// All predefined Purpose values with their expected names and codes.
    /// </summary>
    /// <remarks>
    /// Explicit enumeration ensures test updates when values are added or removed.
    /// </remarks>
    public static IEnumerable<object[]> GetAllValues()
    {
        yield return new object[] { Purpose.None, NoneName, NoneCode };
        yield return new object[] { Purpose.Verification, VerificationName, VerificationCode };
        yield return new object[] { Purpose.Signing, SigningName, SigningCode };
        yield return new object[] { Purpose.Exchange, ExchangeName, ExchangeCode };
        yield return new object[] { Purpose.Wrapped, WrappedName, WrappedCode };
        yield return new object[] { Purpose.Signature, SignatureName, SignatureCode };
        yield return new object[] { Purpose.Encryption, EncryptionName, EncryptionCode };
    }


    /// <summary>
    /// Pairs of different values for inequality testing.
    /// </summary>
    public static IEnumerable<object[]> GetDistinctValuePairs()
    {
        yield return new object[] { Purpose.Verification, Purpose.Signing };
        yield return new object[] { Purpose.Exchange, Purpose.Encryption };
        yield return new object[] { Purpose.None, Purpose.Wrapped };
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void ToStringReturnsExpectedName(Purpose value, string expectedName, int _)
    {
        ContextTypeTestHelpers.AssertToStringReturnsExpectedName(value, expectedName);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void NamesGetNameReturnsExpectedValue(Purpose _, string expectedName, int code)
    {
        ContextTypeTestHelpers.AssertNamesReturnsExpected(PurposeNames.GetName, code, expectedName);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void NamesGetNameWithInstanceReturnsExpectedValue(Purpose value, string expectedName, int _)
    {
        Assert.AreEqual(expectedName, PurposeNames.GetName(value));
    }


    [TestMethod]
    public void NamesGetNameReturnsCustomForUnknownCode()
    {
        ContextTypeTestHelpers.AssertNamesReturnsCustomForUnknown(PurposeNames.GetName, UnknownCode);
    }


    [TestMethod]
    [DynamicData(nameof(GetDistinctValuePairs))]
    public void DifferentValuesAreNotEqual(Purpose value1, Purpose value2)
    {
        ContextTypeTestHelpers.AssertDifferentValuesAreNotEqual(
            value1,
            value2,
            static (a, b) => a == b,
            static (a, b) => a != b);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void SameValuesAreEqual(Purpose value, string _, int __)
    {
        ContextTypeTestHelpers.AssertSameValuesAreEqual(
            value,
            static (a, b) => a == b,
            static (a, b) => a != b);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void ObjectEqualityWorksForSameValue(Purpose value, string _, int __)
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
    public void ObjectInequalityWorksForDifferentValues(Purpose value1, Purpose value2)
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
    public void EqualsHandlesNullAndDifferentTypes(Purpose value, string _, int __)
    {
        ContextTypeTestHelpers.AssertEqualsHandlesNullAndDifferentTypes(value);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void HashCodeContractForEqualValues(Purpose value, string _, int __)
    {
        ContextTypeTestHelpers.AssertHashCodeContractForEqualValues(value);
    }


    [TestMethod]
    [DynamicData(nameof(GetDistinctValuePairs))]
    public void HashCodesAreDistinctForDifferentValues(Purpose value1, Purpose value2)
    {
        ContextTypeTestHelpers.AssertHashCodesAreDistinct(value1, value2);
    }


    [TestMethod]
    [DynamicData(nameof(GetAllValues))]
    public void CodePropertyReturnsExpectedValue(Purpose value, string _, int expectedCode)
    {
        Assert.AreEqual(expectedCode, value.Code);
    }


    [TestMethod]
    public void PurposesCollectionContainsAllPredefinedValues()
    {
        ContextTypeTestHelpers.AssertCollectionContainsAllValues(
            Purpose.Purposes,
            Purpose.None,
            Purpose.Verification,
            Purpose.Signing,
            Purpose.Exchange,
            Purpose.Wrapped,
            Purpose.Signature,
            Purpose.Encryption);
    }


    [TestMethod]
    public void PurposesCollectionHasExpectedCount()
    {
        //Seven predefined values.
        ContextTypeTestHelpers.AssertCollectionHasExpectedCount(Purpose.Purposes, 12);
    }
}