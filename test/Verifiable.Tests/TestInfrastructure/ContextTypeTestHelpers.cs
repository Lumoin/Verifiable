namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Helpers for testing context types that follow the dynamic enum pattern.
/// </summary>
/// <remarks>
/// <para>
/// Context types (<see cref="Verifiable.Cryptography.Context.CryptoAlgorithm"/>,
/// <see cref="Verifiable.Cryptography.Context.Purpose"/>,
/// <see cref="Verifiable.Cryptography.Context.EncodingScheme"/>,
/// <see cref="Verifiable.Cryptography.Context.MaterialSemantics"/>) share a common
/// implementation pattern: readonly struct with integer code, static predefined values,
/// IEquatable implementation, operator overloads, and companion *Names class.
/// </para>
/// <para>
/// These helpers test the common contracts without duplicating assertion logic
/// across each type's test class.
/// </para>
/// </remarks>
public static class ContextTypeTestHelpers
{
    /// <summary>
    /// Tests IEquatable contract for two different values.
    /// </summary>
    /// <typeparam name="T">The context type being tested.</typeparam>
    /// <param name="value1">First value.</param>
    /// <param name="value2">Second value, must be different from first.</param>
    /// <param name="equalsOperator">The == operator as a delegate.</param>
    /// <param name="notEqualsOperator">The != operator as a delegate.</param>
    public static void AssertDifferentValuesAreNotEqual<T>(
        T value1,
        T value2,
        Func<T, T, bool> equalsOperator,
        Func<T, T, bool> notEqualsOperator)
        where T: IEquatable<T>
    {
        Assert.IsFalse(value1.Equals(value2), "Equals should return false for different values.");
        Assert.IsFalse(equalsOperator(value1, value2), "== operator should return false for different values.");
        Assert.IsTrue(notEqualsOperator(value1, value2), "!= operator should return true for different values.");
    }


    /// <summary>
    /// Tests IEquatable contract for same/equal values.
    /// </summary>
    /// <typeparam name="T">The context type being tested.</typeparam>
    /// <param name="value">The value to test.</param>
    /// <param name="equalsOperator">The == operator as a delegate.</param>
    /// <param name="notEqualsOperator">The != operator as a delegate.</param>
    public static void AssertSameValuesAreEqual<T>(
        T value,
        Func<T, T, bool> equalsOperator,
        Func<T, T, bool> notEqualsOperator)
        where T: IEquatable<T>
    {
        var duplicate = value;
        Assert.IsTrue(value.Equals(duplicate), "Equals should return true for same value.");
        Assert.IsTrue(equalsOperator(value, duplicate), "== operator should return true for same value.");
        Assert.IsFalse(notEqualsOperator(value, duplicate), "!= operator should return false for same value.");
    }


    /// <summary>
    /// Tests object equality operators work correctly.
    /// </summary>
    /// <typeparam name="T">The context type being tested.</typeparam>
    /// <param name="value">The value to test.</param>
    /// <param name="typeEqualsObject">The T == object operator as a delegate.</param>
    /// <param name="objectEqualsType">The object == T operator as a delegate.</param>
    /// <param name="typeNotEqualsObject">The T != object operator as a delegate.</param>
    /// <param name="objectNotEqualsType">The object != T operator as a delegate.</param>
    public static void AssertObjectEqualityWorks<T>(
        T value,
        Func<T, object, bool> typeEqualsObject,
        Func<object, T, bool> objectEqualsType,
        Func<T, object, bool> typeNotEqualsObject,
        Func<object, T, bool> objectNotEqualsType)
        where T: IEquatable<T>
    {
        object valueAsObject = value!;
        Assert.IsTrue(value.Equals(valueAsObject), "Equals(object) should return true for boxed same value.");
        Assert.IsTrue(typeEqualsObject(value, valueAsObject), "T == object should return true for same value.");
        Assert.IsTrue(objectEqualsType(valueAsObject, value), "object == T should return true for same value.");
        Assert.IsFalse(typeNotEqualsObject(value, valueAsObject), "T != object should return false for same value.");
        Assert.IsFalse(objectNotEqualsType(valueAsObject, value), "object != T should return false for same value.");
    }


    /// <summary>
    /// Tests object inequality operators work correctly for different values.
    /// </summary>
    /// <typeparam name="T">The context type being tested.</typeparam>
    /// <param name="value1">First value.</param>
    /// <param name="value2">Second value, must be different from first.</param>
    /// <param name="typeEqualsObject">The T == object operator as a delegate.</param>
    /// <param name="objectEqualsType">The object == T operator as a delegate.</param>
    /// <param name="typeNotEqualsObject">The T != object operator as a delegate.</param>
    /// <param name="objectNotEqualsType">The object != T operator as a delegate.</param>
    public static void AssertObjectInequalityWorks<T>(
        T value1,
        T value2,
        Func<T, object, bool> typeEqualsObject,
        Func<object, T, bool> objectEqualsType,
        Func<T, object, bool> typeNotEqualsObject,
        Func<object, T, bool> objectNotEqualsType)
        where T: IEquatable<T>
    {
        object value2AsObject = value2!;
        Assert.IsFalse(typeEqualsObject(value1, value2AsObject), "T == object should return false for different values.");
        Assert.IsFalse(objectEqualsType(value2AsObject, value1), "object == T should return false for different values.");
        Assert.IsTrue(typeNotEqualsObject(value1, value2AsObject), "T != object should return true for different values.");
        Assert.IsTrue(objectNotEqualsType(value2AsObject, value1), "object != T should return true for different values.");
    }


    /// <summary>
    /// Tests Equals returns false for null and different types.
    /// </summary>
    /// <typeparam name="T">The context type being tested.</typeparam>
    /// <param name="value">The value to test.</param>
    public static void AssertEqualsHandlesNullAndDifferentTypes<T>(T value) where T: IEquatable<T>
    {
        Assert.IsFalse(value.Equals(null), "Equals(null) should return false.");
        Assert.IsFalse(value.Equals(new object()), "Equals(different type) should return false.");
    }


    /// <summary>
    /// Tests GetHashCode contract - equal values must have equal hash codes.
    /// </summary>
    /// <typeparam name="T">The context type being tested.</typeparam>
    /// <param name="value">The value to test.</param>
    public static void AssertHashCodeContractForEqualValues<T>(T value) where T: IEquatable<T>
    {
        var duplicate = value;
        Assert.AreEqual(value!.GetHashCode(), duplicate!.GetHashCode(), "Equal values must have equal hash codes.");
    }


    /// <summary>
    /// Tests that different values have different hash codes.
    /// </summary>
    /// <remarks>
    /// Not strictly required by GetHashCode contract, but expected for good distribution.
    /// </remarks>
    /// <typeparam name="T">The context type being tested.</typeparam>
    /// <param name="value1">First value.</param>
    /// <param name="value2">Second value, must be different from first.</param>
    public static void AssertHashCodesAreDistinct<T>(T value1, T value2) where T: IEquatable<T>
    {
        Assert.AreNotEqual(value1!.GetHashCode(), value2!.GetHashCode(), "Different values should have different hash codes.");
    }


    /// <summary>
    /// Tests ToString returns the expected name.
    /// </summary>
    /// <remarks>
    /// This validates DebuggerDisplay effectiveness since ToString is typically
    /// used in the DebuggerDisplay attribute.
    /// </remarks>
    /// <typeparam name="T">The context type being tested.</typeparam>
    /// <param name="value">The value to test.</param>
    /// <param name="expectedName">The expected name from ToString.</param>
    public static void AssertToStringReturnsExpectedName<T>(T value, string expectedName)
    {
        var result = value!.ToString();
        Assert.IsNotNull(result, "ToString should not return null.");
        Assert.AreEqual(expectedName, result, "ToString should return the expected name.");
    }


    /// <summary>
    /// Tests *Names helper returns expected name for known code.
    /// </summary>
    /// <param name="getName">The GetName method from the *Names class.</param>
    /// <param name="code">The numeric code to look up.</param>
    /// <param name="expectedName">The expected name.</param>
    public static void AssertNamesReturnsExpected(Func<int, string> getName, int code, string expectedName)
    {
        Assert.AreEqual(expectedName, getName(code), $"GetName({code}) should return '{expectedName}'.");
    }


    /// <summary>
    /// Tests *Names helper returns "Custom (code)" format for unknown codes.
    /// </summary>
    /// <param name="getName">The GetName method from the *Names class.</param>
    /// <param name="unknownCode">A code that is not predefined.</param>
    public static void AssertNamesReturnsCustomForUnknown(Func<int, string> getName, int unknownCode)
    {
        var name = getName(unknownCode);
        Assert.StartsWith("Custom", name, $"Expected 'Custom' prefix for unknown code but got '{name}'.");
        Assert.Contains(unknownCode.ToString(), name, StringComparison.Ordinal, $"Expected name to contain code {unknownCode}.");
    }


    /// <summary>
    /// Tests the collection property contains all expected values.
    /// </summary>
    /// <typeparam name="T">The context type being tested.</typeparam>
    /// <param name="collection">The collection from the type's static property.</param>
    /// <param name="expectedValues">All values that should be in the collection.</param>
    public static void AssertCollectionContainsAllValues<T>(IReadOnlyList<T> collection, params T[] expectedValues)
    {
        var list = collection.ToList();
        foreach(var expected in expectedValues)
        {
            CollectionAssert.Contains(list, expected, $"Collection should contain {expected}.");
        }
    }


    /// <summary>
    /// Tests the collection property has the expected count.
    /// </summary>
    /// <typeparam name="T">The context type being tested.</typeparam>
    /// <param name="collection">The collection from the type's static property.</param>
    /// <param name="expectedCount">The expected number of elements.</param>
    public static void AssertCollectionHasExpectedCount<T>(IReadOnlyList<T> collection, int expectedCount)
    {
        Assert.HasCount(expectedCount, collection, $"Collection should have {expectedCount} elements.");
    }
}