using Verifiable.Core;

namespace Verifiable.Tests;

/// <summary>
/// Tests for <see cref="Result{TValue, TError}"/> <see cref="IEquatable{T}"/> implementation.
/// </summary>
[TestClass]
public sealed class ResultEqualityTests
{
    /// <summary>
    /// Success result with value "value1".
    /// </summary>
    private static Result<string, string> SuccessResult1 { get; } = Result.Success<string, string>("value1");

    /// <summary>
    /// Success result with value "value2".
    /// </summary>
    private static Result<string, string> SuccessResult2 { get; } = Result.Success<string, string>("value2");

    /// <summary>
    /// Failure result with error "error1".
    /// </summary>
    private static Result<string, string> FailureResult1 { get; } = Result.Failure<string, string>("error1");

    /// <summary>
    /// Failure result with error "error2".
    /// </summary>
    private static Result<string, string> FailureResult2 { get; } = Result.Failure<string, string>("error2");


    [TestMethod]
    public void SuccessResultsWithSameValueAreEqual()
    {
        var result1 = Result.Success<string, string>("test");
        var result2 = Result.Success<string, string>("test");

        Assert.IsTrue(result1.Equals(result2));
        Assert.IsTrue(result1 == result2);
        Assert.IsFalse(result1 != result2);
    }


    [TestMethod]
    public void SuccessResultsWithDifferentValuesAreNotEqual()
    {
        Assert.IsFalse(SuccessResult1.Equals(SuccessResult2));
        Assert.IsFalse(SuccessResult1 == SuccessResult2);
        Assert.IsTrue(SuccessResult1 != SuccessResult2);
    }


    [TestMethod]
    public void FailureResultsWithSameErrorAreEqual()
    {
        var result1 = Result.Failure<string, string>("error");
        var result2 = Result.Failure<string, string>("error");

        Assert.IsTrue(result1.Equals(result2));
        Assert.IsTrue(result1 == result2);
        Assert.IsFalse(result1 != result2);
    }


    [TestMethod]
    public void FailureResultsWithDifferentErrorsAreNotEqual()
    {
        Assert.IsFalse(FailureResult1.Equals(FailureResult2));
        Assert.IsFalse(FailureResult1 == FailureResult2);
        Assert.IsTrue(FailureResult1 != FailureResult2);
    }


    [TestMethod]
    public void SuccessAndFailureResultsAreNotEqual()
    {
        Assert.IsFalse(SuccessResult1.Equals(FailureResult1));
        Assert.IsFalse(SuccessResult1 == FailureResult1);
        Assert.IsTrue(SuccessResult1 != FailureResult1);
    }


    [TestMethod]
    public void EqualsWithObjectOfSameTypeSucceeds()
    {
        object resultAsObject = Result.Success<string, string>("value1");

        Assert.IsTrue(SuccessResult1.Equals(resultAsObject));
    }


    [TestMethod]
    public void EqualsWithDifferentTypeReturnsFalse()
    {
        object differentType = new object();

        Assert.IsFalse(SuccessResult1.Equals(differentType));
    }


    [TestMethod]
    public void EqualsWithNullReturnsFalse()
    {
        object? nullObject = null;

        Assert.IsFalse(SuccessResult1.Equals(nullObject));
    }


    [TestMethod]
    public void GetHashCodeIsSameForEqualResults()
    {
        var result1 = Result.Success<string, string>("test");
        var result2 = Result.Success<string, string>("test");

        Assert.AreEqual(result1.GetHashCode(), result2.GetHashCode());
    }


    [TestMethod]
    public void GetHashCodeDiffersForDifferentResults()
    {
        var hash1 = SuccessResult1.GetHashCode();
        var hash2 = SuccessResult2.GetHashCode();
        var hash3 = FailureResult1.GetHashCode();

        Assert.AreNotEqual(hash1, hash2);
        Assert.AreNotEqual(hash1, hash3);
    }


    [TestMethod]
    public void ImplicitConversionCreatesSuccessResult()
    {
        Result<string, string> result = "implicitValue";

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("implicitValue", result.Value);
    }


    [TestMethod]
    public void ResultWithIntValueTypeWorksCorrectly()
    {
        var success = Result.Success<int, string>(42);
        var failure = Result.Failure<int, string>("error");

        Assert.IsTrue(success.IsSuccess);
        Assert.AreEqual(42, success.Value);
        Assert.IsFalse(failure.IsSuccess);
        Assert.AreEqual("error", failure.Error);
    }


    [TestMethod]
    public void ResultWithComplexTypesWorksCorrectly()
    {
        var list = new List<int> { 1, 2, 3 };
        var success = Result.Success<List<int>, Exception>(list);

        Assert.IsTrue(success.IsSuccess);
        Assert.AreSame(list, success.Value);
    }


    [TestMethod]
    public void MatchExecutesCorrectBranchForSuccess()
    {
        var result = Result.Success<string, string>("value");

        string output = result.Match(
            v => $"Success: {v}",
            e => $"Failure: {e}");

        Assert.AreEqual("Success: value", output);
    }


    [TestMethod]
    public void MatchExecutesCorrectBranchForFailure()
    {
        var result = Result.Failure<string, string>("error");

        string output = result.Match(
            v => $"Success: {v}",
            e => $"Failure: {e}");

        Assert.AreEqual("Failure: error", output);
    }


    [TestMethod]
    public void MapTransformsSuccessValue()
    {
        var result = Result.Success<int, string>(5);

        var mapped = result.Map(x => x * 2);

        Assert.IsTrue(mapped.IsSuccess);
        Assert.AreEqual(10, mapped.Value);
    }


    [TestMethod]
    public void MapPreservesFailure()
    {
        var result = Result.Failure<int, string>("error");

        var mapped = result.Map(x => x * 2);

        Assert.IsFalse(mapped.IsSuccess);
        Assert.AreEqual("error", mapped.Error);
    }


    [TestMethod]
    public void BindChainsSuccessfulOperations()
    {
        var result = Result.Success<int, string>(5);

        var bound = result.Bind(x => Result.Success<int, string>(x * 2));

        Assert.IsTrue(bound.IsSuccess);
        Assert.AreEqual(10, bound.Value);
    }


    [TestMethod]
    public void BindShortCircuitsOnFailure()
    {
        var result = Result.Failure<int, string>("initial error");

        var bound = result.Bind(x => Result.Success<int, string>(x * 2));

        Assert.IsFalse(bound.IsSuccess);
        Assert.AreEqual("initial error", bound.Error);
    }


    [TestMethod]
    public void BindPropagatesFailureFromChainedOperation()
    {
        var result = Result.Success<int, string>(5);

        var bound = result.Bind(x => Result.Failure<int, string>("chained error"));

        Assert.IsFalse(bound.IsSuccess);
        Assert.AreEqual("chained error", bound.Error);
    }
}