using System;
using System.Globalization;

using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class ApduResultTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void SuccessResultHasCorrectState()
    {
        var result = ApduResult<int>.Success(42);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsFalse(result.IsCardError);
        Assert.IsFalse(result.IsTransportError);
        Assert.AreEqual(42, result.Value);
        Assert.AreEqual(StatusWord.Success, result.StatusWord);
    }

    [TestMethod]
    public void SuccessResultWithExplicitStatusWord()
    {
        var sw = StatusWord.FromValue(0x9000);
        var result = ApduResult<string>.Success("data", sw);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("data", result.Value);
        Assert.AreEqual(sw, result.StatusWord);
    }

    [TestMethod]
    public void CardErrorResultHasCorrectState()
    {
        var sw = StatusWord.FromValue(0x6A82);
        var result = ApduResult<int>.CardError(sw);

        Assert.IsFalse(result.IsSuccess);
        Assert.IsTrue(result.IsCardError);
        Assert.IsFalse(result.IsTransportError);
        Assert.AreEqual(sw, result.StatusWord);
    }

    [TestMethod]
    public void TransportErrorResultHasCorrectState()
    {
        var result = ApduResult<int>.TransportError(0x80100069);

        Assert.IsFalse(result.IsSuccess);
        Assert.IsFalse(result.IsCardError);
        Assert.IsTrue(result.IsTransportError);
        Assert.AreEqual(0x80100069u, result.TransportErrorCode);
    }

    [TestMethod]
    public void AccessingValueOnCardErrorThrows()
    {
        var result = ApduResult<int>.CardError(StatusWord.FromValue(0x6A82));

        Assert.ThrowsExactly<InvalidOperationException>(() => _ = result.Value);
    }

    [TestMethod]
    public void AccessingValueOnTransportErrorThrows()
    {
        var result = ApduResult<int>.TransportError(0x80100069);

        Assert.ThrowsExactly<InvalidOperationException>(() => _ = result.Value);
    }

    [TestMethod]
    public void AccessingStatusWordOnTransportErrorThrows()
    {
        var result = ApduResult<int>.TransportError(0x80100069);

        Assert.ThrowsExactly<InvalidOperationException>(() => _ = result.StatusWord);
    }

    [TestMethod]
    public void AccessingTransportErrorCodeOnSuccessThrows()
    {
        var result = ApduResult<int>.Success(42);

        Assert.ThrowsExactly<InvalidOperationException>(() => _ = result.TransportErrorCode);
    }

    [TestMethod]
    public void TryGetValueReturnsTrueOnSuccess()
    {
        var result = ApduResult<int>.Success(42);

        bool got = result.TryGetValue(out int value);

        Assert.IsTrue(got);
        Assert.AreEqual(42, value);
    }

    [TestMethod]
    public void TryGetValueReturnsFalseOnError()
    {
        var result = ApduResult<int>.CardError(StatusWord.FromValue(0x6A82));

        bool got = result.TryGetValue(out int value);

        Assert.IsFalse(got);
        Assert.AreEqual(0, value);
    }

    [TestMethod]
    public void MapTransformsSuccessValue()
    {
        var result = ApduResult<int>.Success(42);

        ApduResult<string> mapped = result.Map(static v => v.ToString(CultureInfo.InvariantCulture));

        Assert.IsTrue(mapped.IsSuccess);
        Assert.AreEqual("42", mapped.Value);
    }

    [TestMethod]
    public void MapPreservesCardError()
    {
        var sw = StatusWord.FromValue(0x6A82);
        var result = ApduResult<int>.CardError(sw);

        ApduResult<string> mapped = result.Map(static v => v.ToString(CultureInfo.InvariantCulture));

        Assert.IsTrue(mapped.IsCardError);
        Assert.AreEqual(sw, mapped.StatusWord);
    }

    [TestMethod]
    public void MapPreservesTransportError()
    {
        var result = ApduResult<int>.TransportError(0x80100069);

        ApduResult<string> mapped = result.Map(static v => v.ToString(CultureInfo.InvariantCulture));

        Assert.IsTrue(mapped.IsTransportError);
        Assert.AreEqual(0x80100069u, mapped.TransportErrorCode);
    }

    [TestMethod]
    public void MatchCallsCorrectBranch()
    {
        var successResult = ApduResult<int>.Success(42);
        var cardErrorResult = ApduResult<int>.CardError(StatusWord.FromValue(0x6A82));
        var transportErrorResult = ApduResult<int>.TransportError(0x80100069);

        string successText = successResult.Match(
            static (v, sw) => $"ok:{v}",
            static sw => $"card:0x{sw.Value:X4}",
            static code => $"transport:0x{code:X8}");

        string cardErrorText = cardErrorResult.Match(
            static (v, sw) => $"ok:{v}",
            static sw => $"card:0x{sw.Value:X4}",
            static code => $"transport:0x{code:X8}");

        string transportErrorText = transportErrorResult.Match(
            static (v, sw) => $"ok:{v}",
            static sw => $"card:0x{sw.Value:X4}",
            static code => $"transport:0x{code:X8}");

        Assert.AreEqual("ok:42", successText);
        Assert.AreEqual("card:0x6A82", cardErrorText);
        Assert.AreEqual("transport:0x80100069", transportErrorText);
    }

    [TestMethod]
    public void IsNotFoundClassifiesFileNotFound()
    {
        var result = ApduResult<int>.CardError(StatusWord.FromValue(0x6A82));

        Assert.IsTrue(result.IsNotFound);
    }

    [TestMethod]
    public void IsNotFoundClassifiesReferencedDataNotFound()
    {
        var result = ApduResult<int>.CardError(StatusWord.FromValue(0x6A88));

        Assert.IsTrue(result.IsNotFound);
    }

    [TestMethod]
    public void IsSecurityErrorClassifiesCorrectly()
    {
        var securityNotSatisfied = ApduResult<int>.CardError(StatusWord.FromValue(0x6982));
        var authBlocked = ApduResult<int>.CardError(StatusWord.FromValue(0x6983));

        Assert.IsTrue(securityNotSatisfied.IsSecurityError);
        Assert.IsTrue(authBlocked.IsSecurityError);
    }

    [TestMethod]
    public void IsRetryCounterWarningClassifiesCorrectly()
    {
        var result = ApduResult<int>.CardError(StatusWord.FromBytes(0x63, 0xC2));

        Assert.IsTrue(result.IsRetryCounterWarning);
        Assert.AreEqual(2, result.RemainingRetries);
    }

    [TestMethod]
    public void EqualityBetweenIdenticalSuccessResults()
    {
        var r1 = ApduResult<int>.Success(42);
        var r2 = ApduResult<int>.Success(42);

        Assert.AreEqual(r1, r2);
        Assert.IsTrue(r1 == r2);
    }

    [TestMethod]
    public void InequalityBetweenDifferentResults()
    {
        var success = ApduResult<int>.Success(42);
        var error = ApduResult<int>.CardError(StatusWord.FromValue(0x6A82));

        Assert.AreNotEqual(success, error);
        Assert.IsTrue(success != error);
    }

    [TestMethod]
    public void ToStringContainsMeaningfulInformation()
    {
        var result = ApduResult<int>.CardError(StatusWord.FromValue(0x6A82));

        string text = result.ToString();

        Assert.IsTrue(text.Contains("6A82", StringComparison.OrdinalIgnoreCase),
            "ToString should contain the hex status word value.");
    }
}
