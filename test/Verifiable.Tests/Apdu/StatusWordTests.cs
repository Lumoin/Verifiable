using System;

using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class StatusWordTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void SuccessIsCorrectValue()
    {
        Assert.AreEqual((ushort)0x9000, StatusWord.Success.Value);
        Assert.IsTrue(StatusWord.Success.IsSuccess);
    }

    [TestMethod]
    public void FromValueCreatesMatchingInstance()
    {
        StatusWord sw = StatusWord.FromValue(0x9000);

        Assert.AreEqual(StatusWord.Success, sw);
        Assert.IsTrue(sw.IsSuccess);
    }

    [TestMethod]
    public void FromBytesCreatesMatchingInstance()
    {
        StatusWord sw = StatusWord.FromBytes(0x90, 0x00);

        Assert.AreEqual(StatusWord.Success, sw);
    }

    [TestMethod]
    public void Sw1Sw2DecompositionIsCorrect()
    {
        StatusWord sw = StatusWord.FromValue(0x6A82);

        Assert.AreEqual((byte)0x6A, sw.Sw1);
        Assert.AreEqual((byte)0x82, sw.Sw2);
    }

    [TestMethod]
    public void MoreDataAvailableDetectedFromWireValue()
    {
        StatusWord sw = StatusWord.FromValue(0x6110);

        Assert.IsTrue(sw.IsMoreDataAvailable);
        Assert.AreEqual((byte)0x10, sw.BytesAvailable);
    }

    [TestMethod]
    public void WrongLeWithCorrectionDetected()
    {
        StatusWord sw = StatusWord.FromValue(0x6C05);

        Assert.IsTrue(sw.IsWrongLeWithCorrection);
        Assert.AreEqual((byte)0x05, sw.CorrectLe);
    }

    [TestMethod]
    public void RetryCounterWarningExtractsCount()
    {
        StatusWord sw = StatusWord.FromValue(0x63C2);

        Assert.IsTrue(sw.IsRetryCounterWarning);
        Assert.AreEqual(2, sw.RetryCount);
    }

    [TestMethod]
    public void RetryCounterZeroMeansLastAttempt()
    {
        StatusWord sw = StatusWord.FromValue(0x63C0);

        Assert.IsTrue(sw.IsRetryCounterWarning);
        Assert.AreEqual(0, sw.RetryCount);
    }

    [TestMethod]
    public void FileNotFoundClassification()
    {
        Assert.IsTrue(StatusWord.FileNotFound.IsFileOrAppNotFound);
        Assert.IsTrue(StatusWord.FileNotFound.IsCheckingError);
        Assert.IsFalse(StatusWord.FileNotFound.IsSuccess);
    }

    [TestMethod]
    public void WrongDataClassification()
    {
        Assert.IsTrue(StatusWord.WrongData.IsWrongData);
        Assert.AreEqual((ushort)0x6A80, StatusWord.WrongData.Value);
    }

    [TestMethod]
    public void IncorrectP1P2Classification()
    {
        Assert.IsTrue(StatusWord.IncorrectP1P2.IsIncorrectP1P2);
        Assert.AreEqual((ushort)0x6A86, StatusWord.IncorrectP1P2.Value);
    }

    [TestMethod]
    public void LogicalChannelNotSupportedClassification()
    {
        Assert.IsTrue(StatusWord.LogicalChannelNotSupported.IsLogicalChannelNotSupported);
        Assert.AreEqual((ushort)0x6881, StatusWord.LogicalChannelNotSupported.Value);
    }

    [TestMethod]
    public void SecurityNotSatisfiedClassification()
    {
        Assert.IsTrue(StatusWord.SecurityNotSatisfied.IsSecurityStatusNotSatisfied);
    }

    [TestMethod]
    public void AuthenticationBlockedClassification()
    {
        Assert.IsTrue(StatusWord.AuthenticationBlocked.IsAuthenticationMethodBlocked);
    }

    [TestMethod]
    public void InstructionNotSupportedClassification()
    {
        Assert.IsTrue(StatusWord.InstructionNotSupported.IsInstructionNotSupported);
    }

    [TestMethod]
    public void WarningRangeDetected()
    {
        StatusWord sw62 = StatusWord.FromValue(0x6200);
        StatusWord sw63 = StatusWord.FromValue(0x6300);

        Assert.IsTrue(sw62.IsWarning);
        Assert.IsTrue(sw63.IsWarning);
    }

    [TestMethod]
    public void ExecutionErrorRangeDetected()
    {
        StatusWord sw64 = StatusWord.FromValue(0x6400);
        StatusWord sw66 = StatusWord.FromValue(0x6600);

        Assert.IsTrue(sw64.IsExecutionError);
        Assert.IsTrue(sw66.IsExecutionError);
    }

    [TestMethod]
    public void CheckingErrorRangeDetected()
    {
        StatusWord sw67 = StatusWord.FromValue(0x6700);
        StatusWord sw6f = StatusWord.FromValue(0x6F00);

        Assert.IsTrue(sw67.IsCheckingError);
        Assert.IsTrue(sw6f.IsCheckingError);
    }

    [TestMethod]
    public void EqualityBetweenRegisteredAndWireValues()
    {
        StatusWord fromWire = StatusWord.FromValue(0x6A82);

        Assert.AreEqual(StatusWord.FileNotFound, fromWire);
        Assert.IsTrue(fromWire == StatusWord.FileNotFound);
    }

    [TestMethod]
    public void InequalityBetweenDifferentValues()
    {
        Assert.AreNotEqual(StatusWord.Success, StatusWord.FileNotFound);
        Assert.IsTrue(StatusWord.Success != StatusWord.FileNotFound);
    }

    [TestMethod]
    public void ToStringIncludesHexValue()
    {
        string name = StatusWord.Success.ToString();

        Assert.Contains("0x9000", name, $"Expected hex value in '{name}'.");
        Assert.Contains("Success", name, $"Expected 'Success' in '{name}'.");
    }

    [TestMethod]
    public void NameForMoreDataAvailableIncludesByteCount()
    {
        StatusWord sw = StatusWord.FromValue(0x6120);
        string name = StatusWordNames.GetName(sw);

        Assert.Contains("32", name, $"Expected byte count 32 in '{name}'.");
        Assert.Contains("More data", name, $"Expected 'More data' in '{name}'.");
    }

    [TestMethod]
    public void NameForRetryCounterIncludesCount()
    {
        StatusWord sw = StatusWord.FromValue(0x63C3);
        string name = StatusWordNames.GetName(sw);

        Assert.Contains("3 remaining", name, $"Expected '3 remaining' in '{name}'.");
    }

    [TestMethod]
    public void NameForUnknownValueIncludesHex()
    {
        StatusWord sw = StatusWord.FromValue(0x1234);
        string name = StatusWordNames.GetName(sw);

        Assert.Contains("0x1234", name, $"Expected hex in '{name}'.");
    }

    [TestMethod]
    public void CreateRegistersVendorCode()
    {
        StatusWord vendorSw = StatusWord.Create(0xFF01, "Vendor test status.");

        Assert.AreEqual((ushort)0xFF01, vendorSw.Value);

        string name = StatusWordNames.GetName(vendorSw);
        Assert.Contains("Vendor test status", name, $"Expected vendor name in '{name}'.");
    }

    [TestMethod]
    public void CreateThrowsOnDuplicate()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            StatusWord.Create(0x9000, "Duplicate."));
    }

    [TestMethod]
    public void WordsContainsAllWellKnownInstances()
    {
        IReadOnlyList<StatusWord> words = StatusWord.Words;

        Assert.Contains(StatusWord.Success, words, "Words should contain Success.");
        Assert.Contains(StatusWord.FileNotFound, words, "Words should contain FileNotFound.");
        Assert.Contains(StatusWord.InstructionNotSupported, words, "Words should contain InstructionNotSupported.");
    }

    [TestMethod]
    public void SafeNetVendorCodeFromFirstTrace()
    {
        //0x6999 appears in the SafeNet eToken trace as a vendor-specific
        //response during AID probing. Without registration, it falls into
        //the "command not allowed" range (SW1=0x69).
        StatusWord sw = StatusWord.FromValue(0x6999);

        Assert.IsFalse(sw.IsSuccess);
        Assert.IsTrue(sw.IsCheckingError);

        string name = StatusWordNames.GetName(sw);
        Assert.Contains("0x6999", name, $"Expected hex in '{name}'.");
    }
}
