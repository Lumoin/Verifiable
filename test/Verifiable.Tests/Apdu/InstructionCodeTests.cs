using System;

using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class InstructionCodeTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void SelectHasCorrectCode()
    {
        Assert.AreEqual((byte)0xA4, InstructionCode.Select.Code);
    }

    [TestMethod]
    public void GetResponseHasCorrectCode()
    {
        Assert.AreEqual((byte)0xC0, InstructionCode.GetResponse.Code);
    }

    [TestMethod]
    public void GetDataSimpleHasCorrectCode()
    {
        Assert.AreEqual((byte)0xCA, InstructionCode.GetDataSimple.Code);
    }

    [TestMethod]
    public void GetDataBerTlvHasCorrectCode()
    {
        Assert.AreEqual((byte)0xCB, InstructionCode.GetDataBerTlv.Code);
    }

    [TestMethod]
    public void PutDataHasCorrectCode()
    {
        Assert.AreEqual((byte)0xDB, InstructionCode.PutData.Code);
    }

    [TestMethod]
    public void VerifyHasCorrectCode()
    {
        Assert.AreEqual((byte)0x20, InstructionCode.Verify.Code);
    }

    [TestMethod]
    public void ChangeReferenceDataHasCorrectCode()
    {
        Assert.AreEqual((byte)0x24, InstructionCode.ChangeReferenceData.Code);
    }

    [TestMethod]
    public void ResetRetryCounterHasCorrectCode()
    {
        Assert.AreEqual((byte)0x2C, InstructionCode.ResetRetryCounter.Code);
    }

    [TestMethod]
    public void GeneralAuthenticateHasCorrectCode()
    {
        Assert.AreEqual((byte)0x87, InstructionCode.GeneralAuthenticate.Code);
    }

    [TestMethod]
    public void GenerateAsymmetricKeyPairHasCorrectCode()
    {
        Assert.AreEqual((byte)0x47, InstructionCode.GenerateAsymmetricKeyPair.Code);
    }

    [TestMethod]
    public void FromValueCreatesMatchingInstance()
    {
        InstructionCode fromWire = InstructionCode.FromValue(0xA4);

        Assert.AreEqual(InstructionCode.Select, fromWire);
    }

    [TestMethod]
    public void FromValueWithUnknownCodeSucceeds()
    {
        InstructionCode unknown = InstructionCode.FromValue(0xFF);

        Assert.AreEqual((byte)0xFF, unknown.Code);
    }

    [TestMethod]
    public void EqualityBetweenRegisteredAndWireValues()
    {
        InstructionCode fromWire = InstructionCode.FromValue(0xCB);

        Assert.AreEqual(InstructionCode.GetDataBerTlv, fromWire);
        Assert.IsTrue(fromWire == InstructionCode.GetDataBerTlv);
    }

    [TestMethod]
    public void InequalityBetweenDifferentCodes()
    {
        Assert.AreNotEqual(InstructionCode.Select, InstructionCode.Verify);
        Assert.IsTrue(InstructionCode.Select != InstructionCode.Verify);
    }

    [TestMethod]
    public void NameForWellKnownCode()
    {
        string name = InstructionCodeNames.GetName(InstructionCode.Select);

        Assert.AreEqual("Select", name);
    }

    [TestMethod]
    public void NameForPutData()
    {
        string name = InstructionCodeNames.GetName(InstructionCode.PutData);

        Assert.AreEqual("PutData", name);
    }

    [TestMethod]
    public void NameForResetRetryCounter()
    {
        string name = InstructionCodeNames.GetName(InstructionCode.ResetRetryCounter);

        Assert.AreEqual("ResetRetryCounter", name);
    }

    [TestMethod]
    public void NameForUnknownCodeIncludesHex()
    {
        InstructionCode unknown = InstructionCode.FromValue(0xAB);
        string name = InstructionCodeNames.GetName(unknown);

        Assert.AreEqual("Unknown (0xAB)", name);
    }

    [TestMethod]
    public void ToStringDelegatesToNames()
    {
        string result = InstructionCode.GeneralAuthenticate.ToString();

        Assert.AreEqual("GeneralAuthenticate", result);
    }

    [TestMethod]
    public void CreateRegistersVendorInstruction()
    {
        InstructionCode vendorIns = InstructionCode.Create(0xFE, "VENDOR TEST");

        Assert.AreEqual((byte)0xFE, vendorIns.Code);

        string name = InstructionCodeNames.GetName(vendorIns);
        Assert.AreEqual("VENDOR TEST", name);
    }

    [TestMethod]
    public void CreateThrowsOnDuplicate()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            InstructionCode.Create(0xA4, "Duplicate SELECT."));
    }

    [TestMethod]
    public void CodesContainsAllWellKnownInstances()
    {
        IReadOnlyList<InstructionCode> codes = InstructionCode.Codes;

        Assert.Contains(InstructionCode.Select, codes, "Codes should contain Select.");
        Assert.Contains(InstructionCode.PutData, codes, "Codes should contain PutData.");
        Assert.Contains(InstructionCode.GeneralAuthenticate, codes, "Codes should contain GeneralAuthenticate.");
        Assert.Contains(InstructionCode.ResetRetryCounter, codes, "Codes should contain ResetRetryCounter.");
    }

    [TestMethod]
    public void HashCodeMatchesForEqualValues()
    {
        InstructionCode a = InstructionCode.Select;
        InstructionCode b = InstructionCode.FromValue(0xA4);

        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
    }

    [TestMethod]
    public void TraceInstructionCodesResolveCorrectly()
    {
        //From the SafeNet eToken traces.
        Assert.AreEqual("Select", InstructionCodeNames.GetName(0xA4));
        Assert.AreEqual("GetDataSimple", InstructionCodeNames.GetName(0xCA));
        Assert.AreEqual("GetDataBerTlv", InstructionCodeNames.GetName(0xCB));
        Assert.AreEqual("PutData", InstructionCodeNames.GetName(0xDB));
        Assert.AreEqual("GeneralAuthenticate", InstructionCodeNames.GetName(0x87));
        Assert.AreEqual("GenerateAsymmetricKeyPair", InstructionCodeNames.GetName(0x47));
        Assert.AreEqual("ResetRetryCounter", InstructionCodeNames.GetName(0x2C));
    }
}
