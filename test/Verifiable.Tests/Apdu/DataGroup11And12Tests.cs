using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the EF.DG11 (additional personal details) and EF.DG12 (additional document details) writers and
/// parsers: each writes only the supplied character-string fields into the BER-TLV template and round-trips
/// them through its parser — the present fields are recovered and the omitted ones parse as
/// <see langword="null"/>. The template tag and the file identifier are checked on write.
/// </summary>
[TestClass]
internal sealed class DataGroup11And12Tests
{
    [TestMethod]
    public void RoundTripsTheDataGroup11PersonalDetails()
    {
        using ElementaryFile dataGroup11 = DataGroup11.Write(
            fullName: "ERIKSSON<<ANNA<MARIA",
            personalNumber: "1234567890",
            placeOfBirth: "STOCKHOLM",
            permanentAddress: "123 MAIN STREET<STOCKHOLM",
            telephone: "+46123456789",
            profession: "ENGINEER",
            title: "DR",
            personalSummary: "NONE",
            BaseMemoryPool.Shared);

        DataGroup11 parsed = DataGroup11.Parse(dataGroup11.AsReadOnlySpan());

        Assert.AreEqual("ERIKSSON<<ANNA<MARIA", parsed.FullName, "The full name must round-trip.");
        Assert.AreEqual("1234567890", parsed.PersonalNumber, "The personal number must round-trip.");
        Assert.AreEqual("STOCKHOLM", parsed.PlaceOfBirth, "The place of birth must round-trip.");
        Assert.AreEqual("123 MAIN STREET<STOCKHOLM", parsed.PermanentAddress, "The permanent address must round-trip.");
        Assert.AreEqual("+46123456789", parsed.Telephone, "The telephone must round-trip.");
        Assert.AreEqual("ENGINEER", parsed.Profession, "The profession must round-trip.");
        Assert.AreEqual("DR", parsed.Title, "The title must round-trip.");
        Assert.AreEqual("NONE", parsed.PersonalSummary, "The personal summary must round-trip.");
    }


    [TestMethod]
    public void DataGroup11OmitsAbsentFields()
    {
        using ElementaryFile dataGroup11 = DataGroup11.Write(
            fullName: "ERIKSSON<<ANNA", personalNumber: null, placeOfBirth: null, permanentAddress: null,
            telephone: null, profession: null, title: null, personalSummary: null, BaseMemoryPool.Shared);

        DataGroup11 parsed = DataGroup11.Parse(dataGroup11.AsReadOnlySpan());

        Assert.AreEqual("ERIKSSON<<ANNA", parsed.FullName, "The full name is present.");
        Assert.IsNull(parsed.PersonalNumber, "An omitted personal number parses as null.");
        Assert.IsNull(parsed.PlaceOfBirth, "An omitted place of birth parses as null.");
        Assert.AreEqual(DataGroup11.FileIdentifier, dataGroup11.FileIdentifier, "DG11 is written under file identifier 0x010B.");
        Assert.AreEqual((byte)0x6B, dataGroup11.AsReadOnlySpan()[0], "DG11 begins with the template tag 0x6B.");
    }


    [TestMethod]
    public void RoundTripsTheDataGroup12DocumentDetails()
    {
        using ElementaryFile dataGroup12 = DataGroup12.Write(
            issuingAuthority: "UTOPIA MINISTRY OF FOREIGN AFFAIRS",
            dateOfIssue: "20240101",
            endorsements: "SEE PAGE 5",
            taxExitRequirements: "NONE",
            personalizationDateTime: "20240101120000",
            personalizationSystemSerialNumber: "PS-0001",
            BaseMemoryPool.Shared);

        DataGroup12 parsed = DataGroup12.Parse(dataGroup12.AsReadOnlySpan());

        Assert.AreEqual("UTOPIA MINISTRY OF FOREIGN AFFAIRS", parsed.IssuingAuthority, "The issuing authority must round-trip.");
        Assert.AreEqual("20240101", parsed.DateOfIssue, "The date of issue must round-trip.");
        Assert.AreEqual("SEE PAGE 5", parsed.Endorsements, "The endorsements must round-trip.");
        Assert.AreEqual("NONE", parsed.TaxExitRequirements, "The tax/exit requirements must round-trip.");
        Assert.AreEqual("20240101120000", parsed.PersonalizationDateTime, "The personalization date and time must round-trip.");
        Assert.AreEqual("PS-0001", parsed.PersonalizationSystemSerialNumber, "The personalization system serial number must round-trip.");
        Assert.AreEqual(DataGroup12.FileIdentifier, dataGroup12.FileIdentifier, "DG12 is written under file identifier 0x010C.");
        Assert.AreEqual((byte)0x6C, dataGroup12.AsReadOnlySpan()[0], "DG12 begins with the template tag 0x6C.");
    }
}
