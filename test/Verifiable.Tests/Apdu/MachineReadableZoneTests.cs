using System;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Mrz;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates MRZ parsing against the worked examples in ICAO Doc 9303 Part 11 Appendix D.2 (a TD2
/// MRZ with a nine-character document number and a TD1 MRZ with a document number exceeding nine
/// characters) and confirms the parsed fields reproduce the BAC 'MRZ information' seed.
/// </summary>
[TestClass]
internal sealed class MachineReadableZoneTests
{
    public required TestContext TestContext { get; set; }


    [TestMethod]
    public void ParsesTheAppendixD2Td2Mrz()
    {
        const string mrz =
            "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
            "L898902C<3UTO6908061F9406236<<<<<<<8";

        MachineReadableZone parsed = MachineReadableZone.Parse(mrz);

        Assert.AreEqual(MrzDocumentFormat.Td2, parsed.Format, "The 72-character MRZ is TD2.");
        Assert.AreEqual("UTO", parsed.IssuingState, "Issuing state.");
        Assert.AreEqual("L898902C<", parsed.DocumentNumber, "The access-key document number is the nine-character field including fillers.");
        Assert.AreEqual("690806", parsed.DateOfBirth, "Date of birth.");
        Assert.AreEqual("940623", parsed.DateOfExpiry, "Date of expiry.");
        Assert.AreEqual("F", parsed.Sex, "Sex.");

        Assert.AreEqual("L898902C<369080619406236",
            BasicAccessControl.BuildMrzInformation(parsed.DocumentNumber, parsed.DateOfBirth, parsed.DateOfExpiry),
            "The parsed fields must reproduce the Appendix D.2 MRZ information.");
    }


    [TestMethod]
    public void ParsesTheAppendixD2Td1MrzWithExtendedDocumentNumber()
    {
        const string mrz =
            "I<UTOD23145890<7349<<<<<<<<<<<" +
            "3407127M9507122UTO<<<<<<<<<<<2" +
            "STEVENSON<<PETER<JOHN<<<<<<<<<";

        MachineReadableZone parsed = MachineReadableZone.Parse(mrz);

        Assert.AreEqual(MrzDocumentFormat.Td1, parsed.Format, "The 90-character MRZ is TD1.");
        Assert.AreEqual("UTO", parsed.IssuingState, "Issuing state.");
        Assert.AreEqual("D23145890734", parsed.DocumentNumber, "The extended document number is reassembled from the field and the optional-data overflow.");
        Assert.AreEqual("340712", parsed.DateOfBirth, "Date of birth.");
        Assert.AreEqual("950712", parsed.DateOfExpiry, "Date of expiry.");

        Assert.AreEqual("D23145890734934071279507122",
            BasicAccessControl.BuildMrzInformation(parsed.DocumentNumber, parsed.DateOfBirth, parsed.DateOfExpiry),
            "The parsed extended document number must reproduce the Appendix D.2 MRZ information.");
    }


    [TestMethod]
    public void ParsesATd3PassportMrz()
    {
        //The same Appendix D.2 person in TD3 (passport) layout: line 2 shares the document-number and
        //date positions with TD2; only the optional (personal number) field is wider. The optional
        //field and composite check digits are computed with the Part 3 algorithm.
        string line2Body = "L898902C<3UTO6908061F9406236" + new string('<', 14);
        string optionalCheck = MachineReadableZone.ComputeCheckDigit(new string('<', 14)).ToString();
        string compositeSource = "L898902C<3" + "6908061" + "9406236" + new string('<', 14) + optionalCheck;
        string composite = MachineReadableZone.ComputeCheckDigit(compositeSource).ToString();

        string mrz =
            "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
            line2Body + optionalCheck + composite;

        MachineReadableZone parsed = MachineReadableZone.Parse(mrz);

        Assert.AreEqual(MrzDocumentFormat.Td3, parsed.Format, "The 88-character MRZ is TD3.");
        Assert.AreEqual("P", parsed.DocumentCode, "Document code.");
        Assert.AreEqual("L898902C<", parsed.DocumentNumber, "Document number.");
        Assert.AreEqual("690806", parsed.DateOfBirth, "Date of birth.");
        Assert.AreEqual("940623", parsed.DateOfExpiry, "Date of expiry.");
    }


    [TestMethod]
    public void RejectsAnMrzWithATamperedDateOfBirthCheckDigit()
    {
        //The Appendix D.2 TD2 MRZ with the date-of-birth check digit flipped from 1 to 2.
        const string mrz =
            "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
            "L898902C<3UTO6908062F9406236<<<<<<<8";

        bool threw = false;
        try
        {
            _ = MachineReadableZone.Parse(mrz);
        }
        catch(InvalidOperationException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "Parsing must reject an MRZ whose date-of-birth check digit does not validate.");
    }
}
