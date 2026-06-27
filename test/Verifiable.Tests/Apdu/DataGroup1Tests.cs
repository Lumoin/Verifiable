using System;
using System.Text;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.Mrz;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates EF.DG1 parsing: the MRZ stored on the chip is unwrapped from its <c>61</c> / <c>5F1F</c>
/// BER-TLV structure and parsed through <see cref="MachineReadableZone"/>. The MRZ used is the ICAO
/// Doc 9303 Appendix D.2 TD2 worked example, and the parsed fields are checked to reproduce the BAC
/// 'MRZ information' seed — so DG1 ties the chip's own data to the access-key derivation.
/// </summary>
[TestClass]
internal sealed class DataGroup1Tests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";


    [TestMethod]
    public void ParsesTheAppendixD2Td2MachineReadableZone()
    {
        DataGroup1 dataGroup1 = DataGroup1.Parse(BuildDataGroup1(Td2MachineReadableZone));
        MachineReadableZone mrz = dataGroup1.MachineReadableZone;

        Assert.AreEqual(MrzDocumentFormat.Td2, mrz.Format, "DG1 carries a TD2 MRZ.");
        Assert.AreEqual("L898902C<", mrz.DocumentNumber, "Document number.");
        Assert.AreEqual("690806", mrz.DateOfBirth, "Date of birth.");
        Assert.AreEqual("940623", mrz.DateOfExpiry, "Date of expiry.");
        Assert.AreEqual("UTO", mrz.IssuingState, "Issuing state.");

        Assert.AreEqual("L898902C<369080619406236",
            BasicAccessControl.BuildMrzInformation(mrz.DocumentNumber, mrz.DateOfBirth, mrz.DateOfExpiry),
            "The MRZ read from DG1 must reproduce the Appendix D.2 BAC seed.");
    }


    [TestMethod]
    public void RejectsDataWithoutTheDataGroup1Template()
    {
        //An EF.COM template (tag 0x60) where a DG1 template (tag 0x61) is expected.
        byte[] notDataGroup1 = Convert.FromHexString("60145F0104303130365F36063034303030305C026175");

        bool threw = false;
        try
        {
            _ = DataGroup1.Parse(notDataGroup1);
        }
        catch(InvalidOperationException)
        {
            threw = true;
        }

        Assert.IsTrue(threw, "Parsing must reject data that is not a DG1 template.");
    }


    /// <summary>
    /// Wraps an MRZ string in the DG1 BER-TLV structure: <c>61 ‖ {5F1F ‖ MRZ}</c>. The MRZ lengths
    /// (TD1 90, TD2 72, TD3 88) fit a single length byte.
    /// </summary>
    private static byte[] BuildDataGroup1(string machineReadableZone)
    {
        byte[] mrz = Encoding.ASCII.GetBytes(machineReadableZone);
        int templateLength = 2 + 1 + mrz.Length;

        byte[] dataGroup1 = new byte[2 + templateLength];
        int offset = 0;
        dataGroup1[offset++] = 0x61;
        dataGroup1[offset++] = (byte)templateLength;
        dataGroup1[offset++] = 0x5F;
        dataGroup1[offset++] = 0x1F;
        dataGroup1[offset++] = (byte)mrz.Length;
        mrz.CopyTo(dataGroup1, offset);

        return dataGroup1;
    }
}
