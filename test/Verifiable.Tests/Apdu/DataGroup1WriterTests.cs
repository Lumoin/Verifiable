using System;
using System.Text;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.Mrz;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the EF.DG1 writer: it wraps an MRZ in the <c>61</c> / <c>5F1F</c> structure byte-for-byte
/// and round-trips through <see cref="DataGroup1.Parse"/>. Uses the Doc 9303 Appendix D.2 TD2 MRZ so the
/// owned producer reproduces the same data the parser tests read.
/// </summary>
[TestClass]
internal sealed class DataGroup1WriterTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";


    [TestMethod]
    public void WritesTheDataGroup1TemplateByteForByte()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);

        string expected = "614B5F1F48" + Convert.ToHexString(Encoding.ASCII.GetBytes(Td2MachineReadableZone));
        Assert.AreEqual(expected, Convert.ToHexString(dataGroup1.AsReadOnlySpan()),
            "DG1 must wrap the MRZ as 61 { 5F1F MRZ } byte-for-byte.");
    }


    [TestMethod]
    public void RoundTripsThroughParse()
    {
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);

        MachineReadableZone mrz = DataGroup1.Parse(dataGroup1.AsReadOnlySpan()).MachineReadableZone;

        Assert.AreEqual(MrzDocumentFormat.Td2, mrz.Format, "DG1 carries a TD2 MRZ.");
        Assert.AreEqual("L898902C<", mrz.DocumentNumber, "Document number must round-trip.");
        Assert.AreEqual("690806", mrz.DateOfBirth, "Date of birth must round-trip.");
        Assert.AreEqual("940623", mrz.DateOfExpiry, "Date of expiry must round-trip.");
    }
}
