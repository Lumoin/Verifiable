using System;
using System.Collections.Generic;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the EF.DG7 (displayed signature), EF.DG13 (free-format optional details), and EF.DG16 (persons
/// to notify) writers and parsers. DG7 and DG13 wrap their bytes in the data-group template and recover them
/// verbatim; DG16 writes a count and one template per person and round-trips the list, recovering the present
/// fields and parsing the omitted ones as <see langword="null"/>. The template tag and the file identifier
/// are checked on write.
/// </summary>
[TestClass]
internal sealed class DataGroup7And13And16Tests
{
    [TestMethod]
    public void RoundTripsTheDataGroup7SignatureImage()
    {
        ReadOnlySpan<byte> signatureImage = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0xAA, 0xBB, 0xCC, 0xDD];

        using ElementaryFile dataGroup7 = DataGroup7.Write(signatureImage, BaseMemoryPool.Shared);
        using DataGroup7 parsed = DataGroup7.Parse(dataGroup7.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(Convert.ToHexString(signatureImage), Convert.ToHexString(parsed.AsReadOnlySpan()), "The displayed signature image must round-trip.");
        Assert.AreEqual(DataGroup7.FileIdentifier, dataGroup7.FileIdentifier, "DG7 is written under file identifier 0x0107.");
        Assert.AreEqual((byte)0x67, dataGroup7.AsReadOnlySpan()[0], "DG7 begins with the template tag 0x67.");
    }


    [TestMethod]
    public void RoundTripsTheDataGroup13FreeFormatContent()
    {
        ReadOnlySpan<byte> content = [0x53, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];

        using ElementaryFile dataGroup13 = DataGroup13.Write(content, BaseMemoryPool.Shared);
        using DataGroup13 parsed = DataGroup13.Parse(dataGroup13.AsReadOnlySpan(), BaseMemoryPool.Shared);

        Assert.AreEqual(Convert.ToHexString(content), Convert.ToHexString(parsed.AsReadOnlySpan()), "The free-format content must round-trip.");
        Assert.AreEqual(DataGroup13.FileIdentifier, dataGroup13.FileIdentifier, "DG13 is written under file identifier 0x010D.");
        Assert.AreEqual((byte)0x6D, dataGroup13.AsReadOnlySpan()[0], "DG13 begins with the template tag 0x6D.");
    }


    [TestMethod]
    public void RoundTripsTheDataGroup16PersonsToNotify()
    {
        List<PersonToNotify> persons =
        [
            new("20240101", "ERIKSSON<<KARL", "+46111111111", "1 FIRST STREET"),
            new("20240202", "ERIKSSON<<INGRID", "+46222222222", null)
        ];

        using ElementaryFile dataGroup16 = DataGroup16.Write(persons, BaseMemoryPool.Shared);
        DataGroup16 parsed = DataGroup16.Parse(dataGroup16.AsReadOnlySpan());

        Assert.HasCount(2, parsed.PersonsToNotify, "Both persons must round-trip.");
        Assert.AreEqual("20240101", parsed.PersonsToNotify[0].DateOfRecord, "The first person's date of record must round-trip.");
        Assert.AreEqual("ERIKSSON<<KARL", parsed.PersonsToNotify[0].Name, "The first person's name must round-trip.");
        Assert.AreEqual("+46111111111", parsed.PersonsToNotify[0].Telephone, "The first person's telephone must round-trip.");
        Assert.AreEqual("1 FIRST STREET", parsed.PersonsToNotify[0].Address, "The first person's address must round-trip.");
        Assert.AreEqual("ERIKSSON<<INGRID", parsed.PersonsToNotify[1].Name, "The second person's name must round-trip.");
        Assert.IsNull(parsed.PersonsToNotify[1].Address, "An omitted address parses as null.");
        Assert.AreEqual(DataGroup16.FileIdentifier, dataGroup16.FileIdentifier, "DG16 is written under file identifier 0x0110.");
        Assert.AreEqual((byte)0x70, dataGroup16.AsReadOnlySpan()[0], "DG16 begins with the template tag 0x70.");
    }
}
