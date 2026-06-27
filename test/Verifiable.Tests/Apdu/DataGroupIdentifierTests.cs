using System;
using Verifiable.Apdu.Lds;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the data-group identifier mapping (number ↔ presence tag ↔ file identifier), including
/// the EF.COM tag list of the real BSI ReferenceDataSet passport (DG1/2/3/4/14).
/// </summary>
[TestClass]
internal sealed class DataGroupIdentifierTests
{
    [TestMethod]
    public void MapsTheStandardDataGroupTagsAndFileIdentifiers()
    {
        //Doc 9303 Part 10: DG1=61/0x0101, DG2=75/0x0102 (special), DG3=63/0x0103, DG4=76/0x0104 (special),
        //DG14=6E/0x010E, DG15=6F/0x010F, DG16=70/0x0110.
        (int Number, byte Tag, ushort File)[] cases =
        [
            (1, 0x61, 0x0101), (2, 0x75, 0x0102), (3, 0x63, 0x0103), (4, 0x76, 0x0104),
            (14, 0x6E, 0x010E), (15, 0x6F, 0x010F), (16, 0x70, 0x0110)
        ];

        foreach((int number, byte tag, ushort file) in cases)
        {
            Assert.AreEqual(tag, DataGroupIdentifier.TagFromNumber(number), $"DG{number} tag.");
            Assert.AreEqual(file, DataGroupIdentifier.FileIdentifierFromNumber(number), $"DG{number} file id.");
            Assert.AreEqual(number, DataGroupIdentifier.NumberFromTag(tag), $"tag 0x{tag:X2} number.");
        }
    }


    [TestMethod]
    public void MapsTheRealEfComTagList()
    {
        //The EF.COM tag list parsed from the real BSI ReferenceDataSet: DG1, DG2, DG3, DG4, DG14.
        byte[] efComTagList = [0x61, 0x75, 0x63, 0x76, 0x6E];
        int[] expectedNumbers = [1, 2, 3, 4, 14];

        for(int i = 0; i < efComTagList.Length; i++)
        {
            Assert.AreEqual(expectedNumbers[i], DataGroupIdentifier.NumberFromTag(efComTagList[i]),
                $"EF.COM tag 0x{efComTagList[i]:X2} must map to DG{expectedNumbers[i]}.");
        }
    }


    [TestMethod]
    public void ReturnsNullForAnUnknownTag()
    {
        Assert.IsNull(DataGroupIdentifier.NumberFromTag(0x77), "0x77 (EF.SOD) is not a data-group tag.");
    }


    [TestMethod]
    public void RejectsAnOutOfRangeNumber()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => DataGroupIdentifier.FileIdentifierFromNumber(0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => DataGroupIdentifier.TagFromNumber(17));
    }
}
