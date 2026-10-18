using System.Text;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// The shapes a reader of a document's members judges a member's value by, read by the library's own reader: the elements of an
/// array member, each a typed answer (<see cref="JsonTopLevelMember.ArrayElements"/>), and whether a number is an integer
/// whatever its spelling (<see cref="DecimalNumber.IsInteger"/>).
/// </summary>
[TestClass]
internal sealed class JsonMemberShapeTests
{
    /// <summary>
    /// An array member a document carries is read element by element in document order, each a typed answer: a string with its
    /// text decoded once (RFC 8259 section 7), a number with its spelling, and every other value by its kind, a <c>null</c>, an
    /// object and an array among them; a member that is no array has no elements.
    /// </summary>
    [TestMethod]
    public void AnArrayMembersElementsAreReadEachAsATypedAnswer()
    {
        var reading = JwkJsonReader.ReadTopLevelMembers(/*lang=json,strict*/ "{\"values\":[\"a\\u00e9\",1.50,null,{\"x\":1},[2],true],\"single\":\"a\"}"u8) as JsonTopLevelMembers;

        Assert.IsNotNull(reading);

        var elements = reading.Members[0].ArrayElements();

        Assert.IsNotNull(elements);
        Assert.AreSequenceEqual(
            new JsonMemberLookup[]
            {
                new JsonMemberString("a\u00e9"),
                new JsonMemberNumber("1.50"),
                new JsonMemberOfOtherKind(JsonTopLevelValueKind.Null),
                new JsonMemberOfOtherKind(JsonTopLevelValueKind.Object),
                new JsonMemberOfOtherKind(JsonTopLevelValueKind.Array),
                new JsonMemberOfOtherKind(JsonTopLevelValueKind.True)
            },
            elements);
        Assert.IsNull(reading.Members[1].ArrayElements(), "A member that is no array has no elements.");
    }


    /// <summary>
    /// A member composed by a caller rather than read by the reader is judged as the reader would judge it: text that is no one
    /// well-formed JSON array, or an array holding a string naming no Unicode text (RFC 8259 section 8.2), has no elements, never
    /// an exception and never a guess.
    /// </summary>
    /// <param name="text">The member's text.</param>
    [TestMethod]
    [DataRow("[1,", DisplayName = "An array never closed")]
    [DataRow("[1] [2]", DisplayName = "An array followed by another")]
    [DataRow(/*lang=json,strict*/ "{\"a\":1}", DisplayName = "An object written as an array member")]
    [DataRow("[\"\\uD800\"]", DisplayName = "A string naming no Unicode text")]
    public void ACallerComposedArrayTextOfAnotherShapeHasNoElements(string text)
    {
        Assert.IsNull(new JsonTopLevelMember("values", JsonTopLevelValueKind.Array, text).ArrayElements(), text);
    }


    /// <summary>
    /// A number is an integer when no significant digit lies after its point, whatever its spelling: <c>1700000000</c>,
    /// <c>1700000000.0</c>, <c>1.7e9</c> and zero are integers; <c>1700000000.5</c> and <c>1e-1</c> are not.
    /// </summary>
    /// <param name="spelling">The number as a document writes it.</param>
    /// <param name="isInteger">Whether it is an integer.</param>
    [TestMethod]
    [DataRow("1700000000", true)]
    [DataRow("1700000000.0", true)]
    [DataRow("1.7e9", true)]
    [DataRow("0", true)]
    [DataRow("-12", true)]
    [DataRow("1700000000.5", false)]
    [DataRow("1e-1", false)]
    public void ANumberIsAnIntegerWhateverItsSpelling(string spelling, bool isInteger)
    {
        var number = DecimalNumber.FromJsonNumber(Encoding.UTF8.GetBytes(spelling));

        Assert.IsNotNull(number, spelling);
        Assert.AreEqual(isInteger, number.IsInteger, spelling);
    }
}
