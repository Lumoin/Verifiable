using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XmlNodeTable.TryFindElementById"/> recognition of an un-prefixed attribute with local
/// name exactly <c>Id</c> and of <c>xml:id</c>, refusal of the platform's promiscuous <c>ID</c>/<c>id</c>
/// case variants, and fail-closed refusal on a document-wide duplicate value rather than resolving to the
/// first match — the same discipline that closes signature-wrapping attacks by ambiguous targets.
/// </summary>
[TestClass]
internal sealed class XmlNodeTableIdLookupTests
{
    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves that an un-prefixed attribute with local name exactly <c>Id</c> resolves to its element —
    /// the XMLDSIG schema's own typed attribute name at every attribute-definition site, which grounds
    /// the null-URI/shortname-XPointer support <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">
    /// XML Signature Syntax and Processing (Second Edition)</see> section 4.3.3.2 requires of every
    /// conformant application.
    /// </summary>
    [TestMethod]
    public void UnprefixedIdAttributeResolvesToItsElement()
    {
        using XmlNodeTable table = Parse("<doc><a Id=\"target\"/><b/></doc>");

        bool isFound = table.TryFindElementById("target"u8, out int elementIndex, out XmlSignatureProcessingError error);

        Assert.IsTrue(isFound, $"The Id attribute must resolve but was refused with {error.Failure}.");
        Assert.AreSequenceEqual("a"u8.ToArray(), table.LocalNameOf(elementIndex).ToArray(), "The lookup must resolve to element 'a'.");
    }


    /// <summary>
    /// Proves the <c>xml:id</c> attribute resolves to its element, per <see
    /// href="https://www.w3.org/TR/2005/REC-xml-id-20050909/">xml:id Version 1.0</see>: an ID
    /// independently of any document type declaration, which this lookup recognizes beside the
    /// un-prefixed <c>Id</c> attribute.
    /// </summary>
    [TestMethod]
    public void XmlIdAttributeResolvesToItsElement()
    {
        using XmlNodeTable table = Parse("<doc><a xml:id=\"target\"/><b/></doc>");

        bool isFound = table.TryFindElementById("target"u8, out int elementIndex, out XmlSignatureProcessingError error);

        Assert.IsTrue(isFound, $"The xml:id attribute must resolve but was refused with {error.Failure}.");
        Assert.AreSequenceEqual("a"u8.ToArray(), table.LocalNameOf(elementIndex).ToArray(), "The lookup must resolve to element 'a'.");
    }


    /// <summary>
    /// Proves that a value no recognized attribute carries refuses as <see
    /// cref="XmlSignatureProcessingFailure.IdNotFound"/> — the lookup this null-URI/shortname XPointer
    /// resolution of <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax
    /// and Processing (Second Edition)</see> section 4.3.3.2 depends on must fail closed rather than silently
    /// match nothing.
    /// </summary>
    [TestMethod]
    public void MissingValueRefusesAsIdNotFound()
    {
        using XmlNodeTable table = Parse("<doc><a Id=\"present\"/></doc>");

        bool isFound = table.TryFindElementById("absent"u8, out int elementIndex, out XmlSignatureProcessingError error);

        Assert.IsFalse(isFound);
        Assert.AreEqual(-1, elementIndex);
        Assert.AreEqual(XmlSignatureProcessingFailure.IdNotFound, error.Failure);
    }


    /// <summary>
    /// Proves that a document-wide duplicate value among recognized <c>ID</c>-typed attributes refuses at
    /// lookup time as <see cref="XmlSignatureProcessingFailure.DuplicateId"/> rather than resolving to the
    /// first match —
    /// fail-closed, because ambiguous targets are how signature-wrapping attacks work. The duplicate spans
    /// both recognized attribute forms: one <c>Id</c> and one <c>xml:id</c> sharing a value are just as
    /// ambiguous as two of the same form, both of which back the null-URI/shortname-XPointer resolution <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.2 requires this lookup to support.
    /// </summary>
    [TestMethod]
    public void DuplicateRecognizedValueRefusesAsDuplicateId()
    {
        using XmlNodeTable table = Parse("<doc><a Id=\"dup\"/><b xml:id=\"dup\"/></doc>");

        bool isFound = table.TryFindElementById("dup"u8, out int elementIndex, out XmlSignatureProcessingError error);

        Assert.IsFalse(isFound, "A document-wide duplicate value must refuse rather than resolve to the first match.");
        Assert.AreEqual(-1, elementIndex);
        Assert.AreEqual(XmlSignatureProcessingFailure.DuplicateId, error.Failure);
    }


    /// <summary>
    /// Proves ONE element carrying the same value on BOTH recognized <c>ID</c>-typed attributes — its own
    /// <c>Id</c> and its own <c>xml:id</c> — resolves as a single unambiguous target rather than refusing
    /// <see cref="XmlSignatureProcessingFailure.DuplicateId"/>, unlike <see
    /// cref="DuplicateRecognizedValueRefusesAsDuplicateId"/>'s TWO different elements: a redundant
    /// self-identification under both recognized ID spellings is not the ambiguous-target shape the
    /// fail-closed posture exists to catch, because both spellings resolve back to the very same element —
    /// the "element node identified by" language of <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.2 names one node, not one attribute occurrence.
    /// </summary>
    [TestMethod]
    public void SameElementCarryingBothRecognizedIdAttributesWithEqualValuesIsUnambiguous()
    {
        using XmlNodeTable table = Parse("<doc><a Id=\"dup\" xml:id=\"dup\"/><b/></doc>");

        bool isFound = table.TryFindElementById("dup"u8, out int elementIndex, out XmlSignatureProcessingError error);

        Assert.IsTrue(isFound, $"One element self-identifying under both recognized spellings must resolve but was refused with {error.Failure}.");
        Assert.AreSequenceEqual("a"u8.ToArray(), table.LocalNameOf(elementIndex).ToArray(), "The lookup must resolve to element 'a'.");
    }


    /// <summary>
    /// Proves that the un-prefixed case variants <c>ID</c> and <c>id</c> are NOT recognized, unlike
    /// platform <c>SignedXml</c>'s promiscuous matching —
    /// a known wrapping-attack surface this lookup deliberately does not absorb: an attacker-controlled element
    /// carrying <c>ID="target"</c> or <c>id="target"</c> instead of the recognized <c>Id="target"</c> is
    /// invisible to the lookup, which still refuses as <see
    /// cref="XmlSignatureProcessingFailure.IdNotFound"/> rather than silently matching it, since <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.2 names a specific recognized attribute set, not any case-folded
    /// variant of it.
    /// </summary>
    [TestMethod]
    public void UppercaseAndLowercaseIdCaseVariantsAreNotRecognized()
    {
        using XmlNodeTable upper = Parse("<doc><a ID=\"target\"/></doc>");
        using XmlNodeTable lower = Parse("<doc><a id=\"target\"/></doc>");

        bool isUpperFound = upper.TryFindElementById("target"u8, out int upperIndex, out XmlSignatureProcessingError upperError);
        bool isLowerFound = lower.TryFindElementById("target"u8, out int lowerIndex, out XmlSignatureProcessingError lowerError);

        Assert.IsFalse(isUpperFound, "The un-prefixed 'ID' case variant must not be recognized.");
        Assert.AreEqual(-1, upperIndex);
        Assert.AreEqual(XmlSignatureProcessingFailure.IdNotFound, upperError.Failure);
        Assert.IsFalse(isLowerFound, "The un-prefixed 'id' case variant must not be recognized.");
        Assert.AreEqual(-1, lowerIndex);
        Assert.AreEqual(XmlSignatureProcessingFailure.IdNotFound, lowerError.Failure);
    }


    /// <summary>
    /// Proves the exact recognized set: a prefixed attribute named <c>Id</c> in a non-<c>xml</c> namespace is
    /// not recognized, since this lookup names exactly the un-prefixed <c>Id</c> attribute and the
    /// <c>xml</c>-namespace <c>id</c> attribute, nothing else — the exact recognized set <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.2's null-URI/shortname-XPointer MUST is scoped to.
    /// </summary>
    [TestMethod]
    public void PrefixedIdInAnotherNamespaceIsNotRecognized()
    {
        using XmlNodeTable table = Parse("<doc xmlns:p=\"urn:example\"><a p:Id=\"target\"/></doc>");

        bool isFound = table.TryFindElementById("target"u8, out int elementIndex, out XmlSignatureProcessingError error);

        Assert.IsFalse(isFound);
        Assert.AreEqual(-1, elementIndex);
        Assert.AreEqual(XmlSignatureProcessingFailure.IdNotFound, error.Failure);
    }
}
