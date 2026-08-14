using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESInclude.TryRead"/> against the <c>IncludeType</c> data type of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see> clauses 5.1.4.3 (schema) and 5.1.4.4.2.1 (semantics): the mandatory
/// <c>URI</c> attribute, the optional <c>xsd:boolean</c> <c>referencedData</c> attribute, and the
/// attribute-only (no child content) shape the acquired v132 XSD's <c>IncludeType</c> declares — no
/// <c>xsd:sequence</c> at all, unlike every other clause-5.1.4 type.
/// </summary>
[TestClass]
internal sealed class XAdESIncludeTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1's XA-5.1.4.4.2.1-3's mandatory <c>URI</c> reads exact-character, and that
    /// <see cref="XAdESInclude.HasReferencedData"/> is <see langword="false"/> when the optional attribute
    /// (XA-5.1.4.4.2.1-5) is absent altogether.
    /// </summary>
    [TestMethod]
    public void RequiredUriReadsAndReferencedDataDefaultsToAbsent()
    {
        using XmlNodeTable table = Parse($"""<Include xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" URI="#target"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESInclude.TryRead(table, table.DocumentElementIndex, out XAdESInclude value, out XAdESReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        Assert.AreEqual("#target", Encoding.UTF8.GetString(value.Uri));
        Assert.IsFalse(value.HasReferencedData);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1, the mandatory <c>URI</c>'s absence is refused — the acquired v132 XSD declares it
    /// <c>use="required"</c>.
    /// </summary>
    [TestMethod]
    public void MissingUriIsRefused()
    {
        using XmlNodeTable table = Parse($"""<Include xmlns="{XAdESIdentifiers.XAdESNamespaceV132}"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESInclude.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "A missing URI must be refused.");
        Assert.AreEqual(XAdESReadFailure.MissingRequiredAttribute, error.Failure);
    }


    /// <summary>
    /// Proves each of the four <c>xsd:boolean</c> lexical literals
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#boolean">XML Schema Part 2:
    /// Datatypes</see> section 3.2.2 permits parses to the expected value for the <c>referencedData</c>
    /// attribute (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1's XA-5.1.4.4.2.1-5).
    /// </summary>
    [TestMethod]
    public void EachOfTheFourXsdBooleanLiteralsParses()
    {
        (string Literal, bool Expected)[] cases = [("true", true), ("1", true), ("false", false), ("0", false)];
        foreach((string literal, bool expected) in cases)
        {
            using XmlNodeTable table = Parse($"""<Include xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" URI="#target" referencedData="{literal}"/>""", BaseMemoryPool.Shared);
            bool isRead = XAdESInclude.TryRead(table, table.DocumentElementIndex, out XAdESInclude value, out XAdESReadError error);
            Assert.IsTrue(isRead, $"referencedData='{literal}' must read but was refused with {error.Failure}.");
            Assert.IsTrue(value.HasReferencedData);
            Assert.AreEqual(expected, value.ReferencedData, $"referencedData='{literal}' must parse to {expected}.");
        }
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1, a <c>referencedData</c> value outside the four canonical/non-canonical <c>xsd:boolean</c>
    /// literals — here the wrong-cased <c>"True"</c> — is refused rather than leniently accepted.
    /// </summary>
    [TestMethod]
    public void InvalidReferencedDataValueIsRefused()
    {
        using XmlNodeTable table = Parse($"""<Include xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" URI="#target" referencedData="True"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESInclude.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An out-of-lexical-space referencedData value must be refused.");
        Assert.AreEqual(XAdESReadFailure.InvalidBooleanAttributeValue, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1, an attribute beyond <c>URI</c>/<c>referencedData</c> is refused fail-closed — <c>IncludeType</c>
    /// declares no <c>xsd:anyAttribute</c> extension point.
    /// </summary>
    [TestMethod]
    public void UnknownAttributeIsRefused()
    {
        using XmlNodeTable table = Parse($"""<Include xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" URI="#target" unexpected="value"/>""", BaseMemoryPool.Shared);
        bool isRead = XAdESInclude.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An unrecognized attribute must be refused.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreAttribute, error.Failure);
    }


    /// <summary>
    /// Proves an element child is refused — the acquired v132 XSD's <c>IncludeType</c> declares no
    /// <c>xsd:sequence</c> at all, so it permits no children whatsoever, unlike every other <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause-5.1.4 type.
    /// </summary>
    [TestMethod]
    public void ElementChildIsRefused()
    {
        using XmlNodeTable table = Parse($"""<Include xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" URI="#target"><Unexpected/></Include>""", BaseMemoryPool.Shared);
        bool isRead = XAdESInclude.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "An element child must be refused — IncludeType has no content model.");
        Assert.AreEqual(XAdESReadFailure.UnknownCoreElement, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1, non-whitespace text content is refused — the same empty-content-model reasoning as
    /// <see cref="ElementChildIsRefused"/>.
    /// </summary>
    [TestMethod]
    public void NonWhitespaceTextContentIsRefused()
    {
        using XmlNodeTable table = Parse($"""<Include xmlns="{XAdESIdentifiers.XAdESNamespaceV132}" URI="#target">stray text</Include>""", BaseMemoryPool.Shared);
        bool isRead = XAdESInclude.TryRead(table, table.DocumentElementIndex, out _, out XAdESReadError error);
        Assert.IsFalse(isRead, "Non-whitespace text content must be refused — IncludeType has no content model.");
        Assert.AreEqual(XAdESReadFailure.UnexpectedElementContent, error.Failure);
    }
}
